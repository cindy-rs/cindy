//! Decompress a byte stream with a pure-Rust codec.
//!
//! The decompression half of the de/compression pair, factored out of
//! [`unarchive`](super::unarchive) so the codec logic lives in one
//! place and is independently usable. The
//! [`unarchive`](super::unarchive) module reuses it through
//! `decompress::bounded` for the tar-based formats.
//!
//! All codecs are pure Rust — `flate2`/miniz_oxide (gzip), `lzma-rs`
//! (xz), `ruzstd` (zstd) — so no C or dynamic libraries are pulled in.

use std::io::Read;

// Only referenced by the macro-generated RPC/dispatch code under the
// `remote`/`orchestrator` features; unused in the plain build.
#[allow(unused_imports)]
use crate::Context;

use super::Codec;

/// Ceiling on decompressed output when no explicit `max_bytes` is
/// given. Kept equal to `fetch`'s default: the two knobs bound the
/// same pipeline (`fetch` stages the archive, `unarchive` expands it),
/// so they should agree on what "unbounded" means.
pub(crate) const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Decompress an in-memory byte buffer on the remote machine.
///
/// In-crate callers (e.g. [`unarchive`](super::unarchive)) invoke the
/// core directly as `decompress::bounded(data, codec, max_bytes)`; the
/// orchestrator can also drive this entry point over RPC, bounded by
/// [`DEFAULT_MAX_BYTES`].
#[crate::remote]
pub fn decompress(data: Vec<u8>, codec: Codec) -> crate::Result<Vec<u8>> {
    bounded(data, codec, DEFAULT_MAX_BYTES)
}

/// The decompression core with an explicit output ceiling, collecting
/// the result in memory.
///
/// The ceiling exists because decompression is multiplication: a few
/// kilobytes of crafted input can expand without bound, and the worker
/// holds the result. `fetch` bounds what it stages to disk; without
/// this bound, `fetch` → `unarchive` would download a small bomb and
/// detonate it in RAM. Hitting the limit is an error that names the
/// knob, mirroring `fetch`'s over-size rejection.
pub(crate) fn bounded(data: Vec<u8>, codec: Codec, max_bytes: u64) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    bounded_into(&data, codec, max_bytes, &mut out)?;
    Ok(out)
}

/// The same core, streaming into any writer — a `Vec<u8>` for
/// [`bounded`], or a temp file when `unarchive` needs the expanded tar
/// on disk instead of in RAM.
pub(crate) fn bounded_into(
    data: &[u8],
    codec: Codec,
    max_bytes: u64,
    out: &mut dyn std::io::Write,
) -> crate::Result<()> {
    match codec {
        // No expansion happens; the caller already holds the buffer.
        Codec::Store => {
            std::io::copy(&mut &data[..], out).context("store copy failed")?;
        }
        Codec::Gzip => {
            // `MultiGzDecoder`, not `GzDecoder`: gzip files are legally a
            // concatenation of members (`pigz`, `cat a.gz b.gz`), and the
            // single-member decoder silently stops after the first one.
            let mut decoder = flate2::read::MultiGzDecoder::new(data);
            copy_bounded(&mut decoder, out, max_bytes, "gzip")?;
        }
        Codec::Xz => {
            // lzma-rs offers no output limit of its own (its `memlimit`
            // bounds dictionary memory), so the bound lives on the sink.
            let mut reader = std::io::BufReader::new(data);
            let mut sink = BoundedWriter::new(out, max_bytes);
            match lzma_rs::xz_decompress(&mut reader, &mut sink) {
                Ok(()) => {}
                Err(_) if sink.exceeded() => return Err(limit_error("xz", max_bytes)),
                Err(e) => return Err(e).context("xz decompression failed"),
            }
        }
        Codec::Zstd => {
            // zstd files may hold multiple frames (`pzstd`, the seekable
            // format); `StreamingDecoder` stops at the end of one frame,
            // so per its docs we recreate it per frame until the input is
            // exhausted, skipping over skippable frames.
            use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};

            let mut input = data;
            let mut remaining = max_bytes;
            while !input.is_empty() {
                match ruzstd::decoding::StreamingDecoder::new(&mut input) {
                    Ok(mut decoder) => {
                        remaining -= copy_bounded(&mut decoder, out, remaining, "zstd")?;
                    }
                    Err(FrameDecoderError::ReadFrameHeaderError(
                        ReadFrameHeaderError::SkipFrame { length, .. },
                    )) => {
                        input = input
                            .get(length as usize..)
                            .context("zstd skippable frame length overruns the input")?;
                    }
                    Err(e) => crate::bail!("Couldn't start zstd decoder: {e}"),
                }
            }
        }
    }
    Ok(())
}

/// Pull a reader to EOF into `out`, refusing to transfer more than
/// `max_bytes` bytes across the whole read. Returns the bytes written.
fn copy_bounded(
    mut reader: impl Read,
    out: &mut dyn std::io::Write,
    max_bytes: u64,
    codec: &str,
) -> crate::Result<u64> {
    let mut chunk = [0u8; 64 * 1024];
    let mut written = 0u64;
    loop {
        let n = reader
            .read(&mut chunk)
            .context(format!("{codec} decompression failed"))?;
        if n == 0 {
            return Ok(written);
        }
        if written + u64::try_from(n).unwrap_or(u64::MAX) > max_bytes {
            return Err(limit_error(codec, max_bytes));
        }
        out.write_all(&chunk[..n])
            .context(format!("{codec} decompression failed"))?;
        written += n as u64;
    }
}

/// A `Write` wrapper that refuses to accept more than `max_bytes`
/// bytes, so a decompression bomb errors instead of allocating its
/// payload. `exceeded` distinguishes the limit being hit (a named
/// error) from the codec failing on its own.
struct BoundedWriter<'a> {
    out: &'a mut dyn std::io::Write,
    max_bytes: u64,
    written: u64,
    exceeded: bool,
}

impl<'a> BoundedWriter<'a> {
    fn new(out: &'a mut dyn std::io::Write, max_bytes: u64) -> Self {
        Self {
            out,
            max_bytes,
            written: 0,
            exceeded: false,
        }
    }

    fn exceeded(&self) -> bool {
        self.exceeded
    }
}

impl std::io::Write for BoundedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written + buf.len() as u64 > self.max_bytes {
            self.exceeded = true;
            return Err(std::io::Error::other("decompression output over the limit"));
        }
        self.out.write_all(buf)?;
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// A `Read` wrapper enforcing the same ceiling on the *reader* side —
/// for streaming a decoded stream straight into a consumer (tar
/// extraction) without an intermediate sink. The error carries the
/// same wording as [`limit_error`] so the log reads identically
/// whichever side tripped it.
pub(crate) struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    limit_message: String,
}

impl<R: Read> BoundedReader<R> {
    pub(crate) fn new(inner: R, codec: &str, max_bytes: u64) -> Self {
        Self {
            inner,
            remaining: max_bytes,
            limit_message: format!(
                "{codec} output exceeds the {max_bytes}-byte decompression limit \
                 (raise `max_bytes` if that really is the content's size)"
            ),
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.remaining {
            self.remaining = 0;
            return Err(std::io::Error::other(self.limit_message.clone()));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// The over-size rejection, worded like `fetch`'s so the two knobs read
/// the same in a log. Returns the error *value* so both the reader-side
/// and writer-side ceilings can raise it from inside `io::Result`s.
fn limit_error(codec: &str, max_bytes: u64) -> crate::Error {
    crate::Error::msg(format!(
        "{codec} output exceeds the {max_bytes}-byte decompression limit \
         (raise `max_bytes` if that really is the content's size)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// A few hundred bytes of crafted gzip that expands to MiB — the
    /// decompression bomb the ceiling exists for. The plan's done-when:
    /// a named error, not an allocation.
    #[test]
    fn oversized_output_is_a_named_error_not_an_allocation() {
        let bomb = gz(&[0u8; 256 * 1024]);
        assert!(bomb.len() < 1024, "the bomb must actually be small");

        let err = bounded(bomb, Codec::Gzip, 64 * 1024).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("gzip"), "{msg}");
        assert!(msg.contains("max_bytes"), "{msg}");
        assert!(msg.contains("64 * 1024") || msg.contains("65536"), "{msg}");
    }

    #[test]
    fn output_at_the_ceiling_passes_and_store_is_untouched() {
        let data = vec![0u8; 64];
        // Store never expands, so the ceiling doesn't apply.
        assert_eq!(bounded(data.clone(), Codec::Store, 32).unwrap(), data);
        // Exactly at the limit is fine — the ceiling is inclusive.
        assert_eq!(bounded(gz(&data), Codec::Gzip, 64).unwrap(), data);
    }
}
