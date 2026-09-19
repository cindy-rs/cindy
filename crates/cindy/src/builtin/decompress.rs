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

/// The decompression core with an explicit output ceiling.
///
/// The ceiling exists because decompression is multiplication: a few
/// kilobytes of crafted input can expand without bound, and the worker
/// holds the result in memory. `fetch` bounds what it stages to disk;
/// without this bound, `fetch` → `unarchive` would download a small
/// bomb and detonate it in RAM. Hitting the limit is an error that
/// names the knob, mirroring `fetch`'s over-size rejection.
pub(crate) fn bounded(data: Vec<u8>, codec: Codec, max_bytes: u64) -> crate::Result<Vec<u8>> {
    match codec {
        // No expansion happens; the caller already holds the buffer.
        Codec::Store => Ok(data),
        Codec::Gzip => {
            // `MultiGzDecoder`, not `GzDecoder`: gzip files are legally a
            // concatenation of members (`pigz`, `cat a.gz b.gz`), and the
            // single-member decoder silently stops after the first one.
            let mut decoder = flate2::read::MultiGzDecoder::new(&data[..]);
            read_all_bounded(&mut decoder, max_bytes, "gzip")
        }
        Codec::Xz => {
            // lzma-rs offers no output limit of its own (its `memlimit`
            // bounds dictionary memory), so the bound lives on the sink.
            let mut reader = std::io::BufReader::new(&data[..]);
            let mut sink = BoundedSink::new(max_bytes);
            match lzma_rs::xz_decompress(&mut reader, &mut sink) {
                Ok(()) => Ok(sink.into_output()),
                Err(_) if sink.exceeded() => limit_error("xz", max_bytes),
                Err(e) => Err(e).context("xz decompression failed"),
            }
        }
        Codec::Zstd => {
            // zstd files may hold multiple frames (`pzstd`, the seekable
            // format); `StreamingDecoder` stops at the end of one frame,
            // so per its docs we recreate it per frame until the input is
            // exhausted, skipping over skippable frames.
            use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};

            let mut input = &data[..];
            let mut out = Vec::new();
            let mut remaining = max_bytes;
            while !input.is_empty() {
                match ruzstd::decoding::StreamingDecoder::new(&mut input) {
                    Ok(mut decoder) => {
                        let frame = read_all_bounded(&mut decoder, remaining, "zstd")?;
                        remaining -= frame.len() as u64;
                        out.extend_from_slice(&frame);
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
            Ok(out)
        }
    }
}

/// Pull a reader to EOF, refusing to accumulate more than `max_bytes`
/// bytes across the whole read.
fn read_all_bounded(mut reader: impl Read, max_bytes: u64, codec: &str) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .context(format!("{codec} decompression failed"))?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() as u64 + u64::try_from(n).unwrap_or(u64::MAX) > max_bytes {
            return limit_error(codec, max_bytes);
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// A `Write` sink that refuses to accept more than `max_bytes` bytes,
/// so a decompression bomb errors instead of allocating its payload.
struct BoundedSink {
    out: Vec<u8>,
    max_bytes: u64,
    exceeded: bool,
}

impl BoundedSink {
    fn new(max_bytes: u64) -> Self {
        Self {
            out: Vec::new(),
            max_bytes,
            exceeded: false,
        }
    }

    fn into_output(self) -> Vec<u8> {
        self.out
    }

    fn exceeded(&self) -> bool {
        self.exceeded
    }
}

impl std::io::Write for BoundedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.out.len() as u64 + buf.len() as u64 > self.max_bytes {
            self.exceeded = true;
            return Err(std::io::Error::other("decompression output over the limit"));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The over-size rejection, worded like `fetch`'s so the two knobs read
/// the same in a log.
fn limit_error(codec: &str, max_bytes: u64) -> crate::Result<Vec<u8>> {
    crate::bail!(
        "{codec} output exceeds the {max_bytes}-byte decompression limit \
         (raise `max_bytes` if that really is the content's size)"
    )
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
