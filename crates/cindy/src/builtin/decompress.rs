//! Decompress a byte stream (pure-Rust codecs).
//!
//! Decompression is multiplication — a few KiB of crafted input can
//! expand without bound — so every decode here has an output ceiling.

use std::io::{BufRead, Read, Write};

use crate::Context;

use super::Codec;

#[crate::remote]
pub fn decompress(data: Vec<u8>, codec: Codec) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    decompress_into(codec, &mut &data[..], super::DEFAULT_MAX_BYTES, &mut out)?;
    Ok(out)
}

/// Decode `input` into `out`, failing with [`LimitExceeded`] past
/// `max_bytes` of output. `Store` doesn't expand and isn't bounded.
pub(crate) fn decompress_into(
    codec: Codec,
    input: &mut dyn BufRead,
    max_bytes: u64,
    out: &mut dyn Write,
) -> crate::Result<()> {
    let limit = LimitExceeded {
        codec: codec_name(codec),
        max_bytes,
    };
    let mut sink = Bounded {
        out,
        remaining: max_bytes,
        exceeded: false,
    };
    let result = match codec {
        Codec::Store => std::io::copy(input, sink.out).map(drop),
        // Multi-member: `pigz` and `cat a.gz b.gz` are valid gzip, and
        // `GzDecoder` stops after the first member.
        Codec::Gzip => {
            std::io::copy(&mut flate2::read::MultiGzDecoder::new(input), &mut sink).map(drop)
        }
        Codec::Xz => {
            lzma_rs::xz_decompress(&mut &mut *input, &mut sink).map_err(std::io::Error::other)
        }
        Codec::Zstd => decode_zstd_frames(input, &mut sink),
    };
    // Checked first: a codec may wrap or swallow the sink's error.
    if sink.exceeded {
        return Err(limit.into());
    }
    result.context(format!("{} decompression failed", limit.codec))
}

/// `StreamingDecoder` stops after one frame, but a zstd file may hold
/// several (`pzstd`, the seekable format), and skippable ones between.
fn decode_zstd_frames(input: &mut dyn BufRead, out: &mut dyn Write) -> std::io::Result<()> {
    use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};

    while !input.fill_buf()?.is_empty() {
        match ruzstd::decoding::StreamingDecoder::new(&mut *input) {
            Ok(mut frame) => {
                std::io::copy(&mut frame, out)?;
            }
            Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                length,
                ..
            })) => {
                std::io::copy(&mut input.take(u64::from(length)), &mut std::io::sink())?;
            }
            Err(e) => return Err(std::io::Error::other(e)),
        }
    }
    Ok(())
}

fn codec_name(codec: Codec) -> &'static str {
    match codec {
        Codec::Store => "store",
        Codec::Gzip => "gzip",
        Codec::Xz => "xz",
        Codec::Zstd => "zstd",
    }
}

/// The decompression ceiling was hit. An error type rather than a
/// message, so callers can find it in a wrapped chain.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LimitExceeded {
    codec: &'static str,
    max_bytes: u64,
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} output exceeds the {}-byte decompression limit \
             (raise `max_bytes` if that really is the content's size)",
            self.codec, self.max_bytes
        )
    }
}

impl std::error::Error for LimitExceeded {}

impl LimitExceeded {
    /// The ceiling, if it is anywhere in `err`'s chain.
    pub(crate) fn find(err: &(dyn std::error::Error + 'static)) -> Option<Self> {
        let mut cause = Some(err);
        while let Some(e) = cause {
            let found = e.downcast_ref::<Self>().or_else(|| {
                e.downcast_ref::<std::io::Error>()
                    .and_then(|io| io.get_ref()?.downcast_ref::<Self>())
            });
            if let Some(limit) = found {
                return Some(*limit);
            }
            cause = e.source();
        }
        None
    }
}

struct Bounded<'a> {
    out: &'a mut dyn Write,
    remaining: u64,
    exceeded: bool,
}

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(left) = self.remaining.checked_sub(buf.len() as u64) else {
            self.exceeded = true;
            return Err(std::io::Error::other("decompression output over the limit"));
        };
        self.out.write_all(buf)?;
        self.remaining = left;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// The same ceiling on a decoded stream that is read rather than
/// written out (a tar being unpacked as it decodes).
pub(crate) struct BoundedReader<R> {
    inner: R,
    remaining: u64,
    limit: LimitExceeded,
}

impl<R: Read> BoundedReader<R> {
    pub(crate) fn new(inner: R, codec: Codec, max_bytes: u64) -> Self {
        Self {
            inner,
            remaining: max_bytes,
            limit: LimitExceeded {
                codec: codec_name(codec),
                max_bytes,
            },
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.remaining = self
            .remaining
            .checked_sub(n as u64)
            .ok_or_else(|| std::io::Error::other(self.limit))?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn decode(codec: Codec, data: &[u8], max_bytes: u64) -> crate::Result<Vec<u8>> {
        let mut out = Vec::new();
        decompress_into(codec, &mut &data[..], max_bytes, &mut out)?;
        Ok(out)
    }

    #[test]
    fn a_bomb_is_a_named_error_not_an_allocation() {
        let bomb = gz(&[0u8; 256 * 1024]);
        assert!(bomb.len() < 1024, "the bomb must actually be small");

        let msg = decode(Codec::Gzip, &bomb, 64 * 1024)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("gzip"), "{msg}");
        assert!(msg.contains("max_bytes"), "{msg}");
        assert!(msg.contains("65536"), "{msg}");
    }

    #[test]
    fn the_ceiling_is_inclusive_and_store_is_unbounded() {
        let data = vec![0u8; 64];
        assert_eq!(decode(Codec::Gzip, &gz(&data), 64).unwrap(), data);
        assert_eq!(decode(Codec::Store, &data, 32).unwrap(), data);
    }

    #[test]
    fn multiple_zstd_frames_and_skippable_frames_all_decode() {
        let frame = |bytes: &[u8]| {
            let mut out = Vec::new();
            super::super::compress::compress_into(Codec::Zstd, &mut &bytes[..], &mut out).unwrap();
            out
        };
        // A skippable frame: magic 0x184D2A50, little-endian length, payload.
        let mut input = frame(b"one ");
        input.extend([0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, b'x', b'y', b'z']);
        input.extend(frame(b"two"));
        assert_eq!(decode(Codec::Zstd, &input, 1024).unwrap(), b"one two");
    }

    #[test]
    fn the_reader_side_ceiling_is_findable_through_a_wrapping_error() {
        let mut reader = BoundedReader::new(&[0u8; 10][..], Codec::Gzip, 4);
        let io_err = reader.read(&mut [0u8; 10]).unwrap_err();
        let wrapped = crate::Error::from(io_err).context("Couldn't unpack tar");
        let found = LimitExceeded::find(wrapped.as_ref()).expect("limit lost in the chain");
        assert!(found.to_string().contains("4-byte"), "{found}");
    }
}
