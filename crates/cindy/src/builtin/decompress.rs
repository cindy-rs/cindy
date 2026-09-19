//! Decompress a byte stream with a pure-Rust codec.
//!
//! The decompression half of the de/compression pair, factored out of
//! [`unarchive`](super::unarchive) so the codec logic lives in one
//! place and is independently usable. The
//! [`unarchive`](super::unarchive) module reuses it through
//! `decompress::decompress::inner` for the tar-based formats.
//!
//! All codecs are pure Rust — `flate2`/miniz_oxide (gzip), `lzma-rs`
//! (xz), `ruzstd` (zstd) — so no C or dynamic libraries are pulled in.

use std::io::Read as _;

// Only referenced by the macro-generated RPC/dispatch code under the
// `remote`/`orchestrator` features; unused in the plain build.
#[allow(unused_imports)]
use crate::Context;

use super::Codec;

/// Decompress an in-memory byte buffer on the remote machine.
///
/// In-crate callers (e.g. [`unarchive`](super::unarchive)) invoke this
/// directly as `decompress::decompress::inner(data, codec)`; the
/// orchestrator can also drive it over RPC.
#[crate::remote]
pub fn decompress(data: Vec<u8>, codec: Codec) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    match codec {
        Codec::Store => out = data,
        Codec::Gzip => {
            // `MultiGzDecoder`, not `GzDecoder`: gzip files are legally a
            // concatenation of members (`pigz`, `cat a.gz b.gz`), and the
            // single-member decoder silently stops after the first one.
            flate2::read::MultiGzDecoder::new(&data[..])
                .read_to_end(&mut out)
                .context("gzip decompression failed")?;
        }
        Codec::Xz => {
            let mut reader = std::io::BufReader::new(&data[..]);
            lzma_rs::xz_decompress(&mut reader, &mut out).context("xz decompression failed")?;
        }
        Codec::Zstd => {
            // zstd files may hold multiple frames (`pzstd`, the seekable
            // format); `StreamingDecoder` stops at the end of one frame,
            // so per its docs we recreate it per frame until the input is
            // exhausted, skipping over skippable frames.
            use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};

            let mut input = &data[..];
            while !input.is_empty() {
                match ruzstd::decoding::StreamingDecoder::new(&mut input) {
                    Ok(mut decoder) => {
                        decoder
                            .read_to_end(&mut out)
                            .context("zstd decompression failed")?;
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
    Ok(out)
}
