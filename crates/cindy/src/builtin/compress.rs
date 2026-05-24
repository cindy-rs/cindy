//! Compress a byte stream with a pure-Rust codec.
//!
//! This is the compression half of the de/compression pair, factored
//! out of [`archive`](super::archive) so the codec logic lives in one
//! place and is independently usable. The [`archive`](super::archive)
//! module reuses it through `compress::compress::inner` for the
//! tar-based formats.
//!
//! All codecs are pure Rust — `flate2`/miniz_oxide (gzip), `lzma-rs`
//! (xz), `ruzstd` (zstd) — so no C or dynamic libraries are pulled in.

use std::io::Write as _;

// Only referenced by the macro-generated RPC/dispatch code under the
// `remote`/`orchestrator` features; unused in the plain build.
#[allow(unused_imports)]
use crate as cindy;
use crate::Context;

use super::Codec;

/// Compress an in-memory byte buffer on the remote machine.
///
/// In-crate callers (e.g. [`archive`](super::archive)) invoke this
/// directly as `compress::compress::inner(data, codec)`; the
/// orchestrator can also drive it over RPC.
#[crate::remote]
pub fn compress(data: Vec<u8>, codec: Codec) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    match codec {
        Codec::Store => out = data,
        Codec::Gzip => {
            let mut enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
            enc.write_all(&data).context("gzip compression failed")?;
            enc.finish().context("gzip finalisation failed")?;
        }
        Codec::Xz => {
            lzma_rs::xz_compress(&mut std::io::Cursor::new(&data), &mut out)
                .context("xz compression failed")?;
        }
        Codec::Zstd => {
            // `ruzstd`'s pure-Rust encoder currently emits the "fastest"
            // level only; that's an intentional, documented limitation.
            ruzstd::encoding::compress(
                std::io::Cursor::new(&data),
                &mut out,
                ruzstd::encoding::CompressionLevel::Fastest,
            );
        }
    }
    Ok(out)
}
