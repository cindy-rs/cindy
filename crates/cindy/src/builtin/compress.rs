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

// Only referenced by the macro-generated RPC/dispatch code under the
// `remote`/`orchestrator` features; unused in the plain build.
#[allow(unused_imports)]
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
    compress_into(codec, &mut &data[..], &mut out)?;
    Ok(out)
}

/// Compress from a reader into a writer without holding either side in
/// memory — the shape [`archive`](super::archive) uses to stream a tar
/// straight into its staged destination file. `Store` is a plain copy,
/// so an uncompressed tar never pays a second pass.
///
/// Codec limitations that hold here as everywhere: `ruzstd`'s encoder
/// emits the "fastest" level only, and `lzma-rs` has no incremental
/// (write-side) encoder, so `xz` reads its whole input from the reader
/// in one shot — callers with an unbounded reader should stage to a
/// file first, as `archive` does for the tar side.
pub(crate) fn compress_into(
    codec: Codec,
    input: &mut dyn std::io::Read,
    output: &mut dyn std::io::Write,
) -> crate::Result<()> {
    match codec {
        Codec::Store => {
            let mut input = std::io::BufReader::new(input);
            std::io::copy(&mut input, output).context("store copy failed")?;
        }
        Codec::Gzip => {
            let mut enc = flate2::write::GzEncoder::new(output, flate2::Compression::default());
            let mut input = std::io::BufReader::new(input);
            std::io::copy(&mut input, &mut enc).context("gzip compression failed")?;
            enc.finish().context("gzip finalisation failed")?;
        }
        Codec::Xz => {
            let mut input = std::io::BufReader::new(input);
            // `&mut w` (not `output`): the generic wants a `Sized`
            // writer, and `&mut dyn Write` is one — rebind first so the
            // binding itself can be borrowed mutably.
            let mut w: &mut dyn std::io::Write = output;
            lzma_rs::xz_compress(&mut input, &mut w).context("xz compression failed")?;
        }
        Codec::Zstd => {
            // `ruzstd`'s pure-Rust encoder currently emits the "fastest"
            // level only; that's an intentional, documented limitation.
            ruzstd::encoding::compress(input, output, ruzstd::encoding::CompressionLevel::Fastest);
        }
    }
    Ok(())
}
