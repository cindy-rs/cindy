//! Compress a byte stream (pure-Rust codecs).

use crate::Context;

use super::Codec;

#[crate::remote]
pub fn compress(data: Vec<u8>, codec: Codec) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    compress_into(codec, &mut &data[..], &mut out)?;
    Ok(out)
}

/// `lzma-rs` has no incremental encoder: xz reads all of `input` before
/// writing, so give it a file, not an unbounded stream.
pub(crate) fn compress_into(
    codec: Codec,
    input: &mut dyn std::io::Read,
    output: &mut dyn std::io::Write,
) -> crate::Result<()> {
    let mut input = std::io::BufReader::new(input);
    match codec {
        Codec::Store => {
            std::io::copy(&mut input, output).context("store copy failed")?;
        }
        Codec::Gzip => {
            let mut enc = flate2::write::GzEncoder::new(output, flate2::Compression::default());
            std::io::copy(&mut input, &mut enc).context("gzip compression failed")?;
            enc.finish().context("gzip finalisation failed")?;
        }
        Codec::Xz => {
            lzma_rs::xz_compress(&mut input, &mut &mut *output).context("xz compression failed")?;
        }
        Codec::Zstd => {
            ruzstd::encoding::compress(input, output, ruzstd::encoding::CompressionLevel::Fastest);
        }
    }
    Ok(())
}
