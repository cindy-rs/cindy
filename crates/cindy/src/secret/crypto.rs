//! Symmetric encryption used to seal a single secret's bytes with a
//! vault's key.
//!
//! ChaCha20-Poly1305 with a 96-bit random nonce: standard AEAD,
//! constant-time, no MAC truncation games. Each sealed blob carries
//! its own random nonce, so the same plaintext encrypted twice yields
//! different ciphertexts.
//!
//! Wire layout: `nonce (12 bytes) || ciphertext (N bytes) || tag (16 bytes)`,
//! assembled by hand in [`seal`] from the AEAD's `encrypt` output
//! (`ciphertext || tag`) plus the fresh nonce it was encrypted under.

use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead as _, OsRng as AeadOsRng, rand_core::RngCore as _},
};
use zeroize::Zeroizing;

/// Length of a vault key in bytes. Matches ChaCha20-Poly1305.
pub const VAULT_KEY_LEN: usize = 32;

/// Length of the AEAD nonce prepended to every ciphertext.
pub const NONCE_LEN: usize = 12;

/// A vault's symmetric key. Held in `Zeroizing` so the underlying
/// bytes are wiped on drop. Pass by reference; never clone unnecessarily.
pub type VaultKey = Zeroizing<[u8; VAULT_KEY_LEN]>;

/// Generate a fresh random key using the OS CSPRNG. We piggy-back on
/// the `rand_core::OsRng` that ships with `chacha20poly1305`'s `aead`
/// re-export to avoid pulling a second version of `rand_core` into the
/// dependency graph.
pub fn generate_vault_key() -> VaultKey {
    let mut bytes = [0u8; VAULT_KEY_LEN];
    AeadOsRng.fill_bytes(&mut bytes);
    Zeroizing::new(bytes)
}

/// Version prefix on sealed blobs, so a future format change is a
/// clean, detectable migration instead of a parse failure
/// indistinguishable from corruption. v1 blobs are
/// `[0x01][nonce (12)][ciphertext (N)][tag (16)]`.
///
/// Legacy (pre-versioning, "v0") blobs are `[nonce][ct][tag]` with no
/// prefix; their first byte is random nonce, so it collides with this
/// marker ~1/256 of the time. Decoding therefore tries v1 on marker
/// match and falls back to the legacy layout when that fails — one
/// rejected decrypt attempt on those few old blobs, nothing otherwise.
pub const BLOB_VERSION: u8 = 1;

/// Encrypt `plaintext` with `key`, returning
/// `[version byte][nonce ‖ ciphertext ‖ tag]`.
pub fn seal(key: &VaultKey, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow_serde::Error::msg(format!("AEAD encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(BLOB_VERSION);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a sealed blob — v1 (version-prefixed) or legacy v0 (bare
/// `nonce ‖ ct ‖ tag`, with the marker-collision fallback described on
/// [`BLOB_VERSION`]). Returns the plaintext (also held in `Zeroizing`
/// so it's wiped if the caller drops it without consuming).
pub fn unseal(key: &VaultKey, framed: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
    if framed.first() == Some(&BLOB_VERSION)
        && let Ok(plaintext) = aead_decrypt(key, &framed[1..])
    {
        return Ok(plaintext);
    }
    aead_decrypt(key, framed)
}

/// Decrypt `nonce ‖ ciphertext ‖ tag` with the vault key.
fn aead_decrypt(key: &VaultKey, framed: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
    if framed.len() < NONCE_LEN {
        crate::bail!(
            "sealed payload too short ({} bytes); expected at least {NONCE_LEN}-byte nonce",
            framed.len()
        );
    }
    let (nonce_bytes, ct_and_tag) = framed.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let plaintext = cipher
        .decrypt(nonce, ct_and_tag)
        .map_err(|e| anyhow_serde::Error::msg(format!("AEAD decryption failed: {e}")))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = generate_vault_key();
        let pt = b"hunter2 is not a good password";
        let ct = seal(&key, pt).unwrap();
        let recovered = unseal(&key, &ct).unwrap();
        assert_eq!(&*recovered, pt);
    }

    #[test]
    fn distinct_nonces_per_encryption() {
        // Same plaintext, same key, two seals must yield different
        // ciphertexts (because each carries its own random nonce).
        let key = generate_vault_key();
        let pt = b"the quick brown fox";
        let a = seal(&key, pt).unwrap();
        let b = seal(&key, pt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tamper_detection() {
        let key = generate_vault_key();
        let pt = b"important";
        let mut ct = seal(&key, pt).unwrap();
        assert_eq!(ct[0], BLOB_VERSION, "new blobs carry the version byte");
        // Flip a bit in the ciphertext body (skip version and nonce).
        ct[1 + NONCE_LEN] ^= 0x01;
        assert!(unseal(&key, &ct).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = generate_vault_key();
        let key_b = generate_vault_key();
        let ct = seal(&key_a, b"x").unwrap();
        assert!(unseal(&key_b, &ct).is_err());
    }

    /// Blobs sealed before the version byte existed have no prefix and
    /// must keep working.
    #[test]
    fn legacy_blobs_unseal() {
        let key = generate_vault_key();
        let pt = b"sealed by cindy 0.3.0";
        let v1 = seal(&key, pt).unwrap();
        // The same AEAD blob without the version prefix is exactly what
        // a legacy blob looks like.
        let legacy = v1[1..].to_vec();
        let recovered = unseal(&key, &legacy).unwrap();
        assert_eq!(&*recovered, pt);
    }

    /// A legacy blob whose random nonce happens to start with the
    /// version byte takes the fallback path and still unseals.
    #[test]
    fn legacy_blob_with_colliding_nonce_prefix_unseals() {
        let key = generate_vault_key();
        let pt = b"unlucky nonce";

        // Build a bare (v0) blob whose nonce starts with BLOB_VERSION.
        let cipher = ChaCha20Poly1305::new(key.as_slice().into());
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = BLOB_VERSION;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), pt.as_slice())
            .unwrap();
        let mut legacy = nonce.to_vec();
        legacy.extend_from_slice(&ct);

        assert_eq!(legacy.first(), Some(&BLOB_VERSION));
        let recovered = unseal(&key, &legacy).unwrap();
        assert_eq!(&*recovered, pt);
    }

    /// An unknown future version is a named error, not silent garbage.
    #[test]
    fn unknown_version_fails_loudly() {
        let key = generate_vault_key();
        let mut ct = seal(&key, b"x").unwrap();
        ct[0] = 0x02;
        assert!(unseal(&key, &ct).is_err());
    }

    #[test]
    fn too_short_payload_rejected() {
        let key = generate_vault_key();
        assert!(unseal(&key, b"short").is_err());
    }
}
