//! Symmetric encryption used to seal a single secret's bytes with a
//! vault's key.
//!
//! ChaCha20-Poly1305 with a 96-bit random nonce: standard AEAD,
//! constant-time, no MAC truncation games. Each sealed blob carries
//! its own random nonce, so the same plaintext encrypted twice yields
//! different ciphertexts.
//!
//! Wire layout: `nonce (12 bytes) || ciphertext (N bytes) || tag (16 bytes)`,
//! which is what `chacha20poly1305`'s default `encrypt_in_place_detached`
//! produces concatenated.

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

/// Encrypt `plaintext` with `key`, returning `nonce || ciphertext || tag`.
pub fn seal(key: &VaultKey, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow_serde::Error::msg(format!("AEAD encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `framed = nonce || ciphertext || tag`. Returns the plaintext
/// (also held in `Zeroizing` so it's wiped if the caller drops it without
/// consuming).
pub fn unseal(key: &VaultKey, framed: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
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
        // Flip a bit in the ciphertext body (skip the nonce).
        ct[NONCE_LEN] ^= 0x01;
        assert!(unseal(&key, &ct).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = generate_vault_key();
        let key_b = generate_vault_key();
        let ct = seal(&key_a, b"x").unwrap();
        assert!(unseal(&key_b, &ct).is_err());
    }

    #[test]
    fn too_short_payload_rejected() {
        let key = generate_vault_key();
        assert!(unseal(&key, b"short").is_err());
    }
}
