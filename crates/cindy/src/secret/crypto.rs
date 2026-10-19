//! Sealing one secret under a vault key: ChaCha20-Poly1305, a fresh
//! random nonce per seal.
//!
//! Blob: `[version][nonce (12)][ciphertext][tag (16)]`.

use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead as _, OsRng as AeadOsRng, rand_core::RngCore as _},
};
use zeroize::Zeroizing;

pub const VAULT_KEY_LEN: usize = 32;

pub const NONCE_LEN: usize = 12;

/// Wiped on drop.
pub type VaultKey = Zeroizing<[u8; VAULT_KEY_LEN]>;

/// From the OS CSPRNG, via the `aead` re-export: no second `rand_core`.
pub fn generate_vault_key() -> VaultKey {
    let mut bytes = [0u8; VAULT_KEY_LEN];
    AeadOsRng.fill_bytes(&mut bytes);
    Zeroizing::new(bytes)
}

/// So a format change is detectable, not indistinguishable from
/// corruption. Legacy blobs have no prefix, and their random first byte
/// matches it 1 time in 256: unsealing tries v1, then the legacy layout.
pub const BLOB_VERSION: u8 = 1;

pub fn seal(key: &VaultKey, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| crate::Error::msg(format!("AEAD encryption failed: {e}")))?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(BLOB_VERSION);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// A current or legacy blob.
pub fn unseal(key: &VaultKey, framed: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
    if framed.first() == Some(&BLOB_VERSION)
        && let Ok(plaintext) = aead_decrypt(key, &framed[1..])
    {
        return Ok(plaintext);
    }
    aead_decrypt(key, framed).map_err(|decrypt_failure| match framed.first() {
        // Both failed. A small byte above ours is most plausibly a newer
        // format (versions count up; legacy nonces fill the whole byte).
        // Ours, failing, is a wrong key or corruption — say that.
        Some(&byte) if byte > BLOB_VERSION && byte < 0x10 => crate::Error::msg(format!(
            "sealed blob reports version {byte}, which this cindy doesn't understand \
             (it knows {BLOB_VERSION}); it was probably sealed by a newer cindy — \
             upgrade and re-run"
        )),
        _ => decrypt_failure,
    })
}

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
        .map_err(|e| crate::Error::msg(format!("AEAD decryption failed: {e}")))?;
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
        ct[1 + NONCE_LEN] ^= 0x01;
        assert!(unseal(&key, &ct).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = generate_vault_key();
        let key_b = generate_vault_key();
        let ct = seal(&key_a, b"x").unwrap();
        let err = unseal(&key_b, &ct).unwrap_err().to_string();
        // b268fa3 shipped "reports version 1 … it knows 1" here.
        assert!(
            err.contains("AEAD decryption failed"),
            "wrong-key failure must name decryption, not a version: {err}"
        );
        assert!(
            !err.contains("version"),
            "wrong key misread as a version: {err}"
        );
    }

    #[test]
    fn legacy_blobs_unseal() {
        let key = generate_vault_key();
        let pt = b"sealed by cindy 0.3.0";
        let v1 = seal(&key, pt).unwrap();
        let legacy = v1[1..].to_vec();
        let recovered = unseal(&key, &legacy).unwrap();
        assert_eq!(&*recovered, pt);
    }

    #[test]
    fn legacy_blob_with_colliding_nonce_prefix_unseals() {
        let key = generate_vault_key();
        let pt = b"unlucky nonce";

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

    #[test]
    fn unknown_version_fails_loudly() {
        let key = generate_vault_key();
        let mut ct = seal(&key, b"x").unwrap();
        ct[0] = 0x02;
        let err = unseal(&key, &ct).unwrap_err().to_string();
        assert!(
            err.contains("version") && err.contains("2"),
            "future-version blob must name the version: {err}"
        );
        ct[0] = 0xab;
        let err = unseal(&key, &ct).unwrap_err().to_string();
        assert!(
            !err.contains("version"),
            "corrupt blob misread as a version: {err}"
        );
    }

    #[test]
    fn too_short_payload_rejected() {
        let key = generate_vault_key();
        assert!(unseal(&key, b"short").is_err());
    }
}
