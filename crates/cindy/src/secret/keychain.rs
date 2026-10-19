//! Vault keys, as boring as `ansible-vault --vault-password-file`:
//! vault `<name>` is the 32 bytes in `keys/<name>.key` (`CINDY_KEYS_DIR`
//! overrides the directory), shared out of band and `.gitignore`d.
//!
//! The CLI hands the orchestrator the keys a host needs in
//! `CINDY_VAULT_KEYS`; the orchestrator forwards them to the worker in
//! the RPC handshake, never through the target's argv or env.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use base64::Engine as _;
use zeroize::Zeroize as _;

use crate::Context;
use crate::secret::crypto::{VAULT_KEY_LEN, VaultKey};

static KEYCHAIN: Mutex<BTreeMap<String, VaultKey>> = Mutex::new(BTreeMap::new());

/// Recovers from poisoning: the lock only guards whole-map operations,
/// so a panic elsewhere can't leave it half-updated.
fn keychain() -> MutexGuard<'static, BTreeMap<String, VaultKey>> {
    KEYCHAIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Checks the length, and wipes `bytes` either way.
fn key_from(mut bytes: Vec<u8>, what: impl FnOnce(usize) -> String) -> crate::Result<VaultKey> {
    let key = <[u8; VAULT_KEY_LEN]>::try_from(bytes.as_slice()).map(zeroize::Zeroizing::new);
    let len = bytes.len();
    bytes.zeroize();
    key.map_err(|_| crate::anyhow!("{}", what(len)))
}

pub fn install_keys(map: HashMap<String, VaultKey>) {
    keychain().extend(map);
}

/// `CINDY_VAULT_KEYS` (JSON `{vault: base64-key}`), or `None` if unset.
pub fn decode_env_keys() -> crate::Result<Option<HashMap<String, Vec<u8>>>> {
    let Some(raw) = std::env::var_os("CINDY_VAULT_KEYS") else {
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|_| crate::anyhow!("CINDY_VAULT_KEYS is not valid UTF-8"))?;
    let table: HashMap<String, String> = serde_json::from_str(&raw)
        .context("CINDY_VAULT_KEYS was not a JSON map of {vault: base64-key}")?;
    table
        .into_iter()
        .map(|(vault, b64)| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .context(format!("CINDY_VAULT_KEYS[{vault}] is not valid base64"))?;
            Ok((vault, bytes))
        })
        .collect::<crate::Result<_>>()
        .map(Some)
}

/// From the env on the orchestrator, from the handshake on the worker.
pub fn install_raw_keys(map: HashMap<String, Vec<u8>>) -> crate::Result<()> {
    let keys = map
        .into_iter()
        .map(|(vault, bytes)| {
            let key = key_from(bytes, |len| {
                format!("Key for vault `{vault}` has the wrong byte length ({len} \u{2260} {VAULT_KEY_LEN})")
            })?;
            Ok((vault, key))
        })
        .collect::<crate::Result<HashMap<_, _>>>()?;
    install_keys(keys);
    Ok(())
}

pub fn keys_dir() -> PathBuf {
    std::env::var_os("CINDY_KEYS_DIR").map_or_else(|| PathBuf::from("keys"), PathBuf::from)
}

pub fn vault_key_path(vault: &str) -> crate::Result<PathBuf> {
    if vault.is_empty() {
        crate::bail!("vault name must not be empty");
    }
    if vault.contains(['/', '\\', '\0']) {
        crate::bail!("vault name {vault:?} contains invalid characters");
    }
    Ok(keys_dir().join(format!("{vault}.key")))
}

/// `Ok(None)` when there's no file. Public for the CLI's `vault rotate`,
/// which handles key files without installing them.
pub fn read_vault_key_file(path: &Path) -> crate::Result<Option<VaultKey>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context(format!("Reading {}", path.display())),
    };
    key_from(bytes, |len| {
        format!(
            "{} has the wrong size ({len} bytes, expected {VAULT_KEY_LEN}). \
             Either it isn't a cindy vault key file, or it got truncated. \
             Delete it and re-run `cindy secret vault create <name>` \
             (or restore it from wherever you have a backup).",
            path.display()
        )
    })
    .map(Some)
}

/// From the keychain, else `keys/<vault>.key` (then cached).
pub fn get_vault_key(vault: &str) -> crate::Result<VaultKey> {
    if let Some(key) = keychain().get(vault) {
        return Ok(key.clone());
    }
    let path = vault_key_path(vault)?;
    let Some(key) = read_vault_key_file(&path)? else {
        crate::bail!(
            "no key for vault `{vault}` \u{2014} expected {} to exist. \
             Either run `cindy secret vault create {vault}` to bootstrap a new vault, \
             or copy the key file from a teammate who already has one.",
            path.display()
        );
    };
    keychain().insert(vault.to_owned(), key.clone());
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_key_path_rejects_traversal_and_separators() {
        assert!(vault_key_path("prod-db_1").is_ok());
        for bad in ["", "../../etc/shadow", "a/b", "a\\b", "with\0nul"] {
            assert!(vault_key_path(bad).is_err(), "{bad:?}");
        }
    }
}
