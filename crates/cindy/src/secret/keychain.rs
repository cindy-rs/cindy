//! Runtime lookup of vault vault keys.
//!
//! V1 model — deliberately as boring as `ansible-vault`'s
//! `--vault-password-file`:
//!
//!   * Each vault `<name>` has a 32-byte key stored at `keys/<name>.key`
//!     (relative to the orchestrator's working directory, overridable
//!     via the `CINDY_KEYS_DIR` env var).
//!   * `Secret::reveal()` reads `keys/<vault>.key` on first use and
//!     caches the bytes in a process-global map.
//!   * Operators distribute `keys/<name>.key` to teammates out-of-band
//!     (Signal, secure file copy, whatever) and `.gitignore` the
//!     directory so it never lands in the repo.
//!
//! The CLI marshals the keys for the vaults a host's secrets reference
//! into the orchestrator process via the `CINDY_VAULT_KEYS` env var (a
//! base64-encoded JSON map; see [`decode_env_keys`]). The orchestrator
//! installs them locally and forwards them to the worker over the RPC
//! handshake — the worker never receives key material through its
//! argv/env, only over the (SSH-protected) channel.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;

use crate::Context;
use crate::secret::crypto::{VAULT_KEY_LEN, VaultKey};

const DEFAULT_KEYS_DIR: &str = "keys";

/// Process-global keychain. Populated lazily as `Secret::reveal` calls
/// land. Thread-safe; cheap to look up; never serialised.
static KEYCHAIN: Mutex<Option<HashMap<String, VaultKey>>> = Mutex::new(None);

fn cache_get(vault: &str) -> Option<VaultKey> {
    KEYCHAIN.lock().ok()?.as_ref()?.get(vault).cloned()
}

fn cache_put(vault: String, key: VaultKey) {
    let mut guard = KEYCHAIN.lock().expect("keychain mutex poisoned");
    guard.get_or_insert_with(HashMap::new).insert(vault, key);
}

/// Bulk-install vault keys into the in-memory keychain. Used on the worker
/// side, where we get the keys in pre-decoded form from the
/// orchestrator through an env var.
pub fn install_keys(map: HashMap<String, VaultKey>) {
    let mut guard = KEYCHAIN.lock().expect("keychain mutex poisoned");
    let chain = guard.get_or_insert_with(HashMap::new);
    for (k, v) in map {
        chain.insert(k, v);
    }
}

/// Decode the `CINDY_VAULT_KEYS` env var (JSON `{vault: base64-key}`)
/// into a `{vault: raw-key-bytes}` map, or `None` if it isn't set.
///
/// Used on the orchestrator: the CLI marshals the operator's local vault keys
/// here (env is fine — it's the operator's own machine, not a target),
/// and the orchestrator both installs them locally *and* forwards the
/// raw bytes to the worker over the RPC handshake.
pub fn decode_env_keys() -> crate::Result<Option<HashMap<String, Vec<u8>>>> {
    let Some(raw) = std::env::var_os("CINDY_VAULT_KEYS") else {
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|_| anyhow_serde::Error::msg("CINDY_VAULT_KEYS is not valid UTF-8"))?;

    let table: HashMap<String, String> = serde_json::from_str(&raw)
        .context("CINDY_VAULT_KEYS was not a JSON map of {vault: base64-key}")?;

    let mut out = HashMap::new();
    for (vault, b64) in table {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .context(format!("CINDY_VAULT_KEYS[{vault}] is not valid base64"))?;
        if bytes.len() != VAULT_KEY_LEN {
            crate::bail!(
                "CINDY_VAULT_KEYS[{vault}] has the wrong byte length ({} \u{2260} {VAULT_KEY_LEN})",
                bytes.len()
            );
        }
        out.insert(vault, bytes);
    }
    Ok(Some(out))
}

/// Install a `{vault: raw-key-bytes}` map into the keychain, validating
/// each key's length. Shared by the orchestrator (from env) and the
/// worker (from the RPC handshake).
pub fn install_raw_keys(map: HashMap<String, Vec<u8>>) -> crate::Result<()> {
    let mut out = HashMap::new();
    for (vault, bytes) in map {
        if bytes.len() != VAULT_KEY_LEN {
            crate::bail!(
                "Key for vault `{vault}` has the wrong byte length ({} \u{2260} {VAULT_KEY_LEN})",
                bytes.len()
            );
        }
        let mut arr = [0u8; VAULT_KEY_LEN];
        arr.copy_from_slice(&bytes);
        out.insert(vault, zeroize::Zeroizing::new(arr));
    }
    install_keys(out);
    Ok(())
}

/// Resolve the keys directory. Defaults to `./keys`, overridable via
/// `CINDY_KEYS_DIR` (useful for tests and air-gapped deployments).
pub fn keys_dir() -> PathBuf {
    std::env::var_os("CINDY_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEYS_DIR))
}

pub fn vault_key_path(vault: &str) -> PathBuf {
    keys_dir().join(format!("{vault}.key"))
}

fn read_key_file(path: &Path) -> crate::Result<Option<VaultKey>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context(format!("Reading {}", path.display())),
    };
    if bytes.len() != VAULT_KEY_LEN {
        crate::bail!(
            "{} has the wrong size ({} bytes, expected {VAULT_KEY_LEN}). \
             Either it isn't a cindy vault key file, or it got truncated. \
             Delete it and re-run `cindy secret vault create <name>` \
             (or restore it from wherever you have a backup).",
            path.display(),
            bytes.len()
        );
    }
    let mut arr = [0u8; VAULT_KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(Some(zeroize::Zeroizing::new(arr)))
}

/// Public entry point: get the vault key for `vault`. Looks at the in-memory
/// cache first, then falls back to the on-disk file. Returns an error
/// if no key is available — at runtime that means the operator forgot
/// to provision `keys/<vault>.key` on this machine.
pub fn get_vault_key(vault: &str) -> crate::Result<VaultKey> {
    if let Some(key) = cache_get(vault) {
        return Ok(key);
    }
    let path = vault_key_path(vault);
    let Some(key) = read_key_file(&path)? else {
        crate::bail!(
            "no key for vault `{vault}` \u{2014} expected {} to exist. \
             Either run `cindy secret vault create {vault}` to bootstrap a new vault, \
             or copy the key file from a teammate who already has one.",
            path.display()
        );
    };
    cache_put(vault.to_owned(), key.clone());
    Ok(key)
}
