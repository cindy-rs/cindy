//! Runtime halves of the `#[cindy::main]` expansion.
//!
//! The macro's job is reduced to splicing the user's `main` body and
//! selecting the orchestrator vs worker path per feature; everything
//! that is ordinary runtime logic — the CLI-driven side modes, vault
//! key installation, preflight, RPC spawn — lives here, where it is
//! reviewable and testable instead of being generated as tokens into
//! every user crate.

#[cfg(feature = "orchestrator")]
use std::process::exit;

#[cfg(feature = "orchestrator")]
use tokio::io::AsyncWriteExt as _;

/// Parse the `CINDY_HOST_CONTEXT` env var (a JSON `cindy::Host<V>`,
/// injected per-target by the CLI) into the host type the user's
/// `main` declares.
#[doc(hidden)]
pub fn host_context<H: serde::de::DeserializeOwned>() -> H {
    let json = match std::env::var("CINDY_HOST_CONTEXT") {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "\x1b[31mCINDY_HOST_CONTEXT not set!\n\
                 The orchestrator process is meant to be launched by the `cindy` command line \
                 tool. If you're trying to run the binary directly, set CINDY_HOST_CONTEXT to \
                 a JSON-serialised `cindy::Host<V>` first.\x1b[0m"
            );
            std::process::exit(1);
        }
    };
    match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "\x1b[31mCINDY_HOST_CONTEXT was not valid JSON for the declared \
                 `cindy::Host<V>` type: {e}\x1b[0m"
            );
            std::process::exit(1);
        }
    }
}

/// Print an error in red and exit 1. The orchestrator's stderr is the
/// operator-facing channel (the CLI tags and forwards it per host).
#[cfg(feature = "orchestrator")]
fn fail(e: anyhow_serde::Error) -> ! {
    eprintln!("\x1b[31m{e:?}\x1b[0m");
    exit(1);
}

/// Orchestrator-process startup, called by the `#[cindy::main]`
/// expansion before the user's `main` body runs.
///
/// First serves the CLI-driven side modes — `CINDY_DUMP_INVENTORY`,
/// `CINDY_DUMP_VAULTS`, `CINDY_SEAL_SECRETS` — each of which writes its
/// result to `rpc_out` and exits without touching the user's `main`.
/// Otherwise: install this run's vault keys from `CINDY_VAULT_KEYS`
/// (env is fine here — this is the operator's machine, not a target),
/// run the vault preflight, and spawn the RPC loop over the pipes. The
/// same key map is forwarded to the worker over the RPC handshake, so
/// key material never appears in the target's argv/env.
#[cfg(feature = "orchestrator")]
#[doc(hidden)]
pub async fn orchestrator_init(rpc_in: tokio::fs::File, rpc_out: tokio::fs::File) {
    if std::env::var_os("CINDY_DUMP_INVENTORY").is_some() {
        dump_inventory(rpc_out).await;
    }
    if std::env::var_os("CINDY_DUMP_VAULTS").is_some() {
        dump_vaults(rpc_out).await;
    }
    if std::env::var_os("CINDY_SEAL_SECRETS").is_some() {
        seal_secrets(rpc_out).await;
    }

    let vault_keys = match crate::secret::keychain::decode_env_keys() {
        Ok(m) => m.unwrap_or_default(),
        Err(e) => fail(e),
    };
    if let Err(e) = crate::secret::keychain::install_raw_keys(vault_keys.clone()) {
        fail(e);
    }

    // Vault preflight: before any RPC or play work, confirm this
    // orchestrator can load every vault key it might need — the union
    // of in-code `secret!` vaults and the sealed-secret vaults present
    // in this host's context. Fail loudly and early instead of partway
    // through the play.
    if let Err(e) = crate::secret::preflight(
        "the orchestrator",
        std::env::var("CINDY_HOST_CONTEXT").ok().as_deref(),
    ) {
        fail(e);
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    crate::orchestrator::ORCHESTRATOR_TX
        .set(tx)
        .expect("ORCHESTRATOR_TX already set");
    tokio::spawn(crate::orchestrator::rpc(rx, rpc_in, rpc_out, vault_keys));
}

/// Write `bytes` to the (saved) RPC stdout and exit 0. Shared tail of
/// the dump modes; the CLI reads the payload from the pipe.
#[cfg(feature = "orchestrator")]
async fn write_and_exit(mut out: tokio::fs::File, bytes: &[u8]) -> ! {
    out.write_all(bytes).await.expect("Failed to write output");
    out.flush().await.expect("Failed to flush output");
    exit(0);
}

/// `CINDY_DUMP_INVENTORY`: serialise the registered inventory as an
/// `InventoryDump` JSON blob for the CLI.
#[cfg(feature = "orchestrator")]
async fn dump_inventory(rpc_out: tokio::fs::File) -> ! {
    let entries: Vec<&crate::inventory::RegisteredInventory> =
        inventory::iter::<crate::inventory::RegisteredInventory>
            .into_iter()
            .collect();
    let dump: crate::inventory::InventoryDump = match entries.as_slice() {
        [one] => (one.dump)().await,
        _ => {
            eprintln!("There must be exactly 1 `#[cindy::inventory]` registered.");
            exit(2);
        }
    };
    let bytes = serde_json::to_vec(&dump).expect("Failed to serialize inventory dump to JSON");
    write_and_exit(rpc_out, &bytes).await
}

/// `CINDY_DUMP_VAULTS`: print the set of vaults referenced by
/// `secret!` invocations compiled into this binary (the "secrets in
/// code" half of the preflight) as a JSON array. The CLI runs this once
/// during preflight to know which vault keys every participating
/// machine must hold.
#[cfg(feature = "orchestrator")]
async fn dump_vaults(rpc_out: tokio::fs::File) -> ! {
    let vaults = crate::secret::registered_vaults();
    let bytes = serde_json::to_vec(&vaults).expect("Failed to serialise vault list");
    write_and_exit(rpc_out, &bytes).await
}

/// `CINDY_SEAL_SECRETS`: encrypt every pending `secret!` value under
/// its vault's key and emit one JSON record per secret on `rpc_out` so
/// the CLI can patch the source files. Exits 2 if any secret failed
/// (missing vault key, encryption error), 0 otherwise.
#[cfg(feature = "orchestrator")]
async fn seal_secrets(rpc_out: tokio::fs::File) -> ! {
    use base64::Engine as _;

    let mut out = rpc_out;
    let mut failed = false;
    for pending in inventory::iter::<crate::secret::PendingSecret>() {
        let plaintext = (pending.serialize)();
        // Refuse to bootstrap a vault on the fly. If the user didn't
        // `cindy secret vault create <name>` before running seal,
        // that's almost certainly a mistake — they probably meant to
        // copy an existing team-shared key file into place. Bail with
        // the (already actionable) error from the keychain layer
        // instead of generating a fresh key whose ciphertext nobody
        // else can decrypt.
        let key = match crate::secret::keychain::get_vault_key(pending.vault) {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "cindy secret seal: couldn't load the key for vault `{}` \
                     (referenced from {}:{}:{}): {e:#}",
                    pending.vault, pending.file, pending.line, pending.column,
                );
                failed = true;
                continue;
            }
        };
        let ciphertext = match crate::secret::crypto::seal(&key, &plaintext) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "cindy secret seal: encryption failed for {}:{}:{} ({e:#})",
                    pending.file, pending.line, pending.column,
                );
                failed = true;
                continue;
            }
        };
        let record = serde_json::json!({
            "file":       pending.file,
            "line":       pending.line,
            "column":     pending.column,
            "vault":      pending.vault,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        });
        let mut bytes = serde_json::to_vec(&record).expect("Failed to serialise seal record");
        bytes.push(b'\n');
        out.write_all(&bytes)
            .await
            .expect("Failed to write seal record");
    }
    out.flush().await.expect("Failed to flush seal records");
    exit(if failed { 2 } else { 0 });
}
