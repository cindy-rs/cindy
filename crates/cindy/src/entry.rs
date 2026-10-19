//! The runtime half of `#[cindy::main]`: everything that isn't splicing
//! the user's body lives here, as code rather than generated tokens.

#[cfg(feature = "orchestrator")]
use std::process::exit;

#[cfg(feature = "orchestrator")]
use tokio::io::AsyncWriteExt as _;

/// The host context (a JSON `cindy::Host<V>`) the CLI wrote for this
/// target. A file, not an env var: one variable is capped at 128 KiB
/// (`MAX_ARG_STRLEN`), and `vars` carrying certificates or whole
/// config files exceed it.
fn load_context_json() -> Option<String> {
    let path = std::env::var("CINDY_HOST_CONTEXT_FILE").ok()?;
    Some(match std::fs::read_to_string(&path) {
        Ok(json) => json,
        Err(e) => {
            eprintln!(
                "\x1b[31mfailed to read the host context file `{path}`: {e}\n\
                 The orchestrator process is meant to be launched by the `cindy` command line \
                 tool.\x1b[0m"
            );
            std::process::exit(1);
        }
    })
}

#[doc(hidden)]
pub fn host_context<H: serde::de::DeserializeOwned>() -> H {
    let json = match load_context_json() {
        Some(v) => v,
        None => {
            eprintln!(
                "\x1b[31mhost context not set!\n\
                 The orchestrator process is meant to be launched by the `cindy` command line \
                 tool. If you're trying to run the binary directly, point CINDY_HOST_CONTEXT_FILE \
                 at a JSON-serialised `cindy::Host<V>` first.\x1b[0m"
            );
            std::process::exit(1);
        }
    };
    match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "\x1b[31mthe host context was not valid JSON for the declared \
                 `cindy::Host<V>` type: {e}\x1b[0m"
            );
            std::process::exit(1);
        }
    }
}

/// The orchestrator's stderr is the operator's channel (the CLI tags
/// and forwards it per host).
#[cfg(feature = "orchestrator")]
fn fail(e: crate::Error) -> ! {
    eprintln!("\x1b[31m{e:?}\x1b[0m");
    exit(1);
}

/// Runs before the user's `main`. The CLI's side modes (dump the
/// inventory, list the vaults, seal secrets) write to `rpc_out` and
/// exit here. Otherwise: install the vault keys (env is fine on the
/// operator's machine; the worker gets them over the handshake), fail
/// early if any key the play may need is missing, and start the RPC
/// channel.
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

    if let Err(e) = crate::secret::preflight("the orchestrator", load_context_json().as_deref()) {
        fail(e);
    }

    crate::orchestrator::start(rpc_in, rpc_out, vault_keys);
}

/// The side modes answer on the RPC pipe.
#[cfg(feature = "orchestrator")]
async fn write_and_exit(mut out: tokio::fs::File, bytes: &[u8]) -> ! {
    out.write_all(bytes).await.expect("Failed to write output");
    out.flush().await.expect("Failed to flush output");
    exit(0);
}

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

/// The vaults `secret!`s in this binary reference, so the CLI knows
/// which keys every machine needs.
#[cfg(feature = "orchestrator")]
async fn dump_vaults(rpc_out: tokio::fs::File) -> ! {
    let vaults = crate::secret::registered_vaults();
    let bytes = serde_json::to_vec(&vaults).expect("Failed to serialise vault list");
    write_and_exit(rpc_out, &bytes).await
}

/// One JSON record per pending `secret!`, sealed under its vault's
/// key, for the CLI to patch into the source. Exits 2 if any failed.
#[cfg(feature = "orchestrator")]
async fn seal_secrets(rpc_out: tokio::fs::File) -> ! {
    use base64::Engine as _;

    let mut out = rpc_out;
    let mut failed = false;
    for pending in inventory::iter::<crate::secret::PendingSecret>() {
        let plaintext = (pending.serialize)();
        // Never create a key here: a missing one usually means a team
        // key file wasn't copied in, and a fresh key would seal what
        // nobody else can open.
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
