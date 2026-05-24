use std::future::Future;
use std::pin::Pin;
use std::{collections::HashMap, sync::LazyLock};

use crate::common::{RemoteFnPayload, RemoteFnResponse, RemoteFnResponsePayload, WorkerInbound};

/// Best-effort extraction of a human-readable string from a panic payload.
///
/// `Box<dyn Any + Send>` is what both `JoinError::into_panic` and
/// `catch_unwind` hand back; in practice almost every panic in the wild
/// carries either `&'static str` (literal `panic!("...")`) or `String`
/// (formatted `panic!("{}", x)`), so we cover those two and fall back to a
/// placeholder for the rare custom-payload case.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[doc(hidden)]
pub type RemoteFnId = &'static str;
/// Every registered remote function is wrapped so it returns a boxed future.
///
/// Sync `#[remote] fn ...` bodies are dispatched inside `spawn_blocking` by
/// the wrapper the macro generates; async `#[remote] async fn ...` bodies are
/// `.await`ed directly. Either way the dispatcher only sees this uniform
/// future-returning signature.
#[doc(hidden)]
pub type RemoteFnFuture = Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
#[doc(hidden)]
pub type RemoteFnSignature = fn(args: &[u8]) -> RemoteFnFuture;

#[doc(hidden)]
pub struct RemoteFn {
    pub id: RemoteFnId,
    pub function: RemoteFnSignature,
}
inventory::collect!(RemoteFn);

pub static REMOTE_FN_MAP: LazyLock<HashMap<RemoteFnId, RemoteFnSignature>> = LazyLock::new(|| {
    inventory::iter::<RemoteFn>
        .into_iter()
        .map(|rfn| (rfn.id, rfn.function))
        .collect()
});

/// Worker-side vault preflight: confirm every vault any `secret!` in
/// this worker references has a key in the keychain (installed from the
/// handshake). Runs before any remote function is dispatched, so a
/// missing key fails immediately instead of partway through the play.
fn worker_vault_preflight() -> crate::Result<()> {
    let missing = crate::secret::missing_vaults(crate::secret::registered_vaults());
    if missing.is_empty() {
        return Ok(());
    }
    crate::bail!(
        "missing decryption keys on the remote worker: no key for vault(s) {missing:?}. \
         The orchestrator did not ship a key for them — ensure `keys/<name>.key` exists \
         on the controller for every vault this play's `secret!`s reference."
    )
}

pub async fn rpc(rpc_in: tokio::fs::File, rpc_out: tokio::fs::File) {
    // The worker binary is uploaded per-play; unlink it on startup so it
    // doesn't accumulate on the target. Best-effort: a read-only location
    // (or an already-unlinked file) shouldn't kill the play.
    if let Ok(exe) = std::env::current_exe()
        && let Err(e) = std::fs::remove_file(&exe)
    {
        eprintln!(
            "warning: couldn't remove worker binary {}: {e}",
            exe.display()
        );
    }

    let (process_tx, mut process_rx) = tokio::sync::mpsc::unbounded_channel::<RemoteFnPayload>();
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt as _;

        let mut stdin = tokio::io::BufReader::new(rpc_in);
        let mut buffer = Vec::with_capacity(4096);

        loop {
            match stdin.read_until(0x00, &mut buffer).await {
                Ok(0) => break,
                Ok(_) => match postcard::from_bytes_cobs::<WorkerInbound>(&mut buffer) {
                    // Handshake: install the vault keys the orchestrator sent
                    // and run the worker-side vault preflight. Both happen
                    // before any `Call` is dispatched, so a missing key fails
                    // here rather than mid-play. The keys arrive over the
                    // (SSH-protected) pipe, never via argv/env.
                    Ok(WorkerInbound::Handshake { vault_keys }) => {
                        if let Err(e) = crate::secret::keychain::install_raw_keys(vault_keys)
                            .and_then(|()| worker_vault_preflight())
                        {
                            eprintln!("\x1b[31m{e:?}\x1b[0m");
                            std::process::exit(1);
                        }
                    }
                    Ok(WorkerInbound::Call(payload)) => {
                        process_tx.send(payload).expect("Processing channel closed");
                    }
                    // A frame we can't decode is unrecoverable: silently
                    // dropping it would leave the orchestrator awaiting a
                    // response that never comes. Die loudly instead — our
                    // EOF makes the orchestrator fail all in-flight calls.
                    Err(e) => {
                        eprintln!("RPC framing corruption on worker stdin: {e:?}");
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("RPC read error on worker stdin: {e}");
                    std::process::exit(1);
                }
            }
            buffer.clear();
        }
    });

    tokio::spawn(async move {
        let mut stdout = rpc_out;
        while let Some(cobs_packet) = writer_rx.recv().await {
            use tokio::io::AsyncWriteExt as _;

            if let Err(e) = async {
                stdout.write_all(&cobs_packet).await?;
                stdout.flush().await
            }
            .await
            {
                // Can't reach the orchestrator any more; there is nothing
                // useful left to do on this host.
                eprintln!("RPC write error on worker stdout: {e}");
                std::process::exit(1);
            }
        }
    });

    while let Some(payload) = process_rx.recv().await {
        let writer_tx = writer_tx.clone();

        tokio::spawn(async move {
            let uuid = payload.uuid;

            // Run the actual user function inside an *inner* `tokio::spawn`
            // so that a panic escaping its body is converted into a
            // `JoinError` instead of taking down this dispatch task. This
            // also covers panics raised before the future is constructed
            // (e.g. arg deserialization in the macro-generated closure) and
            // panics during result serialization, both of which live inside
            // the inner async block.
            //
            // Tokio's default panic hook still runs first, so the full
            // panic location is printed to the worker's stderr — the CLI
            // tags those lines with `[hostname]` so the operator gets a
            // useful breadcrumb regardless of what the orchestrator does
            // with the failure.
            let work = tokio::spawn(async move {
                let registered_fn =
                    REMOTE_FN_MAP
                        .get(payload.fn_id.as_str())
                        .unwrap_or_else(|| {
                            panic!("called an unregistered remote function: {}", payload.fn_id)
                        });

                // The macro-generated wrapper is responsible for picking
                // the right execution strategy: sync bodies are run inside
                // `spawn_blocking`, async bodies are polled directly.
                registered_fn(&payload.data).await
            });

            let response = match work.await {
                Ok(bytes) => RemoteFnResponse::Ok(bytes),
                Err(join_err) if join_err.is_panic() => {
                    RemoteFnResponse::Panic(panic_message(&*join_err.into_panic()))
                }
                Err(_) => RemoteFnResponse::Panic("remote task was cancelled".to_string()),
            };

            let response_payload = RemoteFnResponsePayload { uuid, response };

            let outbound_cobs = postcard::to_allocvec_cobs(&response_payload)
                .expect("Failed to serialize response");

            writer_tx
                .send(outbound_cobs)
                .expect("Writer channel closed");
        });
    }
}
