//! The worker's end of the RPC channel.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::common::{RemoteFnPayload, RemoteFnResponse, RemoteFnResponsePayload, WorkerInbound};

#[doc(hidden)]
pub type RemoteFnId = &'static str;
/// Sync bodies are run in `spawn_blocking` by the macro's wrapper; the
/// dispatcher only sees this.
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

static REMOTE_FN_MAP: LazyLock<HashMap<RemoteFnId, RemoteFnSignature>> = LazyLock::new(|| {
    inventory::iter::<RemoteFn>
        .into_iter()
        .map(|rfn| (rfn.id, rfn.function))
        .collect()
});

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn die(message: impl std::fmt::Display) -> ! {
    eprintln!("\x1b[31m{message}\x1b[0m");
    std::process::exit(1);
}

/// Every vault this worker's `secret!`s reference must have arrived.
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

#[doc(hidden)]
pub async fn rpc(rpc_in: tokio::fs::File, rpc_out: tokio::fs::File) {
    // Agent-less: nothing cindy brings may outlive the play.
    if let Ok(exe) = std::env::current_exe()
        && let Err(e) = std::fs::remove_file(&exe)
    {
        eprintln!(
            "warning: couldn't remove worker binary {}: {e}",
            exe.display()
        );
    }

    let budget = crate::common::rpc_byte_budget();
    let (calls_tx, mut calls_rx) = mpsc::unbounded_channel();
    let (writer_tx, writer_rx) = mpsc::unbounded_channel();
    tokio::spawn(read_frames(rpc_in, budget, calls_tx));
    tokio::spawn(write_frames(rpc_out, writer_rx));

    while let Some((payload, permit)) = calls_rx.recv().await {
        tokio::spawn(serve(payload, permit, writer_tx.clone()));
    }
}

/// Each call holds budget permits for its frame size (floored) from
/// here until its response is queued, and the reader takes them before
/// reading on. When the budget is spent the reader stops, the stall
/// travels back through SSH flow control, and the box with the least
/// RAM is never asked to hold more than its budget of in-flight
/// arguments — without capping cheap-but-numerous calls.
async fn read_frames(
    rpc_in: tokio::fs::File,
    budget: usize,
    calls: mpsc::UnboundedSender<(RemoteFnPayload, OwnedSemaphorePermit)>,
) {
    use tokio::io::AsyncBufReadExt as _;

    let permits = Arc::new(Semaphore::new(budget));
    let mut stdin = tokio::io::BufReader::new(rpc_in);
    let mut buffer = Vec::with_capacity(4096);
    let mut handshaken = false;
    loop {
        match stdin.read_until(0x00, &mut buffer).await {
            Ok(0) => break,
            Ok(frame_len) => match postcard::from_bytes_cobs::<WorkerInbound>(&mut buffer) {
                Ok(WorkerInbound::Handshake {
                    vault_keys,
                    dry_run,
                }) => {
                    crate::check::install(dry_run);
                    if let Err(e) = crate::secret::keychain::install_raw_keys(vault_keys)
                        .and_then(|()| worker_vault_preflight())
                    {
                        die(format!("{e:?}"));
                    }
                    handshaken = true;
                }
                // Check mode and the keys arrive with the handshake: a
                // call before it would run with neither.
                Ok(WorkerInbound::Call(_)) if !handshaken => {
                    die("RPC protocol violation: a call arrived before the handshake")
                }
                Ok(WorkerInbound::Call(payload)) => {
                    let cost = crate::common::call_cost(frame_len, budget);
                    let permit = permits
                        .clone()
                        .acquire_many_owned(u32::try_from(cost).unwrap_or(u32::MAX))
                        .await
                        .expect("RPC budget semaphore closed");
                    calls
                        .send((payload, permit))
                        .expect("Processing channel closed");
                }
                // Dropping a frame would leave the orchestrator waiting
                // forever; our exit fails its in-flight calls instead.
                Err(e) => die(format!("RPC framing corruption on worker stdin: {e:?}")),
            },
            Err(e) => die(format!("RPC read error on worker stdin: {e}")),
        }
        buffer.clear();
    }
}

async fn write_frames(mut rpc_out: tokio::fs::File, mut frames: mpsc::UnboundedReceiver<Vec<u8>>) {
    use tokio::io::AsyncWriteExt as _;

    while let Some(frame) = frames.recv().await {
        let written = async {
            rpc_out.write_all(&frame).await?;
            rpc_out.flush().await
        };
        if let Err(e) = written.await {
            die(format!("RPC write error on worker stdout: {e}"));
        }
    }
}

async fn serve(
    payload: RemoteFnPayload,
    _permit: OwnedSemaphorePermit,
    writer: mpsc::UnboundedSender<Vec<u8>>,
) {
    let uuid = payload.uuid;
    // An inner task, so a panic anywhere in the call — argument
    // decoding included — becomes a response, not a dead dispatcher.
    // The panic hook has already printed its location to stderr.
    let work = tokio::spawn(async move {
        let function = REMOTE_FN_MAP
            .get(payload.fn_id.as_str())
            .unwrap_or_else(|| panic!("called an unregistered remote function: {}", payload.fn_id));
        function(&payload.data).await
    });
    let response = match work.await {
        Ok(bytes) => RemoteFnResponse::Ok(bytes),
        Err(e) if e.is_panic() => RemoteFnResponse::Panic(panic_message(&*e.into_panic())),
        Err(_) => RemoteFnResponse::Panic("remote task was cancelled".to_string()),
    };
    let frame = postcard::to_allocvec_cobs(&RemoteFnResponsePayload { uuid, response })
        .expect("Failed to serialize response");
    writer.send(frame).expect("Writer channel closed");
}
