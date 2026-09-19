use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::common::{RemoteFnPayload, RemoteFnResponse, RemoteFnResponsePayload, WorkerInbound};

pub struct OutboundRegistration {
    pub payload: RemoteFnPayload,
    pub tx: oneshot::Sender<RemoteFnResponse>,
}

pub static ORCHESTRATOR_TX: std::sync::OnceLock<mpsc::UnboundedSender<OutboundRegistration>> =
    std::sync::OnceLock::new();

/// Dispatch a remote-function call and return a future that resolves to
/// its (postcard-decoded) return value.
///
/// Dispatch is *eager*: the call is queued on the RPC channel before
/// this function returns, not on first poll. Two calls started before
/// an `.await` therefore already run concurrently on the worker:
///
/// ```ignore
/// let a = task_a(); // already running remotely
/// let b = task_b(); // so is this
/// let (a, b) = (a.await, b.await);
/// ```
///
/// A remote panic is re-raised locally so it bubbles through whatever
/// `join!`/`try_join!` the orchestrator's `main` uses and surfaces in
/// the `#[cindy::main]` `JoinError` arm as `exit(1)`. The worker
/// already printed the full panic location to its stderr (tagged with
/// `[hostname]` by the CLI). If the RPC connection dies before the
/// response arrives (worker crashed, SSH dropped), the future panics
/// with that message instead of hanging.
#[doc(hidden)]
pub fn call<T: serde::de::DeserializeOwned>(
    fn_id: &'static str,
    args: Vec<u8>,
) -> impl std::future::Future<Output = T> {
    let (tx, rx) = oneshot::channel();
    ORCHESTRATOR_TX
        .get()
        .expect("ORCHESTRATOR_TX not set")
        .send(OutboundRegistration {
            payload: RemoteFnPayload {
                uuid: Uuid::new_v4(),
                fn_id: fn_id.to_string(),
                data: args,
            },
            tx,
        })
        .expect("Orchestrator channel closed");

    async move {
        match rx.await {
            Ok(RemoteFnResponse::Ok(bytes)) => postcard::from_bytes(&bytes).unwrap_or_else(|e| {
                panic!("failed to deserialize return value of `{fn_id}`: {e:?}")
            }),
            Ok(RemoteFnResponse::Panic(msg)) => panic!("remote task panicked: {msg}"),
            Err(_) => panic!(
                "RPC connection to the worker closed before `{fn_id}` returned \
                 (worker crashed or the SSH channel dropped)"
            ),
        }
    }
}

pub async fn rpc(
    mut registration_rx: mpsc::UnboundedReceiver<OutboundRegistration>,
    rpc_in: tokio::fs::File,
    rpc_out: tokio::fs::File,
    vault_keys: HashMap<String, Vec<u8>>,
) {
    let (reader_tx, mut reader_rx) = mpsc::unbounded_channel::<RemoteFnResponsePayload>();
    let (writer_tx, mut writer_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // First frame on the wire is always the handshake: hand the worker
    // its vault keys over the (SSH-protected) pipe so the key material
    // never lands in the target's argv/env. Everything after this is a
    // `WorkerInbound::Call`.
    let handshake = postcard::to_allocvec_cobs(&WorkerInbound::Handshake { vault_keys })
        .expect("Failed to serialize handshake");
    let _ = writer_tx.send(handshake);

    let mut pending_futures: HashMap<Uuid, oneshot::Sender<RemoteFnResponse>> = HashMap::new();

    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt as _;

        let mut stdin = tokio::io::BufReader::new(rpc_in);
        let mut buffer = Vec::with_capacity(4096);

        // Ending this task for any reason (EOF, I/O error, corrupt
        // frame) drops `reader_tx`, which the select loop below sees as
        // `None` and treats as "the worker is gone".
        loop {
            match stdin.read_until(0x00, &mut buffer).await {
                Ok(0) => break,
                Ok(_) => match postcard::from_bytes_cobs::<RemoteFnResponsePayload>(&mut buffer) {
                    Ok(response) => {
                        let _ = reader_tx.send(response);
                    }
                    Err(e) => {
                        // No raw-bytes dump: a response frame can carry a
                        // revealed secret value, and stderr is forwarded to
                        // the operator's terminal verbatim. Length only.
                        eprintln!(
                            "RPC framing corruption on the worker channel: {e:?} \
                             (frame length: {} bytes)",
                            buffer.len()
                        );
                        break;
                    }
                },
                Err(e) => {
                    eprintln!("RPC read error on the worker channel: {e}");
                    break;
                }
            }
            buffer.clear();
        }
    });

    tokio::spawn(async move {
        let mut stdout = rpc_out;
        while let Some(cobs_packet) = writer_rx.recv().await {
            use tokio::io::AsyncWriteExt as _;

            if let Err(e) = stdout.write_all(&cobs_packet).await {
                // A broken write pipe means the same dead-worker scenario
                // the reader side sees as EOF: stop here and let the reader
                // task's teardown fail the in-flight calls.
                eprintln!("RPC write error on the worker channel: {e}");
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    loop {
        tokio::select! {
            registration = registration_rx.recv() => match registration {
                Some(registration) => {
                    let uuid = registration.payload.uuid;

                    let outbound_bytes =
                        postcard::to_allocvec_cobs(&WorkerInbound::Call(registration.payload))
                            .expect("Failed to serialize `WorkerInbound::Call`");
                    let _ = writer_tx.send(outbound_bytes);

                    pending_futures.insert(uuid, registration.tx);
                }
                // Defensive: `ORCHESTRATOR_TX` is a `OnceLock` that is never
                // reset, so this arm is not expected to fire; if it ever
                // does, stop rather than spin on a closed channel.
                None => break,
            },

            response = reader_rx.recv() => match response {
                Some(response) => {
                    // If the receiving future was dropped before the
                    // response arrived (e.g. a sibling in a `try_join!`
                    // already errored), there's nothing to deliver to —
                    // ignore rather than crash the RPC loop.
                    if let Some(tx) = pending_futures.remove(&response.uuid) {
                        let _ = tx.send(response.response);
                    }
                }
                // Reader task ended: worker EOF, I/O error, or corrupt
                // frame. Stop the loop; dropping `pending_futures` below
                // drops every in-flight oneshot sender, which fails the
                // corresponding awaiting futures with a clear message
                // instead of letting them hang forever.
                None => {
                    if !pending_futures.is_empty() {
                        eprintln!(
                            "RPC connection to the worker closed with {} call(s) still in flight",
                            pending_futures.len()
                        );
                    }
                    break;
                }
            },
        }
    }
}
