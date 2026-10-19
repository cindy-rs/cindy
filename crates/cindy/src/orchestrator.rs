//! The orchestrator's end of the RPC channel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use uuid::Uuid;

use crate::common::{RemoteFnPayload, RemoteFnResponse, RemoteFnResponsePayload, WorkerInbound};

/// A frame and the budget it holds until it is on the pipe, so at most
/// `budget` bytes of unwritten frames exist at once.
type QueuedFrame = (Vec<u8>, OwnedSemaphorePermit);

/// Caps the frame count; bytes are already capped by the budget.
const WRITER_QUEUE_SLOTS: usize = 256;

struct Dispatch {
    writer_tx: mpsc::Sender<QueuedFrame>,
    pending: Mutex<Pending>,
    budget: Arc<Semaphore>,
    budget_size: usize,
}

#[derive(Default)]
struct Pending {
    /// Set once the worker is gone: later calls fail at once instead of
    /// queueing a frame nobody will answer.
    dead: bool,
    calls: HashMap<Uuid, oneshot::Sender<RemoteFnResponse>>,
}

impl Dispatch {
    fn lock(&self) -> MutexGuard<'_, Pending> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn permits(&self, cost: usize) -> u32 {
        u32::try_from(cost).unwrap_or(u32::MAX)
    }
}

static DISPATCH: OnceLock<Dispatch> = OnceLock::new();

/// Set up the channel to the worker. Synchronous on purpose: check mode
/// is installed and the handshake is first in the (FIFO) writer queue
/// before this returns — before the play's `main` can make a call, or
/// run a builtin in-process.
#[doc(hidden)]
pub fn start(
    rpc_in: tokio::fs::File,
    rpc_out: tokio::fs::File,
    vault_keys: HashMap<String, Vec<u8>>,
) {
    // The flag describes the run, not the process: in-process builtins
    // here honour it like their worker-side twins.
    let dry_run = std::env::var_os("CINDY_DRY_RUN").is_some_and(|v| v == "1");
    crate::check::install(dry_run);

    let budget_size = crate::common::rpc_byte_budget();
    let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE_SLOTS);
    let dispatch = Dispatch {
        writer_tx,
        pending: Mutex::default(),
        budget: Arc::new(Semaphore::new(budget_size)),
        budget_size,
    };

    // Keys over the SSH-protected pipe, never the target's argv or env.
    let handshake = postcard::to_allocvec_cobs(&WorkerInbound::Handshake {
        vault_keys,
        dry_run,
    })
    .expect("Failed to serialize handshake");
    let cost = crate::common::call_cost(handshake.len(), budget_size);
    let permit = dispatch
        .budget
        .clone()
        .try_acquire_many_owned(dispatch.permits(cost))
        .expect("a fresh budget admits the handshake");
    dispatch
        .writer_tx
        .try_send((handshake, permit))
        .expect("a fresh queue has room for the handshake");

    if DISPATCH.set(dispatch).is_err() {
        panic!("the RPC channel was started twice");
    }
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    tokio::spawn(read_responses(rpc_in, response_tx));
    tokio::spawn(write_frames(rpc_out, writer_rx));
    tokio::spawn(route_responses(response_rx));
}

/// Dispatch a remote call; the future resolves to its encoded result.
///
/// Dispatch is eager — queued before this returns, not on first poll —
/// so calls started before an `.await` run concurrently on the worker:
///
/// ```ignore
/// let a = task_a(); // already running remotely
/// let b = task_b(); // so is this
/// let (a, b) = (a.await, b.await);
/// ```
///
/// Each call first takes budget permits for its frame, in its own task:
/// when the worker stalls, new calls park there instead of piling frames
/// up in memory. A remote panic, or the worker going away, panics here,
/// so it surfaces through the play's `join!`s.
#[doc(hidden)]
pub fn call(fn_id: &'static str, args: Vec<u8>) -> impl std::future::Future<Output = Vec<u8>> {
    let (tx, rx) = oneshot::channel();
    let dispatch = DISPATCH.get().expect("the RPC channel isn't started");
    let uuid = Uuid::new_v4();
    let payload = RemoteFnPayload {
        uuid,
        fn_id: fn_id.to_string(),
        data: args,
    };

    tokio::spawn(async move {
        let cost = crate::common::outbound_cost(payload.data.len(), dispatch.budget_size);
        let permit = dispatch
            .budget
            .clone()
            .acquire_many_owned(dispatch.permits(cost))
            .await
            .expect("RPC budget semaphore closed");
        // Registered before the frame exists, so the response can't
        // arrive first.
        {
            let mut pending = dispatch.lock();
            if pending.dead {
                let _ = tx.send(RemoteFnResponse::Panic(
                    "RPC connection to the worker closed before this call was dispatched"
                        .to_owned(),
                ));
                return;
            }
            pending.calls.insert(uuid, tx);
        }
        let frame = postcard::to_allocvec_cobs(&WorkerInbound::Call(payload))
            .expect("Failed to serialize `WorkerInbound::Call`");
        if dispatch.writer_tx.send((frame, permit)).await.is_err() {
            dispatch.lock().calls.remove(&uuid);
        }
    });

    async move {
        match rx.await {
            Ok(RemoteFnResponse::Ok(bytes)) => bytes,
            Ok(RemoteFnResponse::Panic(msg)) => panic!("remote task panicked: {msg}"),
            Err(_) => panic!(
                "RPC connection to the worker closed before `{fn_id}` returned \
                 (worker crashed or the SSH channel dropped)"
            ),
        }
    }
}

/// Ends on EOF, an I/O error or a corrupt frame; dropping the sender is
/// how [`route_responses`] learns the worker is gone.
async fn read_responses(
    rpc_in: tokio::fs::File,
    responses: mpsc::UnboundedSender<RemoteFnResponsePayload>,
) {
    use tokio::io::AsyncBufReadExt as _;

    let mut stdin = tokio::io::BufReader::new(rpc_in);
    let mut buffer = Vec::with_capacity(4096);
    loop {
        match stdin.read_until(0x00, &mut buffer).await {
            Ok(0) => break,
            Ok(_) => match postcard::from_bytes_cobs::<RemoteFnResponsePayload>(&mut buffer) {
                Ok(response) => {
                    let _ = responses.send(response);
                }
                Err(e) => {
                    // Length only: a response can carry a revealed secret,
                    // and stderr reaches the operator's terminal.
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
}

async fn write_frames(mut rpc_out: tokio::fs::File, mut frames: mpsc::Receiver<QueuedFrame>) {
    use tokio::io::AsyncWriteExt as _;

    while let Some((frame, permit)) = frames.recv().await {
        if let Err(e) = rpc_out.write_all(&frame).await {
            // The reader sees the same dead worker and fails the calls.
            eprintln!("RPC write error on the worker channel: {e}");
            break;
        }
        let _ = rpc_out.flush().await;
        // On the pipe: SSH flow control owns the backpressure now.
        drop(permit);
    }
}

/// Never parks on the budget: the worker's budget only frees as its
/// responses flow through here, so parking would deadlock both sides.
async fn route_responses(mut responses: mpsc::UnboundedReceiver<RemoteFnResponsePayload>) {
    let dispatch = DISPATCH.get().expect("the RPC channel isn't started");
    while let Some(response) = responses.recv().await {
        // The caller may have gone (a `try_join!` sibling failed).
        if let Some(tx) = dispatch.lock().calls.remove(&response.uuid) {
            let _ = tx.send(response.response);
        }
    }
    let mut pending = dispatch.lock();
    if !pending.calls.is_empty() {
        eprintln!(
            "RPC connection to the worker closed with {} call(s) still in flight",
            pending.calls.len()
        );
    }
    pending.dead = true;
    for (_, tx) in pending.calls.drain() {
        let _ = tx.send(RemoteFnResponse::Panic(
            "RPC connection to the worker closed before the call returned \
             (worker crashed or the SSH channel dropped)"
                .to_owned(),
        ));
    }
}
