use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::common::{RemoteFnPayload, RemoteFnResponse, RemoteFnResponsePayload, WorkerInbound};

/// One queued outbound frame, with the budget permits that admitted it.
/// The permit rides with the frame and is dropped by the writer task
/// once the bytes are on the pipe — that's the moment the budget is
/// handed back, so at most `budget` bytes of not-yet-written frames can
/// exist at any time.
pub(crate) type QueuedFrame = (Vec<u8>, tokio::sync::OwnedSemaphorePermit);

/// How many frames may sit in the writer queue. Bytes are already
/// bounded by the budget (every queued frame holds its permits); this
/// only caps the *count*, keeping queue bookkeeping flat even under
/// floods of floor-cost calls.
const WRITER_QUEUE_SLOTS: usize = 256;

/// Everything a remote call needs to reach the worker: the budgeted
/// writer queue and the response-routing table.
#[derive(Clone)]
struct Dispatch {
    writer_tx: mpsc::Sender<QueuedFrame>,
    pending: Arc<Mutex<Pending>>,
    budget: Arc<tokio::sync::Semaphore>,
    budget_size: usize,
}

/// In-flight calls by uuid, plus the `dead` flag the routing loop sets
/// when the worker is gone: later dispatch attempts must fail their
/// caller immediately instead of queueing a frame nobody will answer.
#[derive(Default)]
struct Pending {
    dead: bool,
    calls: HashMap<Uuid, oneshot::Sender<RemoteFnResponse>>,
}

impl Dispatch {
    fn lock(&self) -> MutexGuard<'_, Pending> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Build the dispatch machinery and install it in the `DISPATCH`
/// global, returning the writer-queue receiver for [`rpc`] to drain.
/// Called once from the `#[cindy::main]` entry, before any call can
/// happen.
pub fn install_dispatch() -> mpsc::Receiver<QueuedFrame> {
    let budget_size = crate::common::rpc_byte_budget();
    let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE_SLOTS);
    let dispatch = Dispatch {
        writer_tx,
        pending: Arc::new(Mutex::new(Pending::default())),
        budget: Arc::new(tokio::sync::Semaphore::new(budget_size)),
        budget_size,
    };
    DISPATCH
        .set(dispatch)
        .map_err(|_| "DISPATCH already set")
        .expect("DISPATCH already set");
    writer_rx
}

/// The dispatch context installed by [`install_dispatch`]. Remote
/// calls read it; it is never reset, so a `get()` here can't fail
/// once the entry has run.
static DISPATCH: OnceLock<Dispatch> = OnceLock::new();

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
/// The dispatch itself happens in a spawned task that first acquires
/// byte-budget permits for the frame. Under a saturated budget — the
/// worker stalled, the SSH pipe full — new calls park there instead of
/// piling serialized frames in orchestrator memory, while in-flight
/// calls keep completing: response routing must never park, because
/// the worker's own budget only releases as responses flow back.
///
/// A remote panic is re-raised locally so it bubbles through whatever
/// `join!`/`try_join!` the orchestrator's `main` uses and surfaces in
/// the `#[cindy::main]` `JoinError` arm as `exit(1)`. The worker
/// already printed the full panic location to its stderr (tagged with
/// `[hostname]` by the CLI). If the RPC connection dies before the
/// response arrives (worker crashed, SSH dropped), the future panics
/// with that message instead of hanging.
#[doc(hidden)]
pub fn call(fn_id: &'static str, args: Vec<u8>) -> impl std::future::Future<Output = Vec<u8>> {
    let (tx, rx) = oneshot::channel();
    let dispatch = DISPATCH.get().expect("DISPATCH not set");
    let uuid = Uuid::new_v4();
    let payload = RemoteFnPayload {
        uuid,
        fn_id: fn_id.to_string(),
        data: args,
    };

    tokio::spawn(async move {
        let cost = u32::try_from(crate::common::outbound_cost(
            payload.data.len(),
            dispatch.budget_size,
        ))
        .unwrap_or(u32::MAX);
        let permit = dispatch
            .budget
            .clone()
            .acquire_many_owned(cost)
            .await
            .expect("RPC budget semaphore closed");

        // Register before the frame is written — the response can't
        // exist before the frame does, so this can't race the routing
        // loop. Failing the `dead` check means the worker is already
        // gone; fail the caller now rather than queue a frame nobody
        // will answer.
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
            // Writer task ended (dead worker) before taking the frame:
            // unregister so the caller fails through the normal
            // closed-connection path instead of hanging.
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

pub async fn rpc(
    rpc_in: tokio::fs::File,
    rpc_out: tokio::fs::File,
    vault_keys: HashMap<String, Vec<u8>>,
    mut writer_rx: mpsc::Receiver<QueuedFrame>,
) {
    let dispatch = DISPATCH.get().expect("DISPATCH not set");
    let (reader_tx, mut reader_rx) = mpsc::unbounded_channel::<RemoteFnResponsePayload>();

    // First frame on the wire is always the handshake: hand the worker
    // its vault keys over the (SSH-protected) pipe so the key material
    // never lands in the target's argv/env. Everything after this is a
    // `WorkerInbound::Call`.
    // Check mode (`cindy play --check`) reaches the worker through the
    // handshake like the vault keys do: one decision, installed before
    // any call is dispatched, never argv/env on the target. It is also
    // installed *here*: builtins invoked in-process on the orchestrator
    // (`::inner` calls, playbook `main()` code) must honour check mode
    // just like their RPC-driven worker-side twins — the flag describes
    // the run, not the process.
    let dry_run = std::env::var_os("CINDY_DRY_RUN").is_some_and(|v| v == "1");
    crate::check::install(dry_run);
    let handshake = postcard::to_allocvec_cobs(&WorkerInbound::Handshake {
        vault_keys,
        dry_run,
    })
    .expect("Failed to serialize handshake");
    // Budgeted like any other frame — at startup nothing competes for
    // permits, so this can't park.
    let permit = dispatch
        .budget
        .clone()
        .acquire_many_owned(
            u32::try_from(crate::common::call_cost(
                handshake.len(),
                dispatch.budget_size,
            ))
            .unwrap_or(u32::MAX),
        )
        .await
        .expect("RPC budget semaphore closed");
    if dispatch.writer_tx.send((handshake, permit)).await.is_err() {
        panic!("writer task died before the handshake was queued");
    }

    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt as _;

        let mut stdin = tokio::io::BufReader::new(rpc_in);
        let mut buffer = Vec::with_capacity(4096);

        // Ending this task for any reason (EOF, I/O error, corrupt
        // frame) drops `reader_tx`, which the routing loop below sees
        // as `None` and treats as "the worker is gone".
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
        while let Some((cobs_packet, permit)) = writer_rx.recv().await {
            use tokio::io::AsyncWriteExt as _;

            if let Err(e) = stdout.write_all(&cobs_packet).await {
                // A broken write pipe means the same dead-worker scenario
                // the reader side sees as EOF: stop here and let the reader
                // task's teardown fail the in-flight calls.
                eprintln!("RPC write error on the worker channel: {e}");
                break;
            }
            let _ = stdout.flush().await;
            // The frame is on the pipe: the budget these permits
            // represent is no longer held as an unwritten copy in this
            // process — SSH flow control owns the backpressure from
            // here. Drop releases the permits.
            drop(permit);
        }
    });

    // Response routing only. Dispatch (budget acquire, registration,
    // frame serialisation) happens in the per-call tasks that
    // `call()` spawns — routing must never park behind a saturated
    // budget, because the worker's own budget only releases as
    // responses flow through this loop; parking here would deadlock
    // both sides.
    loop {
        match reader_rx.recv().await {
            Some(response) => {
                // If the receiving future was dropped before the
                // response arrived (e.g. a sibling in a `try_join!`
                // already errored), there's nothing to deliver to —
                // ignore rather than crash the RPC loop.
                if let Some(tx) = dispatch.lock().calls.remove(&response.uuid) {
                    let _ = tx.send(response.response);
                }
            }
            // Reader task ended: worker EOF, I/O error, or corrupt
            // frame. Mark the dispatch dead, fail every in-flight
            // call (dropping the oneshot senders would do it too, but
            // an explicit message beats a generic "channel closed"),
            // and let late dispatch attempts fail fast at their
            // registration instead of hanging.
            None => {
                let mut pending = dispatch.lock();
                let in_flight = pending.calls.len();
                if in_flight > 0 {
                    eprintln!(
                        "RPC connection to the worker closed with {in_flight} call(s) still \
                         in flight"
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
                break;
            }
        }
    }
}
