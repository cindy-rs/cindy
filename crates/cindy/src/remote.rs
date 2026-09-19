use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
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

/// Per-call floor on the RPC byte budget: even a tiny frame is
/// accounted at least this much, covering the task stack and dispatch
/// overhead its wire size doesn't reflect.
const RPC_BUDGET_CALL_FLOOR: usize = 8 * 1024;

/// Budget used when the worker can't determine the host's RAM.
const RPC_BUDGET_FALLBACK: usize = 16 * 1024 * 1024;

/// Clamps for the memory-sized budget: the floor keeps tiny targets
/// workable, the cap keeps a huge box from holding absurd in-flight
/// buffers on a machine it shares with real services.
const RPC_BUDGET_MIN: usize = 8 * 1024 * 1024;
const RPC_BUDGET_MAX: usize = 256 * 1024 * 1024;

/// `MemTotal` from a `/proc/meminfo` rendering, in kB.
fn parse_mem_total_kb(text: &str) -> Option<u64> {
    let kb: u64 = text
        .lines()
        .find(|l| l.starts_with("MemTotal:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb)
}

/// Total physical RAM of the target, in bytes.
fn total_memory_bytes() -> Option<u64> {
    parse_mem_total_kb(&std::fs::read_to_string("/proc/meminfo").ok()?).map(|kb| kb * 1024)
}

/// Budget from the host's RAM: 1/16 (6.25%). The budget is a cap on
/// in-flight arg buffers, not an allocation — a generous cap on a big
/// box just means backpressure rarely engages, which is exactly what
/// that box can afford.
fn budget_from_total(total: Option<u64>) -> usize {
    match total {
        Some(total) => {
            usize::try_from((total / 16).clamp(RPC_BUDGET_MIN as u64, RPC_BUDGET_MAX as u64))
                .unwrap_or(RPC_BUDGET_MAX)
        }
        None => RPC_BUDGET_FALLBACK,
    }
}

/// The worker's RPC byte budget. Auto-sized from the target's RAM;
/// `CINDY_RPC_BUDGET` (bytes) overrides it exactly, bypassing the
/// clamps — a hook for tests and debugging, not reachable through the
/// CLI's ssh launch (which sets no worker env).
fn rpc_byte_budget() -> usize {
    if let Ok(raw) = std::env::var("CINDY_RPC_BUDGET") {
        return match raw.trim().parse::<usize>() {
            Ok(bytes) => bytes.max(1),
            Err(_) => {
                eprintln!("\x1b[31mCINDY_RPC_BUDGET must be a number of bytes, got `{raw}`\x1b[0m");
                std::process::exit(1);
            }
        };
    }
    budget_from_total(total_memory_bytes())
}

/// Budget cost of one call: its frame's wire size, at least the
/// per-call floor, never more than the whole budget (a frame bigger
/// than the budget runs alone rather than deadlocking on permits
/// that can never coexist).
fn call_cost(frame_len: usize, budget: usize) -> usize {
    frame_len.max(RPC_BUDGET_CALL_FLOOR).min(budget)
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

    // Byte-weighted backpressure. The worker used to spawn one task
    // per incoming call with no cap: a play fanning out thousands of
    // sizeable calls amplified into unbounded concurrent executions on
    // the machine with the least RAM. Rather than an arbitrary
    // concurrency limit — which would also throttle cheap-but-numerous
    // work — each in-flight call holds semaphore permits for its
    // frame's wire size (floored for per-call overhead). The reader
    // task acquires them *before* reading on: when the budget is
    // saturated it stops reading from the socket, the stall propagates
    // back through SSH flow control to the orchestrator's writer, and
    // queue growth is bounded by what the play itself already holds in
    // memory. Lightweight fan-outs stay wide open (1k small calls cost
    // a few MiB of budget); heavyweight args throttle to roughly
    // budget/size concurrent.
    let budget = rpc_byte_budget();
    let budget_sem = Arc::new(tokio::sync::Semaphore::new(budget));

    let (process_tx, mut process_rx) = tokio::sync::mpsc::unbounded_channel::<(
        RemoteFnPayload,
        tokio::sync::OwnedSemaphorePermit,
    )>();
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt as _;

        let mut stdin = tokio::io::BufReader::new(rpc_in);
        let mut buffer = Vec::with_capacity(4096);

        loop {
            match stdin.read_until(0x00, &mut buffer).await {
                Ok(0) => break,
                Ok(_) => {
                    let frame_len = buffer.len();
                    match postcard::from_bytes_cobs::<WorkerInbound>(&mut buffer) {
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
                            // Acquiring before the send (and before the next
                            // read) is what makes the budget bite: a saturated
                            // semaphore parks this loop, not just the tasks.
                            let cost = call_cost(frame_len, budget);
                            let cost = u32::try_from(cost).unwrap_or(u32::MAX);
                            let permit = budget_sem
                                .clone()
                                .acquire_many_owned(cost)
                                .await
                                .expect("RPC budget semaphore closed");
                            process_tx
                                .send((payload, permit))
                                .expect("Processing channel closed");
                        }
                        // A frame we can't decode is unrecoverable: silently
                        // dropping it would leave the orchestrator awaiting a
                        // response that never comes. Die loudly instead — our
                        // EOF makes the orchestrator fail all in-flight calls.
                        Err(e) => {
                            eprintln!("RPC framing corruption on worker stdin: {e:?}");
                            std::process::exit(1);
                        }
                    }
                }
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

    while let Some((payload, permit)) = process_rx.recv().await {
        let writer_tx = writer_tx.clone();

        tokio::spawn(async move {
            // Held for the call's whole in-flight life — from the
            // reader's acquire until the response is queued — then
            // released with the task, handing the budget back.
            let _budget_permit = permit;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_scales_with_memory_and_clamps() {
        let mib: u64 = 1024 * 1024;
        // Degenerate / tiny hosts get the floor, not a useless budget.
        assert_eq!(budget_from_total(None), RPC_BUDGET_FALLBACK);
        assert_eq!(budget_from_total(Some(0)), RPC_BUDGET_MIN);
        assert_eq!(budget_from_total(Some(64 * mib)), RPC_BUDGET_MIN);
        // 1/16 of RAM in the normal range.
        assert_eq!(budget_from_total(Some(2 * 1024 * mib)), 128 * 1024 * 1024);
        // Huge hosts are capped.
        assert_eq!(budget_from_total(Some(u64::MAX)), RPC_BUDGET_MAX);
    }

    #[test]
    fn memtotal_line_is_parsed_and_garbage_is_rejected() {
        assert_eq!(
            parse_mem_total_kb("MemTotal:       16384256 kB\nMemFree:  1 kB\n"),
            Some(16384256)
        );
        assert_eq!(parse_mem_total_kb("MemTotal:  42  kB"), Some(42));
        assert_eq!(parse_mem_total_kb("no meminfo here"), None);
        assert_eq!(parse_mem_total_kb("MemTotal: xyz kB"), None);
    }

    #[test]
    fn call_cost_floors_small_frames_and_caps_oversized_ones() {
        let budget = 16 * 1024 * 1024;
        assert_eq!(call_cost(100, budget), RPC_BUDGET_CALL_FLOOR);
        assert_eq!(call_cost(100_000, budget), 100_000);
        // A frame bigger than the whole budget runs alone rather than
        // deadlocking on permits that can never coexist.
        assert_eq!(call_cost(999_999_999, budget), budget);
        // A budget overridden below the floor still admits one call at
        // a time.
        assert_eq!(call_cost(100, 1), 1);
    }
}
