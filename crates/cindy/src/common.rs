use uuid::Uuid;

#[doc(hidden)]
#[crate::wire]
pub struct RemoteFnPayload {
    pub uuid: Uuid,
    pub fn_id: String,
    pub data: Vec<u8>,
}

/// A message the orchestrator sends *to* the worker over the RPC
/// channel.
///
/// The first frame is always a [`Handshake`](WorkerInbound::Handshake)
/// carrying the vault keys this worker needs; everything after is a
/// [`Call`](WorkerInbound::Call). Routing keys through the channel
/// (rather than an env var or argv) means the raw key material never
/// appears in the target's process table — it lives only in the
/// SSH-protected pipe and the worker's memory.
#[doc(hidden)]
#[crate::wire]
pub enum WorkerInbound {
    /// Sent once, first: the `{vault: raw-key-bytes}` map the worker
    /// installs into its keychain before serving any calls, plus the
    /// check-mode decision (`cindy play --check`) installed before any
    /// call is dispatched.
    Handshake {
        vault_keys: std::collections::HashMap<String, Vec<u8>>,
        dry_run: bool,
    },
    /// A remote-function invocation.
    Call(RemoteFnPayload),
}

#[doc(hidden)]
#[crate::wire]
pub enum RemoteFnResponse {
    Ok(Vec<u8>),
    Panic(String),
}

#[doc(hidden)]
#[crate::wire]
pub struct RemoteFnResponsePayload {
    pub uuid: Uuid,
    pub response: RemoteFnResponse,
}

#[doc(hidden)]
pub fn quarantine_stdio() -> (tokio::fs::File, tokio::fs::File) {
    let saved_in = nix::unistd::dup(std::io::stdin()).expect("Couldn't dup RPC stdin off FD 0");
    let saved_out = nix::unistd::dup(std::io::stdout()).expect("Couldn't dup RPC stdout off FD 1");

    // Mark the saved RPC fds close-on-exec. Without this, every process a
    // `#[remote]` fn spawns inherits the pipe ends: a daemonizing child
    // would hold the RPC stream open (so the orchestrator never sees EOF
    // when the worker exits) and could even write garbage into it.
    for fd in [&saved_in, &saved_out] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .expect("Couldn't set FD_CLOEXEC on the saved RPC fd");
    }

    nix::unistd::dup2_stdout(std::io::stderr()).expect("Couldn't redirect FD 1 to stderr");

    let dev_null =
        std::fs::File::open("/dev/null").expect("Couldn't open /dev/null for FD 0 redirect");
    nix::unistd::dup2_stdin(&dev_null).expect("Couldn't redirect FD 0 to /dev/null");
    // `dev_null` drops here; the kernel still holds the underlying file
    // via FD 0, which `dup2_stdin` just pointed at it.

    (
        tokio::fs::File::from_std(std::fs::File::from(saved_in)),
        tokio::fs::File::from_std(std::fs::File::from(saved_out)),
    )
}

/// Per-call floor on the RPC byte budget: even a tiny frame is
/// accounted at least this much, covering the task stack and dispatch
/// overhead its wire size doesn't reflect.
pub(crate) const RPC_BUDGET_CALL_FLOOR: usize = 8 * 1024;

/// Budget used when the worker can't determine the host's RAM.
pub(crate) const RPC_BUDGET_FALLBACK: usize = 16 * 1024 * 1024;

/// Clamps for the memory-sized budget: the floor keeps tiny targets
/// workable, the cap keeps a huge box from holding absurd in-flight
/// buffers on a machine it shares with real services.
pub(crate) const RPC_BUDGET_MIN: usize = 8 * 1024 * 1024;
pub(crate) const RPC_BUDGET_MAX: usize = 256 * 1024 * 1024;

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
pub(crate) fn rpc_byte_budget() -> usize {
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
pub(crate) fn call_cost(frame_len: usize, budget: usize) -> usize {
    frame_len.max(RPC_BUDGET_CALL_FLOOR).min(budget)
}

/// Orchestrator-side cost estimate for one outbound call, taken
/// before the frame is serialised (the frame copy must never exist
/// above budget): the arg bytes plus COBS framing (~1 byte per 254)
/// and the uuid/fn-id wrapper.
pub(crate) fn outbound_cost(arg_len: usize, budget: usize) -> usize {
    call_cost(arg_len + arg_len / 254 + 64, budget)
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

    #[test]
    fn outbound_cost_estimates_cobs_and_wrapper_overhead() {
        // Tiny args land on the floor; a 1 MiB arg estimates a touch
        // over its own size; nothing exceeds the budget.
        assert_eq!(outbound_cost(100, 16 * 1024 * 1024), RPC_BUDGET_CALL_FLOOR);
        assert_eq!(
            outbound_cost(1024 * 1024, 16 * 1024 * 1024),
            1024 * 1024 + 1024 * 1024 / 254 + 64
        );
        assert_eq!(outbound_cost(999_999_999, 1024), 1024);
    }
}
