use uuid::Uuid;

#[doc(hidden)]
#[crate::wire]
pub struct RemoteFnPayload {
    pub uuid: Uuid,
    pub fn_id: String,
    pub data: Vec<u8>,
}

/// Orchestrator → worker. The first frame is the handshake, every later
/// one a call; the worker refuses a call that comes first.
#[doc(hidden)]
#[crate::wire]
pub enum WorkerInbound {
    /// Keys travel here, never in the target's argv or env.
    Handshake {
        vault_keys: std::collections::HashMap<String, Vec<u8>>,
        dry_run: bool,
    },
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

/// Moves the RPC pipes off fds 0 and 1 — stdout becomes stderr and stdin
/// `/dev/null` — so a stray `println!` can't corrupt the stream.
#[doc(hidden)]
pub fn quarantine_stdio() -> (tokio::fs::File, tokio::fs::File) {
    let saved_in = nix::unistd::dup(std::io::stdin()).expect("Couldn't dup RPC stdin off FD 0");
    let saved_out = nix::unistd::dup(std::io::stdout()).expect("Couldn't dup RPC stdout off FD 1");

    // Close-on-exec: a daemonizing child of a `#[remote]` fn would
    // otherwise hold the RPC stream open past the worker's exit.
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

    (
        tokio::fs::File::from_std(std::fs::File::from(saved_in)),
        tokio::fs::File::from_std(std::fs::File::from(saved_out)),
    )
}

/// What even a tiny call costs: its task and dispatch overhead.
pub(crate) const RPC_BUDGET_CALL_FLOOR: usize = 8 * 1024;

/// Budget used when the worker can't determine the host's RAM.
pub(crate) const RPC_BUDGET_FALLBACK: usize = 16 * 1024 * 1024;

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

/// 1/16 of RAM, clamped. A cap on in-flight arguments, not an
/// allocation.
fn budget_from_total(total: Option<u64>) -> usize {
    match total {
        Some(total) => {
            usize::try_from((total / 16).clamp(RPC_BUDGET_MIN as u64, RPC_BUDGET_MAX as u64))
                .unwrap_or(RPC_BUDGET_MAX)
        }
        None => RPC_BUDGET_FALLBACK,
    }
}

/// `CINDY_RPC_BUDGET` (bytes) overrides it, unclamped — for tests; the
/// CLI's ssh launch sets no worker env.
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

/// A frame's size, floored, and capped at the whole budget so an
/// oversized frame runs alone instead of waiting forever.
pub(crate) fn call_cost(frame_len: usize, budget: usize) -> usize {
    frame_len.max(RPC_BUDGET_CALL_FLOOR).min(budget)
}

/// Estimated before serialising, so the frame never exists over budget:
/// args, COBS overhead (1 in 254) and the uuid/fn-id wrapper.
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
