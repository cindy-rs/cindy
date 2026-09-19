//! Check mode (`cindy play --check`): report, don't apply.
//!
//! The decision arrives in the worker's RPC handshake and is installed
//! here as a process-global before any call is dispatched, so every
//! builtin can ask [`dry_run`] at its mutation point. Builtins respond
//! by rendering their diff as usual and returning
//! [`Changed`](crate::builtin::Return::Changed) for anything that
//! *would* have been applied — the report is the point.
//!
//! What check mode deliberately does **not** cover:
//!
//! - `command`/`shell` don't execute (their [`Output`](crate::builtin::command::Output)
//!   marks itself not-run; `exit_ok` passes so plays flow through),
//!   but a play's *own* `#[remote]` functions still run — cindy can't
//!   know what user code mutates. Treat a green `--check` as "the
//!   builtins wouldn't touch anything", not "nothing would happen".
//! - `fetch` can't verify a checksum without downloading the body, so
//!   an existing destination reports `Unchanged` on content it can't
//!   re-check.

use std::sync::OnceLock;

static DRY_RUN: OnceLock<bool> = OnceLock::new();

/// Install the check-mode decision. Called exactly once, from the
/// worker's handshake processing, before any remote call is dispatched.
#[doc(hidden)]
pub fn install(dry_run: bool) {
    let _ = DRY_RUN.set(dry_run);
}

/// True when this process runs under `cindy play --check`: builtins
/// must report the change they *would* make without applying it.
///
/// Also usable from playbook code, to branch around work that check
/// mode can't fake (e.g. skip a step whose meaning depends on a
/// command's output).
pub fn dry_run() -> bool {
    DRY_RUN.get().copied().unwrap_or(false)
}
