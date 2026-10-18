//! Check mode (`cindy play --check`): report, don't apply.
//!
//! Builtins ask [`dry_run`] at each mutation point and return
//! [`Changed`](crate::builtin::Return::Changed) for what they *would*
//! have applied, diff included.
//!
//! Check mode answers "has this converged host drifted, and what would
//! I put back?". It can't predict provisioning a fresh host: a step
//! whose input is an earlier step's effect (a device node a skipped
//! driver install would create) sees a host that doesn't exist yet —
//! Terraform's `(known after apply)`. Run it against converged hosts;
//! use [`probe`](crate::builtin::command::probe) where the dependency is
//! only information; otherwise guard the region with [`dry_run`] and
//! say on stderr that it went unexamined.
//!
//! Not covered: a play's own `#[remote]` fns run as usual (cindy can't
//! know what they mutate — guard them with [`dry_run`]), and `fetch`
//! can't re-verify an existing destination's checksum without
//! downloading it.

use std::sync::OnceLock;

static DRY_RUN: OnceLock<bool> = OnceLock::new();

/// Set once, from the worker's handshake (or orchestrator startup),
/// before any call is dispatched.
#[doc(hidden)]
pub fn install(dry_run: bool) {
    let _ = DRY_RUN.set(dry_run);
}

/// True under `cindy play --check`: report the change, don't make it.
pub fn dry_run() -> bool {
    DRY_RUN.get().copied().unwrap_or(false)
}
