//! Check mode (`cindy play --check`): report, don't apply.
//!
//! The decision arrives in the worker's RPC handshake and is installed
//! here as a process-global before any call is dispatched, so every
//! builtin can ask [`dry_run`] at its mutation point. Builtins respond
//! by rendering their diff as usual and returning
//! [`Changed`](crate::builtin::Return::Changed) for anything that
//! *would* have been applied — the report is the point.
//!
//! # What check mode is for
//!
//! Drift detection on a host the play has already converged — "has
//! anything moved since last time, and what would I put back?" It is
//! *not* a prediction of provisioning a fresh host, and can't be: see
//! the dependency limit below.
//!
//! # What it deliberately does **not** cover
//!
//! - `command`/`shell` don't execute unless declared
//!   [`Effect::ReadOnly`](crate::builtin::command::Effect::ReadOnly)
//!   (that's what [`probe`](crate::builtin::command::probe) is); a
//!   skipped one's [`Output`](crate::builtin::command::Output) marks
//!   itself not-run and `exit_ok` passes, so plays flow through. A
//!   play's *own* `#[remote]` functions still run — cindy can't know
//!   what user code mutates. Custom functions that mutate should guard
//!   themselves with [`dry_run`], reporting the would-change instead of
//!   applying it.
//! - **Steps that depend on an earlier step's effects.** A driver
//!   install that doesn't run leaves no device nodes, so everything
//!   downstream of it sees a host that doesn't exist yet — it fails, or
//!   worse, reports confidently about the wrong state. This is inherent
//!   to the idea, not a gap to close: you cannot know what a program
//!   produces without running it. Terraform spells the same hole
//!   `(known after apply)`.
//!
//!   The honest shapes, in order of preference: run `--check` against a
//!   host that is already converged, where those prerequisites exist
//!   (that's what check mode is good at); use
//!   [`probe`](crate::builtin::command::probe) where the dependency is
//!   only *information*, so the branch stays truthful; or guard the
//!   dependent region with [`dry_run`] and **say so on stderr**, so the
//!   operator can see check mode left a region unexamined rather than
//!   silently covering 60% of the play and reporting green.
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
