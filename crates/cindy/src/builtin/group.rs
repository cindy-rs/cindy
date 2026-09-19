//! Manage a Unix group on the remote machine via
//! `groupadd`/`groupmod`/`groupdel`.
//!
//! State is read back through `nix` (the same NSS-backed lookup the
//! other builtins use for user/group resolution), so the module is
//! idempotent: it only shells out to the `group*` tools when the live
//! group doesn't already match the desired [`State`].

use std::process::Command;

use crate::Context;

/// Whether the group should exist, and how.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Presence {
    /// `groupdel`: ensure the group does not exist. Idempotent over the
    /// already-absent case.
    Absent,
    /// `groupadd` / `groupmod`: ensure the group exists. `gid` pins the
    /// numeric GID (`None` ⇒ let the system allocate one on create, and
    /// leave it alone on an existing group). `system` steers the GID
    /// range on create and must stay consistent with the resulting GID
    /// afterwards (see the field docs).
    Present {
        /// Desired numeric GID. `None` ⇒ system-allocated on create,
        /// untouched on an existing group.
        gid: Option<u32>,
        /// Create as a system group (GID from the system range). Only
        /// steers GID allocation when the group is **created**. For an
        /// existing group, system-ness is not an independent attribute:
        /// a group is a system group iff its GID ≤ `SYS_GID_MAX`. A
        /// `Some(..)` must therefore agree with the GID the group will
        /// have after reconciliation — the requested `gid` if set,
        /// else the live one — and a disagreement errors instead of
        /// silently never converging. `None` (the default) lets it
        /// follow the GID.
        system: Option<bool>,
    },
}

impl Default for Presence {
    fn default() -> Self {
        Self::Present {
            gid: None,
            system: None,
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Group name.
    pub name: String,
    /// Desired presence. Defaults to `Present { gid: None, system: None }`.
    pub presence: Presence,
}

/// Default `{:#?}`-based diff is fine — small scalars only.
impl crate::Diff for State {}

/// The highest GID considered a "system" group on this host.
///
/// Read from `SYS_GID_MAX` in `/etc/login.defs` (the value `groupadd
/// --system` itself honours), so our observation of system-ness matches
/// how the group would actually have been created. Falls back to 999,
/// the near-universal default, when the file is absent or unparseable.
fn sys_gid_max() -> u32 {
    super::login_defs_value("SYS_GID_MAX", 999)
}

/// What we observed about the group on the remote, normalized into a
/// `Presence` for diffing.
fn observe(name: &str) -> crate::Result<Presence> {
    match nix::unistd::Group::from_name(name).context("Group lookup failed")? {
        Some(g) => {
            let gid = g.gid.as_raw();
            Ok(Presence::Present {
                gid: Some(gid),
                // Observed from the live GID against the host's own
                // `SYS_GID_MAX`, so a requested mismatch can be detected
                // (see `apply`).
                system: Some(gid <= sys_gid_max()),
            })
        }
        None => Ok(Presence::Absent),
    }
}

/// Render a `State` struct diff of `old` vs `new` to stderr
/// (informational; write errors ignored), matching the other builtins.
fn show_diff(name: &str, old: Presence, new: Presence) {
    let old_view = State {
        name: name.to_owned(),
        presence: old,
    };
    let new_view = State {
        name: name.to_owned(),
        presence: new,
    };
    if old_view != new_view {
        let _ = <State as crate::Diff>::diff(&old_view, &new_view, &mut std::io::stderr().lock());
    }
}

/// Manage a single Unix group on the remote machine.
///
/// This is the full-control entry point taking a [`State`]. For the common
/// cases, prefer the intent-named helpers: [`present`], [`absent`],
/// [`system`].
#[crate::remote]
pub fn group(state: State) -> crate::Result<super::Return> {
    apply(state)
}

// Intent-named helpers, each a single `#[crate::action]` fn whose body builds
// a `State` and calls `apply`. The macro generates the concrete `#[remote]`
// wire entry point, the orchestrator shim, and the in-process `::inner`.

/// Ensure group `name` exists, letting the system allocate its GID.
/// Orchestrator: `present(name).await?`.
#[crate::action]
pub fn present(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Present {
            gid: None,
            system: None,
        },
    })
}

/// Ensure group `name` exists with exactly `gid`. Orchestrator:
/// `present_with_gid(name, gid).await?`.
#[crate::action]
pub fn present_with_gid(name: impl Into<String>, gid: u32) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Present {
            gid: Some(gid),
            system: None,
        },
    })
}

/// Ensure a *system* group `name` exists (GID from the system range on
/// create). Orchestrator: `system(name).await?`.
#[crate::action]
pub fn system(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Present {
            gid: None,
            system: Some(true),
        },
    })
}

/// Ensure group `name` does not exist (`groupdel`). Idempotent.
/// Orchestrator: `absent(name).await?`.
#[crate::action]
pub fn absent(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Absent,
    })
}

/// The desired `system` flag vs the GID the group would actually end
/// up with — the requested `gid` if set, else `fallback_gid` (the live
/// GID when reconciling an existing group). Returns the offending
/// `(want_system, effective_gid)` when they contradict: a group is a
/// system group iff its GID ≤ `sys_gid_max`, so e.g. `system:
/// Some(true)` together with a GID above the boundary is a request
/// that can never converge.
fn system_conflict(
    want: &Presence,
    fallback_gid: Option<u32>,
    sys_gid_max: u32,
) -> Option<(bool, u32)> {
    let Presence::Present {
        gid: want_gid,
        system: Some(want_system),
    } = want
    else {
        return None;
    };
    let effective_gid = want_gid.or(fallback_gid)?;
    if (effective_gid <= sys_gid_max) != *want_system {
        Some((*want_system, effective_gid))
    } else {
        None
    }
}

/// Reject a `system` request that contradicts the GID it implies, with
/// an error that states the derived rule instead of a tool limitation.
fn check_system_consistency(
    name: &str,
    want: &Presence,
    fallback_gid: Option<u32>,
) -> crate::Result<()> {
    if let Some((want_system, effective_gid)) = system_conflict(want, fallback_gid, sys_gid_max()) {
        let side = if want_system { "at or below" } else { "above" };
        crate::bail!(
            "group `{name}`: `system: Some({want_system})` contradicts GID {effective_gid} — \
             a group is a system group iff its GID ≤ SYS_GID_MAX ({}). System-ness follows \
             the GID: drop the `system` field, or pick a GID {side} that boundary.",
            sys_gid_max()
        );
    }
    Ok(())
}

/// Reconcile an existing group towards `want`: reconcile the GID, with
/// the "new" diff view reporting system derived from the target GID —
/// honest about the side effect of moving it across the system
/// boundary. Any requested `system` is checked against the GID the
/// group would keep or move to, covering both the plain reconcile
/// path and the create-race path (where the group another agent
/// created may sit on the wrong side of the boundary for the request).
/// Returns whether the group changed.
fn reconcile_existing(name: &str, want: &Presence, observed: &Presence) -> crate::Result<bool> {
    let (
        Presence::Present { gid: want_gid, .. },
        Presence::Present {
            gid: Some(have_gid),
            ..
        },
    ) = (want, observed)
    else {
        // Observed groups always carry a GID.
        unreachable!("reconcile_existing expects a live Present group");
    };
    check_system_consistency(name, want, Some(*have_gid))?;
    match want_gid {
        Some(w) if *w != *have_gid => {
            show_diff(
                name,
                observed.clone(),
                Presence::Present {
                    gid: Some(*w),
                    system: Some(*w <= sys_gid_max()),
                },
            );
            super::run_check_retry_locks(Command::new("groupmod").args([
                "--gid",
                &w.to_string(),
                "--",
                name,
            ]))?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn apply(state: State) -> crate::Result<super::Return> {
    let observed = observe(&state.name)?;

    let changed = match (&state.presence, &observed) {
        // Want absent, already gone.
        (Presence::Absent, Presence::Absent) => false,

        // Want absent, currently present → delete.
        (Presence::Absent, present @ Presence::Present { .. }) => {
            show_diff(&state.name, present.clone(), Presence::Absent);
            super::run_check_retry_locks(Command::new("groupdel").args(["--", &state.name]))?;
            true
        }

        // Want present, currently absent → create.
        (want @ Presence::Present { gid, system }, Presence::Absent) => {
            check_system_consistency(&state.name, want, None)?;
            show_diff(&state.name, Presence::Absent, want.clone());
            let mut cmd = Command::new("groupadd");
            if *system == Some(true) {
                cmd.arg("--system");
            }
            if let Some(gid) = gid {
                cmd.args(["--gid", &gid.to_string()]);
            }
            match super::run_check_retry_locks(cmd.args(["--", &state.name])) {
                Ok(()) => true,
                // A concurrent run created the group between our
                // observation and our `groupadd` — the desired end
                // state arriving by another hand, not a lock problem
                // (that path retried already). Re-observe and
                // reconcile what actually landed; if it is somehow
                // still gone, the failure was real and is reported
                // as-is.
                Err(e) if super::is_create_race(&e) => {
                    let now = observe(&state.name)?;
                    match &now {
                        present @ Presence::Present { .. } => {
                            reconcile_existing(&state.name, want, present)?
                        }
                        _ => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }

        // Want present, already present → reconcile.
        (want @ Presence::Present { .. }, Presence::Present { .. }) => {
            reconcile_existing(&state.name, want, &observed)?
        }
    };

    Ok(super::Return::from_changed(changed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn want(gid: Option<u32>, system: Option<bool>) -> Presence {
        Presence::Present { gid, system }
    }

    /// The consistency rule the hoisted check enforces: `system` must
    /// agree with the GID the group would end up with. The GID-change
    /// arm used to sit above the check and never saw `system` at all.
    #[test]
    fn system_request_must_agree_with_the_resulting_gid() {
        const MAX: u32 = 999;

        // The two rows PLAN.md flagged: reachable before only without a
        // pinned GID.
        assert!(system_conflict(&want(None, Some(true)), Some(1500), MAX).is_some());
        assert!(system_conflict(&want(Some(2000), Some(true)), Some(1500), MAX).is_some());

        // The flip side: non-system asserted against a system GID.
        assert!(system_conflict(&want(Some(500), Some(false)), Some(1500), MAX).is_some());
        assert!(system_conflict(&want(None, Some(false)), Some(500), MAX).is_some());

        // Consistent requests pass, including a migration across the
        // boundary with an explicit, agreeing `system`.
        assert!(system_conflict(&want(Some(500), Some(true)), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(2000), Some(false)), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(1500), Some(false)), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(MAX), Some(true)), Some(1500), MAX).is_none());

        // `None` never conflicts — system-ness just follows the GID.
        assert!(system_conflict(&want(None, None), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(500), None), Some(1500), MAX).is_none());

        // Create-side: only an explicitly pinned GID can conflict.
        assert!(system_conflict(&want(Some(2000), Some(true)), None, MAX).is_some());
        assert!(system_conflict(&want(None, Some(true)), None, MAX).is_none());
        assert!(system_conflict(&want(None, Some(false)), None, MAX).is_none());
    }
}
