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
    /// leave it alone on an existing group). `system` only affects
    /// creation (picks a GID from the system range); it can't be
    /// changed after the fact.
    Present {
        /// Desired numeric GID. `None` ⇒ system-allocated on create,
        /// untouched on an existing group.
        gid: Option<u32>,
        /// Create as a system group (GID from the system range). Only
        /// consulted when the group is being **created** — a group's
        /// system-ness is fixed by its GID at creation and cannot be
        /// changed afterwards without deleting and recreating it (which
        /// would orphan every file owned by the old GID). `None` (the
        /// default) leaves an existing group's system-ness alone; a
        /// `Some(..)` that disagrees with the live group errors instead
        /// of silently never converging. This matches Ansible's `group`
        /// module.
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

fn apply(state: State) -> crate::Result<super::Return> {
    let observed = observe(&state.name)?;

    let changed = match (&state.presence, &observed) {
        // Want absent, already gone.
        (Presence::Absent, Presence::Absent) => false,

        // Want absent, currently present → delete.
        (Presence::Absent, present @ Presence::Present { .. }) => {
            show_diff(&state.name, present.clone(), Presence::Absent);
            super::run_check(Command::new("groupdel").args(["--", &state.name]))?;
            true
        }

        // Want present, currently absent → create.
        (
            want @ Presence::Present { gid, system },
            Presence::Absent,
        ) => {
            show_diff(&state.name, Presence::Absent, want.clone());
            let mut cmd = Command::new("groupadd");
            if *system == Some(true) {
                cmd.arg("--system");
            }
            if let Some(gid) = gid {
                cmd.args(["--gid", &gid.to_string()]);
            }
            super::run_check(cmd.args(["--", &state.name]))?;
            true
        }

        // Want present, already present → reconcile the GID only. We
        // never migrate system-ness (see `Presence::Present::system`);
        // an explicit request that disagrees with the live group errors
        // instead of silently never converging. The "new" diff view
        // reports system inferred from the target GID purely so the
        // rendered diff is honest about the side effect of moving the
        // GID across the system boundary.
        (
            Presence::Present {
                gid: Some(want), ..
            },
            Presence::Present {
                gid: Some(have), ..
            },
        ) if want != have => {
            show_diff(
                &state.name,
                observed.clone(),
                Presence::Present {
                    gid: Some(*want),
                    system: Some(*want <= sys_gid_max()),
                },
            );
            super::run_check(Command::new("groupmod").args([
                "--gid",
                &want.to_string(),
                "--",
                &state.name,
            ]))?;
            true
        }

        (
            Presence::Present { system, .. },
            Presence::Present {
                system: observed_system,
                ..
            },
        ) => {
            if let Some(want_system) = *system
                && let Some(live_system) = *observed_system
                && want_system != live_system
            {
                crate::bail!(
                    "group `{}` exists with system={live_system}, but the desired \
                     state says system={want_system}: groupmod cannot move a group \
                     between the system and regular GID ranges. Drop the `system` \
                     field from the desired state, or delete and recreate the group.",
                    state.name
                );
            }
            false
        }
    };

    Ok(super::Return::from_changed(changed))
}
