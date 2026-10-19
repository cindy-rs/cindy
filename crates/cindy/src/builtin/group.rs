//! A Unix group, via `groupadd`/`groupmod`/`groupdel`.

use std::process::Command;

use crate::Context;

#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Presence {
    Absent,
    Present {
        /// `None`: allocated on create, left alone afterwards.
        gid: Option<u32>,
        /// Create in the system GID range. Afterwards it isn't
        /// independent: a group is a system group iff its GID ≤
        /// `SYS_GID_MAX`, so a `Some` that contradicts the resulting
        /// GID is an error.
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
    pub name: String,
    pub presence: Presence,
}

impl crate::Diff for State {}

/// The full-control entry point; the verbs cover the common cases.
#[crate::remote]
pub fn group(state: State) -> crate::Result<super::Return> {
    apply(state)
}

#[crate::action]
pub fn present(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::default(),
    })
}

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

/// A system group (GID from the system range on create).
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

#[crate::action]
pub fn absent(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Absent,
    })
}

fn sys_gid_max() -> u32 {
    super::login_defs_value("SYS_GID_MAX", 999)
}

fn live_gid(name: &str) -> crate::Result<Option<u32>> {
    Ok(nix::unistd::Group::from_name(name)
        .context("Group lookup failed")?
        .map(|g| g.gid.as_raw()))
}

fn as_present(gid: u32) -> Presence {
    Presence::Present {
        gid: Some(gid),
        system: Some(gid <= sys_gid_max()),
    }
}

/// `Some((want_system, gid))` when `system` contradicts the GID the
/// group ends up with — the wanted one, else `live_gid`.
fn system_conflict(
    want: &Presence,
    live_gid: Option<u32>,
    sys_gid_max: u32,
) -> Option<(bool, u32)> {
    let Presence::Present {
        gid,
        system: Some(want_system),
    } = want
    else {
        return None;
    };
    let gid = gid.or(live_gid)?;
    ((gid <= sys_gid_max) != *want_system).then_some((*want_system, gid))
}

fn check_system_consistency(
    name: &str,
    want: &Presence,
    live_gid: Option<u32>,
) -> crate::Result<()> {
    if let Some((want_system, gid)) = system_conflict(want, live_gid, sys_gid_max()) {
        let side = if want_system { "at or below" } else { "above" };
        crate::bail!(
            "group `{name}`: `system: Some({want_system})` contradicts GID {gid} — \
             a group is a system group iff its GID ≤ SYS_GID_MAX ({}). System-ness follows \
             the GID: drop the `system` field, or pick a GID {side} that boundary.",
            sys_gid_max()
        );
    }
    Ok(())
}

fn show_diff(name: &str, old: Presence, new: Presence) {
    let view = |presence| State {
        name: name.to_owned(),
        presence,
    };
    let (old, new) = (view(old), view(new));
    if old != new {
        let _ = crate::Diff::diff(&old, &new, &mut std::io::stderr().lock());
    }
}

/// Also what a lost create race lands in: the group another run created
/// may not match the request.
fn reconcile_existing(name: &str, want: &Presence, live: u32) -> crate::Result<bool> {
    check_system_consistency(name, want, Some(live))?;
    let Presence::Present { gid: Some(gid), .. } = *want else {
        return Ok(false);
    };
    if gid == live {
        return Ok(false);
    }
    show_diff(name, as_present(live), as_present(gid));
    if !crate::dry_run() {
        super::run_check_retry_locks(Command::new("groupmod").args([
            "--gid",
            &gid.to_string(),
            "--",
            name,
        ]))?;
    }
    Ok(true)
}

fn apply(state: State) -> crate::Result<super::Return> {
    let name = &state.name;
    let changed = match (&state.presence, live_gid(name)?) {
        (Presence::Absent, None) => false,
        (Presence::Absent, Some(live)) => {
            show_diff(name, as_present(live), Presence::Absent);
            if !crate::dry_run() {
                super::run_check_retry_locks(Command::new("groupdel").args(["--", name]))?;
            }
            true
        }
        (want @ Presence::Present { gid, system }, None) => {
            check_system_consistency(name, want, None)?;
            show_diff(name, Presence::Absent, want.clone());
            if !crate::dry_run() {
                let mut cmd = Command::new("groupadd");
                if *system == Some(true) {
                    cmd.arg("--system");
                }
                if let Some(gid) = gid {
                    cmd.args(["--gid", &gid.to_string()]);
                }
                if let Err(e) = super::run_check_retry_locks(cmd.args(["--", name])) {
                    // A concurrent run created it first: reconcile that.
                    match live_gid(name)? {
                        Some(live) if super::is_create_race(&e) => {
                            reconcile_existing(name, want, live)?;
                        }
                        _ => return Err(e),
                    }
                }
            }
            true
        }
        (want, Some(live)) => reconcile_existing(name, want, live)?,
    };
    Ok(super::Return::from_changed(changed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn want(gid: Option<u32>, system: Option<bool>) -> Presence {
        Presence::Present { gid, system }
    }

    #[test]
    fn system_request_must_agree_with_the_resulting_gid() {
        const MAX: u32 = 999;

        assert!(system_conflict(&want(None, Some(true)), Some(1500), MAX).is_some());
        assert!(system_conflict(&want(Some(2000), Some(true)), Some(1500), MAX).is_some());

        assert!(system_conflict(&want(Some(500), Some(false)), Some(1500), MAX).is_some());
        assert!(system_conflict(&want(None, Some(false)), Some(500), MAX).is_some());

        assert!(system_conflict(&want(Some(500), Some(true)), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(2000), Some(false)), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(1500), Some(false)), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(MAX), Some(true)), Some(1500), MAX).is_none());

        assert!(system_conflict(&want(None, None), Some(1500), MAX).is_none());
        assert!(system_conflict(&want(Some(500), None), Some(1500), MAX).is_none());

        assert!(system_conflict(&want(Some(2000), Some(true)), None, MAX).is_some());
        assert!(system_conflict(&want(None, Some(true)), None, MAX).is_none());
        assert!(system_conflict(&want(None, Some(false)), None, MAX).is_none());
    }
}
