//! Manage a Unix user account on the remote machine via
//! `useradd`/`usermod`/`userdel`.
//!
//! Current state is read back through `nix` (`/etc/passwd` via NSS) plus
//! a group-membership scan for supplementary groups, so the module is
//! idempotent: it only invokes the `user*` tools when the live account
//! diverges from the desired [`State`].
//!
//! Passwords are deliberately **not supported**: infrastructure should
//! authenticate with SSH keys, not account passwords, and an API that
//! accepts a password invites cleartext secrets into inventories. If
//! you genuinely need to set one (bootstrapping a console login on an
//! appliance, say), pipe a pre-hashed crypt(3) line into `chpasswd -e`
//! yourself via [`command`](super::command) — the escape hatch keeps
//! the sharp edge visible instead of wrapping it in convenience.

use std::process::Command;

use crate::Context;

/// Desired supplementary-group membership.
///
/// `None` on the `groups` field means "don't touch membership at all".
/// When set, this picks the reconciliation strategy:
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Groups {
    /// Membership is made to match this set **exactly**: groups not
    /// listed are removed (`usermod --groups a,b,c`). Use when you own
    /// the user's full supplementary membership.
    Exact(Vec<String>),
    /// Ensure the user is in **at least** these groups, leaving any
    /// other existing memberships intact (`usermod --append --groups
    /// a,b,c`). Use when several plays each manage one group and must
    /// not stomp each other.
    Append(Vec<String>),
}

/// Whether the account should exist, and its desired attributes.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Presence {
    /// `userdel`: ensure the account does not exist. Idempotent over
    /// the already-absent case.
    Absent {
        /// Also delete the home directory and mail spool
        /// (`userdel --remove`). Lives on this variant — not on
        /// [`State`] — because it only means something when the account
        /// is being removed.
        remove_home: bool,
    },
    /// `useradd` / `usermod`: ensure the account exists with these
    /// attributes. Every field is "don't care" when `None`/empty:
    /// on create the system default is used; on an existing account the
    /// attribute is left untouched.
    Present {
        /// Numeric UID. `None` ⇒ system-allocated on create, untouched
        /// otherwise.
        uid: Option<u32>,
        /// Primary group name. `None` ⇒ distro default (usually a
        /// per-user group) on create, untouched otherwise.
        group: Option<String>,
        /// Supplementary group membership. `None` ⇒ leave membership
        /// alone. See [`Groups`] for the `Exact` (replace) vs `Append`
        /// (add without removing) strategies.
        groups: Option<Groups>,
        /// Login shell, e.g. `/bin/bash`. `None` ⇒ default / untouched.
        shell: Option<std::path::PathBuf>,
        /// Home directory path. `None` ⇒ default / untouched. Changing
        /// it on an existing user moves the directory (`usermod -m`).
        home: Option<std::path::PathBuf>,
        /// GECOS / comment field (full name etc.). `None` ⇒ untouched.
        comment: Option<String>,
        /// Create as a system account (UID from the system range, no
        /// per-user group skeleton by default). Only steers UID
        /// allocation when the account is **created**. For an existing
        /// account, system-ness is not an independent attribute: an
        /// account is a system account iff its UID ≤ `SYS_UID_MAX`. A
        /// `Some(..)` must therefore agree with the UID the account
        /// will have after reconciliation — the requested `uid` if
        /// set, else the live one — and a disagreement errors instead
        /// of silently never converging. `None` (the default) lets it
        /// follow the UID.
        system: Option<bool>,
    },
}

impl Default for Presence {
    fn default() -> Self {
        Self::Present {
            uid: None,
            group: None,
            groups: None,
            shell: None,
            home: None,
            comment: None,
            system: None,
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Login name.
    pub name: String,
    /// Desired presence and attributes.
    pub presence: Presence,
}

/// Default `{:#?}`-based struct diff — small scalars only.
impl crate::Diff for State {}

/// Read the supplementary groups (by name) that `name` is a member of,
/// excluding the user's primary group.
fn supplementary_groups(name: &str, primary_gid: nix::unistd::Gid) -> crate::Result<Vec<String>> {
    // `getgrouplist(3)` resolves the full set of groups for `name`
    // through the C library. Caveat: workers are static-musl binaries,
    // and musl has no NSS plugin support — the lookup reads
    // `/etc/group` only, so memberships from LDAP/SSSD-backed hosts are
    // invisible here. It returns the primary group too, so we filter it
    // out to leave only the supplementary set — the thing
    // `usermod --groups` manages.
    let cname = std::ffi::CString::new(name).context("User name contains an interior NUL byte")?;
    let gids = nix::unistd::getgrouplist(&cname, primary_gid)
        .context("getgrouplist failed for the user")?;

    let mut out = Vec::new();
    for gid in gids {
        if gid == primary_gid {
            continue;
        }
        // Map each GID back to a name; fall back to the numeric GID so
        // a group without an NSS entry still shows up rather than being
        // silently dropped.
        out.push(super::name_of_gid(gid.as_raw()));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The highest UID considered a "system" account on this host, read
/// from `SYS_UID_MAX` in `/etc/login.defs` (the value `useradd --system`
/// honours). Falls back to 999 when the file is absent or unparseable.
fn sys_uid_max() -> u32 {
    super::login_defs_value("SYS_UID_MAX", 999)
}

/// What we observed about the account, normalized into a `Presence`.
fn observe(name: &str) -> crate::Result<Presence> {
    let Some(user) = nix::unistd::User::from_name(name).context("User lookup failed")? else {
        return Ok(Presence::Absent { remove_home: false });
    };

    // Map the primary GID back to a group name for a readable diff;
    // fall back to the numeric GID string if the group has no entry.
    let group = super::name_of_gid(user.gid.as_raw());

    let groups = supplementary_groups(name, user.gid)?;
    let comment = user.gecos.to_string_lossy().into_owned();

    Ok(Presence::Present {
        uid: Some(user.uid.as_raw()),
        group: Some(group),
        // We observe the user's full supplementary set, so the live
        // membership is naturally an `Exact` view for diffing.
        groups: Some(Groups::Exact(groups)),
        shell: Some(user.shell),
        home: Some(user.dir),
        // Reported verbatim, *including* an empty string: normalising
        // empty → `None` would make a desired `Some("")` compare unequal
        // forever, re-running `usermod --comment ""` on every play.
        comment: Some(comment),
        // Observed from the live UID against the host's `SYS_UID_MAX` so
        // a requested mismatch can be detected (see `apply`).
        system: Some(user.uid.as_raw() <= sys_uid_max()),
    })
}

/// The desired `system` flag vs the UID the account would actually end
/// up with — the requested `uid` if set, else `fallback_uid` (the live
/// UID when reconciling an existing account). Returns the offending
/// `(want_system, effective_uid)` when they contradict: an account is
/// a system account iff its UID ≤ `sys_uid_max`, so e.g. `system:
/// Some(true)` together with a UID above the boundary is a request
/// that can never converge.
fn system_conflict(
    want: &Presence,
    fallback_uid: Option<u32>,
    sys_uid_max: u32,
) -> Option<(bool, u32)> {
    let Presence::Present {
        uid: want_uid,
        system: Some(want_system),
        ..
    } = want
    else {
        return None;
    };
    let effective_uid = want_uid.or(fallback_uid)?;
    if (effective_uid <= sys_uid_max) != *want_system {
        Some((*want_system, effective_uid))
    } else {
        None
    }
}

/// Reject a `system` request that contradicts the UID it implies, with
/// an error that states the derived rule instead of a tool limitation.
fn check_system_consistency(
    name: &str,
    want: &Presence,
    fallback_uid: Option<u32>,
) -> crate::Result<()> {
    if let Some((want_system, effective_uid)) = system_conflict(want, fallback_uid, sys_uid_max()) {
        let side = if want_system { "at or below" } else { "above" };
        crate::bail!(
            "user `{name}`: `system: Some({want_system})` contradicts UID {effective_uid} — \
             an account is a system account iff its UID ≤ SYS_UID_MAX ({}). System-ness \
             follows the UID: drop the `system` field, or pick a UID {side} that boundary.",
            sys_uid_max()
        );
    }
    Ok(())
}

/// Reconcile the desired `Present` attributes against the observed
/// ones, returning the `usermod` flags needed to close the gap.
///
/// This is the single source of truth for "what changed on an existing
/// account": every field is compared exactly once. The returned
/// argument vector drives the `usermod` call, and the [`reconciled`]
/// `Presence` (desired values back-filled with observed ones) is what
/// the struct diff is rendered against — so the diff and the command
/// can never disagree.
///
/// [`reconciled`]: ReconcileResult::desired
struct ReconcileResult {
    args: Vec<std::ffi::OsString>,
    desired: Presence,
}

/// Compare one `Option` attribute, pushing its `usermod` flag(s) when it
/// differs and yielding the value the account will end up with (desired
/// if set, else the observed fallback) for the diff view.
fn reconcile_field<T: Clone + PartialEq>(
    args: &mut Vec<std::ffi::OsString>,
    flag: &str,
    want: &Option<T>,
    have: &Option<T>,
    arg_value: impl Fn(&T) -> std::ffi::OsString,
) -> Option<T> {
    if let Some(w) = want
        && want != have
    {
        args.push(flag.into());
        args.push(arg_value(w));
    }
    want.clone().or_else(|| have.clone())
}

fn reconcile(want: &Presence, have: &Presence) -> ReconcileResult {
    let (
        Presence::Present {
            uid,
            group,
            groups,
            shell,
            home,
            comment,
            system,
        },
        Presence::Present {
            uid: o_uid,
            group: o_group,
            groups: o_groups,
            shell: o_shell,
            home: o_home,
            comment: o_comment,
            system: o_system,
        },
    ) = (want, have)
    else {
        // Only ever called with two `Present` values.
        unreachable!("reconcile expects two Present presences");
    };

    let mut args = Vec::new();

    let uid = reconcile_field(&mut args, "--uid", uid, o_uid, |u| u.to_string().into());
    let group = reconcile_field(&mut args, "--gid", group, o_group, |g| g.clone().into());
    let shell = reconcile_field(&mut args, "--shell", shell, o_shell, |s| s.clone().into());
    let comment = reconcile_field(&mut args, "--comment", comment, o_comment, |c| {
        c.clone().into()
    });

    // Home moves take two flags (`--home` + `--move-home`), so it can't
    // go through the scalar helper.
    let home = if let Some(h) = home {
        if Some(h) != o_home.as_ref() {
            args.push("--home".into());
            args.push(h.into());
            args.push("--move-home".into());
        }
        Some(h.clone())
    } else {
        o_home.clone()
    };

    // The observed side is always an `Exact` snapshot of the current
    // supplementary set (see `observe`).
    let observed_groups: &[String] = match o_groups {
        Some(Groups::Exact(g)) => g,
        // `Append` never appears on the observed side, and `None` means
        // we didn't look — treat both as "no known membership".
        Some(Groups::Append(_)) | None => &[],
    };
    let sorted = |gs: &[String]| {
        let mut v = gs.to_vec();
        v.sort();
        v.dedup();
        v
    };
    let groups = match groups {
        // Replace: make membership exactly this set.
        Some(Groups::Exact(want)) => {
            if sorted(want) != sorted(observed_groups) {
                args.push("--groups".into());
                args.push(want.join(",").into());
            }
            Some(Groups::Exact(want.clone()))
        }
        // Append: add only the groups not already present, leaving the
        // rest of the membership untouched (`usermod --append`).
        Some(Groups::Append(want)) => {
            let observed: std::collections::BTreeSet<&str> =
                observed_groups.iter().map(String::as_str).collect();
            let missing: Vec<String> = want
                .iter()
                .filter(|g| !observed.contains(g.as_str()))
                .cloned()
                .collect();
            if !missing.is_empty() {
                args.push("--append".into());
                args.push("--groups".into());
                args.push(missing.join(",").into());
            }
            // Diff view: the resulting membership is the union.
            let mut union = observed_groups.to_vec();
            union.extend(want.iter().cloned());
            Some(Groups::Exact(sorted(&union)))
        }
        None => o_groups.clone(),
    };

    ReconcileResult {
        args,
        desired: Presence::Present {
            uid,
            group,
            groups,
            shell,
            home,
            comment,
            // Diff view: system-ness follows the final (post-reconcile)
            // UID — the same derived rule `apply` enforces — so a UID
            // move across the boundary renders the flip it causes.
            system: system
                .or_else(|| uid.map(|u| u <= sys_uid_max()))
                .or(*o_system),
        },
    }
}

/// Append the `useradd` flags for every set attribute (used only when
/// creating an account from scratch — there's nothing to compare against).
fn useradd_args(want: &Presence) -> Vec<std::ffi::OsString> {
    let Presence::Present {
        uid,
        group,
        groups,
        shell,
        home,
        comment,
        system,
    } = want
    else {
        return Vec::new();
    };

    let mut args: Vec<std::ffi::OsString> = Vec::new();
    if *system == Some(true) {
        args.push("--system".into());
    }
    if let Some(uid) = uid {
        args.push("--uid".into());
        args.push(uid.to_string().into());
    }
    if let Some(group) = group {
        args.push("--gid".into());
        args.push(group.into());
    }
    if let Some(shell) = shell {
        args.push("--shell".into());
        args.push(shell.into());
    }
    if let Some(home) = home {
        args.push("--home-dir".into());
        args.push(home.into());
    }
    if let Some(comment) = comment {
        args.push("--comment".into());
        args.push(comment.into());
    }
    // On create there's no prior membership, so `Exact` and `Append`
    // are equivalent — both just seed the initial supplementary set.
    let initial_groups: &[String] = match groups {
        Some(Groups::Exact(g)) | Some(Groups::Append(g)) => g,
        None => &[],
    };
    if !initial_groups.is_empty() {
        args.push("--groups".into());
        args.push(initial_groups.join(",").into());
    }
    args
}

/// Render a `State` struct diff to stderr (informational; write errors
/// ignored), matching the other builtins.
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

/// Manage a single Unix user account on the remote machine.
///
/// This is the full-control entry point taking a [`State`]. For the common
/// cases, prefer the intent-named helpers: [`present`], [`system`],
/// [`absent`], [`absent_with_home`]. Reach for [`State`] directly only when
/// you need to pin attributes like uid, shell, groups or home.
#[crate::remote]
pub fn user(state: State) -> crate::Result<super::Return> {
    apply(state)
}

// Intent-named helpers, each a single `#[crate::action]` fn whose body builds
// a `State` and calls `apply`. The macro generates the concrete `#[remote]`
// wire entry point, the orchestrator shim, and the in-process `::inner`.
//
// These cover the "just make the account (not) exist" cases with system
// defaults; anything that pins specific attributes (uid, shell, supplementary
// groups, …) is expressed through the full [`State`] entry point, where a
// flat helper signature would be worse than the struct.

/// Ensure user `name` exists with system defaults (default shell, a
/// per-user primary group, system-allocated uid). Orchestrator:
/// `present(name).await?`.
#[crate::action]
pub fn present(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::default(),
    })
}

/// Ensure a *system* account `name` exists (uid from the system range on
/// create). Orchestrator: `system(name).await?`.
#[crate::action]
pub fn system(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Present {
            uid: None,
            group: None,
            groups: None,
            shell: None,
            home: None,
            comment: None,
            system: Some(true),
        },
    })
}

/// Ensure user `name` does not exist (`userdel`), leaving its home
/// directory in place. Orchestrator: `absent(name).await?`.
#[crate::action]
pub fn absent(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Absent { remove_home: false },
    })
}

/// Ensure user `name` does not exist and remove its home directory and
/// mail spool too (`userdel --remove`). Orchestrator:
/// `absent_with_home(name).await?`.
#[crate::action]
pub fn absent_with_home(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Absent { remove_home: true },
    })
}

/// Reconcile an existing account towards `want`: one comparison pass
/// builds both the diff view and the `usermod` argv. Returns whether
/// the account changed. Used both for the plain reconcile path and
/// after losing a create race, where the account another agent
/// created may not match the request.
fn reconcile_existing(name: &str, want: &Presence, observed: &Presence) -> crate::Result<bool> {
    let have @ Presence::Present { uid: live_uid, .. } = observed else {
        unreachable!("reconcile_existing expects a live Present account");
    };
    // System-ness is not independent of the UID: an account is a
    // system account iff its UID ≤ SYS_UID_MAX. The request must agree
    // with the UID the account will end up with — the requested `uid`
    // if set, else the live one. A consistent `uid` + `system` pair
    // can migrate an account across the boundary; an inconsistent one
    // can never converge.
    check_system_consistency(name, want, *live_uid)?;
    let ReconcileResult { args, desired } = reconcile(want, have);
    show_diff(name, observed.clone(), desired);

    if args.is_empty() {
        Ok(false)
    } else {
        let mut cmd = Command::new("usermod");
        cmd.args(&args).args(["--", name]);
        super::run_check_retry_locks(&mut cmd)?;
        Ok(true)
    }
}

fn apply(state: State) -> crate::Result<super::Return> {
    let observed = observe(&state.name)?;

    let changed = match (&state.presence, &observed) {
        // Absent, and already gone.
        (Presence::Absent { .. }, Presence::Absent { .. }) => false,

        // Remove an existing account.
        (Presence::Absent { remove_home }, Presence::Present { .. }) => {
            show_diff(&state.name, observed.clone(), state.presence.clone());
            let mut cmd = Command::new("userdel");
            if *remove_home {
                cmd.arg("--remove");
            }
            super::run_check_retry_locks(cmd.args(["--", &state.name]))?;
            true
        }

        // Create a new account: every requested attribute applies.
        (want @ Presence::Present { .. }, Presence::Absent { .. }) => {
            check_system_consistency(&state.name, want, None)?;
            show_diff(&state.name, observed.clone(), want.clone());
            let mut cmd = Command::new("useradd");
            cmd.args(useradd_args(want)).args(["--", &state.name]);
            match super::run_check_retry_locks(&mut cmd) {
                Ok(()) => true,
                // A concurrent run created the account between our
                // observation and our `useradd` — the desired end
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

        // Reconcile an existing account.
        (want @ Presence::Present { .. }, Presence::Present { .. }) => {
            reconcile_existing(&state.name, want, &observed)?
        }
    };

    Ok(super::Return::from_changed(changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn want(
        uid: Option<u32>,
        group: Option<&str>,
        groups: Option<Groups>,
        shell: Option<&str>,
        home: Option<&str>,
        comment: Option<&str>,
        system: Option<bool>,
    ) -> Presence {
        Presence::Present {
            uid,
            group: group.map(str::to_owned),
            groups,
            shell: shell.map(PathBuf::from),
            home: home.map(PathBuf::from),
            comment: comment.map(str::to_owned),
            system,
        }
    }

    fn observed(system: bool) -> Presence {
        // Keep the fixture honest with the derived rule: a system
        // account carries a UID below SYS_UID_MAX (999 in these tests).
        let uid = if system { 500 } else { 1000 };
        want(
            Some(uid),
            Some("users"),
            Some(Groups::Exact(vec!["docker".into()])),
            Some("/bin/bash"),
            Some("/home/alice"),
            Some("Alice"),
            Some(system),
        )
    }

    fn sys_want(uid: Option<u32>, system: Option<bool>) -> Presence {
        want(uid, None, None, None, None, None, system)
    }

    fn args_of(res: &ReconcileResult) -> Vec<String> {
        res.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn reconcile_emits_flags_only_for_changed_fields() {
        let res = reconcile(
            &want(
                Some(1500),
                Some("staff"),
                None,
                Some("/bin/zsh"),
                Some("/home/alice"), // unchanged → no --home/--move-home
                None,
                None,
            ),
            &observed(false),
        );
        let args = args_of(&res);
        assert_eq!(
            args,
            vec!["--uid", "1500", "--gid", "staff", "--shell", "/bin/zsh"]
        );
    }

    #[test]
    fn reconcile_home_move_uses_two_flags() {
        let res = reconcile(
            &want(None, None, None, None, Some("/srv/alice"), None, None),
            &observed(false),
        );
        assert_eq!(args_of(&res), vec!["--home", "/srv/alice", "--move-home"]);
    }

    #[test]
    fn reconcile_backfills_system_from_observed_when_dont_care() {
        // `None` must not fight the live account's system-ness — that
        // was the never-converging diff.
        let res = reconcile(
            &want(None, None, None, None, None, None, None),
            &observed(true),
        );
        assert!(args_of(&res).is_empty());
        assert_eq!(
            res.desired,
            want(
                Some(500),
                Some("users"),
                Some(Groups::Exact(vec!["docker".into()])),
                Some("/bin/bash"),
                Some("/home/alice"),
                Some("Alice"),
                Some(true),
            )
        );
    }

    /// The consistency rule `apply` enforces before reconciling or
    /// creating: `system` must agree with the UID the account would end
    /// up with — the requested `uid` if set, else the live one.
    #[test]
    fn system_request_must_agree_with_the_resulting_uid() {
        const MAX: u32 = 999;

        // Assertions against the UID the account keeps…
        assert!(system_conflict(&sys_want(None, Some(true)), Some(1500), MAX).is_some());
        assert!(system_conflict(&sys_want(None, Some(false)), Some(500), MAX).is_some());
        // …and against a pinned one on the wrong side of the boundary.
        assert!(system_conflict(&sys_want(Some(2000), Some(true)), Some(1500), MAX).is_some());
        assert!(system_conflict(&sys_want(Some(500), Some(false)), Some(1500), MAX).is_some());
        // Create-side: only an explicitly pinned UID can conflict.
        assert!(system_conflict(&sys_want(Some(2000), Some(true)), None, MAX).is_some());
        assert!(system_conflict(&sys_want(None, Some(true)), None, MAX).is_none());
        assert!(system_conflict(&sys_want(None, Some(false)), None, MAX).is_none());

        // Consistent requests pass, including a migration across the
        // boundary with an explicit, agreeing `system`.
        assert!(system_conflict(&sys_want(Some(500), Some(true)), Some(1500), MAX).is_none());
        assert!(system_conflict(&sys_want(Some(2000), Some(false)), Some(1500), MAX).is_none());
        assert!(system_conflict(&sys_want(Some(MAX), Some(true)), None, MAX).is_none());
        // `None` never conflicts — system-ness just follows the UID.
        assert!(system_conflict(&sys_want(None, None), Some(1500), MAX).is_none());
        assert!(system_conflict(&sys_want(Some(500), None), Some(1500), MAX).is_none());
    }

    /// A UID move across the boundary flips system-ness in the diff
    /// view even when the request never mentions `system`.
    #[test]
    fn reconcile_derives_system_from_the_moved_uid() {
        let res = reconcile(&sys_want(Some(500), None), &observed(false));
        assert!(args_of(&res).contains(&"--uid".to_string()));
        assert_eq!(
            res.desired,
            Presence::Present {
                uid: Some(500),
                group: Some("users".into()),
                groups: Some(Groups::Exact(vec!["docker".into()])),
                shell: Some("/bin/bash".into()),
                home: Some("/home/alice".into()),
                comment: Some("Alice".into()),
                system: Some(true),
            }
        );

        let res = reconcile(&sys_want(Some(1500), None), &observed(true));
        assert_eq!(
            res.desired,
            Presence::Present {
                uid: Some(1500),
                group: Some("users".into()),
                groups: Some(Groups::Exact(vec!["docker".into()])),
                shell: Some("/bin/bash".into()),
                home: Some("/home/alice".into()),
                comment: Some("Alice".into()),
                system: Some(false),
            }
        );
    }

    #[test]
    fn reconcile_exact_groups_replaces_membership() {
        let res = reconcile(
            &want(
                None,
                None,
                Some(Groups::Exact(vec!["wheel".into(), "video".into()])),
                None,
                None,
                None,
                None,
            ),
            &observed(false),
        );
        assert_eq!(args_of(&res), vec!["--groups", "wheel,video"]);
    }

    #[test]
    fn reconcile_append_only_adds_missing() {
        let res = reconcile(
            &want(
                None,
                None,
                Some(Groups::Append(vec!["docker".into(), "audit".into()])),
                None,
                None,
                None,
                None,
            ),
            &observed(false),
        );
        // `docker` is already there; only `audit` is appended.
        assert_eq!(args_of(&res), vec!["--append", "--groups", "audit"]);
        // Desired view is the union.
        assert!(matches!(
            res.desired,
            Presence::Present {
                groups: Some(Groups::Exact(ref g)),
                ..
            } if g == &["audit", "docker"]
        ));
    }

    #[test]
    fn useradd_args_passes_system_only_when_explicitly_true() {
        let sys = useradd_args(&want(None, None, None, None, None, None, Some(true)));
        assert!(sys.contains(&"--system".into()));
        let dont_care = useradd_args(&want(None, None, None, None, None, None, None));
        assert!(!dont_care.contains(&"--system".into()));
    }
}
