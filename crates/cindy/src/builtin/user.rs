//! A Unix user account, via `useradd`/`usermod`/`userdel`.
//!
//! No passwords: infrastructure authenticates with keys, and a password
//! field invites cleartext secrets into inventories. If you must, pipe
//! a pre-hashed line into `chpasswd -e` with [`command`](super::command).

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::Context;

/// Supplementary group membership.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Groups {
    /// Exactly these: others are removed.
    Exact(Vec<String>),
    /// At least these: others stay, so several plays can each manage one.
    Append(Vec<String>),
}

#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Presence {
    Absent {
        /// Also delete the home directory and mail spool.
        remove_home: bool,
    },
    Present(Account),
}

impl Default for Presence {
    fn default() -> Self {
        Self::Present(Account::default())
    }
}

/// An account's attributes. `None` means the system default on create
/// and "leave it" on an existing account.
#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct Account {
    pub uid: Option<u32>,
    /// The primary group, by name.
    pub group: Option<String>,
    pub groups: Option<Groups>,
    pub shell: Option<PathBuf>,
    /// Changing it moves the directory.
    pub home: Option<PathBuf>,
    /// GECOS.
    pub comment: Option<String>,
    /// Create in the system UID range. Afterwards it isn't independent:
    /// an account is a system account iff its UID ≤ `SYS_UID_MAX`, so a
    /// `Some` that contradicts the resulting UID is an error.
    pub system: Option<bool>,
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    pub name: String,
    pub presence: Presence,
}

impl crate::Diff for State {}

/// The full-control entry point; the verbs cover the system-default
/// cases.
#[crate::remote]
pub fn user(state: State) -> crate::Result<super::Return> {
    apply(state)
}

#[crate::action]
pub fn present(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::default(),
    })
}

/// A system account (UID from the system range on create).
#[crate::action]
pub fn system(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Present(Account {
            system: Some(true),
            ..Account::default()
        }),
    })
}

/// Gone; the home directory stays.
#[crate::action]
pub fn absent(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Absent { remove_home: false },
    })
}

/// Gone, home directory and mail spool included.
#[crate::action]
pub fn absent_with_home(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        presence: Presence::Absent { remove_home: true },
    })
}

fn sys_uid_max() -> u32 {
    super::login_defs_value("SYS_UID_MAX", 999)
}

/// The live account, every field filled in.
fn observe(name: &str) -> crate::Result<Option<Account>> {
    let Some(user) = nix::unistd::User::from_name(name).context("User lookup failed")? else {
        return Ok(None);
    };
    Ok(Some(Account {
        uid: Some(user.uid.as_raw()),
        group: Some(super::name_of_gid(user.gid.as_raw())),
        // The full set, so the live membership is an `Exact` view.
        groups: Some(Groups::Exact(supplementary_groups(name, user.gid)?)),
        shell: Some(user.shell),
        home: Some(user.dir),
        // Verbatim, empty included: `None` here would make a wanted
        // `Some("")` differ forever.
        comment: Some(user.gecos.to_string_lossy().into_owned()),
        system: Some(user.uid.as_raw() <= sys_uid_max()),
    }))
}

/// By name, without the primary group, sorted. Workers are static musl
/// with no NSS plugins: this reads `/etc/group` only, so LDAP/SSSD
/// memberships are invisible.
fn supplementary_groups(name: &str, primary: nix::unistd::Gid) -> crate::Result<Vec<String>> {
    let cname = std::ffi::CString::new(name).context("User name contains an interior NUL byte")?;
    let gids =
        nix::unistd::getgrouplist(&cname, primary).context("getgrouplist failed for the user")?;
    let mut out: Vec<String> = gids
        .into_iter()
        .filter(|&gid| gid != primary)
        .map(|gid| super::name_of_gid(gid.as_raw()))
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// `Some((want_system, uid))` when `system` contradicts the UID the
/// account ends up with — `want.uid`, else `live_uid`.
fn system_conflict(want: &Account, live_uid: Option<u32>, sys_uid_max: u32) -> Option<(bool, u32)> {
    let want_system = want.system?;
    let uid = want.uid.or(live_uid)?;
    ((uid <= sys_uid_max) != want_system).then_some((want_system, uid))
}

fn check_system_consistency(
    name: &str,
    want: &Account,
    live_uid: Option<u32>,
) -> crate::Result<()> {
    if let Some((want_system, uid)) = system_conflict(want, live_uid, sys_uid_max()) {
        let side = if want_system { "at or below" } else { "above" };
        crate::bail!(
            "user `{name}`: `system: Some({want_system})` contradicts UID {uid} — \
             an account is a system account iff its UID ≤ SYS_UID_MAX ({}). System-ness \
             follows the UID: drop the `system` field, or pick a UID {side} that boundary.",
            sys_uid_max()
        );
    }
    Ok(())
}

/// The `usermod` arguments that close the gap, and the account as it
/// will be — one comparison pass, so the command and the diff agree.
struct Reconciled {
    args: Vec<OsString>,
    desired: Account,
}

fn reconcile(want: &Account, have: &Account) -> Reconciled {
    let mut args: Vec<OsString> = Vec::new();
    // The value the account ends up with, plus its flag when it differs.
    fn field<T: Clone + PartialEq>(
        args: &mut Vec<OsString>,
        flag: &str,
        want: &Option<T>,
        have: &Option<T>,
        arg: impl Fn(&T) -> OsString,
    ) -> Option<T> {
        if let Some(w) = want
            && want != have
        {
            args.extend([flag.into(), arg(w)]);
        }
        want.clone().or_else(|| have.clone())
    }

    let uid = field(&mut args, "--uid", &want.uid, &have.uid, |u| {
        u.to_string().into()
    });
    let group = field(&mut args, "--gid", &want.group, &have.group, |g| g.into());
    let shell = field(&mut args, "--shell", &want.shell, &have.shell, |s| s.into());
    let comment = field(&mut args, "--comment", &want.comment, &have.comment, |c| {
        c.into()
    });
    let home = field(&mut args, "--home", &want.home, &have.home, |h| h.into());
    if want.home.is_some() && want.home != have.home {
        args.push("--move-home".into());
    }

    let live: &[String] = match &have.groups {
        Some(Groups::Exact(g)) => g,
        _ => &[],
    };
    let sorted = |gs: &[String]| {
        let mut v = gs.to_vec();
        v.sort();
        v.dedup();
        v
    };
    let groups = match &want.groups {
        Some(Groups::Exact(g)) => {
            if sorted(g) != sorted(live) {
                args.extend(["--groups".into(), g.join(",").into()]);
            }
            Some(Groups::Exact(g.clone()))
        }
        Some(Groups::Append(g)) => {
            let missing: Vec<&str> = g
                .iter()
                .filter(|name| !live.contains(name))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                args.extend([
                    "--append".into(),
                    "--groups".into(),
                    missing.join(",").into(),
                ]);
            }
            Some(Groups::Exact(sorted(&[live, g].concat())))
        }
        None => have.groups.clone(),
    };

    Reconciled {
        args,
        desired: Account {
            uid,
            group,
            groups,
            shell,
            home,
            comment,
            // Follows the final UID, so a move across the boundary shows.
            system: want
                .system
                .or_else(|| uid.map(|u| u <= sys_uid_max()))
                .or(have.system),
        },
    }
}

fn useradd_args(want: &Account) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    if want.system == Some(true) {
        args.push("--system".into());
    }
    let mut flag = |name: &str, value: Option<OsString>| {
        if let Some(value) = value {
            args.extend([name.into(), value]);
        }
    };
    flag("--uid", want.uid.map(|u| u.to_string().into()));
    flag("--gid", want.group.as_ref().map(Into::into));
    flag("--shell", want.shell.as_ref().map(Into::into));
    flag("--home-dir", want.home.as_ref().map(Into::into));
    flag("--comment", want.comment.as_ref().map(Into::into));
    // Nothing to keep on create: Exact and Append both just seed it.
    if let Some(Groups::Exact(g) | Groups::Append(g)) = &want.groups
        && !g.is_empty()
    {
        flag("--groups", Some(g.join(",").into()));
    }
    args
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

/// Also what a lost create race lands in: the account another run
/// created may not match the request.
fn reconcile_existing(name: &str, want: &Account, live: &Account) -> crate::Result<bool> {
    check_system_consistency(name, want, live.uid)?;
    let Reconciled { args, desired } = reconcile(want, live);
    show_diff(
        name,
        Presence::Present(live.clone()),
        Presence::Present(desired),
    );
    if args.is_empty() {
        return Ok(false);
    }
    if !crate::dry_run() {
        super::run_check_retry_locks(Command::new("usermod").args(&args).args(["--", name]))?;
    }
    Ok(true)
}

fn apply(state: State) -> crate::Result<super::Return> {
    let name = &state.name;
    let changed = match (&state.presence, observe(name)?) {
        (Presence::Absent { .. }, None) => false,
        (Presence::Absent { remove_home }, Some(live)) => {
            show_diff(name, Presence::Present(live), state.presence.clone());
            if !crate::dry_run() {
                let mut cmd = Command::new("userdel");
                if *remove_home {
                    cmd.arg("--remove");
                }
                super::run_check_retry_locks(cmd.args(["--", name]))?;
            }
            true
        }
        (Presence::Present(want), None) => {
            check_system_consistency(name, want, None)?;
            show_diff(
                name,
                Presence::Absent { remove_home: false },
                state.presence.clone(),
            );
            if !crate::dry_run() {
                let mut cmd = Command::new("useradd");
                cmd.args(useradd_args(want)).args(["--", name]);
                if let Err(e) = super::run_check_retry_locks(&mut cmd) {
                    // A concurrent run created it first: reconcile that.
                    match observe(name)? {
                        Some(live) if super::is_create_race(&e) => {
                            reconcile_existing(name, want, &live)?;
                        }
                        _ => return Err(e),
                    }
                }
            }
            true
        }
        (Presence::Present(want), Some(live)) => reconcile_existing(name, want, &live)?,
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
    ) -> Account {
        Account {
            uid,
            group: group.map(str::to_owned),
            groups,
            shell: shell.map(PathBuf::from),
            home: home.map(PathBuf::from),
            comment: comment.map(str::to_owned),
            system,
        }
    }

    /// System accounts below SYS_UID_MAX (999 here), as the rule says.
    fn observed(system: bool) -> Account {
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

    fn sys_want(uid: Option<u32>, system: Option<bool>) -> Account {
        want(uid, None, None, None, None, None, system)
    }

    fn args_of(res: &Reconciled) -> Vec<String> {
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
                Some("/home/alice"),
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

    #[test]
    fn system_request_must_agree_with_the_resulting_uid() {
        const MAX: u32 = 999;

        assert!(system_conflict(&sys_want(None, Some(true)), Some(1500), MAX).is_some());
        assert!(system_conflict(&sys_want(None, Some(false)), Some(500), MAX).is_some());
        assert!(system_conflict(&sys_want(Some(2000), Some(true)), Some(1500), MAX).is_some());
        assert!(system_conflict(&sys_want(Some(500), Some(false)), Some(1500), MAX).is_some());
        assert!(system_conflict(&sys_want(Some(2000), Some(true)), None, MAX).is_some());
        assert!(system_conflict(&sys_want(None, Some(true)), None, MAX).is_none());
        assert!(system_conflict(&sys_want(None, Some(false)), None, MAX).is_none());

        assert!(system_conflict(&sys_want(Some(500), Some(true)), Some(1500), MAX).is_none());
        assert!(system_conflict(&sys_want(Some(2000), Some(false)), Some(1500), MAX).is_none());
        assert!(system_conflict(&sys_want(Some(MAX), Some(true)), None, MAX).is_none());
        assert!(system_conflict(&sys_want(None, None), Some(1500), MAX).is_none());
        assert!(system_conflict(&sys_want(Some(500), None), Some(1500), MAX).is_none());
    }

    #[test]
    fn reconcile_derives_system_from_the_moved_uid() {
        let res = reconcile(&sys_want(Some(500), None), &observed(false));
        assert!(args_of(&res).contains(&"--uid".to_string()));
        assert_eq!(
            res.desired,
            Account {
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
            Account {
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
        assert_eq!(args_of(&res), vec!["--append", "--groups", "audit"]);
        assert!(matches!(
            res.desired.groups,
            Some(Groups::Exact(ref g)) if g == &["audit", "docker"]
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
