use std::process::Command;

use crate as cindy;
use crate::Context;

/// Desired install/remove status of a package.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Presence {
    /// `apt-get remove`: package not installed; config files may stay
    /// behind in `/etc/`. Idempotent over the already-removed and
    /// never-installed cases.
    Absent,
    /// `apt-get purge`: package not installed *and* config files
    /// removed. Cleaner than [`Absent`] when you want a clean slate for
    /// future reinstalls.
    Purged,
    /// `apt-get install <name>`: ensure the package is installed at
    /// any version. If it's already installed, this is a no-op (apt
    /// will not auto-upgrade an installed package on a bare `install`).
    Present,
    /// `apt-get install <name>=<version>`: ensure the package is
    /// installed at exactly this version string. The version string
    /// must match what `dpkg-query` reports for the package (including
    /// any epoch like `1:2.3.4-1`).
    Version(String),
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Package name as apt knows it (`nginx`, `python3-pip`, …).
    pub name: String,
    /// Desired install state. `None` ⇒ leave install state alone.
    pub presence: Option<Presence>,
    /// Desired `apt-mark hold` state. `None` ⇒ leave hold state alone.
    ///
    /// `Some(false)` first issues `apt-mark unhold`, then runs the
    /// presence step (so a version bump can land on a held package).
    /// `Some(true)` issues `apt-mark hold` *after* the presence step,
    /// re-holding at the post-install version. When `presence`
    /// requires a change and the package happens to be held, the hold
    /// is *transparently* released and (if `hold` is `None` or
    /// `Some(true)`) re-applied — i.e. you never need to spell out a
    /// manual unhold-just-to-upgrade dance.
    pub hold: Option<bool>,
}

/// Default `{:#?}`-based diff is fine here — the payload is just a
/// handful of names and small enums, no binary blobs to special-case.
impl crate::Diff for State {}

/// Snapshot of what `dpkg-query` / `apt-mark` say about the package
/// right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstallStatus {
    /// `dpkg-query` Status-Abbrev second char is `i` — fully installed.
    Installed,
    /// `dpkg-query` Status-Abbrev second char is `c` — package removed
    /// but config files remain (`rc` is the classic abbrev).
    ConfigFiles,
    /// Anything else (`un`, package unknown, empty output, …).
    NotInstalled,
}

struct CurrentState {
    install_status: InstallStatus,
    /// Installed version, if (and only if) `install_status == Installed`.
    version: Option<String>,
    /// `apt-mark` currently holding this package.
    held: bool,
}

use crate::builtin::run_check;

/// Prebuilt `apt-get` invocation with `DEBIAN_FRONTEND=noninteractive`
/// + `-y` so prompts don't stall the run.
fn apt_get() -> Command {
    let mut c = Command::new("apt-get");
    c.env("DEBIAN_FRONTEND", "noninteractive");
    c.arg("-y");
    c
}

fn read_current_state(pkg: &str) -> crate::Result<CurrentState> {
    // Status-Abbrev is two characters: `<desired><current>`. We only
    // care about the current state for "is it installed?". The format
    // string deliberately puts `|` between Status-Abbrev and Version
    // so we can split unambiguously even on packages whose version
    // contains spaces (in theory it shouldn't, but defence-in-depth).
    let dpkg = Command::new("dpkg-query")
        .args(["-W", "-f", "${db:Status-Abbrev}|${Version}", "--", pkg])
        .output()
        .context("Failed to spawn `dpkg-query`")?;

    let (install_status, version) = if dpkg.status.success() {
        let raw = String::from_utf8_lossy(&dpkg.stdout);
        let (abbrev, ver) = raw.split_once('|').unwrap_or((raw.as_ref(), ""));
        let current = abbrev.chars().nth(1).unwrap_or(' ');
        let status = match current {
            'i' => InstallStatus::Installed,
            'c' => InstallStatus::ConfigFiles,
            _ => InstallStatus::NotInstalled,
        };
        let version = matches!(status, InstallStatus::Installed).then(|| ver.trim().to_owned());
        (status, version)
    } else {
        // `dpkg-query` exits non-zero when the package is unknown to
        // dpkg. That's a perfectly valid "not installed" outcome — not
        // an error condition for us.
        (InstallStatus::NotInstalled, None)
    };

    let mark = Command::new("apt-mark")
        .arg("showhold")
        .output()
        .context("Failed to spawn `apt-mark showhold`")?;
    if !mark.status.success() {
        crate::bail!(
            "`apt-mark showhold` failed:\n{}",
            String::from_utf8_lossy(&mark.stderr)
        );
    }
    let held = String::from_utf8_lossy(&mark.stdout)
        .lines()
        .any(|line| line.trim() == pkg);

    Ok(CurrentState {
        install_status,
        version,
        held,
    })
}

/// Render `CurrentState` as a `Presence` for diff display.
fn current_to_presence(cur: &CurrentState) -> Presence {
    match cur.install_status {
        InstallStatus::Installed => match &cur.version {
            Some(v) => Presence::Version(v.clone()),
            None => Presence::Present,
        },
        InstallStatus::ConfigFiles => Presence::Absent,
        InstallStatus::NotInstalled => Presence::Purged,
    }
}

/// Compare two dpkg version strings for equality using
/// `dpkg --compare-versions`, the only correct arbiter of dpkg version
/// semantics (epochs, `~` pre-release ordering, etc.).
///
/// This is what makes `Presence::Version("1.3.0")` idempotent against a
/// package dpkg actually records as `1:1.3.0`: a plain string `==`
/// would see them as different and reinstall on *every* run. We treat a
/// spawn failure as "not equal" so a broken/absent `dpkg` degrades to
/// re-applying rather than silently claiming satisfaction.
fn dpkg_versions_equal(have: &str, want: &str) -> bool {
    Command::new("dpkg")
        .args(["--compare-versions", have, "eq", want])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Does the live state already satisfy the desired `Presence`?
fn presence_satisfied(cur: &CurrentState, desired: &Presence) -> bool {
    match desired {
        Presence::Absent => matches!(
            cur.install_status,
            InstallStatus::ConfigFiles | InstallStatus::NotInstalled
        ),
        Presence::Purged => matches!(cur.install_status, InstallStatus::NotInstalled),
        Presence::Present => matches!(cur.install_status, InstallStatus::Installed),
        Presence::Version(v) => {
            cur.install_status == InstallStatus::Installed
                && cur
                    .version
                    .as_deref()
                    .is_some_and(|have| dpkg_versions_equal(have, v))
        }
    }
}

/// Manage a single apt package on a Debian/Ubuntu remote.
///
/// Reads the current install status via `dpkg-query` and hold state via
/// `apt-mark showhold`, then runs the minimum set of `apt-get` /
/// `apt-mark` commands needed to bring the system into the desired
/// state. `DEBIAN_FRONTEND=noninteractive` is set for every apt call so
/// debconf prompts don't stall the run.
///
/// The apt **package cache is not refreshed** by this module — if you
/// need a fresh `apt-get update` (because you're chasing a newly
/// published `Version(...)` or installing a package that wasn't in the
/// cache the last time someone ran `update`), do it from a separate
/// `#[cindy::remote]` of your own.
///
/// This is the full-control entry point taking a [`State`]. For the
/// common cases, prefer the intent-named helpers: [`install`],
/// [`install_version`], [`hold`], [`remove`], [`purge`].
#[crate::remote]
pub fn apt(state: State) -> crate::Result<crate::builtin::Return> {
    apply(state)
}

// The intent-named helpers below are each a single `#[crate::action]` fn:
// ergonomic `impl Into<String>` arguments plus a body that builds a `State`
// and calls `apply`. The macro generates the concrete `#[remote]` wire entry
// point, the orchestrator shim, and the in-process `::inner` from each.

/// Ensure `name` is installed at any version (no-op if already present).
/// Orchestrator: `install(name).await?`. Local: `install::inner(name)?`.
#[crate::action]
pub fn install(name: impl Into<String>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        name,
        presence: Some(Presence::Present),
        hold: None,
    })
}

/// Ensure `name` is installed at exactly `version` (a dpkg version string,
/// epochs and all). Orchestrator: `install_version(name, ver).await?`.
#[crate::action]
pub fn install_version(
    name: impl Into<String>,
    version: impl Into<String>,
) -> crate::Result<crate::builtin::Return> {
    apply(State {
        name,
        presence: Some(Presence::Version(version)),
        hold: None,
    })
}

/// Install `name` at exactly `version`, then `apt-mark hold` it so a later
/// `apt upgrade` won't move it. Orchestrator: `hold(name, ver).await?`.
#[crate::action]
pub fn hold(
    name: impl Into<String>,
    version: impl Into<String>,
) -> crate::Result<crate::builtin::Return> {
    apply(State {
        name,
        presence: Some(Presence::Version(version)),
        hold: Some(true),
    })
}

/// `apt-get remove` (config files may remain in `/etc`). Idempotent.
/// Orchestrator: `remove(name).await?`.
#[crate::action]
pub fn remove(name: impl Into<String>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        name,
        presence: Some(Presence::Absent),
        hold: None,
    })
}

/// `apt-get purge` (also removes config files). Idempotent.
/// Orchestrator: `purge(name).await?`.
#[crate::action]
pub fn purge(name: impl Into<String>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        name,
        presence: Some(Presence::Purged),
        hold: None,
    })
}

fn apply(state: State) -> crate::Result<crate::builtin::Return> {
    let cur = read_current_state(&state.name)?;

    // Build diff views. `old_view` is what we observed on disk;
    // `new_view` is what the system will look like after we're done,
    // with any unspecified (`None`) fields back-filled from `cur` so
    // the diff highlights only what's actually changing.
    let old_view = State {
        name: state.name.clone(),
        presence: Some(current_to_presence(&cur)),
        hold: Some(cur.held),
    };
    let new_view = State {
        name: state.name.clone(),
        presence: Some(
            state
                .presence
                .clone()
                .unwrap_or_else(|| current_to_presence(&cur)),
        ),
        hold: Some(state.hold.unwrap_or(cur.held)),
    };
    if old_view != new_view {
        let _ = <State as crate::Diff>::diff(&old_view, &new_view, &mut std::io::stderr().lock());
    }

    let mut changed = false;
    let mut effective_held = cur.held;

    let presence_needs_change = state
        .presence
        .as_ref()
        .is_some_and(|p| !presence_satisfied(&cur, p));

    // Final hold state we want when this function returns. If the
    // caller didn't pin `hold`, we preserve whatever the package
    // started at — even when step 1 below has to release a transient
    // hold to land a version bump.
    let final_held = state.hold.unwrap_or(effective_held);

    // Step 1: unhold if (a) the caller asked for it, or (b) a presence
    // change is needed on a held package. The latter is transparent —
    // step 3 re-holds afterwards if `final_held` ends up true.
    if effective_held && (state.hold == Some(false) || presence_needs_change) {
        run_check(Command::new("apt-mark").args(["unhold", "--", &state.name]))?;
        effective_held = false;
        changed = true;
    }

    // Step 2: apply the presence change.
    if let Some(presence) = state.presence.as_ref()
        && !presence_satisfied(&cur, presence)
    {
        match presence {
            Presence::Absent => {
                run_check(apt_get().args(["remove", "--", &state.name]))?;
            }
            Presence::Purged => {
                run_check(apt_get().args(["purge", "--", &state.name]))?;
            }
            Presence::Present => {
                run_check(apt_get().args(["install", "--", &state.name]))?;
            }
            Presence::Version(v) => {
                // `--allow-downgrades`: pinning to an exact version must
                // also work when the installed version is *newer* (rolling
                // back a bad release is the flagship use of `Version`);
                // plain `install pkg=older` refuses to downgrade.
                let spec = format!("{}={}", state.name, v);
                run_check(apt_get().args(["install", "--allow-downgrades", "--", &spec]))?;
            }
        }
        changed = true;
    }

    // Step 3: re-establish the final hold state.
    if effective_held != final_held {
        let subcmd = if final_held { "hold" } else { "unhold" };
        run_check(Command::new("apt-mark").args([subcmd, "--", &state.name]))?;
        changed = true;
    }

    Ok(crate::builtin::Return::from_changed(changed))
}
