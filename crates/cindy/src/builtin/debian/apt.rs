use std::collections::BTreeMap;
use std::process::Command;

use crate::Context;
use crate::builtin::{run_check, run_check_retry_locks};

/// One package, optionally pinned to an exact version.
///
/// Built by `Into` from a bare name in the common case — `"nginx"` or
/// `String` — so a call site rarely spells this out. Reach for
/// [`Package::pinned`] when a single call needs a mix of pinned and
/// unpinned packages.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub struct Package {
    /// Package name as apt knows it (`nginx`, `python3-pip`, …).
    pub name: String,
    /// Exact dpkg version to pin to, compared with
    /// `dpkg --compare-versions eq` semantics: epoch and revision are
    /// significant, so `1.3.0` does *not* satisfy a dpkg-reported
    /// `1:1.3.0` (and vice versa). Copy the exact string
    /// `dpkg-query -W -f '${Version}'` reports. `None` ⇒ any version
    /// satisfies.
    pub version: Option<String>,
}

impl Package {
    /// A package pinned to an exact version.
    pub fn pinned(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: Some(version.into()),
        }
    }

    /// The `apt-get install` argument for this package: `name`, or
    /// `name=version` when pinned.
    fn spec(&self) -> String {
        match &self.version {
            Some(v) => format!("{}={}", self.name, v),
            None => self.name.clone(),
        }
    }
}

impl From<&str> for Package {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            version: None,
        }
    }
}

impl From<String> for Package {
    fn from(name: String) -> Self {
        Self {
            name,
            version: None,
        }
    }
}

/// The packages one [`apt`] call operates on.
///
/// Exists so the builtins can take `impl Into<PackageList>` and accept a
/// single name or any collection of them from the same entry point:
///
/// ```ignore
/// apt::install("nginx").await?;
/// apt::install(["nginx", "curl", "ca-certificates"]).await?;
/// apt::install([Package::from("nginx"), Package::pinned("curl", "8.5.0-1")]).await?;
/// ```
///
/// Batching is not only ergonomics. One `apt-get install a b c` takes
/// the dpkg lock once and solves dependencies for the whole set, which
/// is both faster and *more correct* than three sequential calls that
/// could each pull a conflicting resolution.
#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct PackageList(pub Vec<Package>);

impl From<Package> for PackageList {
    fn from(p: Package) -> Self {
        Self(vec![p])
    }
}

impl From<&str> for PackageList {
    fn from(name: &str) -> Self {
        Self(vec![name.into()])
    }
}

impl From<String> for PackageList {
    fn from(name: String) -> Self {
        Self(vec![name.into()])
    }
}

// The iterable impls are generic over `Into<Package>`, so `Vec<&str>`,
// `[String; N]` and `&[Package]` all work without one impl each. A
// blanket `impl<I: IntoIterator>` would be nicer still, but coherence
// rejects it alongside `From<String>`: rustc can't lean on
// `String: !IntoIterator` remaining true for a foreign type.
impl<T: Into<Package>> From<Vec<T>> for PackageList {
    fn from(names: Vec<T>) -> Self {
        Self(names.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Package>, const N: usize> From<[T; N]> for PackageList {
    fn from(names: [T; N]) -> Self {
        Self(names.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Package> + Clone> From<&[T]> for PackageList {
    fn from(names: &[T]) -> Self {
        Self(names.iter().cloned().map(Into::into).collect())
    }
}

/// Desired install status, applied to every package in the
/// [`State::packages`] list.
#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Presence {
    /// `apt-get remove`: packages not installed; config files may stay
    /// behind in `/etc/`. Idempotent over the already-removed and
    /// never-installed cases.
    Absent,
    /// `apt-get purge`: packages not installed *and* config files
    /// removed. Cleaner than [`Absent`](Self::Absent) when you want a
    /// clean slate for future reinstalls.
    Purged,
    /// `apt-get install`: ensure each package is installed — at its
    /// [`Package::version`] if it pins one, otherwise at *some* version.
    /// An unpinned package that dpkg already records as installed is
    /// satisfied immediately: cindy makes no apt call for it, so an
    /// available newer candidate is deliberately *not* pulled in.
    Present,
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Packages to act on. Takes a bare name, or any collection of
    /// names / [`Package`]s — see [`PackageList`].
    pub packages: PackageList,
    /// Desired install state for every listed package. `None` ⇒ leave
    /// install state alone.
    pub presence: Option<Presence>,
    /// Desired `apt-mark hold` state for every listed package. `None` ⇒
    /// leave hold state alone.
    ///
    /// `Some(false)` first issues `apt-mark unhold`, then runs the
    /// presence step (so a version bump can land on a held package).
    /// `Some(true)` issues `apt-mark hold` *after* the presence step,
    /// re-holding at the post-install version. When `presence` requires
    /// a change and a package happens to be held, the hold is
    /// *transparently* released and (if `hold` is `None` or
    /// `Some(true)`) re-applied — i.e. you never need to spell out a
    /// manual unhold-just-to-upgrade dance.
    pub hold: Option<bool>,
}

/// Install status as the diff renders it. The observed side is built
/// from dpkg's report and the desired side from the request, and both
/// render identically so the line diff means something.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    /// Not installed and no config files left — dpkg doesn't know the
    /// package, or it was purged.
    Purged,
    /// Removed, but config files remain (dpkg's classic `rc`).
    ConfigFiles,
    /// Installed; the version when it is known or pinned, `None` for a
    /// "any version will do" request whose outcome we can't name yet.
    Installed(Option<String>),
}

/// One package's full state, for the struct diff.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageView {
    name: String,
    status: Status,
    held: bool,
}

/// `{:#?}`-based diff over the per-package views — the payload is names,
/// version strings and small enums, so no custom rendering is needed.
impl crate::Diff for Vec<PackageView> {}

/// Snapshot of what `dpkg-query` / `apt-mark` say about one package
/// right now.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CurrentState {
    status: Status,
    /// `apt-mark` currently holding this package.
    held: bool,
}

impl CurrentState {
    fn view(&self, name: &str) -> PackageView {
        PackageView {
            name: name.to_owned(),
            status: self.status.clone(),
            held: self.held,
        }
    }
}

/// How long `apt-get` is told to wait for the dpkg lock before giving
/// up, in seconds.
///
/// Delegating the wait to apt is what makes concurrent use safe, and it
/// is strictly better than anything cindy could implement itself: the
/// lock's contenders include `unattended-upgrades` and a human at a
/// shell, which no cindy-side lock could ever coordinate with. Checking
/// for a free lock and *then* spawning apt would also just lose the race
/// in the window between.
///
/// `DPkg::Lock::Timeout` landed in apt 2.1.10 (so bullseye and later
/// have it). Older apt accepts the unknown `-o` key silently and simply
/// keeps its fail-fast behaviour.
const DPKG_LOCK_TIMEOUT_SECS: u32 = 300;

/// Prebuilt `apt-get` invocation: `DEBIAN_FRONTEND=noninteractive` and
/// `-y` so prompts don't stall the run, plus a dpkg lock timeout so a
/// concurrent apt user doesn't fail the play outright.
fn apt_get() -> Command {
    let mut c = Command::new("apt-get");
    c.env("DEBIAN_FRONTEND", "noninteractive");
    c.arg("-y");
    c.arg("-o");
    c.arg(format!("DPkg::Lock::Timeout={DPKG_LOCK_TIMEOUT_SECS}"));
    c
}

/// Parse one `dpkg-query -W -f '${db:Status-Abbrev}|${Version}'` line.
///
/// Status-Abbrev is two characters `<desired><current>`; only the
/// current state matters for "is it installed?". The `|` separator
/// keeps the split unambiguous even on versions containing spaces
/// (in theory they can't, but defence-in-depth). A version is only
/// recorded for the fully-installed state.
fn parse_dpkg_line(raw: &str) -> Status {
    let (abbrev, ver) = raw.split_once('|').unwrap_or((raw, ""));
    match abbrev.chars().nth(1).unwrap_or(' ') {
        'i' => Status::Installed(Some(ver.trim().to_owned())),
        'c' => Status::ConfigFiles,
        _ => Status::Purged,
    }
}

/// Read every listed package's install status and hold state.
///
/// `apt-mark showhold` lists the whole hold set, so it runs once for the
/// call rather than once per package.
fn read_current_states(packages: &[Package]) -> crate::Result<BTreeMap<String, CurrentState>> {
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
    let holds: Vec<String> = String::from_utf8_lossy(&mark.stdout)
        .lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect();

    let mut out = BTreeMap::new();
    for package in packages {
        let dpkg = Command::new("dpkg-query")
            .args([
                "-W",
                "-f",
                "${db:Status-Abbrev}|${Version}",
                "--",
                &package.name,
            ])
            .output()
            .context("Failed to spawn `dpkg-query`")?;

        // `dpkg-query` exits non-zero when the package is unknown to
        // dpkg. That's a perfectly valid "not installed" outcome — not
        // an error condition for us.
        let status = if dpkg.status.success() {
            parse_dpkg_line(&String::from_utf8_lossy(&dpkg.stdout))
        } else {
            Status::Purged
        };

        out.insert(
            package.name.clone(),
            CurrentState {
                status,
                held: holds.contains(&package.name),
            },
        );
    }
    Ok(out)
}

/// Compare two dpkg version strings for equality using
/// `dpkg --compare-versions`, the only correct arbiter of dpkg version
/// semantics (epochs, `~` pre-release ordering, etc.).
///
/// Note the flip side: `1.3.0` and `1:1.3.0` are *different* versions to
/// dpkg, so a pin missing its epoch never satisfies and apt re-runs (and
/// errors) every time. We treat a spawn failure as "not equal" so a
/// broken/absent `dpkg` degrades to re-applying rather than silently
/// claiming satisfaction.
fn dpkg_versions_equal(have: &str, want: &str) -> bool {
    Command::new("dpkg")
        .args(["--compare-versions", have, "eq", want])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Does the live state already satisfy `desired` for this package?
fn presence_satisfied(cur: &CurrentState, package: &Package, desired: Presence) -> bool {
    match desired {
        Presence::Absent => matches!(cur.status, Status::ConfigFiles | Status::Purged),
        Presence::Purged => matches!(cur.status, Status::Purged),
        Presence::Present => match (&cur.status, &package.version) {
            // Installed and no pin: any version satisfies.
            (Status::Installed(_), None) => true,
            // Installed with a pin: dpkg decides equality.
            (Status::Installed(Some(have)), Some(want)) => dpkg_versions_equal(have, want),
            // Installed but dpkg reported no version while a pin was
            // requested — can't claim satisfaction.
            (Status::Installed(None), Some(_)) => false,
            _ => false,
        },
    }
}

/// The view of one package *after* this call, built by starting from the
/// observed state and applying only what will actually change.
///
/// Backfilling from the observation is what keeps the diff free of
/// spurious churn: an unpinned `Present` request against an
/// already-installed package must render as its existing version, not as
/// "some version", or every run would show a change it isn't making.
fn desired_view(observed: &CurrentState, package: &Package, state: &State) -> PackageView {
    let status = match state.presence {
        None => observed.status.clone(),
        Some(Presence::Purged) => Status::Purged,
        // `apt-get remove` leaves config files behind; an already-absent
        // package stays exactly as it is.
        Some(Presence::Absent) => match &observed.status {
            Status::Installed(_) => Status::ConfigFiles,
            other => other.clone(),
        },
        Some(Presence::Present) => match (&package.version, &observed.status) {
            (Some(v), _) => Status::Installed(Some(v.clone())),
            (None, Status::Installed(have)) => Status::Installed(have.clone()),
            (None, _) => Status::Installed(None),
        },
    };
    PackageView {
        name: package.name.clone(),
        status,
        held: state.hold.unwrap_or(observed.held),
    }
}

/// The `apt-mark` work one call implies, decided up front so the whole
/// hold state machine is one pure function rather than three mutable
/// flags threaded through [`apply`].
#[derive(Debug, Default, PartialEq, Eq)]
struct HoldPlan {
    /// Holds to release *before* the presence step, so a version bump
    /// can land on a held package.
    release: Vec<String>,
    /// The subset of `release` that cindy decided on by itself (the
    /// caller didn't ask for `hold: Some(false)`). A failed presence
    /// step must put these back, so the call leaves the host as it found
    /// it.
    transparent: Vec<String>,
    /// `apt-mark hold`/`unhold` to run *after* the presence step, as
    /// `(hold?, packages)`.
    finalise: Option<(bool, Vec<String>)>,
}

/// Decide the hold plan from the observed state and the set of packages
/// whose presence has to change.
fn plan_holds(
    state: &State,
    current: &BTreeMap<String, CurrentState>,
    unsatisfied: &[&Package],
) -> HoldPlan {
    let held = |name: &str| current.get(name).is_some_and(|c| c.held);
    let needs_presence_change = |name: &str| unsatisfied.iter().any(|u| u.name == name);

    // Release a hold when the caller asked, or when it stands in the way
    // of a presence change this call has to make.
    let release: Vec<String> = state
        .packages
        .0
        .iter()
        .filter(|p| held(&p.name) && (state.hold == Some(false) || needs_presence_change(&p.name)))
        .map(|p| p.name.clone())
        .collect();

    let transparent = if state.hold == Some(false) {
        Vec::new()
    } else {
        release.clone()
    };

    // What each package's hold flag will be once `release` has run. The
    // final step must compare against *this*, not the original
    // observation: a package released above still looks held there, and
    // a requested hold would be skipped as already-satisfied.
    let effective_held = |name: &str| held(name) && !release.iter().any(|r| r == name);

    let finalise = match state.hold {
        Some(want) => {
            let names: Vec<String> = state
                .packages
                .0
                .iter()
                .filter(|p| effective_held(&p.name) != want)
                .map(|p| p.name.clone())
                .collect();
            (!names.is_empty()).then_some((want, names))
        }
        // The caller didn't pin `hold`, so anything released on our own
        // initiative goes back on — at the post-install version.
        None => (!transparent.is_empty()).then(|| (true, transparent.clone())),
    };

    HoldPlan {
        release,
        transparent,
        finalise,
    }
}

/// Reject requests that can't mean what they say, before touching the
/// system.
fn validate(state: &State) -> crate::Result<()> {
    if state.packages.0.is_empty() {
        crate::bail!("`apt` needs at least one package");
    }
    for package in &state.packages.0 {
        if package.name.trim().is_empty() {
            crate::bail!("`apt` was given an empty package name");
        }
        // `apt-get install nginx=1.2` is apt's own pin syntax, so a name
        // carrying `=` would install the right thing and then never
        // converge: `dpkg-query -W 'nginx=1.2'` finds nothing, so every
        // run would report Changed. Point at the typed pin instead.
        if package.name.contains('=') {
            crate::bail!(
                "package name {:?} contains `=`; pin a version with \
                 `apt::install_version(name, version)` or \
                 `apt::Package::pinned(name, version)` rather than in the name",
                package.name
            );
        }
        if let Some(version) = &package.version {
            if version.trim().is_empty() {
                crate::bail!(
                    "package `{}` has an empty version pin; use `None` for \
                     \"any version\"",
                    package.name
                );
            }
            if !matches!(state.presence, None | Some(Presence::Present)) {
                crate::bail!(
                    "package `{}` pins version `{version}` but the request is \
                     {:?}: a version is only meaningful when the package is to \
                     be present. Drop the pin, or ask for Presence::Present.",
                    package.name,
                    state.presence.unwrap(),
                );
            }
        }
    }
    Ok(())
}

/// Manage apt packages on a Debian/Ubuntu remote.
///
/// Reads each package's install status via `dpkg-query` and the hold set
/// via `apt-mark showhold`, then runs the minimum set of `apt-get` /
/// `apt-mark` commands needed to reach the desired state — batched into
/// one `apt-get` invocation for the whole list.
/// `DEBIAN_FRONTEND=noninteractive` is set for every apt call so debconf
/// prompts don't stall the run, and `DPkg::Lock::Timeout` is set so a
/// concurrent apt user (another operator's play, `unattended-upgrades`,
/// a human at a shell) makes this call *wait* rather than fail.
///
/// The apt **package cache is not refreshed** by this module — if you
/// need a fresh `apt-get update` (because you're chasing a newly
/// published pinned version, or installing a package that wasn't in the
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
// ergonomic `impl Into<PackageList>` arguments plus a body that builds a
// `State` and calls `apply`. The macro generates the concrete `#[remote]` wire
// entry point, the orchestrator shim, and the in-process `::inner` from each.

/// Ensure every package is installed at any version (no-op for those
/// already present). Takes one name or a collection:
/// `install("nginx")`, `install(["nginx", "curl"])`. Orchestrator:
/// `install(packages).await?`.
#[crate::action]
pub fn install(packages: impl Into<PackageList>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        packages,
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
        packages: PackageList(vec![Package::pinned(name, version)]),
        presence: Some(Presence::Present),
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
        packages: PackageList(vec![Package::pinned(name, version)]),
        presence: Some(Presence::Present),
        hold: Some(true),
    })
}

/// `apt-get remove` (config files may remain in `/etc`). Idempotent.
/// Orchestrator: `remove(packages).await?`.
#[crate::action]
pub fn remove(packages: impl Into<PackageList>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        packages,
        presence: Some(Presence::Absent),
        hold: None,
    })
}

/// `apt-get purge` (also removes config files). Idempotent.
/// Orchestrator: `purge(packages).await?`.
#[crate::action]
pub fn purge(packages: impl Into<PackageList>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        packages,
        presence: Some(Presence::Purged),
        hold: None,
    })
}

fn apply(state: State) -> crate::Result<crate::builtin::Return> {
    validate(&state)?;

    let current = read_current_states(&state.packages.0)?;
    let observed = |package: &Package| -> CurrentState {
        current
            .get(&package.name)
            .cloned()
            .expect("read_current_states covers every requested package")
    };

    // Build diff views: what we observed, and what the system will look
    // like when we're done, with unspecified fields back-filled from the
    // observation so the diff highlights only what's actually changing.
    let old_view: Vec<PackageView> = state
        .packages
        .0
        .iter()
        .map(|p| observed(p).view(&p.name))
        .collect();
    let new_view: Vec<PackageView> = state
        .packages
        .0
        .iter()
        .map(|p| desired_view(&observed(p), p, &state))
        .collect();
    if old_view != new_view {
        let _ = <Vec<PackageView> as crate::Diff>::diff(
            &old_view,
            &new_view,
            &mut std::io::stderr().lock(),
        );
    }

    let mut changed = false;

    // Only the packages that actually need work go to apt. Handing it an
    // already-satisfied unpinned package would *upgrade* it to the
    // candidate version, which is exactly what `Presence::Present`
    // promises not to do.
    let unsatisfied: Vec<&Package> = match state.presence {
        None => Vec::new(),
        Some(presence) => state
            .packages
            .0
            .iter()
            .filter(|p| !presence_satisfied(&observed(p), p, presence))
            .collect(),
    };

    let plan = plan_holds(&state, &current, &unsatisfied);

    // Check mode: the plan above is read-only analysis; report what it
    // would do without driving apt.
    if crate::dry_run() {
        let would = !plan.release.is_empty()
            || !unsatisfied.is_empty()
            || (plan.finalise.is_some() && state.hold.is_some());
        return Ok(crate::builtin::Return::from_changed(would));
    }

    // Step 1: release the holds that stand in the way.
    if !plan.release.is_empty() {
        run_check_retry_locks(apt_mark("unhold", &plan.release).as_mut())?;
        changed = true;
    }

    // Step 2: one batched presence change for everything that needs it.
    if let Some(presence) = state.presence
        && !unsatisfied.is_empty()
    {
        let mut cmd = apt_get();
        match presence {
            Presence::Absent => {
                cmd.arg("remove");
            }
            Presence::Purged => {
                cmd.arg("purge");
            }
            Presence::Present => {
                cmd.arg("install");
                // `--allow-downgrades`: pinning to an exact version must
                // also work when the installed version is *newer*
                // (rolling back a bad release is the flagship use of a
                // pin); plain `install pkg=older` refuses to downgrade.
                if unsatisfied.iter().any(|p| p.version.is_some()) {
                    cmd.arg("--allow-downgrades");
                }
            }
        }
        cmd.arg("--");
        for p in &unsatisfied {
            cmd.arg(p.spec());
        }

        if let Err(e) = run_check(&mut cmd) {
            // Put back only what we released on our own initiative: a
            // failed call must leave the host as it found it.
            if !plan.transparent.is_empty() {
                let _ = run_check_retry_locks(apt_mark("hold", &plan.transparent).as_mut());
            }
            return Err(e);
        }
        changed = true;
    }

    // Step 3: establish the final hold state.
    if let Some((want_held, packages)) = &plan.finalise {
        run_check_retry_locks(
            apt_mark(if *want_held { "hold" } else { "unhold" }, packages).as_mut(),
        )?;
        // Restoring a hold we transparently released is not itself a
        // change — the package ends where it started on that axis, and
        // `changed` is already true from the presence step that needed
        // the release.
        if state.hold.is_some() {
            changed = true;
        }
    }

    Ok(crate::builtin::Return::from_changed(changed))
}

/// `apt-mark <subcommand> -- <packages>`, argv-only (no shell) like
/// every other process launch in the framework.
///
/// `apt-mark` is an apt tool and reads the same config space, so it gets
/// the dpkg lock timeout too. It is also wrapped in
/// [`run_check_retry_locks`] at every call site, because unlike
/// `apt-get` it isn't documented to honour the timeout — belt and
/// braces, since the retry costs nothing when the first attempt works.
fn apt_mark(subcommand: &str, packages: &[String]) -> Box<Command> {
    let mut cmd = Box::new(Command::new("apt-mark"));
    cmd.arg("-o")
        .arg(format!("DPkg::Lock::Timeout={DPKG_LOCK_TIMEOUT_SECS}"))
        .arg(subcommand)
        .arg("--");
    for name in packages {
        cmd.arg(name);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(version: &str) -> CurrentState {
        CurrentState {
            status: Status::Installed(Some(version.to_owned())),
            held: false,
        }
    }
    const RC: CurrentState = CurrentState {
        status: Status::ConfigFiles,
        held: false,
    };
    const GONE: CurrentState = CurrentState {
        status: Status::Purged,
        held: false,
    };

    #[test]
    fn dpkg_line_parsing_covers_all_statuses() {
        assert_eq!(
            parse_dpkg_line("ii |1:2.3.4-1"),
            Status::Installed(Some("1:2.3.4-1".to_owned()))
        );
        assert_eq!(
            parse_dpkg_line("ii|1.0"),
            Status::Installed(Some("1.0".to_owned()))
        );
        // The version is trimmed.
        assert_eq!(
            parse_dpkg_line("ii | 1.0 \n"),
            Status::Installed(Some("1.0".to_owned()))
        );
        assert_eq!(parse_dpkg_line("rc |"), Status::ConfigFiles);
        assert_eq!(parse_dpkg_line("un |"), Status::Purged);
        // Unknown package: dpkg-query fails, caller passes nothing —
        // defensive parse of garbage must not panic.
        assert_eq!(parse_dpkg_line(""), Status::Purged);
        assert_eq!(parse_dpkg_line("i"), Status::Purged);
    }

    #[test]
    fn presence_satisfaction_matrix() {
        let any = Package::from("nginx");

        // Present: satisfied iff fully installed (version irrelevant).
        assert!(presence_satisfied(
            &installed("1.0"),
            &any,
            Presence::Present
        ));
        assert!(!presence_satisfied(&RC, &any, Presence::Present));
        assert!(!presence_satisfied(&GONE, &any, Presence::Present));

        // Absent tolerates left-behind config files…
        assert!(presence_satisfied(&RC, &any, Presence::Absent));
        assert!(presence_satisfied(&GONE, &any, Presence::Absent));
        assert!(!presence_satisfied(
            &installed("1.0"),
            &any,
            Presence::Absent
        ));

        // …Purged does not.
        assert!(!presence_satisfied(&RC, &any, Presence::Purged));
        assert!(presence_satisfied(&GONE, &any, Presence::Purged));

        // A pin on a non-installed package is never satisfied (the dpkg
        // comparison is never even consulted).
        let pinned = Package::pinned("nginx", "1.0");
        assert!(!presence_satisfied(&RC, &pinned, Presence::Present));
        assert!(!presence_satisfied(&GONE, &pinned, Presence::Present));
    }

    #[test]
    fn package_list_accepts_names_and_collections() {
        let one: PackageList = "nginx".into();
        assert_eq!(one.0, vec![Package::from("nginx")]);

        let from_string: PackageList = String::from("nginx").into();
        assert_eq!(from_string.0, one.0);

        let array: PackageList = ["nginx", "curl"].into();
        assert_eq!(array.0, vec![Package::from("nginx"), Package::from("curl")]);

        let owned: PackageList = vec![String::from("nginx"), String::from("curl")].into();
        assert_eq!(owned.0, array.0);

        let slice: PackageList = ["nginx", "curl"].as_slice().into();
        assert_eq!(slice.0, array.0);

        // Mixed pinned and unpinned in one call.
        let mixed: PackageList =
            [Package::from("nginx"), Package::pinned("curl", "8.5.0-1")].into();
        assert_eq!(mixed.0[1].version.as_deref(), Some("8.5.0-1"));

        let single: PackageList = Package::pinned("nginx", "1.2").into();
        assert_eq!(single.0.len(), 1);
    }

    #[test]
    fn package_spec_is_apts_pin_syntax() {
        assert_eq!(Package::from("nginx").spec(), "nginx");
        assert_eq!(Package::pinned("nginx", "1:1.2-3").spec(), "nginx=1:1.2-3");
    }

    #[test]
    fn validate_rejects_requests_that_cannot_converge() {
        let present = |packages: PackageList| State {
            packages,
            presence: Some(Presence::Present),
            hold: None,
        };

        assert!(validate(&present("nginx".into())).is_ok());
        assert!(validate(&present(PackageList(vec![]))).is_err());
        assert!(validate(&present("  ".into())).is_err());

        // A version smuggled into the name installs the right thing and
        // then reports Changed forever, because dpkg-query can't find
        // `nginx=1.2`.
        assert!(validate(&present("nginx=1.2".into())).is_err());

        // An empty pin is a mistake, not "any version".
        assert!(
            validate(&present(PackageList(vec![Package {
                name: "nginx".into(),
                version: Some(String::new()),
            }])))
            .is_err()
        );

        // A pin only means something for a package that is to be present.
        assert!(
            validate(&State {
                packages: Package::pinned("nginx", "1.2").into(),
                presence: Some(Presence::Absent),
                hold: None,
            })
            .is_err()
        );
        // …but it is fine with a `None` presence (hold-only calls).
        assert!(
            validate(&State {
                packages: Package::pinned("nginx", "1.2").into(),
                presence: None,
                hold: Some(true),
            })
            .is_ok()
        );
    }

    #[test]
    fn desired_view_backfills_so_unchanged_packages_do_not_diff() {
        let any = Package::from("nginx");
        let state = State {
            packages: any.clone().into(),
            presence: Some(Presence::Present),
            hold: None,
        };
        // Installed at 1.0, asked for "any version": the view must show
        // 1.0, not "some version", or every run would diff.
        let obs = installed("1.0");
        assert_eq!(desired_view(&obs, &any, &state), obs.view("nginx"));

        // A pin renders the pinned version.
        let pinned = Package::pinned("nginx", "2.0");
        let state = State {
            packages: pinned.clone().into(),
            presence: Some(Presence::Present),
            hold: None,
        };
        assert_eq!(
            desired_view(&obs, &pinned, &state).status,
            Status::Installed(Some("2.0".to_owned()))
        );

        // `Absent` on an installed package leaves config files behind;
        // `Purged` does not.
        let state = State {
            packages: any.clone().into(),
            presence: Some(Presence::Absent),
            hold: None,
        };
        assert_eq!(desired_view(&obs, &any, &state).status, Status::ConfigFiles);
        let state = State {
            packages: any.clone().into(),
            presence: Some(Presence::Purged),
            hold: None,
        };
        assert_eq!(desired_view(&obs, &any, &state).status, Status::Purged);

        // A `None` presence touches neither axis but still reflects a
        // requested hold.
        let state = State {
            packages: any.clone().into(),
            presence: None,
            hold: Some(true),
        };
        let view = desired_view(&obs, &any, &state);
        assert_eq!(view.status, obs.status);
        assert!(view.held);
    }

    /// Build the `(current, unsatisfied)` pair `plan_holds` consumes.
    /// `packages` is `(name, currently_held, needs_presence_change)`.
    fn hold_scenario(
        packages: &[(&str, bool, bool)],
        hold: Option<bool>,
    ) -> (State, BTreeMap<String, CurrentState>, Vec<Package>) {
        let state = State {
            packages: PackageList(packages.iter().map(|(n, ..)| Package::from(*n)).collect()),
            presence: Some(Presence::Present),
            hold,
        };
        let current = packages
            .iter()
            .map(|(name, held, needs)| {
                (
                    (*name).to_owned(),
                    CurrentState {
                        // "needs a presence change" is spelled as "not
                        // installed" here; `plan_holds` only ever reads
                        // `held`, so the status just has to be coherent.
                        status: if *needs {
                            Status::Purged
                        } else {
                            Status::Installed(Some("1.0".to_owned()))
                        },
                        held: *held,
                    },
                )
            })
            .collect();
        let unsatisfied = packages
            .iter()
            .filter(|(.., needs)| *needs)
            .map(|(n, ..)| Package::from(*n))
            .collect();
        (state, current, unsatisfied)
    }

    fn plan(packages: &[(&str, bool, bool)], hold: Option<bool>) -> HoldPlan {
        let (state, current, unsatisfied) = hold_scenario(packages, hold);
        plan_holds(&state, &current, &unsatisfied.iter().collect::<Vec<_>>())
    }

    #[test]
    fn a_transparently_released_hold_is_restored() {
        // hold: None, package held, presence change needed → release it
        // to land the change, then put it back.
        let p = plan(&[("nginx", true, true)], None);
        assert_eq!(p.release, vec!["nginx"]);
        assert_eq!(p.transparent, vec!["nginx"]);
        assert_eq!(p.finalise, Some((true, vec!["nginx".to_owned()])));
    }

    #[test]
    fn a_requested_hold_survives_its_own_transparent_release() {
        // The regression: with `hold: Some(true)` on an
        // already-held package that needs a presence change, step 1
        // releases the hold. Comparing the final state against the
        // *original* observation would see "already held" and skip the
        // re-hold, silently leaving the package unheld.
        let p = plan(&[("nginx", true, true)], Some(true));
        assert_eq!(p.release, vec!["nginx"]);
        assert_eq!(
            p.finalise,
            Some((true, vec!["nginx".to_owned()])),
            "the hold released in step 1 must be re-applied"
        );
    }

    #[test]
    fn an_explicit_unhold_is_not_restored() {
        let p = plan(&[("nginx", true, true)], Some(false));
        assert_eq!(p.release, vec!["nginx"]);
        // The caller asked for it, so it is not ours to put back.
        assert!(p.transparent.is_empty());
        assert_eq!(p.finalise, None);
    }

    #[test]
    fn nothing_to_do_plans_nothing() {
        // Not held, no hold requested, nothing to change.
        assert_eq!(plan(&[("nginx", false, false)], None), HoldPlan::default());
        // Held, no presence change, no hold request: leave it alone —
        // a hold we didn't ask about is not ours to touch.
        assert_eq!(plan(&[("nginx", true, false)], None), HoldPlan::default());
        // Already held and a hold is requested: satisfied.
        assert_eq!(
            plan(&[("nginx", true, false)], Some(true)),
            HoldPlan::default()
        );
    }

    #[test]
    fn holds_are_planned_per_package_across_a_batch() {
        // nginx: held + needs a change → released and restored.
        // curl:  held, satisfied      → left alone.
        // git:   unheld + needs change → nothing on the hold axis.
        let p = plan(
            &[
                ("nginx", true, true),
                ("curl", true, false),
                ("git", false, true),
            ],
            None,
        );
        assert_eq!(p.release, vec!["nginx"]);
        assert_eq!(p.finalise, Some((true, vec!["nginx".to_owned()])));

        // Asking for a hold across the batch picks up only the two that
        // aren't effectively held once step 1 has run.
        let p = plan(
            &[
                ("nginx", true, true),
                ("curl", true, false),
                ("git", false, true),
            ],
            Some(true),
        );
        assert_eq!(
            p.finalise,
            Some((true, vec!["nginx".to_owned(), "git".to_owned()]))
        );
    }

    #[test]
    fn lock_contention_is_recognised_for_both_tool_families() {
        use crate::builtin::is_lock_contention;

        // shadow-utils.
        assert!(is_lock_contention(
            "useradd: cannot lock /etc/passwd; try again later.\n"
        ));
        assert!(is_lock_contention("groupmod: cannot lock /etc/group.\n"));

        // apt's tools, which never say "cannot lock" — the reason the
        // matcher can't just carry shadow's wording.
        assert!(is_lock_contention(
            "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 42\n"
        ));
        assert!(is_lock_contention(
            "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), \
             is another process using it?\n"
        ));
        assert!(is_lock_contention(
            "E: Could not open lock file - open (11: Resource temporarily unavailable)\n"
        ));

        // Genuine errors must fail on the first attempt, not eight
        // backoffs later.
        assert!(!is_lock_contention("useradd: user 'bob' already exists\n"));
        assert!(!is_lock_contention(
            "E: Unable to locate package nosuchpkg\n"
        ));
        assert!(!is_lock_contention("dpkg: error: read-only file system\n"));
        assert!(!is_lock_contention(""));
    }
}
