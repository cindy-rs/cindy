//! apt packages on Debian and Ubuntu. The package cache isn't
//! refreshed here: run `apt-get update` yourself when you need it.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use crate::Context;
use crate::builtin::{run_check, run_check_retry_locks};

/// A package, optionally pinned. A bare name converts with `Into`.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub struct Package {
    pub name: String,
    /// Compared as `dpkg --compare-versions eq`: epoch and revision
    /// count, so `1.3.0` doesn't match `1:1.3.0`. Copy what
    /// `dpkg-query -W -f '${Version}'` reports. `None` ⇒ any version.
    pub version: Option<String>,
}

impl Package {
    pub fn pinned(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: Some(version.into()),
        }
    }

    /// `name` or `name=version`, as `apt-get install` takes it.
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

/// One name or any collection, so every verb takes either:
///
/// ```ignore
/// apt::install("nginx").await?;
/// apt::install(["nginx", "curl", "ca-certificates"]).await?;
/// apt::install([Package::from("nginx"), Package::pinned("curl", "8.5.0-1")]).await?;
/// ```
///
/// One `apt-get install a b c` takes the lock once and solves the set
/// together, rather than three resolutions that may conflict.
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

// Not one blanket `impl<I: IntoIterator>`: coherence can't rule out
// `String: IntoIterator`, so it would overlap `From<String>`.
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

#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Presence {
    /// `apt-get remove`: config files may stay behind.
    Absent,
    /// `apt-get purge`: config files go too.
    Purged,
    /// `apt-get install`, at the pinned version if any. An unpinned
    /// package already installed is left alone, never upgraded.
    Present,
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    pub packages: PackageList,
    /// `None` leaves install state alone.
    pub presence: Option<Presence>,
    /// `apt-mark hold` state; `None` leaves it alone. A hold standing in
    /// the way of a presence change is released for it and put back
    /// afterwards, at the new version.
    pub hold: Option<bool>,
}

/// Install status, observed or wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    /// Unknown to dpkg, or purged.
    Purged,
    /// Removed, config files left (`rc`).
    ConfigFiles,
    /// Part-way through dpkg (unpacked, half-installed, half-configured):
    /// on disk, but neither installed nor gone.
    Broken,
    /// `None` for an unpinned request whose version isn't known yet.
    Installed(Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageView {
    name: String,
    status: Status,
    held: bool,
}

impl crate::Diff for Vec<PackageView> {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CurrentState {
    status: Status,
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

/// apt waits for the dpkg lock itself: its other holders
/// (`unattended-upgrades`, a human) are nothing cindy could coordinate
/// with. Needs apt ≥ 2.1.10; older apt ignores the option.
const DPKG_LOCK_TIMEOUT_SECS: u32 = 300;

fn apt_get() -> Command {
    let mut c = Command::new("apt-get");
    c.env("DEBIAN_FRONTEND", "noninteractive");
    c.arg("-y");
    c.arg("-o");
    c.arg(format!("DPkg::Lock::Timeout={DPKG_LOCK_TIMEOUT_SECS}"));
    c
}

/// One `dpkg-query -W -f '${db:Status-Abbrev}|${Version}'` line. The
/// second character is the current state.
fn parse_dpkg_line(raw: &str) -> Status {
    let (abbrev, ver) = raw.split_once('|').unwrap_or((raw, ""));
    match abbrev.chars().nth(1) {
        // `t` and `W`: installed, with triggers still to run.
        Some('i' | 't' | 'W') => Status::Installed(Some(ver.trim().to_owned())),
        Some('c') => Status::ConfigFiles,
        Some('n') | None => Status::Purged,
        // `U`, `H`, `F`, and anything newer dpkg invents.
        Some(_) => Status::Broken,
    }
}

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
    let holds: BTreeSet<String> = String::from_utf8_lossy(&mark.stdout)
        .lines()
        .map(|l| l.trim().to_owned())
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

        // Non-zero: dpkg doesn't know the package.
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

/// dpkg is the only arbiter of its version semantics (epochs, `~`). A
/// failure to ask reads as "not equal": re-apply rather than claim.
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
            (Status::Installed(_), None) => true,
            (Status::Installed(Some(have)), Some(want)) => dpkg_versions_equal(have, want),
            _ => false,
        },
    }
}

/// The package after this call: the observation with only the requested
/// changes applied, so an unpinned install of an installed package
/// renders its version, not "some version", and doesn't diff.
fn desired_view(observed: &CurrentState, package: &Package, state: &State) -> PackageView {
    let status = match state.presence {
        None => observed.status.clone(),
        Some(Presence::Purged) => Status::Purged,
        Some(Presence::Absent) => match &observed.status {
            Status::Installed(_) | Status::Broken => Status::ConfigFiles,
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

/// The `apt-mark` work one call implies, decided up front.
#[derive(Debug, Default, PartialEq, Eq)]
struct HoldPlan {
    /// Released before the presence step, so it can land.
    release: Vec<String>,
    /// The part of `release` the caller didn't ask for: put back
    /// afterwards, and on failure.
    transparent: Vec<String>,
    /// `(hold?, packages)`, after the presence step.
    finalise: Option<(bool, Vec<String>)>,
}

fn plan_holds(
    state: &State,
    current: &BTreeMap<String, CurrentState>,
    unsatisfied: &[&Package],
) -> HoldPlan {
    let held = |name: &str| current.get(name).is_some_and(|c| c.held);
    let needs_presence_change = |name: &str| unsatisfied.iter().any(|u| u.name == name);

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

    // Compared against the state after `release`, not the observation:
    // a released package still looks held there, and a requested hold
    // would be skipped as already satisfied.
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
        None => (!transparent.is_empty()).then(|| (true, transparent.clone())),
    };

    HoldPlan {
        release,
        transparent,
        finalise,
    }
}

/// Whether the call changes anything — read by check mode and the real
/// run alike. Restoring a hold released for the presence step is not a
/// change on its own.
fn changes(plan: &HoldPlan, unsatisfied: &[&Package], state: &State) -> bool {
    !plan.release.is_empty()
        || !unsatisfied.is_empty()
        || (plan.finalise.is_some() && state.hold.is_some())
}

fn validate(state: &State) -> crate::Result<()> {
    if state.packages.0.is_empty() {
        crate::bail!("`apt` needs at least one package");
    }
    for package in &state.packages.0 {
        if package.name.trim().is_empty() {
            crate::bail!("`apt` was given an empty package name");
        }
        // It would install, then never converge: dpkg-query can't find
        // `nginx=1.2`.
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

/// The full-control entry point; the verbs below cover the common cases.
#[crate::remote]
pub fn apt(state: State) -> crate::Result<crate::builtin::Return> {
    apply(state)
}

/// Installed, at any version.
#[crate::action]
pub fn install(packages: impl Into<PackageList>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        packages,
        presence: Some(Presence::Present),
        hold: None,
    })
}

/// Installed at exactly `version` (dpkg's string, epoch and all).
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

/// Installed at exactly `version` and held there.
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

/// Removed; config files may remain.
#[crate::action]
pub fn remove(packages: impl Into<PackageList>) -> crate::Result<crate::builtin::Return> {
    apply(State {
        packages,
        presence: Some(Presence::Absent),
        hold: None,
    })
}

/// Removed with their config files.
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

    // Only these go to apt: handing it a satisfied unpinned package
    // would upgrade it, which `Present` promises not to.
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
    let changed = changes(&plan, &unsatisfied, &state);
    if crate::dry_run() {
        return Ok(crate::builtin::Return::from_changed(changed));
    }

    if !plan.release.is_empty() {
        run_check_retry_locks(&mut apt_mark("unhold", &plan.release))?;
    }
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
                // Rolling back a bad release is what pins are for.
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
            if !plan.transparent.is_empty() {
                let _ = run_check_retry_locks(&mut apt_mark("hold", &plan.transparent));
            }
            return Err(e);
        }
    }
    if let Some((want_held, packages)) = &plan.finalise {
        let verb = if *want_held { "hold" } else { "unhold" };
        run_check_retry_locks(&mut apt_mark(verb, packages))?;
    }
    Ok(crate::builtin::Return::from_changed(changed))
}

/// Callers also retry on lock contention: unlike `apt-get`, `apt-mark`
/// isn't documented to honour the lock timeout.
fn apt_mark(subcommand: &str, packages: &[String]) -> Command {
    let mut cmd = Command::new("apt-mark");
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
        assert_eq!(
            parse_dpkg_line("ii | 1.0 \n"),
            Status::Installed(Some("1.0".to_owned()))
        );
        assert_eq!(parse_dpkg_line("rc |"), Status::ConfigFiles);
        assert_eq!(parse_dpkg_line("un |"), Status::Purged);
        assert_eq!(parse_dpkg_line(""), Status::Purged);
        assert_eq!(parse_dpkg_line("i"), Status::Purged);
        // Triggers pending: installed, not missing (else: reinstall loop).
        for abbrev in ["it", "iW"] {
            assert_eq!(
                parse_dpkg_line(&format!("{abbrev}|1.0")),
                Status::Installed(Some("1.0".to_owned())),
                "{abbrev}"
            );
        }
        // Part-way through dpkg: neither installed nor gone.
        for abbrev in ["iU", "iH", "iF", "rH"] {
            assert_eq!(
                parse_dpkg_line(&format!("{abbrev}|1.0")),
                Status::Broken,
                "{abbrev}"
            );
        }
    }

    #[test]
    fn presence_satisfaction_matrix() {
        let any = Package::from("nginx");

        assert!(presence_satisfied(
            &installed("1.0"),
            &any,
            Presence::Present
        ));
        assert!(!presence_satisfied(&RC, &any, Presence::Present));
        assert!(!presence_satisfied(&GONE, &any, Presence::Present));

        assert!(presence_satisfied(&RC, &any, Presence::Absent));
        assert!(presence_satisfied(&GONE, &any, Presence::Absent));
        assert!(!presence_satisfied(
            &installed("1.0"),
            &any,
            Presence::Absent
        ));

        assert!(!presence_satisfied(&RC, &any, Presence::Purged));
        assert!(presence_satisfied(&GONE, &any, Presence::Purged));

        let pinned = Package::pinned("nginx", "1.0");
        assert!(!presence_satisfied(&RC, &pinned, Presence::Present));
        assert!(!presence_satisfied(&GONE, &pinned, Presence::Present));

        // A half-installed package satisfies nothing: install, remove
        // and purge all have work to do.
        let broken = CurrentState {
            status: Status::Broken,
            held: false,
        };
        for presence in [Presence::Present, Presence::Absent, Presence::Purged] {
            assert!(!presence_satisfied(&broken, &any, presence));
        }
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

        assert!(validate(&present("nginx=1.2".into())).is_err());

        assert!(
            validate(&present(PackageList(vec![Package {
                name: "nginx".into(),
                version: Some(String::new()),
            }])))
            .is_err()
        );

        assert!(
            validate(&State {
                packages: Package::pinned("nginx", "1.2").into(),
                presence: Some(Presence::Absent),
                hold: None,
            })
            .is_err()
        );
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
        let obs = installed("1.0");
        assert_eq!(desired_view(&obs, &any, &state), obs.view("nginx"));

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
        let p = plan(&[("nginx", true, true)], None);
        assert_eq!(p.release, vec!["nginx"]);
        assert_eq!(p.transparent, vec!["nginx"]);
        assert_eq!(p.finalise, Some((true, vec!["nginx".to_owned()])));
    }

    #[test]
    fn a_requested_hold_survives_its_own_transparent_release() {
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
        assert!(p.transparent.is_empty());
        assert_eq!(p.finalise, None);
    }

    #[test]
    fn nothing_to_do_plans_nothing() {
        assert_eq!(plan(&[("nginx", false, false)], None), HoldPlan::default());
        assert_eq!(plan(&[("nginx", true, false)], None), HoldPlan::default());
        assert_eq!(
            plan(&[("nginx", true, false)], Some(true)),
            HoldPlan::default()
        );
    }

    #[test]
    fn holds_are_planned_per_package_across_a_batch() {
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

        assert!(is_lock_contention(
            "useradd: cannot lock /etc/passwd; try again later.\n"
        ));
        assert!(is_lock_contention("groupmod: cannot lock /etc/group.\n"));

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

        assert!(!is_lock_contention("useradd: user 'bob' already exists\n"));
        assert!(!is_lock_contention(
            "E: Unable to locate package nosuchpkg\n"
        ));
        assert!(!is_lock_contention("dpkg: error: read-only file system\n"));
        assert!(!is_lock_contention(""));
    }
}
