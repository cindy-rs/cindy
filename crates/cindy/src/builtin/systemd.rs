//! One systemd unit, on two independent axes: whether it starts at boot
//! ([`Enablement`]) and what it is doing now ([`RuntimeAction`]).
//!
//! Unit files written with [`path`](super::path) aren't seen until
//! [`daemon_reload`]; nothing here reloads implicitly.

use std::str::FromStr;

use zbus_systemd::systemd1::{JobRemovedStream, ManagerProxy, UnitProxy};
use zbus_systemd::zbus;

use crate::Context;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[crate::wire]
pub enum RuntimeAction {
    Started,
    Stopped,
    Restarted,
    Reloaded,
}

/// At boot, persistently: a runtime-only enable or mask (`/run`)
/// doesn't count, since it is gone after the next reboot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[crate::wire]
pub enum Enablement {
    Masked,
    Disabled,
    Enabled,
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// A bare name gets `.service`; anything with a `.` is used as is.
    pub name: String,
    /// `None` leaves enablement alone. Masked with a runtime action is
    /// rejected: a masked unit can't run.
    pub enablement: Option<Enablement>,
    /// `None` leaves the running state alone.
    pub runtime: Option<RuntimeAction>,
    /// How long a start/stop/restart/reload job may take. `None` ⇒ 90s,
    /// systemd's own default.
    pub job_timeout: Option<std::time::Duration>,
}

impl crate::Diff for State {}

/// Re-read unit files from disk, after writing one yourself:
///
/// ```rust,ignore
/// if path::file(unit_path, unit, "root", "root", mode).await?.changed() {
///     systemd::daemon_reload().await?;
/// }
/// systemd::enable_and_start("myapp").await?;
/// ```
#[crate::remote]
pub async fn daemon_reload() -> crate::Result<()> {
    if crate::dry_run() {
        eprintln!("check mode: would run daemon-reload");
        return Ok(());
    }
    manager()
        .await?
        .reload()
        .await
        .context("Daemon-reload failed")
}

/// The full-control entry point; the verbs below cover the common cases.
#[crate::remote]
pub async fn systemd(state: State) -> crate::Result<super::Return> {
    apply(state).await
}

fn intent(name: String, enablement: Option<Enablement>, runtime: Option<RuntimeAction>) -> State {
    State {
        name,
        enablement,
        runtime,
        job_timeout: None,
    }
}

/// Enable at boot; doesn't start it now.
#[crate::action]
pub async fn enable(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(name, Some(Enablement::Enabled), None)).await
}

/// Disable at boot; doesn't stop it now.
#[crate::action]
pub async fn disable(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(name, Some(Enablement::Disabled), None)).await
}

/// Prevent any future start; doesn't stop a running instance. A real
/// unit file in `/etc/systemd/system` is removed (loudly) to make room
/// for the mask; a `.d/` drop-in directory is left alone.
#[crate::action]
pub async fn mask(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(name, Some(Enablement::Masked), None)).await
}

#[crate::action]
pub async fn start(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(name, None, Some(RuntimeAction::Started))).await
}

#[crate::action]
pub async fn stop(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(name, None, Some(RuntimeAction::Stopped))).await
}

/// Always restarts.
#[crate::action]
pub async fn restart(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(name, None, Some(RuntimeAction::Restarted))).await
}

/// Always reloads.
#[crate::action]
pub async fn reload(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(name, None, Some(RuntimeAction::Reloaded))).await
}

#[crate::action]
pub async fn enable_and_start(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(
        name,
        Some(Enablement::Enabled),
        Some(RuntimeAction::Started),
    ))
    .await
}

#[crate::action]
pub async fn disable_and_stop(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(intent(
        name,
        Some(Enablement::Disabled),
        Some(RuntimeAction::Stopped),
    ))
    .await
}

/// systemd's `UnitFileState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnitState {
    Enabled,
    EnabledRuntime,
    Linked,
    LinkedRuntime,
    Alias,
    Masked,
    MaskedRuntime,
    Static,
    Disabled,
    Generated,
    Transient,
    Indirect,
    Bad,
}

impl FromStr for UnitState {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        Ok(match s {
            "enabled" => Self::Enabled,
            "enabled-runtime" => Self::EnabledRuntime,
            "linked" => Self::Linked,
            "linked-runtime" => Self::LinkedRuntime,
            "alias" => Self::Alias,
            "masked" => Self::Masked,
            "masked-runtime" => Self::MaskedRuntime,
            "static" => Self::Static,
            "disabled" => Self::Disabled,
            "generated" => Self::Generated,
            "transient" => Self::Transient,
            "indirect" => Self::Indirect,
            "bad" | "" => Self::Bad,
            other => crate::bail!("unknown UnitFileState: {other:?}"),
        })
    }
}

impl UnitState {
    /// The boot axis this state amounts to, for the diff.
    fn at_boot(self) -> Enablement {
        match self {
            Self::Masked => Enablement::Masked,
            Self::Enabled => Enablement::Enabled,
            _ => Enablement::Disabled,
        }
    }
}

/// One step toward the wanted enablement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Mask,
    /// After which the state is re-read and planned again.
    Unmask {
        runtime: bool,
    },
    Enable,
    Disable {
        runtime: bool,
    },
}

/// The next step, decided from what systemd reports (`None`: there).
/// Pure, so check mode reports exactly what the real run would do.
fn plan(want: Enablement, observed: Option<UnitState>) -> Result<Option<Step>, String> {
    use UnitState as S;
    if want == Enablement::Masked {
        return Ok((observed != Some(S::Masked)).then_some(Step::Mask));
    }
    Ok(Some(match observed {
        Some(s @ (S::Masked | S::MaskedRuntime)) => Step::Unmask {
            runtime: s == S::MaskedRuntime,
        },
        Some(S::Bad) => {
            return Err(
                "is in the `bad` unit-file state (broken symlink or unreadable unit \
                        file); fix or remove it before managing enablement"
                    .into(),
            );
        }
        Some(s @ (S::Static | S::Generated | S::Transient)) => {
            return Err(format!(
                "is {s:?}: it has no [Install] section, so there is nothing to {} — {}",
                if want == Enablement::Enabled {
                    "enable"
                } else {
                    "disable"
                },
                if want == Enablement::Enabled {
                    "static/generated units are always available; just start it"
                } else {
                    "if you want it unable to run, mask it"
                },
            ));
        }
        Some(S::Enabled) if want == Enablement::Enabled => return Ok(None),
        // A runtime-only enable is gone at reboot: enable for real.
        _ if want == Enablement::Enabled => Step::Enable,
        Some(s @ (S::Enabled | S::EnabledRuntime | S::Linked | S::LinkedRuntime | S::Alias)) => {
            Step::Disable {
                runtime: matches!(s, S::EnabledRuntime | S::LinkedRuntime),
            }
        }
        _ => return Ok(None),
    }))
}

/// systemd's `ActiveState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveState {
    Active,
    Reloading,
    Inactive,
    Failed,
    Activating,
    Deactivating,
}

impl FromStr for ActiveState {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        Ok(match s {
            "active" => Self::Active,
            "reloading" => Self::Reloading,
            "inactive" => Self::Inactive,
            "failed" => Self::Failed,
            "activating" => Self::Activating,
            "deactivating" => Self::Deactivating,
            other => crate::bail!("unknown ActiveState: {other:?}"),
        })
    }
}

impl ActiveState {
    /// Ansible's "started": running or on the way there.
    fn is_running(self) -> bool {
        matches!(self, Self::Active | Self::Reloading | Self::Activating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    Start,
    Stop,
    Restart,
    Reload,
}

impl Job {
    fn verb(self) -> &'static str {
        match self {
            Job::Start => "start",
            Job::Stop => "stop",
            Job::Restart => "restart",
            Job::Reload => "reload",
        }
    }
}

/// The job a runtime action needs, if any.
fn runtime_job(action: RuntimeAction, running: bool) -> Option<Job> {
    match action {
        RuntimeAction::Started if !running => Some(Job::Start),
        RuntimeAction::Stopped if running => Some(Job::Stop),
        RuntimeAction::Restarted => Some(Job::Restart),
        RuntimeAction::Reloaded => Some(Job::Reload),
        RuntimeAction::Started | RuntimeAction::Stopped => None,
    }
}

/// One system-bus connection per worker: plays fan out over many units,
/// and a host without a bus still fails every call with the real error.
static SYSTEM_BUS: tokio::sync::OnceCell<Result<zbus::Connection, String>> =
    tokio::sync::OnceCell::const_new();

async fn system_bus() -> crate::Result<&'static zbus::Connection> {
    SYSTEM_BUS
        .get_or_init(|| async { zbus::Connection::system().await.map_err(|e| e.to_string()) })
        .await
        .as_ref()
        .map_err(|e| crate::anyhow!("{e}"))
}

async fn manager() -> crate::Result<ManagerProxy<'static>> {
    ManagerProxy::new(system_bus().await?)
        .await
        .context("Couldn't construct Manager proxy")
}

fn is_no_such_unit(err: &zbus::Error) -> bool {
    let zbus::Error::MethodError(name, _, _) = err else {
        return false;
    };
    let name = name.to_string();
    [".NoSuchUnit", ".NoSuchUnitFile", ".LoadFailed"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// `None` when systemd has no such unit file.
async fn read_file_state(
    manager: &ManagerProxy<'_>,
    unit: &str,
) -> crate::Result<Option<UnitState>> {
    match manager.get_unit_file_state(unit.to_owned()).await {
        Ok(s) => Ok(Some(s.parse().context("Parsing UnitFileState")?)),
        Err(e) if is_no_such_unit(&e) => Ok(None),
        Err(e) => Err(e).context(format!("GetUnitFileState({unit}) failed")),
    }
}

async fn is_running(manager: &ManagerProxy<'_>, unit: &str) -> crate::Result<bool> {
    // GetUnit, not LoadUnit: LoadUnit loads the unit as a side effect.
    // A unit that isn't loaded isn't running; systemd says so either as
    // NoSuchUnit or, depending on version, as the root path.
    let path = match manager.get_unit(unit.to_owned()).await {
        Ok(path) if path.as_str() != "/" => path,
        Ok(_) => return Ok(false),
        Err(e) if is_no_such_unit(&e) => return Ok(false),
        Err(e) => return Err(e).context(format!("GetUnit({unit}) failed")),
    };
    let state: ActiveState = UnitProxy::builder(system_bus().await?)
        .path(path)
        .context("Invalid unit object path")?
        .build()
        .await
        .context("Couldn't construct Unit proxy")?
        .active_state()
        .await
        .context("Reading ActiveState failed")?
        .parse()
        .context("Parsing ActiveState")?;
    Ok(state.is_running())
}

async fn apply(state: State) -> crate::Result<super::Return> {
    let unit = if state.name.contains('.') {
        state.name.clone()
    } else {
        format!("{}.service", state.name)
    };
    if let (Some(Enablement::Masked), Some(runtime)) = (state.enablement, state.runtime) {
        crate::bail!(
            "invalid systemd request for `{unit}`: a unit can't be masked and have a \
             runtime action ({runtime:?}) at once — a masked unit cannot run. Mask it, \
             or pick Enabled/Disabled if you need it running.",
        );
    }

    let manager = manager().await?;
    let file_state = read_file_state(&manager, &unit).await?;
    let running = is_running(&manager, &unit).await?;

    let observed = State {
        name: state.name.clone(),
        enablement: file_state.map(UnitState::at_boot),
        runtime: Some(if running {
            RuntimeAction::Started
        } else {
            RuntimeAction::Stopped
        }),
        job_timeout: None,
    };
    let wanted = State {
        enablement: state.enablement.or(observed.enablement),
        // Restart and reload leave it running.
        runtime: match state.runtime {
            None => observed.runtime,
            Some(RuntimeAction::Stopped) => Some(RuntimeAction::Stopped),
            Some(_) => Some(RuntimeAction::Started),
        },
        ..observed.clone()
    };
    if observed != wanted {
        let _ = crate::Diff::diff(&observed, &wanted, &mut std::io::stderr().lock());
    }

    let mut changed = false;
    if let Some(want) = state.enablement {
        changed = reconcile_enablement(&manager, &unit, want, file_state).await?;
    }
    if let Some(action) = state.runtime {
        // An enablement change (an unmask) can change what is running.
        let running = if changed && !crate::dry_run() {
            is_running(&manager, &unit).await?
        } else {
            running
        };
        if let Some(job) = runtime_job(action, running) {
            if !crate::dry_run() {
                run_job(&manager, &unit, job, state.job_timeout).await?;
            }
            changed = true;
        }
    }
    Ok(super::Return::from_changed(changed))
}

/// Step until systemd reports the wanted state. Each step is followed
/// by a re-read: an unmask reveals what was underneath, and a unit with
/// both persistent and runtime links reports only one of them at a time.
async fn reconcile_enablement(
    manager: &ManagerProxy<'_>,
    unit: &str,
    want: Enablement,
    initial: Option<UnitState>,
) -> crate::Result<bool> {
    let files = vec![unit.to_owned()];
    let mut observed = initial;
    let mut taken: Vec<Step> = Vec::new();
    loop {
        let step = match plan(want, observed) {
            Ok(Some(step)) => step,
            Ok(None) => return Ok(!taken.is_empty()),
            Err(why) => {
                if taken.iter().any(|s| matches!(s, Step::Unmask { .. })) {
                    // Best effort: leave the host as it was found.
                    let runtime = initial == Some(UnitState::MaskedRuntime);
                    let _ = manager.mask_unit_files(files.clone(), runtime, true).await;
                }
                crate::bail!("`{unit}` {why}");
            }
        };
        if taken.contains(&step) {
            crate::bail!("`{unit}` is still {observed:?} after {step:?}");
        }
        if step == Step::Mask {
            clear_mask_target(unit).await?;
        }
        if crate::dry_run() {
            // What follows a step is unknowable without taking it, so
            // this may over-report — never under-report.
            return Ok(true);
        }
        let result = match step {
            Step::Mask => manager
                .mask_unit_files(files.clone(), false, true)
                .await
                .map(drop),
            Step::Unmask { runtime } => manager
                .unmask_unit_files(files.clone(), runtime)
                .await
                .map(drop),
            // `force` replaces stale links pointing elsewhere.
            Step::Enable => manager
                .enable_unit_files(files.clone(), false, true)
                .await
                .map(drop),
            Step::Disable { runtime } => manager
                .disable_unit_files(files.clone(), runtime)
                .await
                .map(drop),
        };
        result.context(format!("{step:?} of {unit} failed"))?;
        if step == Step::Mask {
            manager.reload().await.context("Daemon-reload failed")?;
        }
        taken.push(step);
        observed = read_file_state(manager, unit).await?;
    }
}

/// A mask is a `/dev/null` symlink in `/etc/systemd/system`. systemd
/// replaces a symlink there itself; a real file or directory (an
/// admin-authored unit) has to go first — `mask` is an explicit request.
/// Announced under `--check` too, but only removed outside it.
async fn clear_mask_target(unit: &str) -> crate::Result<()> {
    let target = std::path::Path::new("/etc/systemd/system").join(unit);
    let Ok(meta) = tokio::fs::symlink_metadata(&target).await else {
        return Ok(());
    };
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    let kind = if meta.is_dir() { "directory" } else { "file" };
    eprintln!(
        "mask: removing admin-authored {kind} {} to complete the mask",
        target.display()
    );
    if crate::dry_run() {
        return Ok(());
    }
    if meta.is_dir() {
        tokio::fs::remove_dir_all(&target).await
    } else {
        tokio::fs::remove_file(&target).await
    }
    .context("Couldn't clear the conflicting unit at the mask target")
}

const DEFAULT_JOB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Queue the job and wait for its outcome. `StartUnit` and friends only
/// queue: returning then would call a service that crashes on startup a
/// success. `systemctl` waits for the `JobRemoved` signal; so do we.
async fn run_job(
    manager: &ManagerProxy<'_>,
    unit: &str,
    job: Job,
    timeout: Option<std::time::Duration>,
) -> crate::Result<()> {
    let verb = job.verb();
    // Subscribed before queueing, or the signal can arrive first.
    let mut jobs = manager
        .receive_job_removed()
        .await
        .context("Couldn't subscribe to JobRemoved")?;
    let (name, mode) = (unit.to_owned(), "replace".to_owned());
    let queued = match job {
        Job::Start => manager.start_unit(name, mode).await,
        Job::Stop => manager.stop_unit(name, mode).await,
        Job::Restart => manager.restart_unit(name, mode).await,
        Job::Reload => manager.reload_unit(name, mode).await,
    }
    .context(format!("{verb} of {unit} failed to queue"))?;

    let timeout = timeout.unwrap_or(DEFAULT_JOB_TIMEOUT);
    let result = tokio::time::timeout(timeout, job_result(&mut jobs, &queued))
        .await
        .map_err(|_| {
            crate::anyhow!(
                "timed out after {timeout:?} waiting for the {verb} job on `{unit}` \
                 to finish (check `journalctl -u {unit}`)"
            )
        })??;
    match result.as_str() {
        "done" | "skipped" => {}
        other => crate::bail!(
            "the {verb} job on `{unit}` finished as {other:?} — check `journalctl -u {unit}`"
        ),
    }
    // A restart or reload leaves the state unchanged, so the diff shows
    // nothing: say it happened.
    if matches!(job, Job::Restart | Job::Reload) {
        let _ = crate::diff::note(&mut std::io::stderr().lock(), &format!("~ {unit} {verb}"));
    }
    Ok(())
}

async fn job_result(
    jobs: &mut JobRemovedStream,
    job: &zbus_systemd::zvariant::OwnedObjectPath,
) -> crate::Result<String> {
    use zbus_systemd::zbus::export::futures_core::Stream as _;
    loop {
        let signal = std::future::poll_fn(|cx| std::pin::Pin::new(&mut *jobs).poll_next(cx))
            .await
            .context("JobRemoved signal stream ended unexpectedly")?;
        let args = signal.args().context("Couldn't parse JobRemoved args")?;
        if args.job() == job {
            return Ok(args.result().clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use UnitState as S;

    #[test]
    fn unit_file_states_parse() {
        let cases = [
            ("enabled", S::Enabled),
            ("enabled-runtime", S::EnabledRuntime),
            ("linked", S::Linked),
            ("linked-runtime", S::LinkedRuntime),
            ("alias", S::Alias),
            ("masked", S::Masked),
            ("masked-runtime", S::MaskedRuntime),
            ("static", S::Static),
            ("disabled", S::Disabled),
            ("generated", S::Generated),
            ("transient", S::Transient),
            ("indirect", S::Indirect),
            ("bad", S::Bad),
            ("", S::Bad),
        ];
        for (s, want) in cases {
            assert_eq!(s.parse::<UnitState>().unwrap(), want, "{s:?}");
        }
        assert!("nope".parse::<UnitState>().is_err());
    }

    #[test]
    fn enabling_acts_on_everything_not_persistently_enabled() {
        assert_eq!(plan(Enablement::Enabled, Some(S::Enabled)), Ok(None));
        for s in [
            S::EnabledRuntime,
            S::Disabled,
            S::Indirect,
            S::Linked,
            S::LinkedRuntime,
            S::Alias,
        ] {
            assert_eq!(
                plan(Enablement::Enabled, Some(s)),
                Ok(Some(Step::Enable)),
                "{s:?}"
            );
        }
        assert_eq!(plan(Enablement::Enabled, None), Ok(Some(Step::Enable)));
    }

    #[test]
    fn disabling_removes_persistent_and_runtime_links() {
        for (s, runtime) in [
            (S::Enabled, false),
            (S::Linked, false),
            (S::Alias, false),
            (S::EnabledRuntime, true),
            (S::LinkedRuntime, true),
        ] {
            assert_eq!(
                plan(Enablement::Disabled, Some(s)),
                Ok(Some(Step::Disable { runtime })),
                "{s:?}"
            );
        }
        for s in [Some(S::Disabled), Some(S::Indirect), None] {
            assert_eq!(plan(Enablement::Disabled, s), Ok(None), "{s:?}");
        }
    }

    #[test]
    fn a_mask_is_lifted_with_its_own_runtime_flag_before_anything_else() {
        for want in [Enablement::Enabled, Enablement::Disabled] {
            assert_eq!(
                plan(want, Some(S::Masked)),
                Ok(Some(Step::Unmask { runtime: false }))
            );
            assert_eq!(
                plan(want, Some(S::MaskedRuntime)),
                Ok(Some(Step::Unmask { runtime: true }))
            );
        }
    }

    #[test]
    fn only_a_persistent_mask_satisfies_masked() {
        assert_eq!(plan(Enablement::Masked, Some(S::Masked)), Ok(None));
        for s in [
            Some(S::MaskedRuntime),
            Some(S::Enabled),
            Some(S::Static),
            None,
        ] {
            assert_eq!(plan(Enablement::Masked, s), Ok(Some(Step::Mask)), "{s:?}");
        }
    }

    #[test]
    fn install_less_and_bad_units_are_refused_with_the_way_out() {
        for s in [S::Static, S::Generated, S::Transient] {
            let enable = plan(Enablement::Enabled, Some(s)).unwrap_err();
            assert!(
                enable.contains("enable") && enable.contains("just start it"),
                "{enable}"
            );
            let disable = plan(Enablement::Disabled, Some(s)).unwrap_err();
            assert!(
                disable.contains("disable") && disable.contains("mask it"),
                "{disable}"
            );
            assert!(!disable.contains("just start it"), "{disable}");
        }
        let bad = plan(Enablement::Enabled, Some(S::Bad)).unwrap_err();
        assert!(bad.contains("`bad`"), "{bad}");
    }

    #[test]
    fn runtime_jobs_only_where_the_state_differs_or_the_action_is_unconditional() {
        assert_eq!(runtime_job(RuntimeAction::Started, false), Some(Job::Start));
        assert_eq!(runtime_job(RuntimeAction::Started, true), None);
        assert_eq!(runtime_job(RuntimeAction::Stopped, true), Some(Job::Stop));
        assert_eq!(runtime_job(RuntimeAction::Stopped, false), None);
        for running in [false, true] {
            assert_eq!(
                runtime_job(RuntimeAction::Restarted, running),
                Some(Job::Restart)
            );
            assert_eq!(
                runtime_job(RuntimeAction::Reloaded, running),
                Some(Job::Reload)
            );
        }
    }
}
