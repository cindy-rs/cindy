use std::str::FromStr;

use zbus_systemd::systemd1::{JobRemovedStream, ManagerProxy, UnitProxy};
use zbus_systemd::zbus;

use crate::Context;

/// Desired **active** (runtime) state of a unit — independent of whether it's
/// enabled at boot. `None` on [`State::runtime`] means "leave the running
/// state alone".
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[crate::wire]
pub enum RuntimeAction {
    Started,
    Stopped,
    Restarted,
    Reloaded,
}

/// Desired **boot** (enablement) state of a unit — independent of whether it's
/// currently running. `None` on [`State::enablement`] means "leave the
/// enablement alone".
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
    /// Unit name. Bare names (`"nginx"`) get `.service` appended; anything
    /// containing a `.` is passed through unchanged (so `"foo.timer"`,
    /// `"multi-user.target"`, `"docker.socket"` etc. work as-is).
    pub name: String,
    /// Desired boot/enablement state. `None` = don't touch enablement.
    /// The two axes are *mostly* independent — you can enable without
    /// starting, or restart without changing enablement — with one
    /// exception: a masked unit cannot run, so `Some(Enablement::Masked)`
    /// together with a `Some(..)` [`runtime`](Self::runtime) is a
    /// contradiction that [`apply`] rejects. (None of the intent-named
    /// verbs can produce it.)
    pub enablement: Option<Enablement>,
    /// Desired runtime/active state. `None` = don't touch the running state.
    pub runtime: Option<RuntimeAction>,
    /// How long to wait for a queued start/stop/restart/reload job to
    /// finish before declaring it stuck. `None` ⇒ 90s (systemd's own
    /// per-unit job default). Raise it for units that legitimately take
    /// minutes to settle — a database after crash recovery, a heavy
    /// `ExecStartPre` chain.
    pub job_timeout: Option<std::time::Duration>,
}

/// Default `Diff` impl renders `State` via `{:#?}` + a unified line diff.
/// No binary payloads here, so no custom rendering is needed.
impl crate::Diff for State {}

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
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
            other => return Err(format!("unknown UnitFileState: {other:?}")),
        })
    }
}

impl UnitState {
    fn is_masked(self) -> bool {
        matches!(self, Self::Masked | Self::MaskedRuntime)
    }

    /// `true` when calling `EnableUnitFiles` would actually do something.
    /// `Indirect` counts: enabling an indirect unit creates the links its
    /// `Also=`/template default names, exactly like `systemctl enable`.
    /// `Linked`/`Alias` count too — `systemctl enable` acts on those, so we
    /// must as well instead of reporting a lying no-op.
    fn needs_enable_call(self) -> bool {
        matches!(
            self,
            Self::Disabled | Self::Indirect | Self::Linked | Self::LinkedRuntime | Self::Alias
        )
    }

    /// Unit-file states that have no `[Install]` section to en/disable:
    /// requesting `Enabled`/`Disabled` for them is a misunderstanding we
    /// answer with an error, not a silent no-op behind a lying diff.
    fn is_uninstallable(self) -> bool {
        matches!(self, Self::Static | Self::Generated | Self::Transient)
    }

    /// `true` when calling `DisableUnitFiles` would actively tear down links.
    fn needs_disable_call(self) -> bool {
        matches!(
            self,
            Self::Enabled | Self::EnabledRuntime | Self::Linked | Self::LinkedRuntime | Self::Alias
        )
    }
}

/// Check mode's prediction for the `Disabled` arm, decided purely from
/// the observed file state: unmasking a masked unit is a change on its
/// own, and whether a disable would follow is unknowable without
/// performing the unmask (the post-unmask state is only readable after
/// mutating) — so it folds into the same report. Check mode
/// over-reports rather than under-reports.
fn disable_would_change(observed: Option<UnitState>) -> bool {
    observed.is_some_and(|s| s.is_masked() || s.needs_disable_call())
}

/// Mirror of systemd's `ActiveState` unit property.
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
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "active" => Self::Active,
            "reloading" => Self::Reloading,
            "inactive" => Self::Inactive,
            "failed" => Self::Failed,
            "activating" => Self::Activating,
            "deactivating" => Self::Deactivating,
            other => return Err(format!("unknown ActiveState: {other:?}")),
        })
    }
}

impl ActiveState {
    /// `true` if the unit is running or actively transitioning to running.
    /// Matches Ansible's "started" predicate.
    fn is_running(self) -> bool {
        matches!(self, Self::Active | Self::Reloading | Self::Activating)
    }
}

fn is_no_such_unit(err: &zbus::Error) -> bool {
    if let zbus::Error::MethodError(name, _, _) = err {
        let n = name.to_string();
        n.ends_with(".NoSuchUnit") || n.ends_with(".NoSuchUnitFile") || n.ends_with(".LoadFailed")
    } else {
        false
    }
}

async fn read_file_state(
    manager: &ManagerProxy<'_>,
    name: &str,
) -> crate::Result<Option<UnitState>> {
    match manager.get_unit_file_state(name.to_owned()).await {
        Ok(s) => {
            let parsed = s
                .parse::<UnitState>()
                .map_err(anyhow_serde::Error::msg)
                .context("Parsing UnitFileState")?;
            Ok(Some(parsed))
        }
        Err(e) if is_no_such_unit(&e) => Ok(None),
        Err(e) => Err(e).context(format!("GetUnitFileState({name}) failed")),
    }
}

/// Best-effort restore of a mask lifted moments ago, so a rejected
/// reconcile leaves the host as it found it.
async fn rollback_mask(
    manager: &ManagerProxy<'_>,
    unit_files: &[String],
    initial_unit_state: Option<UnitState>,
) {
    // Check mode never masked/unmasked anything to roll back; doing it
    // here would be the run's first mutation.
    if crate::dry_run() {
        return;
    }
    if initial_unit_state.is_some_and(UnitState::is_masked) {
        let runtime = matches!(initial_unit_state, Some(UnitState::MaskedRuntime));
        let _ = manager
            .mask_unit_files(unit_files.to_vec(), runtime, true)
            .await;
    }
}

/// Worker-global system-bus connection. A play touching N units used to
/// open N connections to the bus (one per builtin call — and intent
/// verbs like [`start`] call `apply` per unit); pooling keeps the bus's
/// per-connection setup out of fan-outs. The system bus can't change
/// within one worker process. Init failures are cached as strings and
/// re-raised per call, so a host with no bus at all still fails every
/// call with the real error.
static SYSTEM_BUS: tokio::sync::OnceCell<Result<zbus::Connection, String>> =
    tokio::sync::OnceCell::const_new();

async fn system_bus() -> crate::Result<&'static zbus::Connection> {
    SYSTEM_BUS
        .get_or_init(|| async { zbus::Connection::system().await.map_err(|e| e.to_string()) })
        .await
        .as_ref()
        .map_err(|e| anyhow_serde::Error::msg(e.clone()))
}

async fn read_active_state(
    manager: &ManagerProxy<'_>,
    conn: &zbus::Connection,
    name: &str,
) -> crate::Result<Option<ActiveState>> {
    // GetUnit is the non-mutating lookup: it resolves the unit's object
    // path without loading it. LoadUnit *queues a load job* — a
    // mutation smuggled into a read path (it can transiently load a
    // unit just by being observed, and load a unit the admin
    // deliberately never loads). Some units legitimately have no object
    // until loaded (a disabled static unit on a fresh boot), so fall
    // back to LoadUnit only when GetUnit can't resolve one. systemd
    // signals that both as a NoSuchUnit error and as the manager's
    // root path ("/"), depending on version.
    let path = match manager.get_unit(name.to_owned()).await {
        Ok(p) if p.as_str() != "/" => p,
        _ => match manager.load_unit(name.to_owned()).await {
            Ok(p) => p,
            Err(e) if is_no_such_unit(&e) => return Ok(None),
            Err(e) => return Err(e).context(format!("LoadUnit({name}) failed")),
        },
    };

    let unit = UnitProxy::builder(conn)
        .path(path)
        .context("Invalid unit object path")?
        .build()
        .await
        .context("Couldn't construct Unit proxy")?;

    let raw = unit
        .active_state()
        .await
        .context("Reading ActiveState failed")?;

    let parsed = raw
        .parse::<ActiveState>()
        .map_err(anyhow_serde::Error::msg)
        .context("Parsing ActiveState")?;
    Ok(Some(parsed))
}

/// How long to wait for a queued start/stop/restart/reload job to
/// finish before declaring it stuck, when the request doesn't say.
/// systemd's own default per-unit job timeout is 90s; match it.
const DEFAULT_JOB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// Wait for `job` to complete and check how it went.
///
/// `StartUnit` & friends only *queue* a job — returning at that point
/// would report success for a service that then crashes on startup.
/// systemd announces every job's fate via the `JobRemoved` signal
/// (`done`, `failed`, `timeout`, `dependency`, …), so we await ours and
/// accept only `done` — the same contract `systemctl start` gives you.
/// The stream must have been subscribed *before* the job was queued, or
/// the signal can be lost to a race.
async fn wait_job(
    jobs: &mut JobRemovedStream,
    job: &zbus_systemd::zvariant::OwnedObjectPath,
    unit: &str,
    verb: &str,
    timeout: std::time::Duration,
) -> crate::Result<()> {
    use zbus_systemd::zbus::export::futures_core::Stream as _;

    let removal = async {
        loop {
            let signal = std::future::poll_fn(|cx| std::pin::Pin::new(&mut *jobs).poll_next(cx))
                .await
                .context("JobRemoved signal stream ended unexpectedly")?;
            let args = signal.args().context("Couldn't parse JobRemoved args")?;
            if args.job() == job {
                return Ok::<String, anyhow_serde::Error>(args.result().clone());
            }
        }
    };

    let result = tokio::time::timeout(timeout, removal).await.map_err(|_| {
        anyhow_serde::Error::msg(format!(
            "timed out after {timeout:?} waiting for the {verb} job on `{unit}` \
                 to finish (check `journalctl -u {unit}`)"
        ))
    })??;

    match result.as_str() {
        "done" | "skipped" => Ok(()),
        other => crate::bail!(
            "the {verb} job on `{unit}` finished as {other:?} — check `journalctl -u {unit}`"
        ),
    }
}

/// Run a systemd `daemon-reload` on the remote, making systemd re-read
/// unit files from disk.
///
/// Call this after you've written or removed a unit file yourself
/// (typically with the [`path`](super::path) builtin) and before you
/// drive that unit with [`systemd`]. The [`systemd`] module no longer
/// reloads unconditionally, so a freshly-dropped unit won't be visible
/// until something reloads — this is that something:
///
/// ```rust,ignore
/// if path(unit_file_state).await?.changed() {
///     systemd::daemon_reload().await?;
/// }
/// systemd::systemd(State { name: "myapp".into(), enablement: Some(..), ..Default::default() }).await?;
/// ```
#[crate::remote]
pub async fn daemon_reload() -> crate::Result<()> {
    if crate::dry_run() {
        // A reload is a system action, not a read — check mode reports
        // it rather than running it. Deliberate, but never silent.
        eprintln!("check mode: would run daemon-reload");
        return Ok(());
    }
    let conn = system_bus().await?;
    let manager = ManagerProxy::new(conn)
        .await
        .context("Couldn't construct Manager proxy")?;
    manager.reload().await.context("Daemon-reload failed")?;
    Ok(())
}

/// Manage a single systemd unit on the remote machine.
///
/// This is the full-control entry point taking a [`State`], whose two axes —
/// boot ([`State::enablement`]) and runtime ([`State::runtime`]) — are
/// independent. For the common cases, prefer the intent-named helpers below.
#[crate::remote]
pub async fn systemd(state: State) -> crate::Result<super::Return> {
    apply(state).await
}

// Intent-named helpers, each a single `#[crate::action]` fn whose body builds
// a `State` and calls `apply`. The macro generates the concrete `#[remote]`
// wire entry point, the orchestrator shim, and the in-process `::inner`.
//
// The boot and runtime axes are orthogonal: `enable`/`disable`/`mask` touch
// only enablement; `start`/`stop`/`restart`/`reload` touch only the running
// state; and `enable_and_start`/`disable_and_stop` do both for the common
// "make sure it's on and running / off and stopped" case.

// --- boot/enablement only ------------------------------------------------

/// Enable `name` at boot. Does **not** start it now — pair with [`start`], or
/// use [`enable_and_start`]. Orchestrator: `enable(name).await?`.
#[crate::action]
pub async fn enable(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: Some(Enablement::Enabled),
        runtime: None,
        job_timeout: None,
    })
    .await
}

/// Disable `name` at boot. Does **not** stop it now — pair with [`stop`], or
/// use [`disable_and_stop`]. Orchestrator: `disable(name).await?`.
#[crate::action]
pub async fn disable(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: Some(Enablement::Disabled),
        runtime: None,
        job_timeout: None,
    })
    .await
}

/// Mask `name`, preventing any *future* start. Note masking does **not**
/// stop a currently running instance — combine with [`stop`] for that.
/// If a real (non-symlink) unit file is in the way at the mask target,
/// it is removed to complete the mask — loudly, on stderr; note a
/// `<unit>.service.d/` drop-in directory is *not* touched. Orchestrator:
/// `mask(name).await?`.
#[crate::action]
pub async fn mask(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: Some(Enablement::Masked),
        // Masking lives on the enablement axis; `runtime` stays `None`
        // so we never hit the "masked + runtime" guard.
        runtime: None,
        job_timeout: None,
    })
    .await
}

// --- runtime/active only -------------------------------------------------

/// Start `name` now if not already running. Leaves enablement untouched.
/// Orchestrator: `start(name).await?`.
#[crate::action]
pub async fn start(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: None,
        runtime: Some(RuntimeAction::Started),
        job_timeout: None,
    })
    .await
}

/// Stop `name` now if running. Leaves enablement untouched.
/// Orchestrator: `stop(name).await?`.
#[crate::action]
pub async fn stop(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: None,
        runtime: Some(RuntimeAction::Stopped),
        job_timeout: None,
    })
    .await
}

/// Restart `name` now (unconditionally) — the usual "I changed the config,
/// bounce the service" action. Leaves enablement untouched.
/// Orchestrator: `restart(name).await?`.
#[crate::action]
pub async fn restart(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: None,
        runtime: Some(RuntimeAction::Restarted),
        job_timeout: None,
    })
    .await
}

/// Reload `name` now (`systemctl reload`). Leaves enablement untouched.
/// Orchestrator: `reload(name).await?`.
#[crate::action]
pub async fn reload(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: None,
        runtime: Some(RuntimeAction::Reloaded),
        job_timeout: None,
    })
    .await
}

// --- both axes (common shortcuts) ----------------------------------------

/// Enable `name` at boot *and* start it now. Orchestrator:
/// `enable_and_start(name).await?`.
#[crate::action]
pub async fn enable_and_start(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: Some(Enablement::Enabled),
        runtime: Some(RuntimeAction::Started),
        job_timeout: None,
    })
    .await
}

/// Disable `name` at boot *and* stop it now. Orchestrator:
/// `disable_and_stop(name).await?`.
#[crate::action]
pub async fn disable_and_stop(name: impl Into<String>) -> crate::Result<super::Return> {
    apply(State {
        name,
        enablement: Some(Enablement::Disabled),
        runtime: Some(RuntimeAction::Stopped),
        job_timeout: None,
    })
    .await
}

/// Print a one-line note for an *action* that has no state delta to diff.
///
/// `restart`/`reload` leave a running unit running, so the structural
/// `State` diff renders nothing even though work happened. This makes
/// that work visible, on the same stream and in the same style as every
/// other builtin's output.
fn print_action(unit_name: &str, verb: &str) {
    let _ = crate::diff::note(
        &mut std::io::stderr().lock(),
        &format!("~ {unit_name} {verb}"),
    );
}

async fn apply(state: State) -> crate::Result<super::Return> {
    let unit_name = {
        let name = &state.name;
        if name.contains('.') {
            name.to_owned()
        } else {
            format!("{name}.service")
        }
    };

    // A masked unit cannot run, so asking to mask *and* drive a runtime
    // action is a contradiction. None of the intent verbs produce this
    // (`mask` leaves `runtime` `None`); reject a hand-built `State` that does,
    // up front, before touching the system.
    if state.enablement == Some(Enablement::Masked)
        && let Some(runtime) = state.runtime
    {
        crate::bail!(
            "invalid systemd request for `{unit_name}`: a unit can't be masked and have a \
             runtime action ({runtime:?}) at once — a masked unit cannot run. Mask it (which \
             stops it), or pick Enabled/Disabled if you need it running.",
        );
    }

    let conn = system_bus().await?;
    let manager = ManagerProxy::new(conn)
        .await
        .context("Couldn't construct Manager proxy")?;

    // No unconditional daemon-reload here: a reload is itself a system
    // action and isn't free on busy hosts, so doing it on every call
    // would make a no-op invocation report work it didn't honestly need
    // to do. We reload *only* after we write/remove unit files below
    // (where systemd genuinely needs to re-read them). If you've just
    // dropped a new unit file via the `path` builtin, call
    // [`daemon_reload`] yourself first, e.g.
    // `if path(...).await?.changed() { daemon_reload().await?; }`.

    let initial_unit_state = read_file_state(&manager, &unit_name).await?;
    let initial_active_state = read_active_state(&manager, conn, &unit_name).await?;

    // Observe the two axes independently.
    let observed_runtime = if initial_active_state
        .map(ActiveState::is_running)
        .unwrap_or(false)
    {
        RuntimeAction::Started
    } else {
        RuntimeAction::Stopped
    };
    let observed_enablement = initial_unit_state.map(|f| {
        if f.is_masked() {
            Enablement::Masked
        } else if matches!(f, UnitState::Enabled | UnitState::EnabledRuntime) {
            Enablement::Enabled
        } else {
            Enablement::Disabled
        }
    });
    // For each axis, a `None` request leaves that axis at its observed value
    // in the diff.
    let old_view = State {
        name: state.name.clone(),
        enablement: observed_enablement,
        runtime: Some(observed_runtime),
        job_timeout: None,
    };
    let new_view = State {
        name: state.name.clone(),
        enablement: state.enablement.or(observed_enablement),
        // `job_timeout` is a knob, not an observable axis — both views
        // carry `None` so it never shows up in a diff.
        job_timeout: None,
        // `Restarted`/`Reloaded` are unconditional actions, not a steady
        // state — they always leave the unit running, so the *post* state is
        // `Started` for diff purposes.
        runtime: Some(match state.runtime {
            None => observed_runtime,
            Some(RuntimeAction::Stopped) => RuntimeAction::Stopped,
            Some(RuntimeAction::Started | RuntimeAction::Restarted | RuntimeAction::Reloaded) => {
                RuntimeAction::Started
            }
        }),
    };
    if old_view != new_view {
        let _ = <State as crate::Diff>::diff(&old_view, &new_view, &mut std::io::stderr().lock());
    }

    // Nothing requested on either axis ⇒ nothing to do.
    if state.enablement.is_none() && state.runtime.is_none() {
        return Ok(super::Return::Unchanged);
    }

    let mut changed = false;
    let unit_files = vec![unit_name.clone()];
    let is_masked = initial_unit_state
        .map(UnitState::is_masked)
        .unwrap_or(false);

    // Track state mutations across dynamic unmask steps cleanly
    let mut current_file_state = initial_unit_state;

    if let Some(wanted_enablement) = state.enablement {
        match wanted_enablement {
            Enablement::Masked => {
                if !is_masked {
                    let unit_path = std::path::Path::new("/etc/systemd/system").join(&unit_name);
                    // The mask is a `/dev/null` symlink at this path. Anything
                    // already there conflicts: a symlink (a previous mask or an
                    // admin link) is replaced safely by `mask_unit_files`, but a
                    // *real* file or directory (an admin-authored unit) has to
                    // be removed first. `mask` is an explicit, unambiguous
                    // request to mask the unit, so we remove whatever is in the
                    // way rather than refusing.
                    let meta = tokio::fs::symlink_metadata(&unit_path).await.ok();
                    if let Some(meta) = meta.as_ref()
                        && !meta.file_type().is_symlink()
                    {
                        // Deliberate, but never silent: an admin-authored
                        // file vanishing with no trace in the run view is
                        // indistinguishable from a bug.
                        let kind = if meta.is_dir() { "directory" } else { "file" };
                        eprintln!(
                            "mask: removing admin-authored {kind} {} to complete the mask",
                            unit_path.display()
                        );
                        if !crate::dry_run() {
                            if meta.is_dir() {
                                tokio::fs::remove_dir_all(&unit_path).await.context(
                                    "Failed to clear conflicting directory at mask target",
                                )?;
                            } else {
                                tokio::fs::remove_file(&unit_path)
                                    .await
                                    .context("Failed to clear conflicting file at mask target")?;
                            }
                        }
                    }

                    if !crate::dry_run() {
                        manager
                            .mask_unit_files(unit_files, false, true) // Force point to /dev/null
                            .await
                            .context(format!("MaskUnitFiles({unit_name}) failed"))?;

                        manager.reload().await.context("Daemon-reload failed")?;
                    }
                    changed = true;
                }
            }
            Enablement::Disabled => {
                if is_masked {
                    if crate::dry_run() {
                        // The pure decision, reported without
                        // mutating: a masked unit would be unmasked,
                        // and whether a disable would follow is only
                        // knowable post-unmask, so it folds in
                        // (over-report beats under-report). The bails
                        // below still fire on the *observed* state,
                        // where masked is neither bad nor
                        // uninstallable.
                        changed = disable_would_change(current_file_state);
                    } else {
                        manager
                            .unmask_unit_files(unit_files.clone(), false)
                            .await
                            .context(format!("UnmaskUnitFiles({unit_name}) failed"))?;
                        changed = true;
                        current_file_state = read_file_state(&manager, &unit_name).await?;
                    }
                }
                if current_file_state == Some(UnitState::Bad) {
                    rollback_mask(&manager, &unit_files, initial_unit_state).await;
                    crate::bail!(
                        "`{unit_name}` is in the `bad` unit-file state (broken symlink or \
                         unreadable unit file); fix or remove it before managing enablement"
                    );
                }
                if current_file_state.is_some_and(UnitState::is_uninstallable) {
                    rollback_mask(&manager, &unit_files, initial_unit_state).await;
                    crate::bail!(
                        "`{unit_name}` is {:?}: it has no [Install] section, so there is \
                         nothing to disable — if you want it unable to run, mask it",
                        current_file_state.unwrap(),
                    );
                }
                if current_file_state
                    .map(UnitState::needs_disable_call)
                    .unwrap_or(false)
                {
                    if !crate::dry_run() {
                        manager
                            .disable_unit_files(unit_files, false)
                            .await
                            .context(format!("DisableUnitFiles({unit_name}) failed"))?;
                    }
                    changed = true;
                }
            }
            Enablement::Enabled => {
                if is_masked {
                    if !crate::dry_run() {
                        manager
                            .unmask_unit_files(unit_files.clone(), false)
                            .await
                            .context(format!("UnmaskUnitFiles({unit_name}) failed"))?;
                        current_file_state = read_file_state(&manager, &unit_name).await?;
                    }
                    changed = true;
                }
                if current_file_state == Some(UnitState::Bad) {
                    rollback_mask(&manager, &unit_files, initial_unit_state).await;
                    crate::bail!(
                        "`{unit_name}` is in the `bad` unit-file state (broken symlink or \
                         unreadable unit file); fix or remove it before managing enablement"
                    );
                }
                if current_file_state.is_some_and(UnitState::is_uninstallable) {
                    rollback_mask(&manager, &unit_files, initial_unit_state).await;
                    crate::bail!(
                        "`{unit_name}` is {:?}: it has no [Install] section, so `enable` \
                         would silently do nothing — static/generated units are always \
                         available; just start it (or write a real unit file)",
                        current_file_state.unwrap(),
                    );
                }
                if current_file_state
                    .map(UnitState::needs_enable_call)
                    .unwrap_or(true)
                {
                    if !crate::dry_run() {
                        manager
                            .enable_unit_files(unit_files, false, true) // Pass force=true to clear stale overrides
                            .await
                            .context(format!("EnableUnitFiles({unit_name}) failed"))?;
                    }
                    changed = true;
                }
            }
        }
    } // end `if let Some(wanted_enablement)`

    if let Some(runtime_action) = state.runtime {
        let active = if changed {
            read_active_state(&manager, conn, &unit_name).await?
        } else {
            initial_active_state
        };
        let is_running = active.map(ActiveState::is_running).unwrap_or(false);

        // Check mode: decide whether a job would be queued without
        // subscribing or driving anything.
        if crate::dry_run() {
            changed |= match runtime_action {
                RuntimeAction::Started => !is_running,
                RuntimeAction::Stopped => is_running,
                // Restart/reload act unconditionally.
                RuntimeAction::Restarted | RuntimeAction::Reloaded => true,
            };
            return Ok(super::Return::from_changed(changed));
        }

        // Subscribe before queueing the job (see `wait_job`).
        let mut jobs = manager
            .receive_job_removed()
            .await
            .context("Couldn't subscribe to JobRemoved")?;

        let job = match runtime_action {
            RuntimeAction::Started if !is_running => Some((
                manager
                    .start_unit(unit_name.clone(), "replace".to_owned())
                    .await
                    .context(format!("StartUnit({unit_name}) failed"))?,
                "start",
            )),
            RuntimeAction::Stopped if is_running => Some((
                manager
                    .stop_unit(unit_name.clone(), "replace".to_owned())
                    .await
                    .context(format!("StopUnit({unit_name}) failed"))?,
                "stop",
            )),
            RuntimeAction::Restarted => Some((
                manager
                    .restart_unit(unit_name.clone(), "replace".to_owned())
                    .await
                    .context(format!("RestartUnit({unit_name}) failed"))?,
                "restart",
            )),
            RuntimeAction::Reloaded => Some((
                manager
                    .reload_unit(unit_name.clone(), "replace".to_owned())
                    .await
                    .context(format!("ReloadUnit({unit_name}) failed"))?,
                "reload",
            )),
            // Already in the requested state; no job to run.
            RuntimeAction::Started | RuntimeAction::Stopped => None,
        };

        if let Some((job, verb)) = job {
            wait_job(
                &mut jobs,
                &job,
                &unit_name,
                verb,
                state.job_timeout.unwrap_or(DEFAULT_JOB_TIMEOUT),
            )
            .await?;
            if matches!(
                runtime_action,
                RuntimeAction::Restarted | RuntimeAction::Reloaded
            ) {
                print_action(&unit_name, verb);
            }
            changed = true;
        }
    }

    Ok(super::Return::from_changed(changed))
}

#[cfg(test)]
mod tests {
    use super::disable_would_change;

    /// The `Disabled` arm's check-mode prediction, from the observed
    /// state — pinned so the dry-run branch can't drift from the pure
    /// decision it's supposed to report.
    #[test]
    fn disable_would_change_covers_masked_and_enabled_family() {
        // A masked unit would be unmasked — a change by itself (the
        // would-disable on top is folded in; see the fn).
        assert!(disable_would_change(Some(UnitState::Masked)));
        assert!(disable_would_change(Some(UnitState::MaskedRuntime)));
        // Anything with links to tear down would be disabled.
        for state in [
            UnitState::Enabled,
            UnitState::EnabledRuntime,
            UnitState::Linked,
            UnitState::LinkedRuntime,
            UnitState::Alias,
        ] {
            assert!(disable_would_change(Some(state)), "{state:?}");
        }
        // Already disabled, static/indirect (no [Install] to disable),
        // bad-but-unmasked is a bail not a change, absent: no change.
        assert!(!disable_would_change(Some(UnitState::Disabled)));
        assert!(!disable_would_change(Some(UnitState::Static)));
        assert!(!disable_would_change(Some(UnitState::Indirect)));
        assert!(!disable_would_change(Some(UnitState::Bad)));
        assert!(!disable_would_change(None));
    }

    use super::*;

    #[test]
    fn unit_file_state_parsing() {
        let cases = [
            ("enabled", UnitState::Enabled),
            ("enabled-runtime", UnitState::EnabledRuntime),
            ("linked", UnitState::Linked),
            ("linked-runtime", UnitState::LinkedRuntime),
            ("alias", UnitState::Alias),
            ("masked", UnitState::Masked),
            ("masked-runtime", UnitState::MaskedRuntime),
            ("static", UnitState::Static),
            ("disabled", UnitState::Disabled),
            ("generated", UnitState::Generated),
            ("transient", UnitState::Transient),
            ("indirect", UnitState::Indirect),
            ("bad", UnitState::Bad),
            ("", UnitState::Bad),
        ];
        for (s, want) in cases {
            assert_eq!(s.parse::<UnitState>().unwrap(), want, "{s:?}");
        }
        assert!("nope".parse::<UnitState>().is_err());
    }

    #[test]
    fn enable_is_attempted_for_every_state_systemctl_would_act_on() {
        for state in [
            UnitState::Disabled,
            UnitState::Indirect,
            UnitState::Linked,
            UnitState::LinkedRuntime,
            UnitState::Alias,
        ] {
            assert!(state.needs_enable_call(), "{state:?}");
        }
        for state in [
            UnitState::Enabled,
            UnitState::EnabledRuntime,
            UnitState::Masked,
            UnitState::MaskedRuntime,
            UnitState::Static,
            UnitState::Generated,
            UnitState::Transient,
            UnitState::Bad,
        ] {
            assert!(!state.needs_enable_call(), "{state:?}");
        }
    }

    #[test]
    fn disable_is_attempted_only_for_linked_states() {
        for state in [
            UnitState::Enabled,
            UnitState::EnabledRuntime,
            UnitState::Linked,
            UnitState::LinkedRuntime,
            UnitState::Alias,
        ] {
            assert!(state.needs_disable_call(), "{state:?}");
        }
        for state in [
            UnitState::Disabled,
            UnitState::Indirect,
            UnitState::Static,
            UnitState::Masked,
            UnitState::Bad,
        ] {
            assert!(!state.needs_disable_call(), "{state:?}");
        }
    }

    #[test]
    fn uninstallable_states_are_exactly_the_install_less_ones() {
        for state in [
            UnitState::Static,
            UnitState::Generated,
            UnitState::Transient,
        ] {
            assert!(state.is_uninstallable(), "{state:?}");
        }
        for state in [
            UnitState::Enabled,
            UnitState::Disabled,
            UnitState::Linked,
            UnitState::Alias,
            UnitState::Masked,
            UnitState::Bad,
        ] {
            assert!(!state.is_uninstallable(), "{state:?}");
        }
    }
}
