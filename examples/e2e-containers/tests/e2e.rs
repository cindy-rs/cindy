//! Container e2e harness: drives the same orchestrator/worker pipe
//! pair as `examples/e2e-localhost`, except the worker runs **inside**
//! a Debian-systemd container — which is what puts the mutating
//! builtins (systemd, apt, user, group) in front of a real system.
//!
//! These tests are **required, not optional**: an unusable harness
//! fails the suite, naming what's missing. A silently-skipped container
//! test is indistinguishable from a passing one in default `cargo test`
//! output (libtest captures the reason), so a broken harness — image
//! gone, socket moved, engine absent — would take the whole of this
//! coverage with it and still read as green. Set
//! `CINDY_E2E_CONTAINERS=skip` to opt out deliberately, on a machine
//! where that's the right trade.
//!
//! Everything goes through the testcontainers crate — building the
//! image, starting the container, copying the worker in, staging it per
//! play — with exactly **one** exception: running the worker itself.
//! The RPC channel needs a bidirectional pipe, and testcontainers
//! 0.28's `exec` surfaces stdout/stderr only (`ExecResult` has no stdin
//! writer; see `core/client.rs`: "We only interested in stdout and
//! stderr"). So the worker is spawned with a CLI `exec -i`, which is
//! also the closest analogue to the SSH child `cindy play` really uses.
//!
//! That one CLI call is engine-agnostic, and the CLI is *derived from
//! the engine socket* rather than probed separately — see
//! [`negotiate`], which exists because picking them independently
//! pairs a podman CLI with a Docker daemon on any machine that has
//! both. `CINDY_E2E_CONTAINER_CLI` forces the choice;
//! `CINDY_E2E_SYSTEMD_IMAGE` names a prebuilt image instead of
//! building, which is how CI skips a build in the test job.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use testcontainers::{
    ContainerAsync, GenericBuildableImage, GenericImage, ImageExt as _,
    core::{ExecCommand, WaitFor, wait::HealthWaitStrategy},
    runners::{AsyncBuilder as _, AsyncRunner as _},
};

/// Locally-built image name (see `Containerfile.systemd` in this
/// crate), without a registry prefix.
const IMAGE_NAME: &str = "cindy-e2e-systemd";
const TAG: &str = "latest";

/// Pristine worker binary, copied in once per container.
const MASTER_WORKER: &str = "/worker/e2e-worker.orig";
/// Per-play copy, consumed by the worker unlinking itself.
const STAGED_WORKER: &str = "/worker/e2e-worker";

/// The negotiated CLI, or `None` if no engine was found. See
/// [`negotiate`] — this is just its happy path.
fn container_cli() -> Option<&'static str> {
    negotiate().as_ref().ok().copied()
}

/// Can this CLI be executed at all?
fn cli_runs(cli: &str) -> bool {
    Command::new(cli)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Settle on an engine *and* the CLI that speaks to it, as one
/// decision, returning the CLI.
///
/// One decision on purpose. Choosing them separately lets them
/// disagree, and the failure is baffling: a GitHub Actions runner has
/// both CLIs installed and Docker's socket live, so "prefer podman"
/// picks a CLI that cannot see a container the Docker engine created,
/// and `exec` fails with "no such container" while the container is
/// plainly running. Deriving the CLI from the socket makes that
/// unrepresentable.
///
/// Order:
///
/// 1. `CINDY_E2E_CONTAINER_CLI` wins, and `DOCKER_HOST` (or bollard's
///    default) is trusted to match it — if you name the CLI, you own
///    the pairing.
/// 2. An explicit `DOCKER_HOST` decides: a path mentioning podman is
///    podman's, anything else (including `tcp://`) is treated as
///    Docker-compatible.
/// 3. A rootless podman socket at `$XDG_RUNTIME_DIR/podman/podman.sock`
///    ⇒ podman, with `DOCKER_HOST` pointed at it (bollard defaults to
///    Docker's path and would otherwise miss it).
/// 4. `/var/run/docker.sock` ⇒ docker, `DOCKER_HOST` left unset because
///    that is already where bollard looks. This is the GitHub Actions
///    case: the runner is a VM with a real Docker daemon, no dind
///    needed.
fn negotiate() -> &'static Result<&'static str, String> {
    static NEGOTIATED: OnceLock<Result<&'static str, String>> = OnceLock::new();
    NEGOTIATED.get_or_init(|| {
        // Safety: `DOCKER_HOST` is only set here, inside this
        // `OnceLock`, before any container exists — every test calls
        // this through `harness_ready` first, and the lock serialises
        // them — so no thread is mid-read of the environment.
        let adopt = |socket: &Path| unsafe {
            std::env::set_var("DOCKER_HOST", format!("unix://{}", socket.display()));
        };

        let cli = match std::env::var("CINDY_E2E_CONTAINER_CLI").as_deref() {
            Ok("podman") => "podman",
            Ok("docker") => "docker",
            Ok(other) => {
                return Err(format!(
                    "CINDY_E2E_CONTAINER_CLI={other:?} is not a CLI I know; \
                     use `podman` or `docker`"
                ));
            }
            Err(_) => {
                let podman_socket = std::env::var_os("XDG_RUNTIME_DIR")
                    .map(|rt| PathBuf::from(rt).join("podman/podman.sock"))
                    .filter(|s| s.exists());
                let docker_socket = Path::new("/var/run/docker.sock");
                match std::env::var("DOCKER_HOST") {
                    Ok(host) if host.contains("podman") => "podman",
                    Ok(_) => "docker",
                    Err(_) => match podman_socket {
                        Some(socket) => {
                            adopt(&socket);
                            "podman"
                        }
                        None if docker_socket.exists() => "docker",
                        None => {
                            return Err("no container engine: DOCKER_HOST unset, no podman \
                                 socket at $XDG_RUNTIME_DIR/podman/podman.sock, and no \
                                 /var/run/docker.sock"
                                .to_owned());
                        }
                    },
                }
            }
        };

        if !cli_runs(cli) {
            return Err(format!(
                "the `{cli}` CLI is needed for the worker's `exec -i` (the one thing \
                 testcontainers can't do) but didn't run"
            ));
        }
        Ok(cli)
    })
}

/// The image to run, built once for the suite if it isn't supplied.
///
/// `CINDY_E2E_SYSTEMD_IMAGE` takes precedence and is assumed present or
/// pullable — that's how CI supplies a prebuilt image without a build
/// in the test job. Otherwise `Containerfile.systemd` is built through
/// the crate, which sidesteps the engine-specific flags a `podman
/// build` / `docker build` shell-out would have needed to reconcile.
async fn image() -> GenericImage {
    static IMAGE: tokio::sync::OnceCell<(String, String)> = tokio::sync::OnceCell::const_new();
    let (name, tag) = IMAGE
        .get_or_init(|| async {
            // CI supplies a prebuilt reference; use it as-is and let
            // the container start report the truth if it's wrong.
            if let Ok(explicit) = std::env::var("CINDY_E2E_SYSTEMD_IMAGE") {
                let (name, tag) = explicit
                    .rsplit_once(':')
                    .map(|(n, t)| (n.to_owned(), t.to_owned()))
                    .unwrap_or((explicit.clone(), "latest".to_owned()));
                return (name, tag);
            }
            // Built through the crate, so no `podman build` shell-out
            // and no engine-specific flags. Built once for the suite:
            // `build_image` is idempotent but not free.
            // The built `GenericImage` is dropped rather than returned:
            // each container start needs its own (it's consumed by
            // `start`), and it carries no state beyond the
            // `IMAGE_NAME:TAG` descriptor this memoises. What's cached
            // here is "the build has happened".
            drop(
                GenericBuildableImage::new(IMAGE_NAME, TAG)
                    .with_dockerfile(
                        Path::new(env!("CARGO_MANIFEST_DIR")).join("Containerfile.systemd"),
                    )
                    .build_image()
                    .await
                    .expect(
                        "building the systemd image failed (needs network on first run); \
                         see Containerfile.systemd, or point CINDY_E2E_SYSTEMD_IMAGE at a \
                         prebuilt one",
                    ),
            );
            (IMAGE_NAME.to_owned(), TAG.to_owned())
        })
        .await
        .clone();
    GenericImage::new(name, tag)
}

/// The resolved CLI, for the worker's `exec -i` — the one thing the
/// crate can't do. Panics if called before [`harness_ready`] vouched
/// for it; every caller is downstream of `setup`.
fn cli() -> &'static str {
    container_cli().expect("harness_ready() established a usable CLI")
}

/// Is the suite able to run? `Err(reason)` fails every test with that
/// reason (or skips, under `CINDY_E2E_CONTAINERS=skip`). All the work
/// is in [`negotiate`]; this is the name the tests read it by.
fn harness_ready() -> Result<(), String> {
    negotiate().clone().map(|_| ())
}

/// Build the example with one feature set and return the binary path.
/// Same dedicated-target-dir trick as the localhost harness: keeps
/// this nested `cargo build` from contending on the outer invocation's
/// build lock.
fn build_variant(feature: &str) -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let target_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target-e2e")
        .join(feature);

    let output = Command::new(env!("CARGO"))
        .args([
            "build",
            "--message-format=json-render-diagnostics",
            "--manifest-path",
        ])
        .arg(&manifest)
        .args([
            "--no-default-features",
            "--features",
            feature,
            "--target-dir",
        ])
        .arg(&target_dir)
        .stderr(Stdio::inherit())
        .output()
        .expect("failed to spawn cargo build");

    assert!(
        output.status.success(),
        "cargo build --features {feature} failed"
    );

    let stdout = String::from_utf8(output.stdout).expect("cargo output not utf-8");
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|j| j["executable"].as_str().map(PathBuf::from))
        .next_back()
        .unwrap_or_else(|| panic!("no executable in cargo output for feature {feature}"))
}

/// A Debian-systemd container with the worker binary staged inside at
/// `/worker/e2e-worker`. The image's HEALTHCHECK (see
/// `Containerfile.systemd`) is the readiness gate — `degraded` counts
/// as up, which is normal in containers.
struct SystemdHost {
    /// Held for its `Drop`: removing the container when the test is
    /// done. Nothing reads it after `start`.
    _container: ContainerAsync<GenericImage>,
    id: String,
}

impl SystemdHost {
    /// Start a container from the systemd image, with the worker binary
    /// already copied in as a pristine master at
    /// `/worker/e2e-worker.orig`.
    ///
    /// The copy happens through testcontainers' `with_copy_to` at
    /// create time rather than a `cp` afterwards — one fewer thing
    /// outside the crate, and it can't race the container's startup.
    async fn start(worker_bin: &Path) -> Self {
        let request = image()
            .await
            .with_wait_for(WaitFor::Healthcheck(
                HealthWaitStrategy::new().with_poll_interval(Duration::from_millis(200)),
            ))
            .with_copy_to(MASTER_WORKER, worker_bin.to_path_buf());
        let container = request
            .start()
            .await
            .expect("failed to start the systemd container");
        let id = container.id().to_owned();
        Self {
            _container: container,
            id,
        }
    }

    /// Stage the worker binary for one play, from the master copy.
    ///
    /// Per play, not per container: the worker unlinks its own
    /// executable on startup — agent-less is load-bearing — so each
    /// play consumes the staged copy and the next needs a fresh one.
    /// This is the dance `cindy play` performs per host, minus SSH.
    ///
    /// `install -m 755` does the copy and the mode in one step, run
    /// through testcontainers' `exec` (no stdin needed here, so the
    /// crate is enough).
    async fn stage_worker(&self) {
        let result = self
            ._container
            .exec(ExecCommand::new([
                "install",
                "-m",
                "755",
                MASTER_WORKER,
                STAGED_WORKER,
            ]))
            .await
            .expect("exec `install` to stage the worker");
        let code = result
            .exit_code()
            .await
            .expect("staging exec exit code")
            .unwrap_or(0);
        assert_eq!(code, 0, "staging the worker binary failed in-container");
    }

    /// The worker runs *inside* the container: `podman exec -i` with
    /// piped stdio is the same child shape the localhost harness
    /// spawns, minus SSH. The worker unlinks its own binary on startup
    /// — inside the container's writable layer, exactly as on a real
    /// host (agent-less is load-bearing).
    fn exec_worker(&self) -> Command {
        let mut cmd = Command::new(cli());
        cmd.args(["exec", "-i"]).arg(&self.id).arg(STAGED_WORKER);
        cmd
    }
}

/// A wired-up orchestrator/worker pair, plumbed exactly the way
/// `cindy play` does it — with the worker half being the
/// `podman exec` child.
struct Play {
    orchestrator: std::process::Child,
    worker: std::process::Child,
    pumps: Vec<std::thread::JoinHandle<()>>,
    /// Kept alive deliberately: the orchestrator reads the host context
    /// from this path at startup, so unlinking it early is a race.
    _context_file: tempfile::NamedTempFile,
}

async fn start_play(
    host: &SystemdHost,
    host_context: &serde_json::Value,
    orchestrator_env: &[(&str, &str)],
) -> Play {
    let orchestrator_bin = build_variant("orchestrator");
    host.stage_worker().await;

    let mut worker_cmd = host.exec_worker();
    worker_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut worker = worker_cmd
        .spawn()
        .expect("spawn container worker (podman exec)");

    let context_file = tempfile::NamedTempFile::new().expect("create context file");
    std::fs::write(context_file.path(), host_context.to_string()).expect("write host context");

    let mut orch_cmd = Command::new(&orchestrator_bin);
    orch_cmd
        .env("CINDY_HOST_CONTEXT_FILE", context_file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for (k, v) in orchestrator_env {
        orch_cmd.env(k, v);
    }
    let mut orchestrator = orch_cmd.spawn().expect("spawn orchestrator");

    let mut o_out = orchestrator.stdout.take().unwrap();
    let mut r_in = worker.stdin.take().unwrap();
    let mut r_out = worker.stdout.take().unwrap();
    let mut o_in = orchestrator.stdin.take().unwrap();

    let pumps = vec![
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut o_out, &mut r_in);
            // Closing the worker's stdin signals end-of-requests so its
            // RPC read loop terminates.
            drop(r_in);
        }),
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut r_out, &mut o_in);
            drop(o_in);
        }),
    ];

    Play {
        orchestrator,
        worker,
        pumps,
        _context_file: context_file,
    }
}

impl Play {
    /// Wait for the orchestrator — it drives the play and holds the
    /// authoritative exit code — then let the worker EOF out.
    fn wait(mut self) -> std::process::ExitStatus {
        let status = self.orchestrator.wait().expect("wait orchestrator");
        for pump in std::mem::take(&mut self.pumps) {
            let _ = pump.join();
        }
        let _ = self.worker.wait();
        status
    }
}

fn host_context() -> serde_json::Value {
    serde_json::json!({
        "name": "cindy-e2e-container",
        "tags": ["example:e2e"],
        "vars": {},
    })
}

/// Shared test prelude: skip (with the reason) or build both halves
/// and start a fresh container. One container per test — isolation is
/// worth the seconds, and scenarios within a test share their
/// container on purpose.
async fn setup() -> Option<(tempfile::TempDir, SystemdHost)> {
    if let Err(reason) = harness_ready() {
        // Fail by default. Skipping silently would make this coverage
        // evaporate without a signal: libtest captures the reason, so
        // in normal output a skipped test and a real one both read
        // `ok`, and the only tell is a 0.00s duration nobody reads.
        assert_eq!(
            std::env::var("CINDY_E2E_CONTAINERS").as_deref(),
            Ok("skip"),
            "container e2e harness unusable: {reason}\n\
             These tests are required. Provide a container engine, or set \
             CINDY_E2E_CONTAINERS=skip to opt out deliberately."
        );
        eprintln!("skipping container e2e (CINDY_E2E_CONTAINERS=skip): {reason}");
        return None;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let worker = build_variant("remote");
    let host = SystemdHost::start(&worker).await;
    Some((tmp, host))
}

/// `systemd`, `apt`, `user` and `group` finally meet a real system:
/// enable/start a fresh unit, converge, stop/disable, mask — the
/// lifecycle a VyOS play actually drives.
#[tokio::test]
async fn systemd_manages_a_unit_lifecycle() {
    let Some((tmp, host)) = setup().await else {
        return;
    };
    let status = start_play(&host, &host_context(), &[("CINDY_E2E_SYSTEMD", "1")])
        .await
        .wait();
    assert!(
        status.success(),
        "systemd lifecycle play failed: {status:?} — see the output above"
    );
    drop(tmp);
}

/// The f576ecc regression, pinned end to end: under `CINDY_DRY_RUN=1`
/// (what `cindy play --check` sets), `disable` on a **masked** unit
/// must report the would-change without unmasking. The unit-test
/// matrix over `disable_would_change` can't catch a missed guard; a
/// real systemd can — this is the exact arm where the bug shipped.
#[tokio::test]
async fn systemd_check_mode_never_unmasks() {
    let Some((tmp, host)) = setup().await else {
        return;
    };

    // Setup: mask a /usr/lib-backed unit (its file survives the mask —
    // an admin-authored one is deleted to complete the mask, by
    // design, leaving nothing to unmask).
    let status = start_play(&host, &host_context(), &[("CINDY_E2E_SYSTEMD_MASK", "1")])
        .await
        .wait();
    assert!(status.success(), "mask run failed: {status:?}");

    // Check mode: report, don't touch. The playbook itself asserts the
    // mask survived via read-only probes; a failure here means a
    // mutation leaked through check mode.
    let status = start_play(
        &host,
        &host_context(),
        &[("CINDY_E2E_SYSTEMD_CHECK", "1"), ("CINDY_DRY_RUN", "1")],
    )
    .await
    .wait();
    assert!(
        status.success(),
        "check-mode run failed: {status:?} — either disable under-reported \
         or it mutated the masked unit"
    );

    // For real: the same request now unmasks.
    let status = start_play(&host, &host_context(), &[("CINDY_E2E_SYSTEMD_UNMASK", "1")])
        .await
        .wait();
    assert!(status.success(), "unmask run failed: {status:?}");
    drop(tmp);
}

/// `user` and `group` against real shadow-utils: create, converge,
/// reconcile pinned attributes, supplementary groups, the shadow-utils
/// create race (eight concurrent identical creates must converge to
/// exactly one account), and absence.
#[tokio::test]
async fn users_and_groups_reconcile_on_a_real_system() {
    let Some((tmp, host)) = setup().await else {
        return;
    };
    let status = start_play(&host, &host_context(), &[("CINDY_E2E_USERS", "1")])
        .await
        .wait();
    assert!(
        status.success(),
        "user/group play failed: {status:?} — see the output above"
    );
    drop(tmp);
}

/// `apt` against the image's baked-in `file://` repo: install, converge,
/// no-op on an already-installed package (no upgrade chase), remove.
/// No test-time network — the repo is a build-time artifact.
#[tokio::test]
async fn apt_installs_converges_and_removes() {
    let Some((tmp, host)) = setup().await else {
        return;
    };
    let status = start_play(&host, &host_context(), &[("CINDY_E2E_APT", "1")])
        .await
        .wait();
    assert!(
        status.success(),
        "apt play failed: {status:?} — see the output above"
    );
    drop(tmp);
}
