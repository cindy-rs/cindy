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
//! **No container CLI is involved**, and so nothing here has to know
//! or care whether the engine is podman or docker: both serve the same
//! Docker API, and everything talks to whatever `DOCKER_HOST` points
//! at.
//!
//! Building the image, starting the container, copying the worker in
//! and staging it per play all go through the testcontainers crate.
//! Running the worker goes one layer below it, to the `bollard` client
//! testcontainers is built on: the RPC channel needs a bidirectional
//! pipe, and testcontainers' own `exec` surfaces stdout/stderr only
//! (`ExecResult` has no stdin writer — see `core/client.rs`, "We only
//! interested in stdout and stderr"), whereas bollard's
//! `StartExecResults::Attached { input, output }` is exactly that pipe.
//! Same socket, same container, one level down.
//!
//! `CINDY_E2E_SYSTEMD_IMAGE` names a prebuilt image instead of
//! building, which is how CI skips a build in the test job.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::{CreateExecOptions, StartExecResults};
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

/// Settle which engine socket bollard will use, so the container and
/// the worker's exec land on the same one.
///
/// There is no container CLI in this harness — bollard's attached exec
/// covers the one thing testcontainers' own `exec` can't — so there is
/// nothing to choose between podman and docker: both serve the same
/// Docker API, and `DOCKER_HOST` is the whole story.
///
/// 1. An explicit `DOCKER_HOST` is trusted as-is.
/// 2. A rootless podman socket at `$XDG_RUNTIME_DIR/podman/podman.sock`
///    is adopted — bollard defaults to Docker's path and would
///    otherwise miss it.
/// 3. `/var/run/docker.sock` needs no action: that is already where
///    bollard looks. This is the GitHub Actions case — the runner is a
///    VM with a real Docker daemon, so no dind and no setup.
fn negotiate() -> &'static Result<(), String> {
    static NEGOTIATED: OnceLock<Result<(), String>> = OnceLock::new();
    NEGOTIATED.get_or_init(|| {
        if std::env::var_os("DOCKER_HOST").is_some() {
            return Ok(());
        }
        let podman_socket = std::env::var_os("XDG_RUNTIME_DIR")
            .map(|rt| PathBuf::from(rt).join("podman/podman.sock"))
            .filter(|s| s.exists());
        if let Some(socket) = podman_socket {
            // Safety: set once, inside this `OnceLock`, before any
            // container exists — every test reaches it through
            // `harness_ready` and the lock serialises them — so no
            // thread is mid-read of the environment.
            unsafe {
                std::env::set_var("DOCKER_HOST", format!("unix://{}", socket.display()));
            }
            return Ok(());
        }
        if Path::new("/var/run/docker.sock").exists() {
            return Ok(());
        }
        Err(
            "no container engine: DOCKER_HOST unset, no podman socket at \
             $XDG_RUNTIME_DIR/podman/podman.sock, and no /var/run/docker.sock"
                .to_owned(),
        )
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

/// Is the suite able to run? `Err(reason)` fails every test with that
/// reason (or skips, under `CINDY_E2E_CONTAINERS=skip`). All the work
/// is in [`negotiate`]; this is the name the tests read it by.
fn harness_ready() -> Result<(), String> {
    negotiate().clone()
}

/// Build the example with one feature set and return the binary path.
///
/// Memoised behind a mutex, and that is load-bearing rather than an
/// optimisation. libtest runs these tests concurrently, so without it
/// several threads invoke `cargo build` for the same feature into the
/// same `--target-dir` at once; one test then copies or execs the
/// output binary while another cargo is still linking it, and the spawn
/// fails with `ETXTBSY` ("Text file busy") or the play dies on a
/// half-written worker. Holding the lock across the build serialises
/// them, and the cache means only the first test pays for it — the
/// binary is identical for every test in the process.
/// Same dedicated-target-dir trick as the localhost harness: keeps
/// this nested `cargo build` from contending on the outer invocation's
/// build lock.
fn build_variant(feature: &str) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> =
        OnceLock::new();
    let mut cache = BUILT
        .get_or_init(Default::default)
        .lock()
        .expect("build cache mutex poisoned");
    if let Some(path) = cache.get(feature) {
        return path.clone();
    }

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
    let path = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|j| j["executable"].as_str().map(PathBuf::from))
        .next_back()
        .unwrap_or_else(|| panic!("no executable in cargo output for feature {feature}"));
    cache.insert(feature.to_owned(), path.clone());
    path
}

/// A Debian-systemd container with the worker binary staged inside at
/// `/worker/e2e-worker`. The image's HEALTHCHECK (see
/// `Containerfile.systemd`) is the readiness gate — `degraded` counts
/// as up, which is normal in containers.
struct SystemdHost {
    /// Held for its `Drop`: removing the container when the test is
    /// done. Also the handle `stage_worker` execs through.
    _container: ContainerAsync<GenericImage>,
    id: String,
    /// The same engine testcontainers is talking to, reached directly
    /// for the one thing the crate can't express: an exec with a
    /// writable stdin.
    docker: Docker,
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
        // `connect_with_defaults` honours DOCKER_HOST, which
        // `negotiate` has already settled — so this lands on the very
        // socket the container was created over.
        let docker = Docker::connect_with_defaults().expect("connect to the container engine");
        Self {
            _container: container,
            id,
            docker,
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

    /// Start the worker inside the container and return the RPC channel
    /// to it: a writer for its stdin and a stream of its output frames.
    ///
    /// This is the piece that used to need a CLI. testcontainers' own
    /// `exec` can't do it — its `ExecResult` exposes stdout/stderr only
    /// — but the bollard client underneath *can*, via
    /// `StartExecResults::Attached { input, output }`, which is exactly
    /// the bidirectional pipe the RPC channel needs. So there is no
    /// container CLI in this harness at all, and nothing to choose
    /// between podman and docker: both serve the same Docker API on the
    /// socket bollard is already connected to.
    ///
    /// `tty: false` is load-bearing twice over. It keeps the output
    /// frame-multiplexed, so stdout (RPC) and stderr (diagnostics) stay
    /// separable; and it keeps the stream raw, where a TTY would
    /// translate newlines and corrupt a postcard/COBS frame.
    ///
    /// The worker unlinks its own binary on startup — inside the
    /// container's writable layer, exactly as on a real host.
    async fn start_worker(&self) -> (WorkerStdin, WorkerOutput) {
        let exec = self
            .docker
            .create_exec(
                &self.id,
                CreateExecOptions {
                    cmd: Some(vec![STAGED_WORKER]),
                    attach_stdin: Some(true),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    tty: Some(false),
                    ..Default::default()
                },
            )
            .await
            .expect("create exec for the container worker");

        match self
            .docker
            .start_exec(&exec.id, None)
            .await
            .expect("start exec for the container worker")
        {
            StartExecResults::Attached { input, output } => (input, output),
            StartExecResults::Detached => {
                panic!("exec detached despite attach_stdin/stdout being requested")
            }
        }
    }
}

/// The worker's stdin: where the orchestrator's RPC frames go.
type WorkerStdin = std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>;
/// The worker's output, as bollard's demultiplexed frames.
type WorkerOutput = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>,
>;

/// A wired-up orchestrator/worker pair, plumbed exactly the way
/// `cindy play` does it — with the worker half being an attached exec
/// inside the container instead of an SSH child.
struct Play {
    orchestrator: tokio::process::Child,
    pumps: Vec<tokio::task::JoinHandle<()>>,
    /// Kept alive deliberately: the orchestrator reads the host context
    /// from this path at startup, so unlinking it early is a race.
    _context_file: tempfile::NamedTempFile,
}

async fn start_play(
    host: &SystemdHost,
    host_context: &serde_json::Value,
    orchestrator_env: &[(&str, &str)],
) -> Play {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let orchestrator_bin = build_variant("orchestrator");
    host.stage_worker().await;
    let (mut worker_stdin, mut worker_output) = host.start_worker().await;

    let context_file = tempfile::NamedTempFile::new().expect("create context file");
    std::fs::write(context_file.path(), host_context.to_string()).expect("write host context");

    // The orchestrator is a `tokio::process` child so both halves of
    // the RPC bridge are async: the worker side is bollard's attached
    // exec, which has no blocking form.
    let mut orch_cmd = tokio::process::Command::new(&orchestrator_bin);
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
    let mut o_in = orchestrator.stdin.take().unwrap();

    let pumps = vec![
        // Orchestrator stdout → worker stdin.
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match o_out.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if worker_stdin.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        // The RPC is request/response: without a flush
                        // per frame the orchestrator waits for a reply
                        // to bytes still sitting in a buffer.
                        if worker_stdin.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
            // Closing the worker's stdin is what ends its RPC read loop.
            let _ = worker_stdin.shutdown().await;
        }),
        // Worker output → orchestrator stdin, demultiplexed. Only
        // stdout carries RPC; the worker's stderr is diagnostics and
        // goes to the test's, tagged, exactly as the CLI tags it
        // per-host in a real play.
        tokio::spawn(async move {
            use futures_util::StreamExt as _;
            while let Some(frame) = worker_output.next().await {
                match frame {
                    Ok(LogOutput::StdOut { message }) => {
                        if o_in.write_all(&message).await.is_err() {
                            break;
                        }
                        if o_in.flush().await.is_err() {
                            break;
                        }
                    }
                    Ok(LogOutput::StdErr { message }) => {
                        eprint!("[worker] {}", String::from_utf8_lossy(&message));
                    }
                    // Console/StdIn frames don't occur with tty:false
                    // and attach_stdin, but a stream error means the
                    // exec is gone.
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("[worker] exec stream error: {e}");
                        break;
                    }
                }
            }
            // Worker gone: EOF the orchestrator so its in-flight calls
            // fail instead of hanging.
            let _ = o_in.shutdown().await;
        }),
    ];

    Play {
        orchestrator,
        pumps,
        _context_file: context_file,
    }
}

impl Play {
    /// Wait for the orchestrator — it drives the play and holds the
    /// authoritative exit code — then let the pumps drain.
    ///
    /// There is no worker process to reap: it lives inside the
    /// container's exec, which the engine cleans up when the process
    /// exits (and the container's `Drop` catches the rest).
    async fn wait(mut self) -> std::process::ExitStatus {
        let status = self.orchestrator.wait().await.expect("wait orchestrator");
        for pump in std::mem::take(&mut self.pumps) {
            let _ = pump.await;
        }
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
        .wait()
        .await;
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
        .wait()
        .await;
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
    .wait()
    .await;
    assert!(
        status.success(),
        "check-mode run failed: {status:?} — either disable under-reported \
         or it mutated the masked unit"
    );

    // For real: the same request now unmasks.
    let status = start_play(&host, &host_context(), &[("CINDY_E2E_SYSTEMD_UNMASK", "1")])
        .await
        .wait()
        .await;
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
        .wait()
        .await;
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
        .wait()
        .await;
    assert!(
        status.success(),
        "apt play failed: {status:?} — see the output above"
    );
    drop(tmp);
}
