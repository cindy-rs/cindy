//! The e2e-localhost pipe pair, with the worker inside a Debian-systemd
//! container — the mutating builtins against a real system.
//!
//! Required: an unusable harness fails the suite, naming what's
//! missing, because libtest hides a skip's reason and a skipped suite
//! reads as green. `CINDY_E2E_CONTAINERS=skip` opts out deliberately.
//!
//! No container CLI, so podman or docker doesn't matter: testcontainers
//! builds the image, starts the container and stages the worker, and
//! its client, bollard, runs the worker — testcontainers' own `exec` has
//! no stdin, and the RPC channel needs one.

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

/// Built from `Containerfile.systemd`.
const IMAGE_NAME: &str = "cindy-e2e-systemd";
const TAG: &str = "latest";

/// Pristine worker binary, copied in once per container.
const MASTER_WORKER: &str = "/worker/e2e-worker.orig";
/// Per-play copy, consumed by the worker unlinking itself.
const STAGED_WORKER: &str = "/worker/e2e-worker";

/// Settle the engine socket: `DOCKER_HOST` if set, else a rootless
/// podman socket (bollard would look only at Docker's path), else
/// `/var/run/docker.sock` (CI) as is.
fn harness_ready() -> &'static Result<(), String> {
    static NEGOTIATED: OnceLock<Result<(), String>> = OnceLock::new();
    NEGOTIATED.get_or_init(|| {
        if std::env::var_os("DOCKER_HOST").is_some() {
            return Ok(());
        }
        let podman_socket = std::env::var_os("XDG_RUNTIME_DIR")
            .map(|rt| PathBuf::from(rt).join("podman/podman.sock"))
            .filter(|s| s.exists());
        if let Some(socket) = podman_socket {
            // Safety: once, under the OnceLock, before any container or
            // engine client exists to read the environment.
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

/// Built once per suite; each start needs its own `GenericImage`.
async fn image() -> GenericImage {
    static BUILT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    BUILT
        .get_or_init(|| async {
            drop(
                GenericBuildableImage::new(IMAGE_NAME, TAG)
                    .with_dockerfile(
                        Path::new(env!("CARGO_MANIFEST_DIR")).join("Containerfile.systemd"),
                    )
                    .build_image()
                    .await
                    .expect(
                        "building the systemd image failed (needs network on first \
                         run); see Containerfile.systemd",
                    ),
            );
        })
        .await;
    GenericImage::new(IMAGE_NAME, TAG)
}

/// Memoised under a lock, as in e2e-localhost: concurrent builds into
/// one target dir hand out half-linked binaries (`ETXTBSY`).
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

/// Ready when the image's HEALTHCHECK passes (`degraded` counts: normal
/// in containers). Removed on drop.
struct SystemdHost {
    container: ContainerAsync<GenericImage>,
    /// The engine testcontainers talks to, for an exec with stdin.
    docker: Docker,
}

impl SystemdHost {
    /// The worker is copied in at create time, so it can't race startup.
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
        // Honours the DOCKER_HOST `harness_ready` settled: the same socket.
        let docker = Docker::connect_with_defaults().expect("connect to the container engine");
        Self { container, docker }
    }

    /// Per play: the worker deletes its own binary on startup.
    async fn stage_worker(&self) {
        let result = self
            .container
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

    /// The RPC channel: the worker's stdin, and its output frames.
    /// `tty: false` keeps stdout and stderr separable, and the bytes
    /// raw — a TTY would translate newlines inside COBS frames.
    async fn start_worker(&self) -> (WorkerStdin, WorkerOutput) {
        let exec = self
            .docker
            .create_exec(
                self.container.id(),
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

/// As `cindy play` pipes them, with an attached exec for SSH.
struct Play {
    orchestrator: tokio::process::Child,
    pumps: Vec<tokio::task::JoinHandle<()>>,
    /// Read by the orchestrator at startup: unlinking it early races.
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

    // Async, because the worker side (bollard) has no blocking form.
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
                        // Request/response: an unflushed frame never gets
                        // its reply.
                        if worker_stdin.flush().await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = worker_stdin.shutdown().await;
        }),
        // Worker stdout → orchestrator stdin; stderr is diagnostics,
        // tagged as the CLI tags it.
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
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("[worker] exec stream error: {e}");
                        break;
                    }
                }
            }
            // EOF, so the orchestrator's in-flight calls fail, not hang.
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
    /// The orchestrator's exit is the play's. The engine reaps the exec.
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

/// A fresh container per test; the plays within a test share it.
async fn setup() -> Option<SystemdHost> {
    if let Err(reason) = harness_ready() {
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
    Some(SystemdHost::start(&build_variant("remote")).await)
}

/// enable+start, converge, runtime-only links, disable+stop, mask.
#[tokio::test]
async fn systemd_manages_a_unit_lifecycle() {
    let Some(host) = setup().await else {
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
}

/// Under `--check`, `disable` on a masked unit reports the change
/// without unmasking — the arm f576ecc's bug shipped in, which only a
/// real systemd can catch.
#[tokio::test]
async fn systemd_check_mode_never_unmasks() {
    let Some(host) = setup().await else {
        return;
    };

    // A /usr/lib unit: its file survives the mask (an /etc one wouldn't).
    let status = start_play(&host, &host_context(), &[("CINDY_E2E_SYSTEMD_MASK", "1")])
        .await
        .wait()
        .await;
    assert!(status.success(), "mask run failed: {status:?}");

    // The play asserts, by probe, that the mask survived.
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
}

/// Real shadow-utils: create, converge, pinned attributes, groups, eight
/// concurrent identical creates converging to one account, absence.
#[tokio::test]
async fn users_and_groups_reconcile_on_a_real_system() {
    let Some(host) = setup().await else {
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
}

/// Against a `file://` repo baked into the image (no network at test
/// time): install, converge, no upgrade chase, remove.
#[tokio::test]
async fn apt_installs_converges_and_removes() {
    let Some(host) = setup().await else {
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
}
