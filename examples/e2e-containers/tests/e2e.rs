//! Container e2e harness: drives the same orchestrator/worker pipe
//! pair as `examples/e2e-localhost`, except the worker runs **inside**
//! a Debian-systemd container via `podman exec -i` — which is what
//! puts the mutating builtins (systemd, apt, user, group) in front of
//! a real system.
//!
//! Degradation is explicit, not a failure: on a machine without
//! podman (CI) or without the image and the network to build it, every
//! test reports why it skipped and passes, so `cargo test --workspace`
//! stays green everywhere the hermetic suite already runs.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use testcontainers::{
    ContainerAsync, GenericImage,
    core::{WaitFor, wait::HealthWaitStrategy},
    runners::AsyncRunner as _,
};

/// Locally-built image (see `Containerfile.systemd` in this crate).
/// `localhost/` is podman's local-only namespace: no registry is ever
/// contacted for it, so testcontainers' create-then-pull fallback can't
/// reach for the network.
const IMAGE: &str = "localhost/cindy-e2e-systemd";
const TAG: &str = "latest";

/// One-time environment negotiation for the whole suite. `Ok(())` =
/// ready to run; `Err(reason)` = every test skips with that reason.
///
/// - `DOCKER_HOST` is pointed at the rootless podman socket when it's
///   the only container socket in town (bollard defaults to Docker's).
/// - The systemd image is used from the local store or built once
///   (`--network=host`: rootless podman's slirp DNS may be absent even
///   where the host itself has egress — the sandbox this was written
///   in is exactly that).
/// - The `podman` CLI is required for `exec` even though
///   testcontainers talks to the socket directly.
fn harness_ready() -> Result<(), String> {
    static ONCE: OnceLock<Result<(), String>> = OnceLock::new();
    ONCE.get_or_init(|| {
        let podman_socket = std::env::var_os("XDG_RUNTIME_DIR")
            .map(|rt| PathBuf::from(rt).join("podman/podman.sock"));
        match (std::env::var_os("DOCKER_HOST"), podman_socket) {
            // Explicit DOCKER_HOST (or a real Docker socket): trust it.
            (Some(_), _) => {}
            (None, Some(socket)) if socket.exists() => {
                // Safety: no container has started yet — every test
                // calls `harness_ready()` before starting one, and this
                // `OnceLock` serialises them — so no thread is mid-read
                // of the environment here.
                unsafe {
                    std::env::set_var("DOCKER_HOST", format!("unix://{}", socket.display()));
                }
            }
            _ => {
                return Err("no DOCKER_HOST and no podman socket at \
                     $XDG_RUNTIME_DIR/podman/podman.sock"
                    .to_owned());
            }
        }

        if !Command::new("podman")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Err("podman CLI not available".to_owned());
        }

        let image = format!("{IMAGE}:{TAG}");
        let have = Command::new("podman")
            .args(["image", "exists", &image])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !have {
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
            let built = Command::new("podman")
                .args([
                    "build",
                    "--format",
                    "docker",
                    "--network=host",
                    "--tag",
                    &image,
                    "--file",
                    "Containerfile.systemd",
                ])
                .current_dir(manifest)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !built {
                return Err(format!(
                    "image {image} not present and couldn't be built \
                     (needs network); see Containerfile.systemd"
                ));
            }
        }
        Ok(())
    })
    .clone()
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
    async fn start() -> Self {
        let request = GenericImage::new(IMAGE, TAG).with_wait_for(WaitFor::Healthcheck(
            HealthWaitStrategy::new().with_poll_interval(Duration::from_millis(200)),
        ));
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

    /// Stage the worker binary for one play. Per play, not per
    /// container: the worker unlinks its own executable on startup —
    /// agent-less is load-bearing — so each play's worker consumes
    /// the staged copy and the next one needs a fresh one. This is
    /// the same dance `cindy play` performs per host, minus SSH.
    fn stage_worker(&self, worker_bin: &Path) {
        let ok = Command::new("podman")
            .args(["exec", &self.id, "mkdir", "-p", "/worker"])
            .stdin(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "mkdir /worker in the container failed");
        let ok = Command::new("podman")
            .arg("cp")
            .arg(worker_bin)
            .arg(format!("{}:/worker/e2e-worker", self.id))
            .stdin(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "podman cp of the worker binary failed");
        let ok = Command::new("podman")
            .args(["exec", &self.id, "chmod", "755", "/worker/e2e-worker"])
            .stdin(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "chmod of the staged worker binary failed");
    }

    /// The worker runs *inside* the container: `podman exec -i` with
    /// piped stdio is the same child shape the localhost harness
    /// spawns, minus SSH. The worker unlinks its own binary on startup
    /// — inside the container's writable layer, exactly as on a real
    /// host (agent-less is load-bearing).
    fn exec_worker(&self) -> Command {
        let mut cmd = Command::new("podman");
        cmd.args(["exec", "-i"])
            .arg(&self.id)
            .arg("/worker/e2e-worker");
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

fn start_play(
    host: &SystemdHost,
    worker_bin: &Path,
    host_context: &serde_json::Value,
    orchestrator_env: &[(&str, &str)],
) -> Play {
    let orchestrator_bin = build_variant("orchestrator");
    host.stage_worker(worker_bin);

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
async fn setup() -> Option<(tempfile::TempDir, SystemdHost, PathBuf)> {
    if let Err(reason) = harness_ready() {
        eprintln!("skipping container e2e: {reason}");
        return None;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let worker = build_variant("remote");
    let host = SystemdHost::start().await;
    Some((tmp, host, worker))
}

/// `systemd`, `apt`, `user` and `group` finally meet a real system:
/// enable/start a fresh unit, converge, stop/disable, mask — the
/// lifecycle a VyOS play actually drives.
#[tokio::test]
async fn systemd_manages_a_unit_lifecycle() {
    let Some((tmp, host, worker)) = setup().await else {
        return;
    };
    let status = start_play(
        &host,
        &worker,
        &host_context(),
        &[("CINDY_E2E_SYSTEMD", "1")],
    )
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
    let Some((tmp, host, worker)) = setup().await else {
        return;
    };

    // Setup: mask a /usr/lib-backed unit (its file survives the mask —
    // an admin-authored one is deleted to complete the mask, by
    // design, leaving nothing to unmask).
    let status = start_play(
        &host,
        &worker,
        &host_context(),
        &[("CINDY_E2E_SYSTEMD_MASK", "1")],
    )
    .wait();
    assert!(status.success(), "mask run failed: {status:?}");

    // Check mode: report, don't touch. The playbook itself asserts the
    // mask survived via read-only probes; a failure here means a
    // mutation leaked through check mode.
    let status = start_play(
        &host,
        &worker,
        &host_context(),
        &[("CINDY_E2E_SYSTEMD_CHECK", "1"), ("CINDY_DRY_RUN", "1")],
    )
    .wait();
    assert!(
        status.success(),
        "check-mode run failed: {status:?} — either disable under-reported \
         or it mutated the masked unit"
    );

    // For real: the same request now unmasks.
    let status = start_play(
        &host,
        &worker,
        &host_context(),
        &[("CINDY_E2E_SYSTEMD_UNMASK", "1")],
    )
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
    let Some((tmp, host, worker)) = setup().await else {
        return;
    };
    let status = start_play(&host, &worker, &host_context(), &[("CINDY_E2E_USERS", "1")]).wait();
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
    let Some((tmp, host, worker)) = setup().await else {
        return;
    };
    let status = start_play(&host, &worker, &host_context(), &[("CINDY_E2E_APT", "1")]).wait();
    assert!(
        status.success(),
        "apt play failed: {status:?} — see the output above"
    );
    drop(tmp);
}
