use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use sha2::Digest as _;

/// Body the in-process HTTP server returns, and that the play downloads.
const FETCH_BODY: &[u8] = b"downloaded-by-cindy-fetch-module\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mint a genuinely sealed `Secret<String>` ciphertext under `key`,
/// the same way `cindy secret seal` does — real AEAD blob, real
/// SealedPayload framing.
fn seal_string(key: &cindy::secret::crypto::VaultKey, value: &str) -> Vec<u8> {
    let payload = cindy::secret::SealedPayload {
        value: cindy::__reexports::postcard::to_allocvec(value)
            .expect("postcard serialise the secret value"),
        source: value.to_owned(),
    };
    let plaintext = cindy::__reexports::postcard::to_allocvec(&payload)
        .expect("postcard serialise the SealedPayload");
    cindy::secret::crypto::seal(key, &plaintext).expect("seal the e2e secret")
}

fn b64(bytes: &[u8]) -> String {
    use cindy::__reexports::base64::Engine as _;
    cindy::__reexports::base64::engine::general_purpose::STANDARD.encode(bytes)
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
///
/// A dedicated `--target-dir` keeps this nested `cargo build` from
/// contending on the outer test invocation's build lock.
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

    // The last cargo "compiler-artifact" message with an executable is
    // our binary.
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

/// Spin up a one-shot localhost HTTP/1.0 server that answers every
/// request with `FETCH_BODY`. Returns its `http://127.0.0.1:PORT/` URL;
/// the server thread runs until the test process exits.
fn start_http_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    let addr = listener.local_addr().expect("local addr");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Drain the request headers (we don't care about them).
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                FETCH_BODY.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(FETCH_BODY);
            let _ = stream.flush();
        }
    });

    format!("http://{addr}/")
}

/// Like [`start_http_server`], but demands an `Authorization` header
/// (`Bearer cindy-e2e-token`) and answers `403` without it — the
/// counterpart for exercising `fetch::State::headers`.
fn start_http_server_authed() -> String {
    // Header *names* arrive lower-cased (HTTP names are
    // case-insensitive and ureq normalises); the value is exact.
    const REQUIRED_VALUE: &str = "Bearer cindy-e2e-token";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    let addr = listener.local_addr().expect("local addr");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let ok = request.lines().any(|l| {
                l.split_once(':').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("authorization")
                        && value.trim() == REQUIRED_VALUE
                })
            });
            let header = if ok {
                format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    FETCH_BODY.len()
                )
            } else {
                "HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_owned()
            };
            let _ = stream.write_all(header.as_bytes());
            if ok {
                let _ = stream.write_all(FETCH_BODY);
            }
            let _ = stream.flush();
        }
    });

    format!("http://{addr}/")
}

/// Like [`start_http_server`] but sends **no** `Content-Length`, so the
/// body is delimited only by the connection close.
///
/// That's the case `max_bytes` has to police mid-stream: with no
/// declared length there is nothing to reject up front, so the limit can
/// only be enforced as the bytes actually arrive.
fn start_http_server_unsized() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    let addr = listener.local_addr().expect("local addr");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n");
            let _ = stream.write_all(FETCH_BODY);
            let _ = stream.flush();
            // Dropping the stream closes the connection, which is what
            // terminates the body for the client.
        }
    });

    format!("http://{addr}/")
}

/// A wired-up orchestrator/worker pair, plumbed exactly the way
/// `cindy play` does it.
struct Play {
    orchestrator: std::process::Child,
    worker: std::process::Child,
    pumps: Vec<std::thread::JoinHandle<()>>,
    /// Kept alive deliberately: the orchestrator reads the host context
    /// from this path at startup, so unlinking it early is a race.
    _context_file: tempfile::NamedTempFile,
    /// Drained into `*_stderr_text` by `wait_and_collect`. Captured
    /// rather than inherited so the vault-refusal scenarios can assert
    /// on the exact wording of the preflight messages; every scenario's
    /// stderr stays far below the 64 KiB pipe buffer, so a child can't
    /// block on an unread pipe.
    orchestrator_stderr: Option<std::process::ChildStderr>,
    worker_stderr: Option<std::process::ChildStderr>,
    orchestrator_stderr_text: String,
    worker_stderr_text: String,
}

/// Build both halves, hand the host context over by temp file (as the
/// CLI does), and cross the pipes: orchestrator stdout → worker stdin,
/// worker stdout → orchestrator stdin.
///
/// The scenarios below differ only in their host context and the env var
/// that selects a branch of the playbook, so they share this driver
/// instead of each repeating the plumbing.
fn start_play(
    tmp: &Path,
    host_context: &serde_json::Value,
    orchestrator_env: &[(&str, &str)],
    worker_env: &[(&str, &str)],
) -> Play {
    start_play_with_worker(tmp, host_context, orchestrator_env, worker_env, "remote")
}

/// [`start_play`] with control over which worker variant to spawn —
/// the keyless-handshake scenario needs the `worker-vault-demand`
/// build, every other scenario the plain one.
#[allow(clippy::too_many_arguments)]
/// Staging an executable and spawning one must not interleave across
/// threads: `fork` duplicates the fd table, so a spawn on one thread
/// inherits another thread's mid-copy write fd, and `execve` fails with
/// `ETXTBSY` — before `O_CLOEXEC` can close it. Hold this from the copy
/// to the last spawn.
fn staging_lock() -> std::sync::MutexGuard<'static, ()> {
    static STAGE_AND_SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());
    STAGE_AND_SPAWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A copy of the worker: it deletes its own executable on startup.
fn stage_worker(tmp: &Path, built: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let staged = tmp.join("remote-worker");
    std::fs::copy(built, &staged).expect("copy remote worker");
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
    staged
}

fn start_play_with_worker(
    tmp: &Path,
    host_context: &serde_json::Value,
    orchestrator_env: &[(&str, &str)],
    worker_env: &[(&str, &str)],
    worker_feature: &str,
) -> Play {
    let orchestrator_bin = build_variant("orchestrator");
    let remote_bin_src = build_variant(worker_feature);

    let _staging = staging_lock();
    let remote_bin = stage_worker(tmp, &remote_bin_src);
    let mut worker_cmd = Command::new(&remote_bin);
    worker_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in worker_env {
        worker_cmd.env(k, v);
    }
    let mut worker = worker_cmd.spawn().expect("spawn remote worker");

    let context_file = tempfile::NamedTempFile::new().expect("create context file");
    std::fs::write(context_file.path(), host_context.to_string()).expect("write host context");

    let mut orch_cmd = Command::new(&orchestrator_bin);
    orch_cmd
        .env("CINDY_HOST_CONTEXT_FILE", context_file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in orchestrator_env {
        orch_cmd.env(k, v);
    }
    let mut orchestrator = orch_cmd.spawn().expect("spawn orchestrator");

    // Both children exist; no further fork can inherit a staging fd.
    drop(_staging);

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
        orchestrator_stderr: orchestrator.stderr.take(),
        worker_stderr: worker.stderr.take(),
        orchestrator,
        worker,
        pumps,
        _context_file: context_file,
        orchestrator_stderr_text: String::new(),
        worker_stderr_text: String::new(),
    }
}

impl Play {
    /// Wait for the orchestrator — it drives the play and holds the
    /// authoritative exit code — then let the worker EOF out, and
    /// collect both children's stderr for message assertions.
    fn wait_and_collect(mut self) -> (std::process::ExitStatus, String, String) {
        let status = self.orchestrator.wait().expect("wait orchestrator");
        for pump in std::mem::take(&mut self.pumps) {
            let _ = pump.join();
        }
        let _ = self.worker.wait();
        if let Some(mut err) = self.orchestrator_stderr.take() {
            let _ = err.read_to_string(&mut self.orchestrator_stderr_text);
        }
        if let Some(mut err) = self.worker_stderr.take() {
            let _ = err.read_to_string(&mut self.worker_stderr_text);
        }
        (
            status,
            std::mem::take(&mut self.orchestrator_stderr_text),
            std::mem::take(&mut self.worker_stderr_text),
        )
    }

    fn wait(self) -> std::process::ExitStatus {
        self.wait_and_collect().0
    }

    /// Kill the worker outright, simulating a host that drops mid-call.
    fn kill_worker(&mut self) {
        self.worker.kill().expect("kill remote worker");
    }

    /// Poll for the orchestrator's exit, asserting it happens within
    /// `deadline` of now rather than hanging the suite.
    fn wait_orchestrator_within(
        &mut self,
        deadline: std::time::Duration,
    ) -> std::process::ExitStatus {
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = self.orchestrator.try_wait().expect("try_wait orchestrator") {
                return status;
            }
            assert!(
                start.elapsed() < deadline,
                "orchestrator still running {deadline:?} after the worker died — RPC hang regression"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

#[test]
fn e2e_localhost_play() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let work_dir = tmp.path().join("work");
    let fetch_url = start_http_server();
    let fetch_sha256 = hex(&sha2::Sha256::digest(FETCH_BODY));

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": work_dir,
            "fetch_url": fetch_url,
            "fetch_sha256": fetch_sha256,
            // Regression for MAX_ARG_STRLEN: a host context bigger
            // than the ~128 KiB a single env var can hold must still
            // reach the orchestrator. It travels via temp file
            // (`CINDY_HOST_CONTEXT_FILE`), exactly like the CLI hands
            // it over for large contexts.
            "padding": "x".repeat(150 * 1024),
        }
    });

    let orch_status = start_play(tmp.path(), &host_context, &[], &[]).wait();
    assert!(
        orch_status.success(),
        "orchestrator exited with failure: {orch_status:?}"
    );

    // --- assert: the play's report reflects every module succeeding --
    let report_raw =
        std::fs::read(work_dir.join("report.json")).expect("play did not produce report.json");
    let report: serde_json::Value =
        serde_json::from_slice(&report_raw).expect("report.json not valid JSON");

    assert_eq!(report["command_stdout"], "command-module-ran");
    assert_eq!(report["shell_marker_exists"], true);
    assert_eq!(report["downloaded_exists"], true);
    assert_eq!(report["tarball_exists"], true);
    assert_eq!(report["extracted_greeting_exists"], true);
    assert_eq!(report["roundtrip_ok"], true);
    assert!(report["compressed_len"].as_u64().unwrap() > 0);

    // Direct filesystem checks too, independent of the play's own report.
    assert_eq!(
        std::fs::read(work_dir.join("greeting.txt")).unwrap(),
        b"hello from cindy\n"
    );
    assert_eq!(
        std::fs::read(work_dir.join("downloaded.bin")).unwrap(),
        FETCH_BODY
    );
    assert_eq!(
        std::fs::read(work_dir.join("shell-marker")).unwrap(),
        b"done"
    );
}

/// Killing the worker while a call is in flight must fail the
/// orchestrator promptly — a dead worker used to leave every pending
/// future `Pending` forever, hanging the play until ^C.
#[test]
fn worker_death_fails_fast() {
    let tmp = tempfile::tempdir().expect("create temp dir");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": tmp.path().join("work"),
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
        }
    });

    let mut play = start_play(tmp.path(), &host_context, &[("CINDY_E2E_SLEEP", "1")], &[]);

    // Give the `sleep 30` call time to dispatch, then kill the worker.
    std::thread::sleep(std::time::Duration::from_secs(2));
    play.kill_worker();

    // The orchestrator must now exit non-zero on its own, well before
    // the 30s the remote call would have taken.
    let status = play.wait_orchestrator_within(std::time::Duration::from_secs(15));
    assert!(
        !status.success(),
        "orchestrator reported success although the worker died mid-call"
    );
}

/// Check mode (`cindy play --check`): the dry-run flag travels the
/// handshake, builtins report would-changes without applying anything,
/// and the play still exits 0 — with the probe file it "created" nowhere
/// on disk and the command it ran marked not-executed.
#[test]
fn check_mode_applies_nothing() {
    let tmp = tempfile::tempdir().expect("create temp dir");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": tmp.path().join("work"),
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
        }
    });

    let status = start_play(
        tmp.path(),
        &host_context,
        &[("CINDY_E2E_DRY_RUN", "1"), ("CINDY_DRY_RUN", "1")],
        &[],
    )
    .wait();
    assert!(
        status.success(),
        "orchestrator exited with failure: {status:?}"
    );

    assert!(
        !tmp.path().join("work/dry-run-probe.txt").exists(),
        "check mode created the probe file it was only supposed to report"
    );
}

/// The worker's RPC byte budget must gate dispatch: with the budget
/// forced to 64 KiB, a fan-out of eight ~40 KiB calls may only run
/// one at a time. The play's probes observe their own concurrency and
/// fail the run if it ever exceeds 1 (see `CINDY_E2E_BUDGET` in
/// src/main.rs).
#[test]
fn backpressure_serialises_oversized_fanout() {
    let tmp = tempfile::tempdir().expect("create temp dir");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": tmp.path().join("work"),
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
        }
    });

    let orch_status = start_play(
        tmp.path(),
        &host_context,
        &[("CINDY_E2E_BUDGET", "1")],
        &[("CINDY_RPC_BUDGET", "65536")],
    )
    .wait();

    assert!(
        orch_status.success(),
        "orchestrator exited with failure: {orch_status:?} — the byte budget \
         failed to serialise an oversized fan-out"
    );
}

/// The orchestrator's own RPC byte budget must park dispatch, not
/// response routing: with the budget forced to 64 KiB, a fan-out of
/// 32 ~40 KiB calls still completes — every frame waits its turn to
/// reach the pipe while responses keep flowing. Acquiring the budget
/// inside the routing loop (the obvious-but-wrong mirror of the
/// worker's read-loop acquire) deadlocks right here: the worker's
/// budget only releases as responses flow, and responses can't flow
/// through a parked loop.
#[test]
fn orchestrator_backpressure_completes_under_tiny_budget() {
    let tmp = tempfile::tempdir().expect("create temp dir");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": tmp.path().join("work"),
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
        }
    });

    let mut play = start_play(
        tmp.path(),
        &host_context,
        &[
            ("CINDY_E2E_ORCH_BUDGET", "1"),
            ("CINDY_RPC_BUDGET", "65536"),
        ],
        &[],
    );
    let orch_status = play.wait_orchestrator_within(std::time::Duration::from_secs(60));

    assert!(
        orch_status.success(),
        "orchestrator exited with failure: {orch_status:?} — the dispatch-side byte budget \
         deadlocked or mangled an oversized fan-out"
    );
}

/// `fetch` streams its body instead of buffering it, which puts three
/// promises on the line: an over-sized body is refused (declared length
/// or not), a failed checksum leaves the destination untouched because
/// verification happens before the atomic publish, and an
/// already-satisfied destination is never re-downloaded. The play
/// asserts all of them from the inside (see `CINDY_E2E_FETCH_LIMITS` in
/// src/main.rs) and fails the run if any breaks; here we re-check the
/// filesystem independently.
#[test]
fn fetch_streams_within_its_limits() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let work_dir = tmp.path().join("work");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": work_dir,
            "fetch_url": start_http_server(),
            "fetch_sha256": hex(&sha2::Sha256::digest(FETCH_BODY)),
            "fetch_url_unsized": start_http_server_unsized(),
            "fetch_url_authed": start_http_server_authed(),
        }
    });

    let orch_status = start_play(
        tmp.path(),
        &host_context,
        &[("CINDY_E2E_FETCH_LIMITS", "1")],
        &[],
    )
    .wait();
    assert!(
        orch_status.success(),
        "orchestrator exited with failure: {orch_status:?} — a streaming-fetch \
         guarantee broke (see its stderr above)"
    );

    // Nothing an over-limit or failed-checksum fetch touched may exist.
    for rejected in ["over-declared.bin", "over-streamed.bin", "bad-checksum.bin"] {
        assert!(
            !work_dir.join(rejected).exists(),
            "{rejected} was published despite the fetch being rejected"
        );
    }

    // The good one landed, byte-exact, with the mode the second (skipped)
    // fetch reconciled.
    let good = work_dir.join("streamed.bin");
    assert_eq!(std::fs::read(&good).unwrap(), FETCH_BODY);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&good).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644, "drifted mode was not reconciled");
    }
}

/// The vault-key handshake reaching a worker-side `reveal()`: a real
/// key minted by the test, a really sealed secret in the host context,
/// keys shipped to the orchestrator via `CINDY_VAULT_KEYS` (as the CLI
/// does) — and the reveal happening *on the worker*, which can only
/// decrypt if the key arrived through the RPC handshake, never via
/// argv/env. Until this test, no sealed secret had crossed the wire in
/// any e2e suite.
#[test]
fn secret_reveals_on_the_worker_through_the_handshake() {
    use cindy::secret::crypto;

    let tmp = tempfile::tempdir().expect("create temp dir");
    let work_dir = tmp.path().join("work");

    let key = crypto::generate_vault_key();
    let plaintext = "e2e-secret-plaintext-7512";
    let ciphertext_b64 = b64(&seal_string(&key, plaintext));

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": work_dir,
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
            "secret": {
                "vault": "e2e-vault",
                "ciphertext": ciphertext_b64,
            },
            "secret_expected": plaintext,
        }
    });

    let vault_keys = serde_json::json!({ "e2e-vault": b64(key.as_slice()) }).to_string();
    let play = start_play(
        tmp.path(),
        &host_context,
        &[
            ("CINDY_E2E_SECRETS", "1"),
            ("CINDY_VAULT_KEYS", &vault_keys),
        ],
        &[],
    );
    let (status, orch_stderr, _worker_stderr) = play.wait_and_collect();
    assert!(status.success(), "orchestrator failed: {orch_stderr}");
    assert!(
        work_dir.join("reveal-ok.marker").exists(),
        "the reveal scenario never completed"
    );
}

/// A remote fn defined in the playbook's lib reaches the worker. The
/// worker build's `main.rs` references nothing from the lib, so rustc
/// used to drop it from the link and its registrations with it: the
/// call died mid-play with "called an unregistered remote function".
#[test]
fn remote_fns_in_the_playbook_lib_reach_the_worker() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let work_dir = tmp.path().join("work");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": work_dir,
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
        }
    });

    let play = start_play(
        tmp.path(),
        &host_context,
        &[("CINDY_E2E_LIB_REMOTE", "1")],
        &[],
    );
    let (status, orch_stderr, worker_stderr) = play.wait_and_collect();
    assert!(
        status.success(),
        "orchestrator failed: {orch_stderr}\nworker: {worker_stderr}"
    );
    assert!(
        !worker_stderr.contains("unregistered remote function"),
        "worker lacked the lib's remote fn: {worker_stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(work_dir.join("lib-remote.marker")).unwrap(),
        "lib:ping"
    );
}

/// A remote fn's error reaches the orchestrator whole: every link of
/// the chain (the wire used to carry only the outermost message), an
/// io error still an `io::Error` of the same kind, and a typed serde
/// error as its own type.
#[test]
fn remote_errors_cross_the_wire_with_their_chain() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let work_dir = tmp.path().join("work");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": work_dir,
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
        }
    });

    let play = start_play(
        tmp.path(),
        &host_context,
        &[("CINDY_E2E_REMOTE_ERRORS", "1")],
        &[],
    );
    let (status, orch_stderr, worker_stderr) = play.wait_and_collect();
    assert!(
        status.success(),
        "orchestrator failed: {orch_stderr}\nworker: {worker_stderr}"
    );

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work_dir.join("remote-errors.json")).unwrap())
            .unwrap();
    let missing = work_dir.join("does-not-exist");
    let chain = report["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2, "{report}");
    assert_eq!(chain[0], format!("reading {}", missing.display()));
    assert!(
        chain[1]
            .as_str()
            .unwrap()
            .contains("No such file or directory"),
        "the io cause was lost: {report}"
    );
    assert!(
        report["rendered"]
            .as_str()
            .unwrap()
            .ends_with("No such file or directory (os error 2)"),
        "{report}"
    );
    assert_eq!(report["io_kind"], "Some(NotFound)");
    assert_eq!(report["typed_what"], "eth0");
}

/// Check mode and the vault keys arrive with the handshake, so a call
/// that overtook it would run with neither: the worker refuses it.
#[test]
fn worker_refuses_a_call_before_the_handshake() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let built = build_variant("remote");
    let mut worker = {
        let _staging = staging_lock();
        Command::new(stage_worker(tmp.path(), &built))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn remote worker")
    };
    let call = cindy::common::WorkerInbound::Call(cindy::common::RemoteFnPayload {
        uuid: uuid::Uuid::nil(),
        fn_id: "e2e_localhost::keyless_marker".to_owned(),
        data: Vec::new(),
    });
    let frame = postcard::to_allocvec_cobs(&call).unwrap();
    worker.stdin.take().unwrap().write_all(&frame).unwrap();

    let out = worker.wait_with_output().expect("wait for worker");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "worker accepted a call before the handshake"
    );
    assert!(stderr.contains("before the handshake"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// Preflight refusal on a missing key: the orchestrator is handed the
/// sealed secret but *no* key for its vault, and must refuse before
/// any playbook code runs — a missing marker and the preflight wording
/// (naming the vault, pointing at remediation) are the proof. The
/// keys dir is pinned to an empty tempdir so a stray `keys/` in the
/// working tree can't make this test pass vacuously.
#[test]
fn missing_key_refuses_before_any_playbook_code_runs() {
    use cindy::secret::crypto;

    let tmp = tempfile::tempdir().expect("create temp dir");
    let work_dir = tmp.path().join("work");
    let empty_keys_dir = tempfile::tempdir().expect("create empty keys dir");

    let key = crypto::generate_vault_key();
    let ciphertext_b64 = b64(&seal_string(&key, "plaintext-without-a-key"));

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": work_dir,
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
            "secret": {
                "vault": "e2e-vault",
                "ciphertext": ciphertext_b64,
            },
            "secret_expected": "plaintext-without-a-key",
        }
    });

    let play = start_play(
        tmp.path(),
        &host_context,
        &[
            ("CINDY_E2E_SECRETS", "1"),
            // Keys for nothing: the preflight must name the vault.
            ("CINDY_VAULT_KEYS", "{}"),
            ("CINDY_KEYS_DIR", empty_keys_dir.path().to_str().unwrap()),
        ],
        &[],
    );
    let (status, orch_stderr, _worker_stderr) = play.wait_and_collect();
    assert!(!status.success(), "a keyless orchestrator must not succeed");
    assert!(
        orch_stderr.contains("missing decryption keys"),
        "stderr must name the refusal: {orch_stderr}"
    );
    assert!(
        orch_stderr.contains("e2e-vault"),
        "stderr must name the vault: {orch_stderr}"
    );
    assert!(
        !orch_stderr.contains("worker-side reveal"),
        "no playbook code may run: {orch_stderr}"
    );
    assert!(
        !work_dir.join("reveal-ok.marker").exists(),
        "no playbook side effects before the refusal"
    );
}

/// The worker-side half of the refusal: the worker binary demands
/// `e2e-worker-vault` (registered by a remote-gated `secret!` site the
/// orchestrator build never sees), the orchestrator ships no keys, and
/// the worker must die at the handshake — before dispatching the
/// scenario's marker-creating call. If it ever dispatched instead, the
/// marker would exist and this test would fail.
#[test]
fn worker_refuses_a_keyless_handshake_before_any_code_runs() {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let work_dir = tmp.path().join("work");
    let empty_keys_dir = tempfile::tempdir().expect("create empty keys dir");

    let host_context = serde_json::json!({
        "name": "localhost",
        "tags": ["example:e2e"],
        "vars": {
            "work_dir": work_dir,
            "fetch_url": "http://127.0.0.1/",
            "fetch_sha256": "",
        },
    });

    let play = start_play_with_worker(
        tmp.path(),
        &host_context,
        &[
            ("CINDY_E2E_WORKER_KEYLESS", "1"),
            ("CINDY_KEYS_DIR", empty_keys_dir.path().to_str().unwrap()),
        ],
        &[("CINDY_KEYS_DIR", empty_keys_dir.path().to_str().unwrap())],
        "remote,worker-vault-demand",
    );
    let (status, _orch_stderr, worker_stderr) = play.wait_and_collect();
    assert!(
        !status.success(),
        "the orchestrator must fail when its worker refuses the handshake"
    );
    assert!(
        worker_stderr.contains("missing decryption keys on the remote worker"),
        "the worker must state its refusal: {worker_stderr}"
    );
    assert!(
        worker_stderr.contains("e2e-worker-vault"),
        "the refusal must name the vault: {worker_stderr}"
    );
    assert!(
        !work_dir.join("must-not-exist.marker").exists(),
        "no playbook code may run after a refused handshake"
    );
}
