use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::Digest as _;

/// Body the in-process HTTP server returns, and that the play downloads.
const FETCH_BODY: &[u8] = b"downloaded-by-cindy-fetch-module\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the example with one feature set and return the binary path.
///
/// A dedicated `--target-dir` keeps this nested `cargo build` from
/// contending on the outer test invocation's build lock.
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

    // The last cargo "compiler-artifact" message with an executable is
    // our binary.
    let stdout = String::from_utf8(output.stdout).expect("cargo output not utf-8");
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|j| j["executable"].as_str().map(PathBuf::from))
        .next_back()
        .unwrap_or_else(|| panic!("no executable in cargo output for feature {feature}"))
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

    // --- build both sides --------------------------------------------
    let orchestrator_bin = build_variant("orchestrator");
    let remote_bin_src = build_variant("remote");

    // The remote worker deletes its own executable on startup (it's
    // designed to be an uploaded throwaway). Copy it to a temp path so
    // the cached build artifact survives for re-runs.
    let remote_bin = tmp.path().join("remote-worker");
    std::fs::copy(&remote_bin_src, &remote_bin).expect("copy remote worker");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&remote_bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&remote_bin, perms).unwrap();
    }

    // --- spawn both processes ----------------------------------------
    let mut remote = Command::new(&remote_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn remote worker");

    // Hand the context over the same way the CLI does: a temp file,
    // with the env var pointing at its path.
    let context_file = tempfile::NamedTempFile::new().expect("create context file");
    std::fs::write(context_file.path(), host_context.to_string()).expect("write host context");

    let mut orchestrator = Command::new(&orchestrator_bin)
        .env("CINDY_HOST_CONTEXT_FILE", context_file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orchestrator");

    // --- cross-pipe: orch stdout -> remote stdin, remote stdout -> orch stdin
    let mut o_out = orchestrator.stdout.take().unwrap();
    let mut r_in = remote.stdin.take().unwrap();
    let mut r_out = remote.stdout.take().unwrap();
    let mut o_in = orchestrator.stdin.take().unwrap();

    let pump_o_to_r = std::thread::spawn(move || {
        let _ = std::io::copy(&mut o_out, &mut r_in);
        // Closing the remote's stdin signals end-of-requests so its RPC
        // read loop terminates.
        drop(r_in);
    });
    let pump_r_to_o = std::thread::spawn(move || {
        let _ = std::io::copy(&mut r_out, &mut o_in);
        drop(o_in);
    });

    // --- wait for the orchestrator (it drives the play) --------------
    let orch_status = orchestrator.wait().expect("wait orchestrator");

    // The remote loops until its stdin closes; once the orchestrator is
    // done, the pump threads finish and the remote exits.
    let _ = pump_o_to_r.join();
    let _ = pump_r_to_o.join();
    let _ = remote.wait();

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

    let orchestrator_bin = build_variant("orchestrator");
    let remote_bin_src = build_variant("remote");
    let remote_bin = tmp.path().join("remote-worker");
    std::fs::copy(&remote_bin_src, &remote_bin).expect("copy remote worker");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&remote_bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&remote_bin, perms).unwrap();
    }

    let mut remote = Command::new(&remote_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn remote worker");

    let mut orchestrator = Command::new(&orchestrator_bin)
        // Deliberately the legacy inline env hand-off: keeps coverage
        // for the `CINDY_HOST_CONTEXT` fallback path.
        .env("CINDY_HOST_CONTEXT", host_context.to_string())
        .env("CINDY_E2E_SLEEP", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orchestrator");

    let mut o_out = orchestrator.stdout.take().unwrap();
    let mut r_in = remote.stdin.take().unwrap();
    let mut r_out = remote.stdout.take().unwrap();
    let mut o_in = orchestrator.stdin.take().unwrap();

    std::thread::spawn(move || {
        let _ = std::io::copy(&mut o_out, &mut r_in);
        drop(r_in);
    });
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut r_out, &mut o_in);
        drop(o_in);
    });

    // Give the `sleep 30` call time to dispatch, then kill the worker.
    std::thread::sleep(std::time::Duration::from_secs(2));
    remote.kill().expect("kill remote worker");
    let killed_at = std::time::Instant::now();

    // The orchestrator must now exit non-zero on its own, well before
    // the 30s the remote call would have taken.
    let deadline = std::time::Duration::from_secs(15);
    let status = loop {
        if let Some(status) = orchestrator.try_wait().expect("try_wait orchestrator") {
            break status;
        }
        assert!(
            killed_at.elapsed() < deadline,
            "orchestrator still running {deadline:?} after the worker died — RPC hang regression"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };

    assert!(
        !status.success(),
        "orchestrator reported success although the worker died mid-call"
    );
    let _ = remote.wait();
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

    let orchestrator_bin = build_variant("orchestrator");
    let remote_bin_src = build_variant("remote");
    let remote_bin = tmp.path().join("remote-worker");
    std::fs::copy(&remote_bin_src, &remote_bin).expect("copy remote worker");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&remote_bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&remote_bin, perms).unwrap();
    }

    let mut remote = Command::new(&remote_bin)
        .env("CINDY_RPC_BUDGET", "65536")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn remote worker");

    let mut orchestrator = Command::new(&orchestrator_bin)
        .env("CINDY_HOST_CONTEXT", host_context.to_string())
        .env("CINDY_E2E_BUDGET", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orchestrator");

    let mut o_out = orchestrator.stdout.take().unwrap();
    let mut r_in = remote.stdin.take().unwrap();
    let mut r_out = remote.stdout.take().unwrap();
    let mut o_in = orchestrator.stdin.take().unwrap();

    let pump_o_to_r = std::thread::spawn(move || {
        let _ = std::io::copy(&mut o_out, &mut r_in);
        drop(r_in);
    });
    let pump_r_to_o = std::thread::spawn(move || {
        let _ = std::io::copy(&mut r_out, &mut o_in);
        drop(o_in);
    });

    let orch_status = orchestrator.wait().expect("wait orchestrator");
    let _ = pump_o_to_r.join();
    let _ = pump_r_to_o.join();
    let _ = remote.wait();

    assert!(
        orch_status.success(),
        "orchestrator exited with failure: {orch_status:?} — the byte budget \
         failed to serialise an oversized fan-out"
    );
}
