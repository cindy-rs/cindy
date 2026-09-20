//! Drives the *real* `cindy` binary through its whole play path —
//! inventory pull, `--limit` selection, preflight, worker build,
//! upload and run over the local transport, and the terminal summary —
//! against the fixture playbook in `fixture/`. That path was the last
//! untested stretch of the CLI: unit tests covered `--limit`'s
//! expression engine in isolation, but nothing proved the selected
//! set actually reaches deployment, or that unselected hosts never
//! run playbook code.
//!
//! Assertions work through the fixture's markers: a `#[remote]` fn
//! writes `<host>.marker` (playbook code ran on that host — even
//! under `--check`, which cindy documents as still running remote
//! fns) and a `path::file` builtin writes `<host>.config` (applied
//! only in a real play). See `fixture/src/main.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use tempfile::TempDir;

/// Serialises `cindy play` invocations across libtest's parallel
/// threads. The CLI shells out to `rustup` before building (the
/// rustup proxy is not concurrency-safe — see the FIXME in the CLI's
/// build path), and every play builds into the fixture's target dirs;
/// concurrent plays would race both for no gain — the first play's
/// builds dominate the suite's runtime and the rest hit the cache.
static PLAY_GATE: Mutex<()> = Mutex::new(());

/// Build the real `cindy` CLI once for the suite, into the monorepo's
/// own target dir. Memoised for the same reason e2e-localhost
/// memoises `build_variant`: concurrent `cargo build`s into one
/// target dir race (`ETXTBSY` on the binary under construction).
fn cindy_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        // examples/e2e-cli sits two levels under the repo root, whose
        // workspace holds cindy-cli. Debug profile: the CLI's logic is
        // what's under test — the heavy builds (the fixture's
        // orchestrator/worker) are driven by the CLI itself.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("e2e-cli sits two levels under the repo root");
        let output = Command::new(env!("CARGO"))
            .current_dir(root)
            .args(["build", "-p", "cindy-cli"])
            .output()
            .expect("failed to spawn cargo build");
        assert!(
            output.status.success(),
            "cargo build -p cindy-cli failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target"))
            .join("debug")
            .join("cindy")
    })
    .clone()
}

/// Run `cindy play --local <args>` in the fixture workspace with the
/// markers directory pointed at a fresh tempdir; returns the run's
/// success, its captured stderr, and the markers dir (kept alive —
/// and auto-cleaned — by the returned handle).
fn play(args: &[&str]) -> (bool, String, TempDir) {
    let _gate = PLAY_GATE.lock().expect("play gate mutex poisoned");
    let markers = TempDir::new().expect("markers tempdir");
    let output = Command::new(cindy_bin())
        .args(["play", "--local"])
        .args(args)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixture"))
        .env("E2E_CLI_MARKERS_DIR", markers.path())
        .output()
        .expect("failed to spawn cindy play");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        markers,
    )
}

/// The `<host>.marker` path — written by the fixture's remote fn when
/// playbook code runs on that host.
fn marker(markers: &TempDir, host: &str) -> PathBuf {
    markers.path().join(format!("{host}.marker"))
}

#[test]
fn full_run_plays_every_host() {
    let (ok, stderr, markers) = play(&[]);
    assert!(ok, "cindy play --local failed:\n{stderr}");
    assert!(
        stderr.contains("OK: all 3 hosts completed successfully"),
        "{stderr}"
    );
    assert!(!stderr.contains("FAILED:"), "{stderr}");
    for host in ["alpha", "beta", "gamma"] {
        assert!(
            marker(&markers, host).exists(),
            "{host} never ran playbook code"
        );
        let config = std::fs::read_to_string(markers.path().join(format!("{host}.config")))
            .unwrap_or_else(|e| panic!("{host} config unreadable: {e}"));
        assert_eq!(
            config,
            format!("managed by cindy for {host}"),
            "the host context (vars) must reach the play"
        );
    }
}

#[test]
fn limit_selects_tagged_hosts_only() {
    let (ok, stderr, markers) = play(&["--limit", "suite:one"]);
    assert!(ok, "cindy play --limit suite:one failed:\n{stderr}");
    assert!(
        stderr.contains("OK: all 2 hosts completed successfully"),
        "{stderr}"
    );
    assert!(!stderr.contains("all 3"), "{stderr}");
    for host in ["alpha", "beta"] {
        assert!(
            marker(&markers, host).exists(),
            "{host} never ran playbook code"
        );
    }
    // The unselected host ran nothing: no remote-fn marker, and no
    // builtin-applied file.
    assert!(
        !marker(&markers, "gamma").exists(),
        "gamma ran playbook code despite --limit suite:one"
    );
    assert!(
        !markers.path().join("gamma.config").exists(),
        "gamma was mutated despite --limit suite:one"
    );
}

#[test]
fn limit_expressions_compose_end_to_end() {
    let (ok, stderr, markers) = play(&["--limit", "suite:one & !beta"]);
    assert!(
        ok,
        "cindy play --limit 'suite:one & !beta' failed:\n{stderr}"
    );
    // Singular "host": the summary's count is the selection's size.
    assert!(
        stderr.contains("OK: all 1 host completed successfully"),
        "{stderr}"
    );
    assert!(
        marker(&markers, "alpha").exists(),
        "alpha never ran playbook code"
    );
    for host in ["beta", "gamma"] {
        assert!(
            !marker(&markers, host).exists(),
            "{host} ran playbook code despite the --limit expression"
        );
    }
}

#[test]
fn unknown_limit_term_fails_without_deploying() {
    let (ok, stderr, markers) = play(&["--limit", "prdo"]);
    assert!(
        !ok,
        "a typo'd --limit must fail the run, not no-op it:\n{stderr}"
    );
    assert!(
        stderr.contains("match no host name or tag"),
        "the failure must say what happened:\n{stderr}"
    );
    assert!(
        stderr.contains("prdo"),
        "the failure must name the unknown term:\n{stderr}"
    );
    assert!(!stderr.contains("OK:"), "{stderr}");
    for host in ["alpha", "beta", "gamma"] {
        assert!(
            !marker(&markers, host).exists(),
            "{host} ran playbook code despite a refused --limit"
        );
    }
}

#[test]
fn check_mode_applies_nothing() {
    let (ok, stderr, markers) = play(&["--check"]);
    assert!(ok, "cindy play --check failed:\n{stderr}");
    assert!(
        stderr.contains("OK: all 3 hosts completed successfully"),
        "{stderr}"
    );
    assert!(
        stderr.contains("check mode: nothing was applied"),
        "{stderr}"
    );
    for host in ["alpha", "beta", "gamma"] {
        // The builtin applied nothing — no managed file anywhere.
        assert!(
            !markers.path().join(format!("{host}.config")).exists(),
            "{host} was mutated under --check"
        );
        // Remote fns still run under --check (cindy can't know what
        // user code mutates — the flag's own docs say so); their
        // marker doubles here as the proof that check mode still
        // connected to every host and served the RPCs.
        assert!(
            marker(&markers, host).exists(),
            "{host} never ran playbook code under --check"
        );
    }
}
