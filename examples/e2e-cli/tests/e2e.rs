//! Drives the real `cindy` binary: whole plays (`play --local`) against
//! the fixture in `fixture/` — `--limit` selection reaching deployment,
//! the summary, `--check` applying nothing — and `secret vault rotate`
//! in throwaway workspaces.
//!
//! A play's evidence is the fixture's files: `<host>.marker` (playbook
//! code ran there) and `<host>.config` (a builtin applied).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use tempfile::TempDir;

/// One play at a time: the CLI runs `rustup`, whose proxy isn't
/// concurrency-safe, and every play builds into the fixture's target
/// dirs.
static PLAY_GATE: Mutex<()> = Mutex::new(());

/// Built once, in debug — the CLI's logic is under test; the heavy
/// builds are the fixture's, driven by the CLI.
fn cindy_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
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
fn local_flag_stays_hidden() {
    // `--local` exists for this suite and maintainer debugging, not as
    // a supported deploy mode — a real playbook run this way converges
    // the operator's own machine. If it ever grows a genuine user
    // case, un-hiding it must be a deliberate decision, not help-text
    // drift; this test forces that conversation.
    let help = Command::new(cindy_bin())
        .args(["play", "--help"])
        .output()
        .expect("failed to spawn cindy play --help");
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(!text.contains("--local"), "{text}");
    // Control: this is really the play subcommand's help.
    assert!(text.contains("--check"), "{text}");
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

/// A throwaway workspace (no dependencies, so `cargo metadata` needs no
/// network) holding one sealed site of vault `rot` under a fresh key,
/// spelled `prefix sealed_b64(..)`.
fn rotation_workspace(prefix: &str) -> (TempDir, Vec<u8>) {
    use base64::Engine as _;

    let ws = TempDir::new().expect("workspace tempdir");
    std::fs::write(
        ws.path().join("Cargo.toml"),
        "[package]\nname = \"rotation\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::create_dir(ws.path().join("src")).unwrap();
    std::fs::write(ws.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    let created = Command::new(cindy_bin())
        .args(["secret", "vault", "create", "rot"])
        .current_dir(ws.path())
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );

    let key = std::fs::read(ws.path().join("keys/rot.key")).unwrap();
    let vault_key = cindy::secret::crypto::VaultKey::new(key.clone().try_into().unwrap());
    let payload = cindy::secret::SealedPayload {
        value: postcard::to_allocvec("hello").unwrap(),
        source: "\"hello\"".to_owned(),
    };
    let blob =
        cindy::secret::crypto::seal(&vault_key, &postcard::to_allocvec(&payload).unwrap()).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    std::fs::write(
        ws.path().join("src/main.rs"),
        format!("fn main() {{\n    let _ = {prefix}sealed_b64(\"rot\", \"{b64}\");\n}}\n"),
    )
    .unwrap();
    (ws, key)
}

fn rotate(ws: &TempDir) -> (bool, String) {
    let out = Command::new(cindy_bin())
        .args(["secret", "vault", "rotate", "rot"])
        .current_dir(ws.path())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn rotate_reseals_onto_a_new_key_and_destroys_the_old() {
    use base64::Engine as _;

    let (ws, old_key) = rotation_workspace("::cindy::Secret::");
    let (ok, stderr) = rotate(&ws);
    assert!(ok, "rotate failed: {stderr}");

    let new_key = std::fs::read(ws.path().join("keys/rot.key")).unwrap();
    assert_ne!(new_key, old_key, "the key didn't change");
    assert!(
        !ws.path().join("keys/rot.key.previous").exists(),
        "the old key survived"
    );

    let source = std::fs::read_to_string(ws.path().join("src/main.rs")).unwrap();
    let b64 = source.split('"').nth(3).expect("a sealed_b64 call");
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    let new_key = cindy::secret::crypto::VaultKey::new(new_key.try_into().unwrap());
    let plaintext =
        cindy::secret::crypto::unseal(&new_key, &blob).expect("site isn't on the new key");
    let payload: cindy::secret::SealedPayload = postcard::from_bytes(&plaintext).unwrap();
    assert_eq!(
        postcard::from_bytes::<String>(&payload.value).unwrap(),
        "hello"
    );
}

/// A file the scanner can't tokenise might hold a site of the vault;
/// destroying the old key would lose it, so rotate refuses up front.
#[test]
fn rotate_refuses_while_an_unparseable_file_mentions_the_vault() {
    let (ws, old_key) = rotation_workspace("::cindy::Secret::");
    std::fs::write(
        ws.path().join("src/broken.rs"),
        "fn broken( { ::cindy::Secret::<String>::sealed_b64(\"rot\", \"AAAA\")",
    )
    .unwrap();

    let (ok, stderr) = rotate(&ws);
    assert!(!ok, "rotate went ahead past an unparseable file");
    assert!(
        stderr.contains("broken.rs") && stderr.contains("doesn't tokenise"),
        "{stderr}"
    );
    assert!(stderr.contains("Nothing was changed"), "{stderr}");
    assert_eq!(
        std::fs::read(ws.path().join("keys/rot.key")).unwrap(),
        old_key
    );
    assert!(!ws.path().join("keys/rot.key.previous").exists());
}

/// The rewriter only recognises `Secret::sealed_b64("vault", "…")`. A
/// site spelled otherwise used to be skipped, and rotation then
/// destroyed the only key that opened it.
#[test]
fn rotate_refuses_a_site_spelling_it_cannot_rewrite() {
    let (ws, old_key) = rotation_workspace("::cindy::Secret::<String>::");
    let (ok, stderr) = rotate(&ws);
    assert!(!ok, "rotate went ahead past a site it can't rewrite");
    assert!(
        stderr.contains("main.rs") && stderr.contains("can't read"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(ws.path().join("keys/rot.key")).unwrap(),
        old_key
    );
    assert!(!ws.path().join("keys/rot.key.previous").exists());
}
