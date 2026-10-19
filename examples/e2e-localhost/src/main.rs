//! The e2e-localhost playbook. Each test in `tests/e2e.rs` picks a
//! scenario by setting its `CINDY_E2E_*` variable; with none set, it is
//! a play over every builtin.

use std::path::PathBuf;

#[cindy::wire]
pub struct Vars {
    work_dir: PathBuf,
    fetch_url: String,
    fetch_sha256: String,
    /// The same body without a `Content-Length`, so `max_bytes` has to
    /// bite mid-stream.
    #[serde(default)]
    fetch_url_unsized: String,
    /// The same body, behind a server that demands `Authorization`.
    #[serde(default)]
    fetch_url_authed: String,
    /// Stuffed past 128 KiB: the host context must survive being larger
    /// than one env var can hold.
    #[serde(default)]
    padding: String,
    /// Sealed, revealed on the worker: the key can only have arrived
    /// over the handshake.
    #[serde(default = "plain_secret")]
    secret: cindy::Secret<String>,
    #[serde(default)]
    secret_expected: String,
}

/// Only used when the context has no `secret` (a `Plain` never
/// serialises).
fn plain_secret() -> cindy::Secret<String> {
    cindy::Secret::new(String::new())
}

/// The tests supply the host context; this only has to exist.
#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    cindy::Inventory::new([cindy::Host::new(
        "localhost",
        ["example:e2e"],
        Vars {
            work_dir: std::env::temp_dir().join("cindy-e2e"),
            fetch_url: "http://127.0.0.1/".into(),
            fetch_sha256: String::new(),
            fetch_url_unsized: "http://127.0.0.1/".into(),
            fetch_url_authed: "http://127.0.0.1/".into(),
            padding: String::new(),
            secret: plain_secret(),
            secret_expected: String::new(),
        },
    )])
}

#[cindy::remote]
fn reveal_on_worker(secret: cindy::Secret<String>) -> cindy::Result<String> {
    secret.reveal()
}

/// Must never run: the keyless-handshake test asserts its marker is
/// absent.
#[cindy::remote]
fn keyless_marker(dest: PathBuf) -> cindy::Result<()> {
    std::fs::write(dest, b"ran")?;
    Ok(())
}

/// Never called; its `secret!` makes the `worker-vault-demand` worker
/// build demand a vault. Link-time registration, so it is gated on
/// both: the orchestrator must not demand it (its own preflight would
/// fire first), nor must any other scenario's worker.
#[cfg(all(feature = "remote", feature = "worker-vault-demand"))]
#[allow(dead_code, deprecated)]
fn worker_side_vault_demand() -> cindy::Secret<String> {
    cindy::secret!("e2e-worker-vault", "never evaluated".to_owned())
}

/// Sleeps long enough for overlapping calls to be seen, and reports
/// the most it saw at once.
#[cindy::remote]
fn budget_probe(data: Vec<u8>) -> (usize, usize) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONCURRENT: AtomicUsize = AtomicUsize::new(0);
    static MAX_SEEN: AtomicUsize = AtomicUsize::new(0);

    let now = CONCURRENT.fetch_add(1, Ordering::SeqCst) + 1;
    MAX_SEEN.fetch_max(now, Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(100));
    CONCURRENT.fetch_sub(1, Ordering::SeqCst);

    (data.len(), MAX_SEEN.load(Ordering::SeqCst))
}

/// An io error under a context, as builtins fail.
#[cindy::remote]
fn read_missing(path: PathBuf) -> cindy::Result<Vec<u8>> {
    use cindy::Context;
    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
}

#[cindy::wire]
enum TypedFailure {
    Missing { what: String },
}

#[cindy::remote]
fn typed_failure(what: String) -> Result<(), TypedFailure> {
    Err(TypedFailure::Missing { what })
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use scenarios::*;

    let on = |var| std::env::var_os(var).is_some();
    let vars = &host.vars;
    if on("CINDY_E2E_SLEEP") {
        worker_dies_mid_call().await
    } else if on("CINDY_E2E_BUDGET") {
        worker_budget_serialises_calls().await
    } else if on("CINDY_E2E_ORCH_BUDGET") {
        orchestrator_budget_paces_without_deadlock().await
    } else if on("CINDY_E2E_SECRETS") {
        secret_reveals_on_the_worker(vars).await
    } else if on("CINDY_E2E_REMOTE_ERRORS") {
        remote_errors_keep_their_chain(vars).await
    } else if on("CINDY_E2E_LIB_REMOTE") {
        lib_remote_fns_reach_the_worker(vars).await
    } else if on("CINDY_E2E_WORKER_KEYLESS") {
        keyless_marker(vars.work_dir.join("must-not-exist.marker")).await
    } else if on("CINDY_E2E_FETCH_LIMITS") {
        fetch_limits(vars).await
    } else if on("CINDY_E2E_DRY_RUN") {
        check_mode_applies_nothing(vars).await
    } else {
        every_builtin(vars).await
    }
}

#[cfg(feature = "orchestrator")]
mod scenarios {
    use super::*;
    use cindy::builtin::{self, command, fetch, path};

    fn mode(bits: u32) -> cindy::Result<path::Mode> {
        path::Mode::try_from(bits)
    }

    async fn work_dir(vars: &Vars) -> cindy::Result<()> {
        let (user, group) = builtin::current_owner_names();
        path::directory(vars.work_dir.clone(), &user, &group, mode(0o755)?).await?;
        Ok(())
    }

    /// The test kills the worker during this; we must fail fast, not
    /// wait forever for the response.
    pub async fn worker_dies_mid_call() -> cindy::Result<()> {
        command::command(vec!["sleep".into(), "30".into()], command::State::default()).await?;
        Ok(())
    }

    /// Under a 64 KiB worker budget only one ~40 KiB call fits at once.
    pub async fn worker_budget_serialises_calls() -> cindy::Result<()> {
        let blob = vec![7u8; 40 * 1024];
        let results =
            futures_util::future::join_all((0..8).map(|_| budget_probe(blob.clone()))).await;
        for (len, max_concurrent) in results {
            if len != blob.len() {
                cindy::bail!("budget probe data mangled: {len} != {}", blob.len());
            }
            if max_concurrent != 1 {
                cindy::bail!(
                    "worker ran {max_concurrent} probes concurrently under a 64 KiB budget"
                );
            }
        }
        Ok(())
    }

    /// A 64 KiB orchestrator budget under 32 such calls: dispatch parks,
    /// routing doesn't, and every call completes intact. (Worker-side
    /// concurrency isn't constrained here.)
    pub async fn orchestrator_budget_paces_without_deadlock() -> cindy::Result<()> {
        let blob = vec![7u8; 40 * 1024];
        let results =
            futures_util::future::join_all((0..32).map(|_| budget_probe(blob.clone()))).await;
        for (len, _) in results {
            if len != blob.len() {
                cindy::bail!(
                    "orchestrator budget probe data mangled: {len} != {}",
                    blob.len()
                );
            }
        }
        Ok(())
    }

    pub async fn secret_reveals_on_the_worker(vars: &Vars) -> cindy::Result<()> {
        let revealed = reveal_on_worker(vars.secret.clone()).await?;
        if revealed != vars.secret_expected {
            cindy::bail!(
                "worker-side reveal returned {revealed:?}, expected {:?}",
                vars.secret_expected
            );
        }
        std::fs::create_dir_all(&vars.work_dir)?;
        std::fs::write(vars.work_dir.join("reveal-ok.marker"), b"ok\n")?;
        Ok(())
    }

    /// Reported, not asserted, so the test shows what actually arrived.
    pub async fn remote_errors_keep_their_chain(vars: &Vars) -> cindy::Result<()> {
        let err = read_missing(vars.work_dir.join("does-not-exist"))
            .await
            .expect_err("reading a missing file succeeded");
        let chain: Vec<String> = err.chain().map(ToString::to_string).collect();
        let io_kind = err.downcast_ref::<std::io::Error>().map(|e| e.kind());
        let typed = match typed_failure("eth0".to_owned()).await {
            Err(TypedFailure::Missing { what }) => what,
            Ok(()) => "<succeeded>".to_owned(),
        };
        std::fs::create_dir_all(&vars.work_dir)?;
        let report = serde_json::json!({
            "chain": chain,
            "rendered": format!("{err:#}"),
            "io_kind": format!("{io_kind:?}"),
            "typed_what": typed,
        });
        std::fs::write(
            vars.work_dir.join("remote-errors.json"),
            serde_json::to_vec(&report)?,
        )?;
        Ok(())
    }

    /// The worker's `main.rs` never names the lib on its own.
    pub async fn lib_remote_fns_reach_the_worker(vars: &Vars) -> cindy::Result<()> {
        let echoed = e2e_localhost::lib_side_echo("ping".to_owned()).await?;
        std::fs::create_dir_all(&vars.work_dir)?;
        std::fs::write(vars.work_dir.join("lib-remote.marker"), echoed)?;
        Ok(())
    }

    /// Fails unless `attempt` fails and leaves nothing at `dest`.
    async fn refused(
        what: &str,
        dest: &std::path::Path,
        attempt: impl std::future::Future<Output = cindy::Result<builtin::Return>>,
    ) -> cindy::Result<()> {
        if attempt.await.is_ok() {
            cindy::bail!("fetch accepted {what}");
        }
        if dest.exists() {
            cindy::bail!("refusing {what} left {} behind", dest.display());
        }
        Ok(())
    }

    /// Streaming fetch keeps its promises: oversized bodies refused
    /// (declared or not), a bad checksum publishes nothing, headers
    /// reach the server, and a satisfied destination isn't re-fetched.
    pub async fn fetch_limits(vars: &Vars) -> cindy::Result<()> {
        work_dir(vars).await?;
        let work = &vars.work_dir;
        let sha256 = || Some(fetch::Checksum::Sha256(vars.fetch_sha256.clone()));
        let token = |t: &str| -> cindy::Result<_> {
            Ok(vec![("Authorization".into(), fetch::HeaderValue::new(t)?)])
        };

        let dest = work.join("over-declared.bin");
        refused(
            "a body whose Content-Length exceeded max_bytes",
            &dest,
            fetch::fetch(fetch::State {
                url: vars.fetch_url.clone(),
                dest: dest.clone(),
                max_bytes: Some(4),
                ..Default::default()
            }),
        )
        .await?;

        let dest = work.join("over-streamed.bin");
        refused(
            "an undeclared body that exceeded max_bytes",
            &dest,
            fetch::fetch(fetch::State {
                url: vars.fetch_url_unsized.clone(),
                dest: dest.clone(),
                max_bytes: Some(4),
                ..Default::default()
            }),
        )
        .await?;

        let dest = work.join("bad-checksum.bin");
        refused(
            "a body that failed its checksum",
            &dest,
            fetch::fetch(fetch::State {
                url: vars.fetch_url.clone(),
                dest: dest.clone(),
                checksum: Some(fetch::Checksum::Sha256("0".repeat(64))),
                ..Default::default()
            }),
        )
        .await?;

        let good = work.join("streamed.bin");
        let fetched = fetch::fetch(fetch::State {
            url: vars.fetch_url.clone(),
            dest: good.clone(),
            checksum: sha256(),
            mode: Some(mode(0o644)?),
            ..Default::default()
        });
        if !fetched.await?.changed() {
            cindy::bail!("first fetch of {} reported Unchanged", good.display());
        }

        let authed = work.join("authed.bin");
        let fetched = fetch::fetch(fetch::State {
            url: vars.fetch_url_authed.clone(),
            dest: authed.clone(),
            checksum: sha256(),
            headers: token("Bearer cindy-e2e-token")?,
            ..Default::default()
        });
        if !fetched.await?.changed() {
            cindy::bail!("authed fetch reported Unchanged for a missing file");
        }

        let dest = work.join("authed-denied.bin");
        refused(
            "a fetch without the header the server demands",
            &dest,
            fetch::fetch(fetch::State {
                url: vars.fetch_url_authed.clone(),
                dest: dest.clone(),
                ..Default::default()
            }),
        )
        .await?;

        // With a token the server rejects: re-requesting would fail.
        let refetched = fetch::fetch(fetch::State {
            url: vars.fetch_url_authed.clone(),
            dest: authed.clone(),
            checksum: sha256(),
            headers: token("Bearer wrong-token")?,
            ..Default::default()
        });
        if refetched.await?.changed() {
            cindy::bail!("satisfied authed fetch re-requested instead of skipping");
        }

        // Drifted mode on satisfied content is repaired without a
        // transfer: the URL is unreachable.
        command::command(
            vec!["chmod".into(), "600".into(), good.display().to_string()],
            command::State::default(),
        )
        .await?
        .exit_ok()?;
        let repaired = fetch::fetch(fetch::State {
            url: "http://127.0.0.1:1/unreachable".into(),
            dest: good.clone(),
            checksum: sha256(),
            mode: Some(mode(0o644)?),
            ..Default::default()
        });
        if !repaired.await?.changed() {
            cindy::bail!("mode drift on a satisfied destination was not reported as Changed");
        }
        Ok(())
    }

    /// Run with CINDY_DRY_RUN=1: everything reports a change, nothing
    /// is applied, probes still run.
    pub async fn check_mode_applies_nothing(vars: &Vars) -> cindy::Result<()> {
        if !cindy::dry_run() {
            cindy::bail!("orchestrator-side dry_run() is false under --check");
        }
        let (user, group) = builtin::current_owner_names();
        let probe = vars.work_dir.join("dry-run-probe.txt");
        let file = path::file(
            probe.clone(),
            b"must not exist after the run".to_vec(),
            &user,
            &group,
            mode(0o644)?,
        );
        if !file.await?.changed() {
            cindy::bail!("path::file reported Unchanged for a missing file under --check");
        }

        let out = command::command(vec!["true".into()], command::State::default()).await?;
        if out.status != command::Status::Skipped {
            cindy::bail!("command executed under --check: the worker never got the flag");
        }
        out.exit_ok()?;

        let probed = command::probe(vec!["echo".into(), "probe-ran-under-check".into()]).await?;
        if probed.status == command::Status::Skipped {
            cindy::bail!("probe was suppressed under --check; its whole point is to run");
        }
        if probed.stdout.trim() != "probe-ran-under-check" {
            cindy::bail!(
                "probe returned {:?} under --check, not its real stdout",
                probed.stdout
            );
        }

        // The file above was reported, not created: a probe sees that.
        let looked = command::probe_shell(
            "/bin/sh",
            format!("test -e {} && echo present || echo absent", probe.display()),
        )
        .await?;
        if looked.stdout.trim() != "absent" {
            cindy::bail!(
                "probe_shell saw {:?}; check mode created the file it only \
                 reported, or the probe didn't really run",
                looked.stdout
            );
        }
        Ok(())
    }

    /// Every builtin once. The play can't hand data back to the harness
    /// except through the target, so it writes a JSON report the test
    /// reads.
    pub async fn every_builtin(vars: &Vars) -> cindy::Result<()> {
        work_dir(vars).await?;
        let work = &vars.work_dir;
        let (user, group) = builtin::current_owner_names();

        let greeting = work.join("greeting.txt");
        path::file(
            greeting.clone(),
            "hello from cindy\n".as_bytes(),
            &user,
            &group,
            mode(0o644)?,
        )
        .await?;
        path::link(work.join("greeting.link"), greeting.clone(), &user, &group).await?;

        let echo = command::command(
            vec!["echo".into(), "command-module-ran".into()],
            command::State::default(),
        )
        .await?
        .exit_ok()?;

        let shell_marker = work.join("shell-marker");
        command::shell(
            "/bin/sh".into(),
            format!("printf done > {}", shell_marker.display()),
            command::State::default(),
        )
        .await?
        .exit_ok()?;

        let downloaded = work.join("downloaded.bin");
        fetch::fetch(fetch::State {
            url: vars.fetch_url.clone(),
            dest: downloaded.clone(),
            checksum: Some(fetch::Checksum::Sha256(vars.fetch_sha256.clone())),
            mode: Some(mode(0o644)?),
            ..Default::default()
        })
        .await?;

        let tarball = work.join("bundle.tar.gz");
        builtin::archive::archive(builtin::archive::State {
            sources: vec![greeting.clone()],
            dest: tarball.clone(),
            format: None,
            mode: Some(mode(0o644)?),
        })
        .await?;
        let extract_dir = work.join("extracted");
        builtin::unarchive::extract(tarball.clone(), extract_dir.clone()).await?;

        let payload = b"the quick brown fox jumps over the lazy dog".repeat(64);
        let compressed = builtin::compress::compress(payload.clone(), builtin::Codec::Zstd).await?;
        let restored =
            builtin::decompress::decompress(compressed.clone(), builtin::Codec::Zstd).await?;

        let report = serde_json::json!({
            "command_stdout": echo.stdout.trim(),
            "shell_marker_exists": shell_marker.exists(),
            "downloaded_exists": downloaded.exists(),
            "tarball_exists": tarball.exists(),
            "extracted_greeting_exists": extract_dir.join("greeting.txt").exists(),
            "compressed_len": compressed.len(),
            "roundtrip_ok": restored == payload,
        });
        path::file(
            work.join("report.json"),
            serde_json::to_vec_pretty(&report)?,
            &user,
            &group,
            mode(0o644)?,
        )
        .await?;
        Ok(())
    }
}
