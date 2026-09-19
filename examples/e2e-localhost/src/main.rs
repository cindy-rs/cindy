use std::path::PathBuf;

#[cindy::wire]
pub struct Vars {
    work_dir: PathBuf,
    fetch_url: String,
    fetch_sha256: String,
    /// Same body as `fetch_url`, served without a `Content-Length` — the
    /// only shape in which `max_bytes` has to bite mid-stream rather
    /// than off the declared length. Defaulted so the scenarios that
    /// don't exercise fetch can leave it out of their host context.
    #[serde(default)]
    fetch_url_unsized: String,
    /// Bulk payload holder: the e2e test stuffs >128 KiB into it to
    /// prove the host-context hand-off survives contexts too large
    /// for a single env var (kernel `MAX_ARG_STRLEN`).
    #[serde(default)]
    padding: String,
}

#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    // The test overrides this via the host-context hand-off; the
    // inventory body just needs to exist and type-check. Defaults are
    // harmless placeholders.
    cindy::Inventory {
        hosts: vec![cindy::Host {
            name: "localhost".into(),
            tags: vec!["example:e2e".into()],
            vars: Vars {
                work_dir: std::env::temp_dir().join("cindy-e2e"),
                fetch_url: "http://127.0.0.1/".into(),
                fetch_sha256: String::new(),
                fetch_url_unsized: "http://127.0.0.1/".into(),
                padding: String::new(),
            },
        }],
    }
}

/// RPC fan-out probe for the backpressure e2e scenario: sleeps long
/// enough that overlapping executions would certainly be observed,
/// and reports data integrity plus the highest concurrency seen so
/// far.
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

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use cindy::builtin;

    // Worker-death regression scenario (see tests/e2e.rs): issue one
    // long-running remote call; the harness kills the worker mid-call
    // and expects this process to fail fast instead of hanging on the
    // never-arriving response.
    if std::env::var_os("CINDY_E2E_SLEEP").is_some() {
        builtin::command::command(
            vec!["sleep".into(), "30".into()],
            builtin::command::State::default(),
        )
        .await?;
        return Ok(());
    }

    // Backpressure regression scenario (see tests/e2e.rs): the harness
    // squeezes the worker's RPC byte budget down to 64 KiB while this
    // play fans out eight ~40 KiB calls. At most one fits the budget
    // at a time, so the probes must execute strictly serially — a
    // leaked budget gate shows up as concurrent executions in the
    // probes' own observations.
    if std::env::var_os("CINDY_E2E_BUDGET").is_some() {
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
        return Ok(());
    }

    // Streaming-fetch regression scenario (see tests/e2e.rs). `fetch`
    // no longer buffers a body in RAM, which puts three promises on the
    // line: an over-sized body is refused (whether or not the server
    // declares a length), a failed checksum leaves the destination
    // untouched because verification happens before the publish, and an
    // already-satisfied destination is *not* re-downloaded.
    if std::env::var_os("CINDY_E2E_FETCH_LIMITS").is_some() {
        use builtin::fetch;

        let work = &host.vars.work_dir;
        let (user, group) = builtin::current_owner_names();
        builtin::path::directory(
            work.clone(),
            &user,
            &group,
            builtin::path::Mode::try_from(0o755)?,
        )
        .await?;

        // A body over the limit, rejected off the declared
        // Content-Length before any transfer starts.
        let declared = work.join("over-declared.bin");
        if fetch::fetch(fetch::State {
            url: host.vars.fetch_url.clone(),
            dest: declared.clone(),
            max_bytes: Some(4),
            ..Default::default()
        })
        .await
        .is_ok()
        {
            cindy::bail!("fetch accepted a body whose Content-Length exceeded max_bytes");
        }
        if declared.exists() {
            cindy::bail!(
                "rejected oversized fetch left {} behind",
                declared.display()
            );
        }

        // The same, with no declared length — the limit has to be
        // enforced as the bytes arrive.
        let streamed = work.join("over-streamed.bin");
        if fetch::fetch(fetch::State {
            url: host.vars.fetch_url_unsized.clone(),
            dest: streamed.clone(),
            max_bytes: Some(4),
            ..Default::default()
        })
        .await
        .is_ok()
        {
            cindy::bail!("fetch accepted an undeclared body that exceeded max_bytes");
        }
        if streamed.exists() {
            cindy::bail!(
                "rejected oversized stream left {} behind",
                streamed.display()
            );
        }

        // A checksum mismatch must not publish: the bytes are staged in
        // a temp file and only renamed once the digest agrees.
        let bad_sum = work.join("bad-checksum.bin");
        if fetch::fetch(fetch::State {
            url: host.vars.fetch_url.clone(),
            dest: bad_sum.clone(),
            checksum: Some(fetch::Checksum::Sha256("0".repeat(64))),
            ..Default::default()
        })
        .await
        .is_ok()
        {
            cindy::bail!("fetch accepted a body that failed its checksum");
        }
        if bad_sum.exists() {
            cindy::bail!(
                "failed-checksum fetch published {} anyway",
                bad_sum.display()
            );
        }

        // A good fetch lands the bytes…
        let good = work.join("streamed.bin");
        if !fetch::fetch(fetch::State {
            url: host.vars.fetch_url.clone(),
            dest: good.clone(),
            checksum: Some(fetch::Checksum::Sha256(host.vars.fetch_sha256.clone())),
            mode: Some(builtin::path::Mode::try_from(0o644)?),
            ..Default::default()
        })
        .await?
        .changed()
        {
            cindy::bail!("first fetch of {} reported Unchanged", good.display());
        }

        // …and a re-run whose content is already satisfied must repair
        // drifted permissions *without* transferring anything. Pointing
        // it at a refused port is the proof: if it re-downloaded, this
        // call would fail instead of fixing the mode.
        builtin::command::command(
            vec!["chmod".into(), "600".into(), good.display().to_string()],
            builtin::command::State::default(),
        )
        .await?
        .exit_ok()?;
        if !fetch::fetch(fetch::State {
            url: "http://127.0.0.1:1/unreachable".into(),
            dest: good.clone(),
            checksum: Some(fetch::Checksum::Sha256(host.vars.fetch_sha256.clone())),
            mode: Some(builtin::path::Mode::try_from(0o644)?),
            ..Default::default()
        })
        .await?
        .changed()
        {
            cindy::bail!("mode drift on a satisfied destination was not reported as Changed");
        }

        return Ok(());
    }

    // Check-mode scenario (see tests/e2e.rs): the harness runs the
    // orchestrator with CINDY_DRY_RUN=1, which reaches the worker
    // through the RPC handshake. Every builtin below must report a
    // would-change and apply nothing — the harness asserts the probe
    // file was never created and this process exited 0.
    if std::env::var_os("CINDY_E2E_DRY_RUN").is_some() {
        let (user, group) = builtin::current_owner_names();
        let probe = host.vars.work_dir.join("dry-run-probe.txt");
        let file_return = builtin::path::file(
            probe.clone(),
            b"must not exist after the run".to_vec(),
            &user,
            &group,
            builtin::path::Mode::try_from(0o644)?,
        )
        .await?;
        if !file_return.changed() {
            cindy::bail!("path::file reported Unchanged for a missing file under --check");
        }
        let out =
            builtin::command::command(vec!["true".into()], builtin::command::State::default())
                .await?;
        if !out.dry_run {
            cindy::bail!("command executed under --check: the worker never got the flag");
        }
        out.exit_ok()?;
        return Ok(());
    }

    let work = &host.vars.work_dir;

    // --- path: directory, file, symlink -------------------------------
    let (user, group) = builtin::current_owner_names();
    builtin::path::directory(
        work.clone(),
        &user,
        &group,
        builtin::path::Mode::try_from(0o755)?,
    )
    .await?;

    let greeting = work.join("greeting.txt");
    builtin::path::file(
        greeting.clone(),
        "hello from cindy\n".as_bytes(),
        &user,
        &group,
        builtin::path::Mode::try_from(0o644)?,
    )
    .await?;

    let link = work.join("greeting.link");
    builtin::path::link(link.clone(), greeting.clone(), &user, &group).await?;

    // --- command: run a program directly, capture its output ----------
    let echo = builtin::command::command(
        vec!["echo".into(), "command-module-ran".into()],
        builtin::command::State::default(),
    )
    .await?
    .exit_ok()?;
    if echo.stdout.trim() != "command-module-ran" {
        cindy::bail!("command stdout was {:?}", echo.stdout);
    }

    // --- shell: explicit interpreter, writes a marker file ------------
    let shell_marker = work.join("shell-marker");
    builtin::command::shell(
        "/bin/sh".into(),
        format!("printf done > {}", shell_marker.display()),
        builtin::command::State::default(),
    )
    .await?
    .exit_ok()?;

    // --- fetch: download with checksum verification -------------------
    let downloaded = work.join("downloaded.bin");
    builtin::fetch::fetch(builtin::fetch::State {
        url: host.vars.fetch_url.clone(),
        dest: downloaded.clone(),
        checksum: Some(builtin::fetch::Checksum::Sha256(
            host.vars.fetch_sha256.clone(),
        )),
        mode: Some(builtin::path::Mode::try_from(0o644)?),
        ..Default::default()
    })
    .await?;

    // --- archive + unarchive: tar.gz round-trip of the work dir -------
    let tarball = work.join("bundle.tar.gz");
    builtin::archive::archive(builtin::archive::State {
        sources: vec![greeting.clone()],
        dest: tarball.clone(),
        format: None,                                      // inferred from `.tar.gz`
        mode: Some(builtin::path::Mode::try_from(0o644)?), // readable so `unarchive` can read it back
    })
    .await?;

    let extract_dir = work.join("extracted");
    builtin::unarchive::unarchive(builtin::unarchive::State {
        src: tarball.clone(),
        dest: extract_dir.clone(),
        format: None,
        max_bytes: None,
    })
    .await?;

    // --- compress + decompress: raw byte round-trip -------------------
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(64);
    let compressed = builtin::compress::compress(payload.clone(), builtin::Codec::Zstd).await?;
    let restored =
        builtin::decompress::decompress(compressed.clone(), builtin::Codec::Zstd).await?;
    if restored != payload {
        cindy::bail!("zstd round-trip mismatch");
    }

    // --- write a machine-readable summary the test asserts on ---------
    //
    // The play can't return structured data to the harness (the process
    // just exits 0/1), so it drops a JSON report into the work dir that
    // the test reads back.
    use std::collections::BTreeMap;
    let mut report: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    report.insert("command_stdout", echo.stdout.trim().into());
    report.insert("shell_marker_exists", shell_marker.exists().into());
    report.insert("downloaded_exists", downloaded.exists().into());
    report.insert("tarball_exists", tarball.exists().into());
    report.insert(
        "extracted_greeting_exists",
        extract_dir.join("greeting.txt").exists().into(),
    );
    report.insert("compressed_len", (compressed.len() as u64).into());
    report.insert("roundtrip_ok", (restored == payload).into());

    let report_path = work.join("report.json");
    builtin::path::file(
        report_path,
        serde_json::to_vec_pretty(&report).expect("serialise report"),
        &user,
        &group,
        builtin::path::Mode::try_from(0o644)?,
    )
    .await?;

    Ok(())
}
