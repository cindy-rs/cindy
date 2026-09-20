mod conditional_sudo_command;
mod limit;
mod picker;
mod progress;
mod secret;
mod transport;

use transport::{HostChild, Transport};

use clap::Parser;
use eyre::{ContextCompat as _, WrapErr as _};
use futures_util::future::try_join_all;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::Instrument as _;

/// Stable replacement for the nightly `ExitStatus::exit_ok`: turn a non-zero
/// process exit into an error rather than silently succeeding.
trait ExitOk {
    fn exit_ok(self) -> eyre::Result<()>;
}
impl ExitOk for std::process::ExitStatus {
    fn exit_ok(self) -> eyre::Result<()> {
        if self.success() {
            Ok(())
        } else {
            eyre::bail!("process exited with {self}");
        }
    }
}

/// Like [`ExitOk`] but for a captured [`std::process::Output`], returning the
/// output on success and the captured stderr as the error otherwise.
trait OutputOrError: Sized {
    fn ok_or_die(self) -> eyre::Result<Self>;
}
impl OutputOrError for std::process::Output {
    fn ok_or_die(self) -> eyre::Result<Self> {
        if !self.status.success() {
            eyre::bail!("{}", String::from_utf8_lossy(&self.stderr));
        }
        Ok(self)
    }
}

#[derive(Debug, clap::Subcommand)]
enum Subcommand {
    Play {
        #[clap(long)]
        limit: Option<String>,
        #[clap(long)]
        unprivileged: bool,
        /// Run every selected host as a local process on this machine —
        /// no SSH, no `cross`/podman (the worker builds and runs
        /// natively). Hidden on purpose: this is the e2e harness's
        /// transport seam and a maintainer debugging aid, not a
        /// supported deploy mode — a real playbook run this way
        /// converges this box as the invoking user. Sudo is never
        /// applied.
        #[clap(long, hide = true)]
        local: bool,
        /// Check mode: build everything, connect everywhere, render
        /// every diff — but apply nothing. Builtins report what they
        /// *would* change; `command`/`shell` don't execute; custom
        /// `#[remote]` functions still run (cindy can't know what user
        /// code mutates).
        #[clap(long)]
        check: bool,
    },
    Inventory {
        #[clap(long)]
        host: Option<String>,
        #[clap(long)]
        json: bool,
        #[clap(long)]
        reveal: bool,
    },
    /// Manage vaulted secrets (`Secret<T>`-typed values in your
    /// inventory). See `cindy secret --help` for sub-commands.
    #[clap(subcommand)]
    Secret(secret::SecretCommand),
}

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Debug)]
struct DiscoveredHost {
    host: cindy::Host<serde_json::Value>,
    transport: Transport,
    platform: &'static platforms::Platform,
    use_sudo: bool,
}

/// Read a child's stderr line by line and forward each (tagged with its
/// `source` and host `idx`) to the progress view. Generic over the reader so
/// it serves both the SSH worker and the local orchestrator. Ends at EOF.
async fn forward_stderr(
    mut reader: impl AsyncBufRead + Unpin,
    tx: tokio::sync::mpsc::UnboundedSender<progress::Msg>,
    idx: usize,
    source: progress::Source,
) {
    let mut line = String::new();
    loop {
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let _ = tx.send(progress::Msg::Line(idx, source, line.trim_end().to_owned()));
                line.clear();
            }
            Err(e) => {
                // A read error usually just means the child died mid-line;
                // its exit status carries the real story.
                tracing::debug!(error = %e, "stderr forwarder read failed");
                break;
            }
        }
    }
}

/// Make `KnownHosts::Add`'s trust-on-first-use visible: when `target`
/// has no entry in the user's known_hosts, scan its host keys and log
/// their fingerprints before connecting.
///
/// `Add` maps to `StrictHostKeyChecking=accept-new`: an unknown key is
/// accepted and recorded with no operator-visible fingerprint (ssh's
/// own "Permanently added" warning names neither the key type nor its
/// hash, and the openssh crate surfaces nothing at all). The scan and
/// the connect are two connections, so a race between them is
/// theoretically possible — but the accept-new model already trusts
/// whatever the connect-time handshake presents; this only records it.
/// Non-fatal by design: an unreachable or keyscan-less host fails at
/// the real connect with the real error.
async fn log_tofu_fingerprints(target: &str) {
    // `target` may carry `user@` and `:port`; keygen matches on the
    // bare host ssh itself uses, keyscan takes `-p` for the port.
    let rest = target.split_once('@').map_or(target, |(_, rest)| rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => (host, port),
        _ => (rest, "22"),
    };

    let already_known = tokio::process::Command::new("ssh-keygen")
        .args(["-F", host])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .map(|out| out.status.success())
        .unwrap_or(false);
    if already_known {
        return;
    }

    let mut scan = tokio::process::Command::new("ssh-keyscan");
    scan.args(["-T", "3"]).stdin(std::process::Stdio::null());
    if port != "22" {
        scan.args(["-p", port]);
    }
    let Ok(scan) = scan.arg(host).output().await else {
        return;
    };
    for line in String::from_utf8_lossy(&scan.stdout).lines() {
        // `<host> <key type> <base64 key blob>`
        let mut fields = line.split_whitespace();
        let (Some(_), Some(key_type), Some(blob)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if let Some(fp) = ssh_fingerprint(blob) {
            tracing::warn!(
                "TOFU: no known_hosts entry for {target} — accepting {key_type} key \
                 SHA256:{fp}; audit with `ssh-keygen -lf ~/.ssh/known_hosts` if this \
                 is a first connection"
            );
        }
    }
}

/// `SHA256:<unpadded base64 of SHA256(key blob)>` — the same digest
/// `ssh-keygen -lf` prints, so logged lines can be diffed against
/// known_hosts entries by eye.
fn ssh_fingerprint(blob_b64: &str) -> Option<String> {
    use base64::Engine as _;
    use sha2::Digest as _;

    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .ok()?;
    let digest = sha2::Sha256::digest(&blob);
    Some(base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
}

/// Staging candidates in preference order. `/tmp` is the traditional
/// default; `/var/tmp` is its rarely-noexec sibling (it usually lives
/// on the root filesystem, while `/tmp` is what hardening guides and
/// systemd tmp.mount flag).
const STAGING_CANDIDATES: [&str; 2] = ["/tmp", "/var/tmp"];

/// The first staging candidate whose mount allows execution, per the
/// target's `/proc/mounts`. Unparseable input or no matching mount
/// falls back to the last candidate — the exec-126 diagnosis is the
/// backstop when even that can't run.
fn staging_dir_from_mounts(mounts: &str) -> &'static str {
    STAGING_CANDIDATES
        .iter()
        .find(|candidate| mount_allows_exec(mounts, candidate))
        .copied()
        .unwrap_or(STAGING_CANDIDATES[STAGING_CANDIDATES.len() - 1])
}

/// `true` unless the longest mount point containing `path` is mounted
/// `noexec`. `/proc/mounts` fields: device, mount point, fstype,
/// options (comma-separated), …
fn mount_allows_exec(mounts: &str, path: &str) -> bool {
    mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _device = fields.next()?;
            let point = fields.next()?;
            let _fstype = fields.next()?;
            let options = fields.next()?;
            Some((point, options))
        })
        .filter(|(point, _)| {
            // Prefix match on path boundaries: `/tmp` must not match a
            // hypothetical `/tmpfoo` mount.
            path == *point
                || path
                    .strip_prefix(point)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .max_by_key(|(point, _)| point.len())
        .map(|(_, options)| !options.split(',').any(|opt| opt == "noexec"))
        .unwrap_or(true)
}

/// The inventory as pulled from the orchestrator: the type-erased
/// `Inventory<Value>` used for `--limit` targeting, plus the per-host
/// (and whole-inventory) `Debug` renderings the orchestrator produced
/// from the user's real `V`.
struct PulledInventory {
    inventory: cindy::Inventory<serde_json::Value>,
    debug: std::collections::BTreeMap<String, String>,
    /// Present only when the dump ran in reveal mode. `Ok` holds the
    /// secrets-decrypted whole-inventory JSON; `Err` holds the failure
    /// (e.g. a missing vault key) to surface if `--json` was requested.
    json_revealed: Option<Result<serde_json::Value, String>>,
}

async fn get_inventory(
    orchestrator_exe_path: &Path,
    reveal_secrets: bool,
) -> eyre::Result<PulledInventory> {
    tracing::info!("Pulling inventory from orchestrator binary...");
    let mut cmd = tokio::process::Command::new(orchestrator_exe_path);
    cmd.env("CINDY_DUMP_INVENTORY", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if reveal_secrets {
        // The orchestrator decrypts `Secret<T>` values while rendering
        // the Debug map. Vault keys are read from `keys/<vault>.key`
        // relative to the orchestrator's cwd (this process's cwd).
        cmd.env("CINDY_REVEAL_SECRETS", "1");
    }
    let dump = cmd.output().await?;
    if !dump.status.success() {
        eyre::bail!(
            "inventory dump exited with {:?}\n{}",
            dump.status,
            String::from_utf8_lossy(&dump.stderr)
        );
    }
    let dump: cindy::inventory::InventoryDump = serde_json::from_slice(&dump.stdout)
        .context("Failed to parse inventory dump from orchestrator")?;
    let inventory = serde_json::from_value(dump.json)
        .context("Failed to parse inventory JSON from orchestrator dump")?;
    Ok(PulledInventory {
        inventory,
        debug: dump.debug,
        json_revealed: dump.json_revealed,
    })
}

/// Absolute path to the Cargo workspace root, resolved via `cargo metadata`.
///
/// Every build the CLI drives uses an absolute `--target-dir` anchored here
/// so the worker/orchestrator binaries land — and are read back from — the
#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    color_eyre::install()?;
    // One `cargo metadata` run for the whole invocation: the workspace
    // root (anchoring `--target-dir`, so a relative one can't silently
    // diverge from the absolute paths we later compute) and the
    // package/target facts `extract_executable` pins the deployed bin
    // with both come from it.
    let cargo_meta = Arc::new(cargo_metadata::MetadataCommand::new().exec()?);
    let workspace_root = cargo_meta.workspace_root.clone().into_std_path_buf();
    let is_play = matches!(args.subcommand, Subcommand::Play { .. });
    let is_check_play = matches!(args.subcommand, Subcommand::Play { check: true, .. });
    // The run view (progress::run) takes over stderr with an alternate
    // screen when stderr is a tty. A tracing layer writing to that same
    // stderr would punch through and corrupt the TUI, so logs are routed
    // into the TUI's log pane instead. Only `play` ever launches that
    // view — every other subcommand must log to stderr like a normal
    // CLI, or its output vanishes into a buffer nothing renders.
    if is_play && std::io::stderr().is_terminal() {
        // Keep ANSI colour in the log lines; the log pane parses it back
        // into styled spans (see progress::draw_log).
        tracing_subscriber::fmt()
            .with_ansi(true)
            .with_writer(progress::LogWriter)
            .init();
    } else {
        // Human-facing format for every non-play invocation (`secret`,
        // `inventory`, …): elapsed-since-start instead of wall-clock
        // timestamps, no module target, no thread ids — the default
        // `tracing` format reads like a log-shipping agent, not a CLI.
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .init();
    }

    // The `secret` subcommands typically don't need the orchestrator
    // — most touch only local files / the SSH agent. The exception is
    // `secret seal`, which has to ask the orchestrator binary to walk
    // its `inventory::iter::<PendingSecret>()` and emit ciphertexts.
    // We compile lazily for that one and short-circuit otherwise.
    if let Subcommand::Secret(cmd) = args.subcommand {
        let orch = if secret::requires_orchestrator(&cmd) {
            Some(compile_orchestrator(&workspace_root, &cargo_meta).await?)
        } else {
            None
        };
        return secret::dispatch(cmd, orch.as_deref()).await;
    }

    // For a `play` run, bring the live view up *now* — before the slow
    // orchestrator/worker compiles and SSH discovery — so the user sees
    // immediate activity (compile/discovery progress flows into the log
    // pane via tracing) instead of a seemingly frozen terminal. The host
    // list starts empty and is populated with `AddHost` once discovery
    // knows the targets. `Inventory`/`Secret` runs print to stdout and must
    // not take over the screen, so they keep `view` as `None`.
    let (progress_tx, progress_rx) = tokio::sync::mpsc::unbounded_channel::<progress::Msg>();
    // Quitting the run view aborts an in-flight play: the view flips this on
    // exit and `main` tears the deployment down (see the select below).
    let (abort_tx, mut abort_rx) = tokio::sync::watch::channel(false);
    let view = is_play.then(|| {
        let abort_tx = abort_tx.clone();
        tokio::spawn(progress::run(progress_rx, abort_tx))
    });

    // Everything below can fail with `?`/`bail!`. While the `play` view owns
    // the alternate screen, returning early would leave the terminal in raw
    // mode with the alt-screen still up. So we run the whole flow in an inner
    // block, capture its result, then *always* close the channel and await
    // the view (letting it restore the terminal) before propagating.
    //
    // If the operator quits the view mid-play, `abort_rx` fires and the
    // `select!` drops `run_after_launch` mid-flight. That is the abort path:
    // every child process is spawned `kill_on_drop`, so the local
    // orchestrators die, the SSH sessions drop, and the workers EOF out of
    // their RPC loops and exit.
    let result: eyre::Result<Option<RunSummary>> = tokio::select! {
        biased;
        r = run_after_launch(args.subcommand, workspace_root, Arc::clone(&cargo_meta), progress_tx.clone()) => r,
        _ = abort_rx.changed() => Err(eyre::eyre!(
            "play aborted from the run view; in-flight deployments were torn down"
        )),
    };

    // An infrastructure error (SSH discovery, compile, rustup, …) aborts
    // the run before the hosts produced anything worth inspecting — often
    // before the host list is even populated. Left alone, the view would
    // idle on an empty screen waiting for `q` while the real error sits
    // undisplayed in `result`: it looks stuck. Tear it down so the error
    // prints on the actual terminal. Per-host failures (`RunFailed`) keep
    // the view up — their diagnostics live in the host panes.
    if let Err(e) = &result
        && e.downcast_ref::<RunSummary>().is_none()
    {
        let _ = progress_tx.send(progress::Msg::Shutdown);
    }

    // Closing our keeper sender lets the view's channel drain and close; the
    // deployment futures hold their own clones until they finish.
    drop(progress_tx);
    if let Some(view) = view {
        // Await the view so it leaves the alternate screen / raw mode before
        // we print anything below.
        let _ = view.await;
    }

    // The play's terminal report — count, duration, failed host names —
    // printed as plain lines (the view is torn down by now, and on a tty
    // the tracing subscriber writes into its no-longer-rendered log pane,
    // so a tracing call here would be invisible). Failed runs exit
    // non-zero without eyre's backtrace decoration; any other error
    // propagates normally (eyre prints it).
    let tty = std::io::stderr().is_terminal();
    match result {
        Ok(Some(summary)) => {
            if tty {
                eprintln!("\x1b[32m✓\x1b[0m {summary}");
            } else {
                eprintln!("OK: {summary}");
            }
            if is_check_play {
                eprintln!("check mode: nothing was applied");
            }
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) if e.downcast_ref::<RunSummary>().is_some() => {
            if tty {
                eprintln!("\x1b[31m✗\x1b[0m {e}");
            } else {
                eprintln!("FAILED: {e}");
            }
            std::process::exit(1);
        }
        Err(e) => Err(e),
    }
}

/// The full `cindy` flow after the (optional) live view has been launched.
/// Pulled into its own function so `main` can guarantee the view is torn
/// down — restoring the terminal — regardless of how this returns.
async fn run_after_launch(
    subcommand: Subcommand,
    workspace_root: PathBuf,
    cargo_meta: Arc<cargo_metadata::Metadata>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<progress::Msg>,
) -> eyre::Result<Option<RunSummary>> {
    let started = std::time::Instant::now();
    let orchestrator_exe_path = compile_orchestrator(&workspace_root, &cargo_meta).await?;

    // `--reveal` must reach the orchestrator dump, which does the
    // decryption (it has the vault keys and the typed `V`); the CLI
    // only ever sees the already-revealed-or-redacted result. So the
    // flag has to be known before we pull the inventory. It applies to
    // both the `Debug` rendering and `--json`.
    let reveal_secrets = matches!(subcommand, Subcommand::Inventory { reveal: true, .. });
    let PulledInventory {
        inventory,
        debug,
        json_revealed,
    } = get_inventory(&orchestrator_exe_path, reveal_secrets).await?;

    // Host names key the per-host context and vault-key maps and address
    // `--host`; a duplicate would silently run one host's play twice and
    // the other's never. Fail loudly at the source instead.
    {
        let mut seen = HashSet::new();
        for host in &inventory.hosts {
            if !seen.insert(host.name.as_str()) {
                eyre::bail!(
                    "duplicate host name `{}` in the inventory — host names must be unique",
                    host.name
                );
            }
        }
    }

    let (limit, unprivileged, check_mode, local) = match subcommand {
        Subcommand::Play {
            limit,
            unprivileged,
            check,
            local,
        } => (limit, unprivileged, check, local),
        Subcommand::Inventory { host, json, reveal } => {
            if json {
                // Pick the JSON source: the secrets-decrypted whole
                // inventory under `--reveal`, otherwise the sealed one.
                // `--host` narrows to that host's object so the output
                // stays a single JSON document for `jq` et al.
                let whole: serde_json::Value = if reveal {
                    match json_revealed
                        .context("orchestrator dump omitted revealed JSON despite `--reveal`")?
                    {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(eyre::eyre!(
                                "failed to reveal secrets for JSON output: {e}"
                            ));
                        }
                    }
                } else {
                    serde_json::to_value(&inventory)?
                };
                let value = match &host {
                    Some(host_name) => whole
                        .get("hosts")
                        .and_then(|h| h.as_array())
                        .and_then(|hosts| {
                            hosts
                                .iter()
                                .find(|h| h.get("name").and_then(|n| n.as_str()) == Some(host_name))
                        })
                        .cloned()
                        .with_context(|| {
                            format!("No such host `{host_name}` found in inventory")
                        })?,
                    None => whole,
                };
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(None);
            }
            // Print the `Debug` rendering the orchestrator produced from
            // the user's real `V`, not the JSON-`Value` `Debug` the CLI
            // would otherwise emit.
            let key = host
                .as_deref()
                .unwrap_or(cindy::inventory::WHOLE_INVENTORY_KEY);
            let rendered = debug.get(key).with_context(|| {
                if host.is_some() {
                    format!("No such host `{key}` found in inventory")
                } else {
                    "Orchestrator dump did not include a whole-inventory rendering".to_owned()
                }
            })?;
            println!("{rendered}");
            return Ok(None);
        }
        Subcommand::Secret(_) => unreachable!("handled above"),
    };

    let selected_indices = limit::select_indices(
        &inventory.hosts,
        limit.as_deref(),
        |h| h.name.as_str(),
        |h| h.tags.as_slice(),
    )?;
    let selected: Vec<cindy::Host<serde_json::Value>> = selected_indices
        .into_iter()
        .map(|i| inventory.hosts[i].clone())
        .collect();

    // Loud failure, not a silent no-op: a play that deploys to zero
    // hosts and exits 0 reads as success (and would leave the TUI
    // idling on an empty host list).
    if selected.is_empty() {
        eyre::bail!(
            "`--limit {}` matched no hosts; nothing to do",
            limit.as_deref().unwrap_or("")
        );
    }
    tracing::info!(count = selected.len(), "selected hosts after --limit");

    tracing::info!("pre-flighting targets");
    let discovery_futures = selected.into_iter().map(|host| async move {
        // `server_alive_interval`: a target that dies without closing the
        // TCP connection (reboot, `sysupgrade`, power loss) would otherwise
        // leave the session "up" until the kernel's TCP timeout — hours of
        // a play lingering on a dead host. With keepalives every 10s and
        // OpenSSH's default ServerAliveCountMax of 3, a silent peer tears
        // the session down after ~30s, which EOFs the RPC pump and fails
        // the play's in-flight calls promptly.
        // Local hosts skip the SSH machinery entirely: no TOFU
        // fingerprints, no session, and the platform is *this* machine
        // (the host triple, glibc — the musl/static choice exists for
        // remote busybox targets, not for a worker that runs here).
        // Sudo never applies locally: the play runs as the invoking
        // user, so `use_sudo` is pinned false.
        let (transport, triplet) = if local {
            (
                Transport::Local,
                format!("{}-unknown-linux-gnu", std::env::consts::ARCH),
            )
        } else {
            log_tofu_fingerprints(&host.name).await;
            let session = openssh::SessionBuilder::default()
                .known_hosts_check(openssh::KnownHosts::Add)
                .connect_timeout(std::time::Duration::from_secs(30))
                .server_alive_interval(std::time::Duration::from_secs(10))
                .connect(&host.name)
                .await?;
            let uname_out = session
                .command("uname")
                .args(["-m"])
                .output()
                .await?
                .ok_or_die()?;
            let machine_arch = String::from_utf8(uname_out.stdout)?.trim().to_string();
            (
                Transport::Ssh(session),
                format!("{machine_arch}-unknown-linux-musl"),
            )
        };
        let platform = platforms::Platform::find(&triplet)
            .context(format!("Couldn't find platform by triplet: '{triplet}'"))?;

        let use_sudo = !local && !unprivileged && {
            let id_out = transport.check_output("id", &["-u"]).await?.ok_or_die()?;
            String::from_utf8(id_out.stdout)?.trim() != "0"
        };

        Ok::<DiscoveredHost, eyre::Error>(DiscoveredHost {
            host,
            transport,
            platform,
            use_sudo,
        })
    });

    let discovered_hosts = try_join_all(discovery_futures).await?;

    // The targets are known now — populate the view's (until-now empty) host
    // list. Send order defines each host's `idx`, matching the order the
    // deployment futures are enumerated below.
    for host in &discovered_hosts {
        let _ = progress_tx.send(progress::Msg::AddHost {
            name: host.host.name.clone(),
            tags: host.host.tags.clone(),
        });
    }

    let unique_platforms: HashSet<&'static platforms::Platform> =
        discovered_hosts.iter().map(|h| h.platform).collect();

    // https://github.com/rust-lang/rustup/issues/988
    tracing::info!(component = "rust-src", "installing component");
    tokio::process::Command::new("rustup")
        .args(["component", "add", "rust-src"])
        .output()
        .await?
        .ok_or_die()?;
    for platform in &unique_platforms {
        if matches!(platform.tier, platforms::Tier::Three) {
            continue;
        }
        tracing::info!(triplet = platform.target_triple, "installing target");
        std::process::Command::new("rustup")
            .args(["target", "add", platform.target_triple])
            .output()?
            .ok_or_die()?;
    }

    let root = Arc::new(workspace_root.clone());
    // FIXME: semaphore here until rustup proxy safe for concurrent use.
    let build_gate = Arc::new(tokio::sync::Semaphore::new(1));
    let compilation_futures = unique_platforms.into_iter().map(|platform| {
        let meta = Arc::clone(&cargo_meta);
        let root = Arc::clone(&root);
        let build_gate = Arc::clone(&build_gate);
        async move {
            let _permit = build_gate
                .acquire()
                .await
                .expect("build gate semaphore is never closed");
            Ok::<_, eyre::Error>((
                platform,
                compile_remote_worker(platform, &meta, &root, local).await?,
            ))
        }
    });
    let compilation_results = try_join_all(compilation_futures)
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();

    // Read each platform's worker binary once, gzip it once, and
    // share the compressed bytes across every host's upload: a
    // 200-host fan-out on one platform used to re-read the same ~8 MB
    // static binary 200 times, once per deployment task, blocking the
    // async runtime's thread each time — and re-send it uncompressed
    // every time. Static musl binaries compress ~2.5-3x, so the
    // upload shrinks by the same factor; the target decompresses with
    // `gzip -dc`, which busybox and coreutils both ship.
    let mut worker_binaries: HashMap<&'static platforms::Platform, Arc<[u8]>> = HashMap::new();
    for (platform, path) in &compilation_results {
        let raw = tokio::fs::read(path)
            .await
            .with_context(|| format!("Reading worker binary {}", path.display()))?;
        let raw_len = raw.len();
        let compressed = tokio::task::spawn_blocking(move || {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            std::io::Write::write_all(&mut encoder, &raw).and_then(|()| encoder.finish())
        })
        .await
        .context("Compressing worker binary")?
        .context("Compressing worker binary")?;
        tracing::debug!(
            platform = platform.target_triple,
            raw = raw_len,
            compressed = compressed.len(),
            "gzipped worker binary"
        );
        worker_binaries.insert(*platform, Arc::from(compressed));
    }
    let worker_binaries = Arc::new(worker_binaries);

    // Vault key preflight (fail-fast). Enumerate the vaults the play's
    // in-code `secret!`s reference, then — per host — union them with
    // that host's inventory-vars sealed-secret vaults, and confirm a
    // local `keys/<vault>.key` exists for each. We do this for *every*
    // selected host before launching *any* of them, so a missing key
    // aborts the whole run up front instead of partway through.
    tracing::info!("Pre-flighting vault keys across targets...");
    let in_code_vaults = dump_in_code_vaults(&orchestrator_exe_path).await?;

    // host name -> serialised host context, and -> CINDY_VAULT_KEYS map.
    let mut host_contexts: HashMap<String, String> = HashMap::new();
    let mut host_vault_keys: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut preflight_failures: Vec<String> = Vec::new();

    for host in &discovered_hosts {
        let host_context_json =
            serde_json::to_string(&host.host).expect("Failed to serialise host context");
        let needed = host_needed_vaults(&in_code_vaults, &host_context_json);
        let (keys, missing) = collect_vault_keys(&needed)?;
        if !missing.is_empty() {
            preflight_failures.push(format!(
                "  {}: missing key(s) for vault(s) {missing:?}",
                host.host.name
            ));
        }
        host_contexts.insert(host.host.name.clone(), host_context_json);
        host_vault_keys.insert(host.host.name.clone(), keys);
    }

    if !preflight_failures.is_empty() {
        eyre::bail!(
            "vault key preflight failed — refusing to start. The following \
             hosts are missing decryption keys:\n{}\n\nProvision the key file(s) \
             (`cindy secret vault create <name>`, or copy `keys/<name>.key` from \
             a teammate) and re-run.",
            preflight_failures.join("\n")
        );
    }
    tracing::info!("Vault key preflight passed for all targets.");

    tracing::info!(count = discovered_hosts.len(), "deploying");
    let orchestrator_path = Arc::new(orchestrator_exe_path);
    let host_contexts = Arc::new(host_contexts);
    let host_vault_keys = Arc::new(host_vault_keys);

    if check_mode {
        tracing::warn!(
            "check mode: builtins report without applying; command/shell won't \
             execute; custom #[remote] functions still run"
        );
    }

    let host_names: Vec<String> = discovered_hosts
        .iter()
        .map(|h| h.host.name.clone())
        .collect();
    let deployment_futures = discovered_hosts.into_iter().enumerate().map(|(idx, host)| {
        let orch_path = Arc::clone(&orchestrator_path);
        let worker_binaries = Arc::clone(&worker_binaries);
        let host_contexts = Arc::clone(&host_contexts);
        let host_vault_keys = Arc::clone(&host_vault_keys);
        let progress_tx = progress_tx.clone();

        async move {
            let hostname = host.host.name.clone();
            let context_span = tracing::info_span!("run", %hostname);
            let progress_status = progress_tx.clone();

            let result = async move {
                let worker_bin = Arc::clone(
                    worker_binaries
                        .get(host.platform)
                        .expect("Not compiled"),
                );

                // Pick a staging directory this host can actually
                // execute from: hardened boxes mount /tmp noexec, and
                // picking it operator-side (a --staging-dir flag) puts
                // per-host trivia in a global flag. The target's own
                // mounts are the authority — read /proc/mounts (one
                // cheap roundtrip, world-readable, no sudo) and take
                // the first candidate whose mount allows exec.
                let mounts = host
                    .transport
                    .check_output("cat", &["/proc/mounts"])
                    .await
                    .ok()
                    .filter(|out| out.status.success());
                let staging_dir = mounts
                    .as_ref()
                    .map(|out| staging_dir_from_mounts(&String::from_utf8_lossy(&out.stdout)))
                    .unwrap_or("/tmp");
                if staging_dir != "/tmp" {
                    tracing::debug!(
                        "staging worker under {staging_dir} — /tmp is noexec or unavailable"
                    );
                }

                // A throwaway name: the worker unlinks its own
                // executable on startup, so nothing accumulates on the
                // target.
                let remote_tmp_path = format!(
                    "{staging_dir}/.cindy-worker.{}",
                    rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16),
                );

                // Upload the gzip-compressed worker, decompressing on
                // the target (`gzip -dc` reading the pipe — busybox and
                // coreutils both ship it, and the decompressed bytes
                // never take a second round-trip).
                //
                // stdout/stderr are piped (not inherited): if `sudo` refuses
                // — e.g. the host needs a password — its message must land in
                // this host's output pane, not on the real terminal where it
                // would corrupt the alternate-screen TUI. We forward the
                // upload's stderr the same way we do the run's.
                let upload_script = format!(
                    "umask 0266 && gzip -dc >'{remote_tmp_path}' && chmod u+x '{remote_tmp_path}'"
                );
                let mut upload: HostChild = host
                    .transport
                    .spawn_piped(host.use_sudo, "sh", &["-c", &upload_script])
                    .await?;

                let upload_stderr = BufReader::new(
                    upload
                        .take_stderr()
                        .expect("upload stderr was piped"),
                );
                tokio::spawn(forward_stderr(
                    upload_stderr,
                    progress_tx.clone(),
                    idx,
                    progress::Source::Worker,
                ));

                if let Some(mut stdin) = upload.take_stdin() {
                    // `worker_bin` is the gzipped payload (see the read
                    // step above).
                    // If the remote command died before we finished writing
                    // (e.g. `sudo -n` exited because a password was required),
                    // the write fails with a broken pipe. That error is just a
                    // symptom — the real cause is on the command's stderr,
                    // already forwarded to the pane — so don't surface it;
                    // fall through to `exit_ok`, which reports the actual
                    // non-zero exit.
                    let _ = stdin.write_all(&worker_bin).await;
                }
                upload.wait().await?.exit_ok()?;

                // The host context (name, tags, vars) and the vault keys
                // this host needs were both computed during preflight.
                let host_context_json = host_contexts
                    .get(&hostname)
                    .expect("preflight populated every host's context")
                    .clone();
                let vault_keys_json = serde_json::to_string(
                    host_vault_keys
                        .get(&hostname)
                        .expect("preflight populated every host's vault keys"),
                )
                .expect("Failed to serialise vault key map");

                // The worker gets *no* secret material in its argv/env:
                // its vault keys travel over the RPC handshake (see the
                // orchestrator below), so they never appear in the
                // target's process table. It also doesn't need the host
                // context — that's an orchestrator-only concern.
                let mut remote_run: HostChild = host
                    .transport
                    .spawn_piped(host.use_sudo, &remote_tmp_path, &[])
                    .await?;

                // The orchestrator runs locally (operator's machine), so
                // env is a fine channel for the vault keys (it installs
                // them for its own orchestrator-side reveals and
                // forwards them to the worker over the RPC handshake).
                // The host context, however, can exceed what env can
                // carry: the kernel caps a single env var at
                // MAX_ARG_STRLEN (~128 KiB), and a host whose `vars`
                // embed large blobs (certificates, whole config files)
                // used to make this spawn fail with a bare E2BIG. Hand
                // the context over as a temp file (unlinked when this
                // per-host task ends) instead — no size ceiling.
                let context_file = tempfile::NamedTempFile::new()?;
                tokio::fs::write(context_file.path(), &host_context_json).await?;
                let mut orchestrator_cmd = tokio::process::Command::new(&*orch_path);
                orchestrator_cmd
                    .kill_on_drop(true)
                    .env("CINDY_HOST_CONTEXT_FILE", context_file.path())
                    .env("CINDY_VAULT_KEYS", &vault_keys_json)
                    .env("CINDY_DRY_RUN", if check_mode { "1" } else { "0" });
                let mut orchestrator_run = orchestrator_cmd
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;

                let mut r_stdout = remote_run
                    .take_stdout()
                    .expect("worker stdout was piped");
                let mut r_stdin = remote_run
                    .take_stdin()
                    .expect("worker stdin was piped");
                let r_stderr = BufReader::new(
                    remote_run
                        .take_stderr()
                        .expect("worker stderr was piped"),
                );

                let mut o_stdout = orchestrator_run.stdout.take().unwrap();
                let mut o_stdin = orchestrator_run.stdin.take().unwrap();
                let o_stderr = BufReader::new(orchestrator_run.stderr.take().unwrap());

                let bridge_c =
                    forward_stderr(r_stderr, progress_tx.clone(), idx, progress::Source::Worker);
                let bridge_d = forward_stderr(
                    o_stderr,
                    progress_tx.clone(),
                    idx,
                    progress::Source::Orchestrator,
                );

                tokio::spawn(bridge_c);
                tokio::spawn(bridge_d);

                // Pump the RPC pipe in both directions until it closes. We
                // only need this to *finish*; whether the run actually
                // succeeded is decided by the process exit codes below — a
                // worker panic closes its stdout and would otherwise look
                // just like a clean EOF here.
                // Each direction shuts down its *destination* when its source
                // EOFs. That's what turns a dead worker into forward progress:
                // closing the orchestrator's stdin makes its RPC reader see
                // EOF and fail all in-flight calls, instead of blocking on a
                // response that will never come (and hanging `wait()` below).
                tokio::select! {
                    biased; // needed to avoid random error prints in case of successful exit
                    res = async {
                        let res = tokio::io::copy(&mut r_stdout, &mut o_stdin).await;
                        let _ = o_stdin.shutdown().await;
                        res
                    } => {
                        tracing::debug!("Remote stdout -> Orchestrator stdin stream closed: {:?}", res);
                    }
                    res = async {
                        let res = tokio::io::copy(&mut o_stdout, &mut r_stdin).await;
                        let _ = r_stdin.shutdown().await;
                        res
                    } => {
                        tracing::debug!("Orchestrator stdout -> Remote stdin stream closed: {:?}", res);
                    }
                }

                // The orchestrator holds the authoritative exit code: it runs
                // the user's play and exits 0 on success, 1 on a play error or
                // a (remote-or-local) panic. The worker, by contrast, stays
                // alive serving RPC and won't exit on its own, so we wait the
                // orchestrator and then tear the worker down.
                let orch_exit = orchestrator_run.wait().await?;
                // The worker stays alive serving RPC; closing the pipe to it
                // (by dropping the child, which we took its stdio out of) ends
                // its read loop so it exits.
                // On failure, get the worker's own exit before letting
                // it go: exit 126 is the shell's "found but couldn't
                // execute" — the signature of a staging directory
                // mounted noexec, which otherwise surfaces only as a
                // cryptic "RPC connection closed". (The worker is dead
                // in that case, so this wait is instant; in a normal
                // play failure its stdin has already EOF'd and it
                // exits on its own.)
                if !orch_exit.success() {
                    // `wait` consumes the child; its exit 126 is the
                    // shell's "found but couldn't execute" — the
                    // signature of a noexec staging directory, which
                    // otherwise surfaces only as a cryptic "RPC
                    // connection closed". (The worker is already dead
                    // in that case, so this wait is instant; in a
                    // normal play failure its stdin has already EOF'd
                    // and it exits on its own.)
                    let worker_exit = remote_run.wait().await;
                    let worker_hint = match worker_exit {
                        Ok(status) if status.code() == Some(126) => String::from(
                            " — the worker couldn't be executed (exit 126): no staging \
                             directory on this host allows execution (tried /tmp and \
                             /var/tmp); one of them must be exec-mounted",
                        ),
                        _ => String::new(),
                    };
                    eyre::bail!("play failed (orchestrator exited with {orch_exit}){worker_hint}");
                }
                drop(remote_run);

                tracing::info!("playbook completed");
                Ok::<(), eyre::Error>(())
            }
            .instrument(context_span)
            .await;

            // Report terminal status from the outcome. We don't propagate
            // the error here: aborting the join would tear down the TUI the
            // moment one host fails. Failures are surfaced in the view and
            // summarised after it closes.
            //
            // An error raised in the deployment closure itself (SSH upload,
            // spawn, `exit_ok`, or the orchestrator exiting non-zero) carries
            // its message in the `eyre::Error` value, *not* on any child's
            // stderr — so unless we push it into the host's output pane here,
            // a host can flip to ✗ with an empty pane and no stated reason.
            // Emit the full cause chain as orchestrator-sourced lines.
            let status = if let Err(e) = &result {
                for line in format!("{e:?}").lines() {
                    let _ = progress_status.send(progress::Msg::Line(
                        idx,
                        progress::Source::Orchestrator,
                        line.to_owned(),
                    ));
                }
                progress::Status::Failed
            } else {
                progress::Status::Finished
            };
            let _ = progress_status.send(progress::Msg::Status(idx, status));
            result
        }
    });

    // Materialise the futures (each captures its own `progress_tx` clone),
    // then drop our keeper handle so the view's channel can close once every
    // host future has finished. The view itself is owned by `main`, which
    // awaits it after we return (so the terminal is always restored).
    let deployment_futures: Vec<_> = deployment_futures.collect();
    drop(progress_tx);

    let results = futures_util::future::join_all(deployment_futures).await;

    let total = host_names.len();
    let failed: Vec<String> = results
        .iter()
        .zip(&host_names)
        .filter(|(r, _)| r.is_err())
        .map(|(_, name)| name.clone())
        .collect();
    let summary = RunSummary {
        total,
        failed,
        elapsed: started.elapsed(),
    };
    if summary.failed.is_empty() {
        Ok(Some(summary))
    } else {
        // The per-host failures (including any panic output) were already
        // shown in the run view; raise the summary as the error so `main`
        // can tear the view down first, then exit non-zero without an
        // eyre backtrace.
        eyre::bail!(summary);
    }
}

/// Sentinel error for "N hosts failed". Carries no backtrace-worthy context —
/// the real per-host failures were already shown in the run view — so `main`
/// can render a single red summary line and exit non-zero.
#[derive(Debug)]
/// The terminal run report carried out of the deployment loops so
/// `main` can print it after the view is torn down (plain `eprintln`
/// — a `tracing` call there would land in the no-longer-rendered log
/// pane on a tty).
struct RunSummary {
    total: usize,
    failed: Vec<String>,
    elapsed: std::time::Duration,
}

impl RunSummary {
    fn plural(&self) -> &'static str {
        if self.total == 1 { "host" } else { "hosts" }
    }
}

impl std::fmt::Display for RunSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mins = self.elapsed.as_secs() / 60;
        let secs = self.elapsed.as_secs() % 60;
        let dur = format!("{mins}m{secs:02}s");
        if self.failed.is_empty() {
            write!(
                f,
                "all {} {} completed successfully in {dur}",
                self.total,
                self.plural()
            )
        } else {
            let list = self.failed.join(", ");
            write!(
                f,
                "{} of {} {} failed in {dur}: {list} \
                 (their output is above, or in the run view via f)",
                self.failed.len(),
                self.total,
                self.plural()
            )
        }
    }
}

impl std::error::Error for RunSummary {}

/// Ask the orchestrator binary which vaults its `secret!` invocations
/// reference (the "secrets in code" half of the preflight), by running
/// it in `CINDY_DUMP_VAULTS` mode and parsing the JSON array it prints.
async fn dump_in_code_vaults(orchestrator_exe_path: &Path) -> eyre::Result<Vec<String>> {
    let out = tokio::process::Command::new(orchestrator_exe_path)
        .env("CINDY_DUMP_VAULTS", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;
    if !out.status.success() {
        eyre::bail!(
            "vault enumeration exited with {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serde_json::from_slice(&out.stdout).context("Failed to parse vault list from orchestrator")
}

/// Read `keys/<vault>.key` for each needed vault and build the
/// `{vault: base64-key}` map the worker/orchestrator expect in
/// `CINDY_VAULT_KEYS`. Returns the names of any vault whose key file is
/// missing or unreadable in `missing`, so the caller can fail the whole
/// run up front with full visibility rather than mid-play. Vault names
/// that are invalid outright (e.g. path separators smuggled in through
/// sealed data) error here instead.
fn collect_vault_keys(
    needed: &std::collections::BTreeSet<String>,
) -> eyre::Result<(HashMap<String, String>, Vec<String>)> {
    use base64::Engine as _;

    let mut map = HashMap::new();
    let mut missing = Vec::new();
    for vault in needed {
        let path =
            cindy::secret::keychain::vault_key_path(vault).map_err(|e| eyre::eyre!("{e:#}"))?;
        match std::fs::read(path) {
            Ok(bytes) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                map.insert(vault.clone(), b64);
            }
            Err(_) => missing.push(vault.clone()),
        }
    }
    Ok((map, missing))
}

/// Compute the vaults a single host needs: the in-code `secret!` vaults
/// (same for every host) unioned with the sealed-secret vaults found in
/// that host's serialised context.
fn host_needed_vaults(
    in_code: &[String],
    host_context_json: &str,
) -> std::collections::BTreeSet<String> {
    let mut needed: std::collections::BTreeSet<String> = in_code.iter().cloned().collect();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(host_context_json) {
        cindy::inventory::collect_sealed_vaults(&value, &mut needed);
    }
    needed
}

async fn compile_orchestrator(
    workspace_root: &Path,
    metadata: &cargo_metadata::Metadata,
) -> eyre::Result<PathBuf> {
    tracing::info!("compiling orchestrator binary");
    let target_dir = workspace_root.join("target/cindy/orchestrator");
    let output = tokio::process::Command::new("cargo")
        .kill_on_drop(true)
        .args([
            "build",
            "--release",
            "--message-format=json",
            "--no-default-features",
            "--features",
            "orchestrator",
            "--target-dir",
        ])
        .arg(&target_dir)
        .output()
        .await?;

    if !output.status.success() {
        eyre::bail!("{}", String::from_utf8_lossy(&output.stderr));
    }

    // On success cargo's stderr still carries the warnings — with
    // `--message-format=json` they don't go anywhere the user would see
    // them. Forward them to the log so a playbook full of deprecations
    // isn't silent.
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        if !line.trim().is_empty() {
            tracing::info!("cargo: {line}");
        }
    }

    let stdout_str = String::from_utf8(output.stdout)?;
    let exe_path = extract_executable(&stdout_str, metadata)?
        .context("Failed to extract orchestrator executable path")?;
    Ok(exe_path)
}

/// Extract the playbook binary's path from `cargo`/`cross` JSON output.
///
/// Cargo emits one `compiler-artifact` line per artifact, and anything
/// carrying an `executable` field includes dependencies' build scripts
/// (with an *empty* path) plus every `[[bin]]` of the build — emitted in
/// alphabetical order, so "the last one" silently deploys the wrong
/// binary whenever a package has several bins (`src/bin/zebra.rs` beats
/// the package's own). Pin the expected bin via cargo metadata instead:
/// the root package (as cargo resolves it from this cwd — the same root
/// the build itself uses) must have exactly one bin target, and only
/// that bin's artifact line is accepted. Virtual workspaces (no root
/// package) can't be pinned; there we take the last non-empty bin-kind
/// artifact, which at least excludes build scripts and libs.
fn extract_executable(
    stdout: &str,
    metadata: &cargo_metadata::Metadata,
) -> eyre::Result<Option<PathBuf>> {
    let expected_name: Option<String> = match metadata.root_package() {
        Some(pkg) => {
            let bins: Vec<&str> = pkg
                .targets
                .iter()
                .filter(|t| t.kind.contains(&cargo_metadata::TargetKind::Bin))
                .map(|t| t.name.as_str())
                .collect();
            match bins.as_slice() {
                [] => None,
                [one] => Some((*one).to_owned()),
                many => {
                    eyre::bail!(
                        "the playbook package `{}` defines {} bin targets [{}]; cindy \
                         deploys exactly one — remove the extra [[bin]]s / src/bin/*.rs \
                         files, or run from the package you want deployed",
                        pkg.name,
                        many.len(),
                        many.join(", ")
                    );
                }
            }
        }
        None => None,
    };

    let mut last = None;
    for line in stdout.lines() {
        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(exe) = json["executable"].as_str() else {
            continue;
        };
        if exe.is_empty() {
            continue;
        }
        let kind_is_bin = json["target"]["kind"]
            .as_array()
            .is_some_and(|k| k.iter().any(|k| k == "bin"));
        if !kind_is_bin {
            continue;
        }
        if let Some(want) = &expected_name
            && json["target"]["name"].as_str() != Some(want.as_str())
        {
            continue;
        }
        last = Some(PathBuf::from(exe));
    }
    Ok(last)
}

#[tracing::instrument(skip_all, fields(triplet = platform.target_triple))]
async fn compile_remote_worker(
    platform: &'static platforms::Platform,
    metadata: &cargo_metadata::Metadata,
    workspace_root: &Path,
    local: bool,
) -> eyre::Result<PathBuf> {
    tracing::info!(platform.target_triple, "compiling remote binary");
    // Absolute so the output lands under the workspace regardless of cwd, and
    // so we can reconstruct the binary path from it below without relying on
    // cargo's container-relative `executable` field.
    let target_dir = workspace_root.join(format!("target/cindy/remote/{}", platform.target_triple));
    // A local play builds the worker with plain cargo for the host
    // triple — no cross, no container: the worker runs on this very
    // machine, so the container round-trip (and its podman
    // requirement) buys nothing.
    let builder = if local { "cargo" } else { "cross" };
    let mut cmd = tokio::process::Command::new(builder);
    cmd.kill_on_drop(true)
        .args([
            "build",
            "--release",
            "--message-format=json",
            "--target",
            platform.target_triple,
            "--no-default-features",
            "--features",
            "remote",
            "--target-dir",
        ])
        .arg(&target_dir);

    if matches!(platform.tier, platforms::Tier::Three) {
        tracing::warn!("tier 3 target, building with `-Zbuild-std`");
        cmd.arg("-Zbuild-std");
    }

    // Everything below is cross-specific: the container volume mount
    // for the framework workspace, the rustc-wrapper clobber, the
    // container opts. A plain-cargo local build wants none of it.
    if local {
        return finish_worker_build(cmd, target_dir, platform, metadata).await;
    }

    // Append to user-exported opts instead of clobbering them.
    let mut container_opts = std::env::var("CROSS_CONTAINER_OPTS").unwrap_or_default();

    if let Some(pkg) = metadata.packages.iter().find(|p| p.name == "cindy")
        && pkg.source.is_none()
        && let Some(pkg_dir) = pkg.manifest_path.parent()
    {
        let metadata = cargo_metadata::MetadataCommand::new()
            .current_dir(pkg_dir)
            .exec()?;
        let framework_workspace = metadata.workspace_root;

        container_opts.push_str(&format!(" -v {framework_workspace}:{framework_workspace}"));
    }

    // A host-configured rustc-wrapper leaks into the build container.
    cmd.args(["--config", r#"build.rustc-wrapper="""#]);

    if !container_opts.trim().is_empty() {
        cmd.env("CROSS_CONTAINER_OPTS", container_opts.trim());
    }

    finish_worker_build(cmd, target_dir, platform, metadata).await
}

/// The shared tail of the worker build: run the builder, surface its
/// output, and pin the produced binary's path. `cross` reports a
/// container path in `executable`, so only the file *name* is trusted
/// and rebased onto our own absolute target-dir; plain cargo reports a
/// host path already — the rebase is the identity for it.
async fn finish_worker_build(
    mut cmd: tokio::process::Command,
    target_dir: PathBuf,
    platform: &'static platforms::Platform,
    metadata: &cargo_metadata::Metadata,
) -> eyre::Result<PathBuf> {
    let output = cmd.output().await?;
    if !output.status.success() {
        eyre::bail!("{}", String::from_utf8_lossy(&output.stderr));
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        if !line.trim().is_empty() {
            tracing::info!("build: {line}");
        }
    }
    let stdout_str = String::from_utf8(output.stdout)?;
    let exe_name = extract_executable(&stdout_str, metadata)?
        .context("Failed to extract remote executable path")?
        .file_name()
        .context("remote executable path had no file name")?
        .to_owned();

    let exe_path = target_dir
        .join(platform.target_triple)
        .join("release")
        .join(exe_name);

    Ok(exe_path)
}

#[cfg(test)]
mod tests {
    use super::{RunSummary, ssh_fingerprint};

    /// The end-of-play summary is operator-facing text: successes state
    /// the count and duration, failures name every failed host and
    /// where to find their output — asserted in both directions, per
    /// the repo's message practice.
    #[test]
    fn run_summary_names_failed_hosts_and_counts() {
        let summary = RunSummary {
            total: 3,
            failed: vec!["web-01".into(), "db-2".into()],
            elapsed: std::time::Duration::from_secs(75),
        };
        let msg = summary.to_string();
        assert!(msg.contains("2 of 3 hosts failed"), "{msg}");
        assert!(msg.contains("web-01, db-2"), "{msg}");
        assert!(msg.contains("1m15s"), "{msg}");
        assert!(msg.contains("run view"), "{msg}");
        assert!(!msg.contains("successfully"), "{msg}");

        let ok = RunSummary {
            total: 8,
            failed: vec![],
            elapsed: std::time::Duration::from_secs(723),
        };
        let msg = ok.to_string();
        assert!(msg.contains("all 8 hosts completed successfully"), "{msg}");
        assert!(msg.contains("12m03s"), "{msg}");
        assert!(!msg.contains("failed"), "{msg}");
    }

    /// The digest must byte-for-byte match `ssh-keygen -lf`, so a logged
    /// TOFU line can be diffed against known_hosts by eye. Vector from a
    /// throwaway keypair, generated and verified with ssh-keygen.
    #[test]
    fn fingerprint_matches_ssh_keygen_output() {
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAILlMXkXIBP+8Yp+UVVfJhj1qOdI63aGooccZ7n3EatNf";
        assert_eq!(
            ssh_fingerprint(blob).as_deref(),
            Some("JdZS5vaJvF8MTUNvj7i4DTMyF6HEv84gFgOmDE2CNeQ")
        );
    }

    #[test]
    fn garbage_blobs_yield_no_fingerprint() {
        assert!(ssh_fingerprint("not base64!!").is_none());
    }

    use super::{mount_allows_exec, staging_dir_from_mounts};

    const MOUNTS: &str = concat!(
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n",
        "devtmpfs /dev devtmpfs rw,nosuid,size=... 0 0\n",
        "/dev/sda2 / ext4 rw,relatime 0 0\n",
        "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n",
        "/dev/sda3 /var ext4 rw,relatime 0 0\n",
        "/dev/sda1 /boot vfat rw,noexec 0 0\n",
    );

    #[test]
    fn exec_allowed_follows_the_longest_mount_prefix() {
        // /tmp is directly noexec.
        assert!(!mount_allows_exec(MOUNTS, "/tmp"));
        // /var/tmp inherits /var's exec-allowing options (longest
        // prefix wins over /).
        assert!(mount_allows_exec(MOUNTS, "/var/tmp"));
        // /boot is noexec; /home falls through to /.
        assert!(!mount_allows_exec(MOUNTS, "/boot/efi"));
        assert!(mount_allows_exec(MOUNTS, "/home/me"));
    }

    #[test]
    fn prefix_matching_respects_path_boundaries() {
        // A mount at /tmp2 must not make judgements about /tmp.
        let mounts = "tmpfs /tmp2 tmpfs rw,noexec 0 0\n/dev/sda1 / ext4 rw 0 0\n";
        assert!(mount_allows_exec(mounts, "/tmp"));
        assert!(!mount_allows_exec(mounts, "/tmp2/x"));
    }

    #[test]
    fn staging_dir_skips_noexec_tmp() {
        assert_eq!(staging_dir_from_mounts(MOUNTS), "/var/tmp");
        // A host where /tmp is fine keeps the traditional default.
        let plain = "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /tmp tmpfs rw 0 0\n";
        assert_eq!(staging_dir_from_mounts(plain), "/tmp");
        // Nothing exec-mounted at all: last candidate + the 126
        // diagnosis as backstop.
        let locked = "/dev/sda1 / ext4 rw,noexec 0 0\ntmpfs /tmp tmpfs rw,noexec 0 0\n";
        assert_eq!(staging_dir_from_mounts(locked), "/var/tmp");
        // Garbage/empty: no mounts parsed means no noexec evidence —
        // keep the traditional default (the deployment path does the
        // same when it can't read /proc/mounts at all).
        assert_eq!(staging_dir_from_mounts(""), "/tmp");
    }
}
