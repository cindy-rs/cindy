mod conditional_sudo_command;
mod limit;
mod picker;
mod progress;
mod secret;

use clap::Parser;
use eyre::{ContextCompat as _, WrapErr as _};
use futures_util::future::try_join_all;
use openssh::Stdio;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::Instrument as _;

use crate::conditional_sudo_command::ConditionalSudoCommand as _;

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
    session: openssh::Session,
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
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
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
    let result: eyre::Result<()> = tokio::select! {
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
        && e.downcast_ref::<RunFailed>().is_none()
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

    // A completed-but-failed run is reported as a single summary line and a
    // non-zero exit, without eyre's backtrace decoration. Any other error
    // propagates normally (eyre prints it).
    match result {
        Ok(()) => {
            // Plain eprintln: the play view is torn down by now, and on a
            // tty the tracing subscriber writes into its (no longer
            // rendered) log pane — a tracing call here would be invisible.
            if is_play {
                eprintln!("All hosts completed successfully.");
            }
            Ok(())
        }
        Err(e) if e.downcast_ref::<RunFailed>().is_some() => {
            if std::io::stderr().is_terminal() {
                eprintln!("\x1b[31m{e}\x1b[0m");
            } else {
                eprintln!("{e}");
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
) -> eyre::Result<()> {
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

    let (limit, unprivileged, check_mode) = match subcommand {
        Subcommand::Play {
            limit,
            unprivileged,
            check,
        } => (limit, unprivileged, check),
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
                return Ok(());
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
            return Ok(());
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

    tracing::info!("Initiating pre-flight checks across targets...");
    let discovery_futures = selected.into_iter().map(|host| async move {
        // `server_alive_interval`: a target that dies without closing the
        // TCP connection (reboot, `sysupgrade`, power loss) would otherwise
        // leave the session "up" until the kernel's TCP timeout — hours of
        // a play lingering on a dead host. With keepalives every 10s and
        // OpenSSH's default ServerAliveCountMax of 3, a silent peer tears
        // the session down after ~30s, which EOFs the RPC pump and fails
        // the play's in-flight calls promptly.
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
        let triplet = format!("{machine_arch}-unknown-linux-musl");
        let platform = platforms::Platform::find(&triplet)
            .context(format!("Couldn't find platform by triplet: '{triplet}'"))?;

        let id_out = session
            .command("id")
            .args(["-u"])
            .output()
            .await?
            .ok_or_die()?;
        let use_sudo = !unprivileged && String::from_utf8(id_out.stdout)?.trim() != "0";

        Ok::<DiscoveredHost, eyre::Error>(DiscoveredHost {
            host,
            session,
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
                compile_remote_worker(platform, &meta, &root).await?,
            ))
        }
    });
    let compilation_results = try_join_all(compilation_futures)
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();

    // Read each platform's worker binary once and share the bytes
    // across every host's upload: a 200-host fan-out on one platform
    // used to re-read the same ~8 MB static binary 200 times, once
    // per deployment task, blocking the async runtime's thread each
    // time.
    let mut worker_binaries: HashMap<&'static platforms::Platform, Arc<[u8]>> = HashMap::new();
    for (platform, path) in &compilation_results {
        worker_binaries.insert(
            *platform,
            tokio::fs::read(path)
                .await
                .map(Arc::from)
                .with_context(|| format!("Reading worker binary {}", path.display()))?,
        );
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

    tracing::info!("Launching parallel deployment loops...");
    let orchestrator_path = Arc::new(orchestrator_exe_path);
    let host_contexts = Arc::new(host_contexts);
    let host_vault_keys = Arc::new(host_vault_keys);

    if check_mode {
        tracing::warn!(
            "check mode: builtins will report without applying; command/shell will not              execute; custom #[remote] functions still run"
        );
    }

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

                let remote_tmp_path = format!(
                    "/tmp/.cindy-worker.{}",
                    rand::distr::SampleString::sample_string(&rand::distr::Alphanumeric, &mut rand::rng(), 16),
                );

                // Upload worker binary executable.
                //
                // stdout/stderr are piped (not inherited): if `sudo` refuses
                // — e.g. the host needs a password — its message must land in
                // this host's output pane, not on the real terminal where it
                // would corrupt the alternate-screen TUI. We forward the
                // upload's stderr the same way we do the run's.
                let mut upload = host
                    .session
                    .conditional_sudo_command(host.use_sudo, "sh")
                    .args(["-c", &format!("umask 0266 && cat >'{remote_tmp_path}' && chmod u+x '{remote_tmp_path}'")])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .await?;

                let upload_stderr = BufReader::new(upload.stderr().take().unwrap());
                tokio::spawn(forward_stderr(
                    upload_stderr,
                    progress_tx.clone(),
                    idx,
                    progress::Source::Worker,
                ));

                if let Some(mut stdin) = upload.stdin().take() {
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
                let mut remote_run = host
                    .session
                    .conditional_sudo_command(host.use_sudo, &remote_tmp_path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
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

                let mut r_stdout = remote_run.stdout().take().unwrap();
                let mut r_stdin = remote_run.stdin().take().unwrap();
                let r_stderr = BufReader::new(remote_run.stderr().take().unwrap());

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
                drop(remote_run);
                if !orch_exit.success() {
                    eyre::bail!("play failed (orchestrator exited with {orch_exit})");
                }

                tracing::info!("Execution successfully completed.");
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

    let failed = results.iter().filter(|r| r.is_err()).count();
    if failed > 0 {
        // The per-host failures (including any panic output) were already
        // shown in the run view; report a one-line summary as the error so
        // `main` can tear the view down first, then exit non-zero without an
        // eyre backtrace.
        eyre::bail!(RunFailed(failed));
    }
    Ok(())
}

/// Sentinel error for "N hosts failed". Carries no backtrace-worthy context —
/// the real per-host failures were already shown in the run view — so `main`
/// can render a single red summary line and exit non-zero.
#[derive(Debug)]
struct RunFailed(usize);

impl std::fmt::Display for RunFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} host(s) failed", self.0)
    }
}

impl std::error::Error for RunFailed {}

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
) -> eyre::Result<PathBuf> {
    tracing::info!(platform.target_triple, "compiling remote binary");
    // Absolute so the output lands under the workspace regardless of cwd, and
    // so we can reconstruct the binary path from it below without relying on
    // cargo's container-relative `executable` field.
    let target_dir = workspace_root.join(format!("target/cindy/remote/{}", platform.target_triple));
    let mut cmd = tokio::process::Command::new("cross");
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

    let output = cmd.output().await?;
    if !output.status.success() {
        eyre::bail!("{}", String::from_utf8_lossy(&output.stderr));
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        if !line.trim().is_empty() {
            tracing::info!("cross: {line}");
        }
    }
    // `cross` runs cargo inside a container, so the `executable` it reports is
    // a container path that may not exist on the host. We only trust it for
    // the binary's *file name*, then rebase that onto our own absolute
    // target-dir (mounted into the container at the same path), giving a host
    // path we can actually read.
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
    use super::ssh_fingerprint;

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
}
