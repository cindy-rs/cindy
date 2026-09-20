//! `cindy secret …` subcommand implementation.
//!
//! V1 model — file-based vault keys, à la `ansible-vault`'s
//! `--vault-password-file`. Each vault has a 32-byte vault
//! key stored at `keys/<name>.key`. The directory should be
//! `.gitignore`d; the file gets distributed to teammates out-of-band.
//!
//! Subcommands:
//!
//!   * `cindy secret vault create <name>` — write a fresh random key to
//!     `keys/<name>.key` (mode 0600).
//!   * `cindy secret vault rotate <name>` — replace the vault's key and
//!     re-seal every `Secret::sealed_b64(...)` site of that vault in
//!     place, with plaintext never touching disk and every crash
//!     window recoverable by re-running the same command (see
//!     [`vault_rotate`]).
//!   * `cindy secret seal`   — encrypt `cindy::secret!(...)` calls in
//!     source, rewriting the file in-place. Interactive picker on a
//!     TTY (skippable with `--all`); missing vaults are an error.
//!   * `cindy secret unseal` — reverse: turn
//!     `Secret::sealed_b64("vault", "...")` back into
//!     `cindy::secret!("vault", <original tokens>)`. Uses the source
//!     tokens that `seal` captured via `stringify!()` and embedded in
//!     the ciphertext, so you get back the exact value expression you
//!     originally wrote (post-`cargo fmt`).

use std::path::{Path, PathBuf};

use base64::Engine as _;
use cindy::secret::SealedPayload;
use cindy::secret::crypto;
use cindy::secret::keychain;
use eyre::{ContextCompat as _, WrapErr as _};

#[derive(Debug, clap::Subcommand)]
pub enum SecretCommand {
    /// Vault management.
    #[clap(subcommand)]
    Vault(VaultCommand),

    /// Encrypt `cindy::secret!(...)` invocations in source.
    ///
    /// Compiles the orchestrator binary, runs it with
    /// `CINDY_SEAL_SECRETS=1` to collect (file, line, column, vault,
    /// ciphertext) records for every registered pending secret, then
    /// rewrites each source file in place by replacing the
    /// `secret!(...)` token tree with `cindy::Secret::sealed_b64(...)`.
    ///
    /// When run interactively (stderr is a TTY), an interactive picker
    /// lets you choose which secrets to seal; `--all` skips it.
    Seal {
        /// Seal everything without the interactive picker.
        #[clap(long)]
        all: bool,
    },

    /// Reverse of `seal`: turn `Secret::sealed_b64(...)` calls in
    /// source back into the original `cindy::secret!(...)` macro
    /// invocation, decrypting via the local key files.
    ///
    /// When run interactively (stderr is a TTY), an interactive picker
    /// lets you choose which secrets to unseal; `--all` skips it.
    Unseal {
        /// Unseal everything without the interactive picker.
        #[clap(long)]
        all: bool,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum VaultCommand {
    /// Generate a fresh 32-byte random key for `<name>` and write it
    /// to `keys/<name>.key` (mode 0600). The directory should be
    /// `.gitignore`d. Errors if the file already exists.
    Create {
        /// Vault name. Lower-case, no slashes; appears verbatim as
        /// `keys/<name>.key` and inside `secret!("<name>", ...)`.
        name: String,
    },

    /// Replace the key of `<name>` with a fresh one and re-seal every
    /// `Secret::sealed_b64(...)` site of that vault in source, so a
    /// leaked old key becomes useless. Recovering from this used to
    /// mean `unseal --all`, delete the key by hand, `vault create`,
    /// `seal --all` — plaintext transiently on disk, no atomicity.
    ///
    /// Every unseal→seal happens in memory; sites are rewritten one
    /// file at a time (write-to-temp + rename), so a crash leaves
    /// whole files on the old or new key — never half a ciphertext —
    /// and re-running the command resumes and converges.
    Rotate {
        /// Vault name whose key and sealed sites move to a fresh key.
        name: String,
    },
}

/// True iff the requested subcommand needs the orchestrator binary
/// compiled. Lets `main` skip the `cargo build` for the cheap
/// subcommands.
pub fn requires_orchestrator(cmd: &SecretCommand) -> bool {
    matches!(cmd, SecretCommand::Seal { .. })
}

pub async fn dispatch(cmd: SecretCommand, orchestrator_path: Option<&Path>) -> eyre::Result<()> {
    match cmd {
        SecretCommand::Vault(VaultCommand::Create { name }) => vault_create(&name),
        SecretCommand::Vault(VaultCommand::Rotate { name }) => vault_rotate(&name),
        SecretCommand::Seal { all } => {
            let orch = orchestrator_path
                .expect("`Seal` requires an orchestrator path (see `requires_orchestrator`)");
            seal_all(orch, all).await
        }
        SecretCommand::Unseal { all } => unseal_all(all),
    }
}

// ---------------------------------------------------------------------
// vault create
// ---------------------------------------------------------------------

fn vault_create(name: &str) -> eyre::Result<()> {
    let path = keychain::vault_key_path(name).map_err(|e| eyre::eyre!("{e:#}"))?;
    if path.exists() {
        eyre::bail!(
            "{} already exists. Refusing to overwrite an existing vault key. \
             To replace it (and re-seal the vault's secrets onto the new key), \
             run `cindy secret vault rotate {name}`.",
            path.display(),
        );
    }
    write_new_vault_key(&path)?;
    println!("created vault `{name}` at {}", path.display());
    println!(
        "(remember to add `{}/` to .gitignore)",
        keychain::keys_dir().display()
    );
    Ok(())
}

fn write_new_vault_key(path: &Path) -> eyre::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating {}", parent.display()))?;
    }

    let key = crypto::generate_vault_key();

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("Creating {} (refusing to overwrite)", path.display()))?;
    f.write_all(key.as_slice())
        .with_context(|| format!("Writing vault key to {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------
// vault rotate
// ---------------------------------------------------------------------

/// `keys/<name>.key.previous` — the pre-rotation key, parked while a
/// rotation is in flight. Derived from the same validated name and
/// keys directory as the live key (so `CINDY_KEYS_DIR` applies), and
/// its presence is the resume marker: it is deleted only once every
/// site of the vault decrypts under the new key.
fn previous_key_path(vault: &str) -> eyre::Result<PathBuf> {
    let live = keychain::vault_key_path(vault).map_err(|e| eyre::eyre!("{e:#}"))?;
    Ok(live.with_file_name(format!("{vault}.key.previous")))
}

/// Read a key file that rotation has already staked its state on —
/// `Ok(None)` here means it vanished mid-rotation, which is a resume
/// case, not a fresh start.
fn read_required_key(path: &Path) -> eyre::Result<cindy::secret::crypto::VaultKey> {
    keychain::read_vault_key_file(path)
        .map_err(|e| eyre::eyre!("{e:#}"))?
        .with_context(|| {
            format!(
                "{} went missing mid-rotation — another cindy process may be \
                 rotating the same vault; re-run this command to resume",
                path.display()
            )
        })
}

/// Install `key` at `path` via write-to-temp + rename, mode 0600.
/// Overwrites: rotation owns this path once the old key is parked at
/// `.key.previous`.
fn write_vault_key_overwrite(
    path: &Path,
    key: &cindy::secret::crypto::VaultKey,
) -> eyre::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("Creating a temp key file next to {}", path.display()))?;
    tmp.as_file()
        .write_all(key.as_slice())
        .with_context(|| format!("Writing the new vault key for {}", path.display()))?;
    // NamedTempFile is created 0600, matching what `vault create`
    // writes — key material should never be wider than that.
    tmp.persist(path)
        .with_context(|| format!("Installing the new vault key at {}", path.display()))?;
    Ok(())
}

/// `cindy secret vault rotate <name>`: replace the vault's key and
/// re-seal every `Secret::sealed_b64` site of that vault in place.
///
/// The old key is what leaked, so it must not survive the rotation;
/// but deleting it before every blob is off it would make a crash
/// unrecoverable. The resolution is the parked `.key.previous` file
/// plus an ordering that makes every crash window a state the same
/// command can resume:
///
/// | state on disk | meaning | action |
/// |---|---|---|
/// | `.key` only | no rotation in flight | fresh: park old as `.previous`, install new |
/// | `.key` + `.previous` | rotation interrupted mid-reseal | resume: converge sites from either key, verify, delete `.previous` |
/// | `.previous` only | died between parking the old key and installing the new one | nothing was ever sealed with a new key, so generate a fresh one and proceed |
///
/// The swap (park, then install) precedes all rewrites, which is what
/// makes the third row safe. Every unseal→seal happens in memory;
/// per-file rewrites are write-to-temp + rename, so a crash leaves
/// whole files on the old or new key — never half a ciphertext.
fn vault_rotate(vault: &str) -> eyre::Result<()> {
    let live = keychain::vault_key_path(vault).map_err(|e| eyre::eyre!("{e:#}"))?;
    let previous = previous_key_path(vault)?;

    // --- settle the key files ---------------------------------------
    let current: cindy::secret::crypto::VaultKey;
    let old: cindy::secret::crypto::VaultKey;
    if previous.exists() && live.exists() {
        current = read_required_key(&live)?;
        old = read_required_key(&previous)?;
        if current.as_slice() == old.as_slice() {
            eyre::bail!(
                "{} and {} hold the same key — that isn't a rotation state. \
                 Inspect the keys directory by hand and remove whichever is wrong.",
                live.display(),
                previous.display()
            );
        }
        tracing::info!("resuming an interrupted rotation of vault `{vault}`");
    } else if previous.exists() {
        // `.key` missing: the process died between parking the old key
        // and installing the new one. The swap precedes all rewrites,
        // so nothing was ever sealed with any new key — a fresh one is
        // safe and the interrupted new key (never on disk) is moot.
        old = read_required_key(&previous)?;
        current = cindy::secret::crypto::generate_vault_key();
        write_vault_key_overwrite(&live, &current)?;
        tracing::info!("completing an interrupted key swap for vault `{vault}`");
    } else if live.exists() {
        old = read_required_key(&live)?;
        current = cindy::secret::crypto::generate_vault_key();
        std::fs::rename(&live, &previous)
            .with_context(|| format!("Parking the old key at {}", previous.display()))?;
        write_vault_key_overwrite(&live, &current)?;
    } else {
        eyre::bail!(
            "no vault `{vault}` at {} — create it with \
             `cindy secret vault create {vault}` first",
            live.display()
        );
    }

    // --- collect this vault's sealed sites --------------------------
    let (workspace_root, cindy_names) = workspace_and_names()?;
    let files = walk_rs_files(&workspace_root);
    let mut per_file = Vec::new();
    for file in &files {
        let collected = collect_sealed_sites(file)?;
        if collected.sites.iter().any(|s| s.vault == vault) {
            per_file.push(collected);
        }
    }

    // --- re-seal pass: converge every site onto the current key -----
    let mut affected = Vec::new();
    let mut converged = 0usize;
    let mut resealed = 0usize;
    for fs in &per_file {
        let (c, r) = rotate_sites(fs, vault, &current, &old, cindy_names.for_file(&fs.path))?;
        if r > 0 {
            affected.push(fs.path.clone());
        }
        converged += c;
        resealed += r;
    }
    if !affected.is_empty() {
        cargo_fmt(&affected);
    }

    // --- verify: every site must decrypt under the current key ------
    // Re-collect, not reuse: the rewrites changed byte offsets (and
    // cargo fmt may have reflowed lines). A failure here keeps
    // `.previous` in place for the resume path.
    let mut verified = 0usize;
    for file in &files {
        let fs = collect_sealed_sites(file)?;
        for site in &fs.sites {
            if site.vault != vault {
                continue;
            }
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(site.ciphertext_b64.as_bytes())
                .with_context(|| {
                    format!(
                        "{}:{}:{}: ciphertext is not valid base64 after rotation",
                        fs.path.display(),
                        site.line,
                        site.column
                    )
                })?;
            crypto::unseal(&current, &ciphertext).map_err(|e| {
                eyre::eyre!(
                    "{}:{}:{}: vault `{vault}` site doesn't decrypt under the new key \
                     ({e}); the previous key is kept at {}. Fix or remove the site, \
                     then re-run `cindy secret vault rotate {vault}` to resume.",
                    fs.path.display(),
                    site.line,
                    site.column,
                    previous.display()
                )
            })?;
            verified += 1;
        }
    }
    if verified != converged + resealed {
        eyre::bail!(
            "site count changed during rotation ({verified} verified, \
             {} seen) — a concurrent edit raced the rewrites. The previous key \
             is kept at {}; re-run to resume",
            converged + resealed,
            previous.display()
        );
    }

    // --- success: destroy the old key -------------------------------
    std::fs::remove_file(&previous)
        .with_context(|| format!("Deleting the parked old key {}", previous.display()))?;
    println!(
        "rotated vault `{vault}`: {resealed} secret(s) re-sealed onto the new key at {}",
        live.display()
    );
    if converged > 0 {
        println!("({converged} site(s) had already converged from an interrupted run)");
    }
    println!(
        "the previous key was destroyed; any copy of it that leaked is now \
         useless for this vault's ciphertexts"
    );
    Ok(())
}

/// Re-seal every site of `vault` in one file onto `current`, reading
/// blobs still sealed with `old`. Returns `(already converged,
/// re-sealed)`. A blob decrypting under neither key is a hard error:
/// this file stays untouched (the rewrites are all-or-nothing per
/// file) and the caller keeps the old key for recovery.
fn rotate_sites(
    fs: &FileSites,
    vault: &str,
    current: &cindy::secret::crypto::VaultKey,
    old: &cindy::secret::crypto::VaultKey,
    cindy_name: &str,
) -> eyre::Result<(usize, usize)> {
    let FileSites {
        path,
        original,
        sites,
    } = fs;

    let mut planned: Vec<(usize, usize, String)> = Vec::new();
    let mut converged = 0usize;
    let mut resealed = 0usize;
    for site in sites {
        if site.vault != vault {
            continue;
        }
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(site.ciphertext_b64.as_bytes())
            .with_context(|| {
                format!(
                    "{}:{}:{}: ciphertext for vault `{vault}` is not valid base64",
                    path.display(),
                    site.line,
                    site.column
                )
            })?;
        if crypto::unseal(current, &ciphertext).is_ok() {
            // Already on the new key — an interrupted run got this far.
            converged += 1;
            continue;
        }
        let plaintext = crypto::unseal(old, &ciphertext).map_err(|e| {
            eyre::eyre!(
                "{}:{}:{}: decrypting vault `{vault}` for rotation: {e}. Neither \
                 the new nor the previous key opens this blob; this file is \
                 untouched and the previous key is kept — fix or remove the \
                 site, then re-run `cindy secret vault rotate {vault}` to resume",
                path.display(),
                site.line,
                site.column
            )
        })?;
        let new_ciphertext = crypto::seal(current, &plaintext).map_err(|e| {
            eyre::eyre!(
                "{}:{}:{}: re-sealing vault `{vault}` onto the new key: {e}",
                path.display(),
                site.line,
                site.column
            )
        })?;
        let new_b64 = base64::engine::general_purpose::STANDARD.encode(&new_ciphertext);
        planned.push((
            site.byte_start,
            site.byte_end,
            format!("::{cindy_name}::Secret::sealed_b64({vault:?}, {new_b64:?})"),
        ));
        resealed += 1;
    }

    apply_planned_replacements(path, original, &mut planned)?;
    Ok((converged, resealed))
}

// ---------------------------------------------------------------------
// seal: run orchestrator with CINDY_SEAL_SECRETS, rewrite source in place
// ---------------------------------------------------------------------

/// How each workspace member's crates refer to the `cindy` framework
/// crate: the dependency rename from that member's manifest (`infra`
/// in `[dependencies] infra = { package = "cindy", … }`), defaulting
/// to `cindy`.
///
/// The seal/unseal rewriters splice paths into the user's source and
/// must emit exactly this name — a hardcoded `::cindy::` breaks every
/// renamed-dependency playbook, the same problem `0fa1373` fixed for
/// the macros (which resolve it per-crate with `proc-macro-crate`).
/// The CLI has the same information in one `cargo metadata --no-deps`
/// run, which needs no dependency resolution and no network.
struct CindyNames {
    /// (member manifest dir, local name); the longest matching prefix
    /// wins, so nested members resolve to the innermost one.
    members: Vec<(PathBuf, String)>,
}

impl CindyNames {
    fn collect(metadata: &cargo_metadata::Metadata) -> Self {
        let members = metadata
            .workspace_members
            .iter()
            .filter_map(|id| {
                let pkg = &metadata[id];
                let root = pkg.manifest_path.parent()?.as_std_path().to_owned();
                let name = pkg
                    .dependencies
                    .iter()
                    .find(|d| d.name == "cindy")
                    .and_then(|d| d.rename.clone())
                    .unwrap_or_else(|| "cindy".to_owned());
                Some((root, name))
            })
            .collect();
        Self { members }
    }

    /// The name the crate containing `file` knows cindy by. Files
    /// outside every member — or inside one that doesn't depend on
    /// cindy at all — fall back to `cindy`, matching what an unrenamed
    /// playbook uses.
    fn for_file(&self, file: &Path) -> &str {
        self.members
            .iter()
            .filter(|(root, _)| file.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())
            .map_or("cindy", |(_, name)| name.as_str())
    }
}

/// The workspace root plus the per-crate cindy names, from a single
/// dependency-free `cargo metadata` run.
fn workspace_and_names() -> eyre::Result<(PathBuf, CindyNames)> {
    let meta = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("`cargo metadata --no-deps` for the workspace failed")?;
    Ok((
        meta.workspace_root.clone().into_std_path_buf(),
        CindyNames::collect(&meta),
    ))
}

#[derive(Debug, serde::Deserialize)]
struct SealRecord {
    file: String,
    line: u32,
    column: u32,
    vault: String,
    ciphertext: String,
}

async fn seal_all(orchestrator_path: &Path, all: bool) -> eyre::Result<()> {
    tracing::info!("Asking orchestrator to seal pending secrets...");

    let output = tokio::process::Command::new(orchestrator_path)
        .env("CINDY_SEAL_SECRETS", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .await
        .context("Couldn't spawn orchestrator in seal mode")?;
    if !output.status.success() {
        eyre::bail!(
            "orchestrator seal mode exited with {:?} (see stderr above for the per-secret reason; \
             missing vaults are bootstrapped with `cindy secret vault create <name>`)",
            output.status
        );
    }

    let stdout =
        std::str::from_utf8(&output.stdout).context("orchestrator emitted non-UTF8 on stdout")?;
    let mut records: Vec<SealRecord> = Vec::new();
    for (i, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let rec: SealRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "orchestrator seal line {} is not valid JSON: {line:?}",
                i + 1
            )
        })?;
        records.push(rec);
    }
    if records.is_empty() {
        tracing::info!("No pending secrets found; nothing to seal.");
        return Ok(());
    }

    // `SealRecord.file` comes from `file!()`, which is relative to the
    // workspace root cargo compiled from — *not* to wherever the user
    // happens to run `cindy` from. Anchor it, so seal works from
    // subdirectories too.
    let (workspace_root, cindy_names) = workspace_and_names()?;
    let anchor = |file: &str| {
        let p = PathBuf::from(file);
        if p.is_absolute() {
            p
        } else {
            workspace_root.join(p)
        }
    };

    if !all && crate::picker::stderr_is_tty() {
        let mut snippets = SnippetCache::default();
        let items: Vec<crate::picker::PickItem> = records
            .iter()
            .map(|r| crate::picker::PickItem {
                label: format!(
                    "{}:{} [{}] {}",
                    r.file,
                    r.line,
                    r.vault,
                    snippets.line(&anchor(&r.file), r.line),
                ),
                path: anchor(&r.file),
                line: r.line,
            })
            .collect();
        let Some(selected) = crate::picker::pick("seal secrets", &items)? else {
            tracing::info!("Cancelled; nothing sealed.");
            return Ok(());
        };
        if selected.is_empty() {
            tracing::info!("Nothing selected; nothing sealed.");
            return Ok(());
        }
        records = keep_indices(records, &selected);
    }
    tracing::info!(count = records.len(), "Sealing pending secrets...");

    let mut by_file: std::collections::BTreeMap<String, Vec<SealRecord>> =
        std::collections::BTreeMap::new();
    for r in records {
        by_file.entry(r.file.clone()).or_default().push(r);
    }
    let mut affected = Vec::new();
    for (file, recs) in by_file {
        let path = anchor(&file);
        rewrite_file_seal(&path, &recs, cindy_names.for_file(&path))?;
        affected.push(path);
    }

    cargo_fmt(&affected);
    Ok(())
}

/// Find each `secret!(...)` macro invocation matching a seal record
/// and splice in a `Secret::sealed_b64(...)` call.
fn rewrite_file_seal(path: &Path, records: &[SealRecord], cindy_name: &str) -> eyre::Result<()> {
    let original = std::fs::read_to_string(path)
        .with_context(|| format!("Reading source file {}", path.display()))?;

    let line_byte_starts = compute_line_starts(&original);

    let tokens: proc_macro2::TokenStream = original.parse().map_err(|e| {
        eyre::eyre!(
            "Tokenising {} while looking for `secret!` calls: {e}",
            path.display(),
        )
    })?;

    let mut macros: Vec<MacroSite> = Vec::new();
    find_secret_macros(&tokens, &original, &line_byte_starts, &mut macros)
        .with_context(|| format!("Locating `secret!` calls in {}", path.display()))?;

    let mut planned: Vec<(usize, usize, String)> = Vec::new();
    for rec in records {
        let m = macros
            .iter()
            .find(|m| m.line == rec.line && m.column == rec.column)
            .with_context(|| {
                format!(
                    "Couldn't locate `secret!` macro at {}:{}:{} \u{2014} did the source \
                     change between seal-prepare and seal-apply?",
                    path.display(),
                    rec.line,
                    rec.column,
                )
            })?;
        let replacement = format!(
            "::{cindy_name}::Secret::sealed_b64({:?}, {:?})",
            rec.vault, rec.ciphertext
        );
        planned.push((m.byte_start, m.byte_end, replacement));
    }

    apply_planned_replacements(path, &original, &mut planned)?;
    tracing::info!(
        file = %path.display(),
        count = records.len(),
        "sealed secrets in source"
    );
    Ok(())
}

// ---------------------------------------------------------------------
// unseal: replace Secret::sealed_b64(...) with cindy::secret!(...)
// ---------------------------------------------------------------------

fn unseal_all(all: bool) -> eyre::Result<()> {
    // Walk the whole workspace, not `./src` under whatever cwd we got:
    // sealed secrets can live in workspace members, `tests/`, `build.rs`
    // — and seal (via `file!()` paths) reaches all of those, so unseal
    // must too or the round-trip is lossy.
    let (workspace_root, cindy_names) = workspace_and_names()?;
    let files = walk_rs_files(&workspace_root);

    // Phase 1: collect every sealed call site (no rewriting yet), so
    // the interactive picker can present them all at once.
    let mut per_file: Vec<FileSites> = Vec::new();
    for file in &files {
        let collected = collect_sealed_sites(file)?;
        if !collected.sites.is_empty() {
            per_file.push(collected);
        }
    }
    if per_file.is_empty() {
        tracing::info!("No `Secret::sealed_b64(...)` calls found; nothing to unseal.");
        return Ok(());
    }

    // Phase 2: optional interactive selection over the flattened list.
    if !all && crate::picker::stderr_is_tty() {
        let items: Vec<crate::picker::PickItem> = per_file
            .iter()
            .flat_map(|fs| {
                fs.sites.iter().map(|site| crate::picker::PickItem {
                    label: format!(
                        "{}:{} [{}] {}",
                        fs.path.display(),
                        site.line,
                        site.vault,
                        site_snippet(&fs.original, site),
                    ),
                    path: fs.path.clone(),
                    line: site.line,
                })
            })
            .collect();
        let Some(selected) = crate::picker::pick("unseal secrets", &items)? else {
            tracing::info!("Cancelled; nothing unsealed.");
            return Ok(());
        };
        if selected.is_empty() {
            tracing::info!("Nothing selected; nothing unsealed.");
            return Ok(());
        }
        let selected: std::collections::BTreeSet<usize> = selected.into_iter().collect();

        // Map flat indices back onto the per-file site lists.
        let mut flat = 0usize;
        for fs in &mut per_file {
            fs.sites.retain(|_| {
                let keep = selected.contains(&flat);
                flat += 1;
                keep
            });
        }
        per_file.retain(|fs| !fs.sites.is_empty());
    }

    // Phase 3: decrypt + rewrite only what survived selection.
    let mut affected = Vec::new();
    let mut total = 0usize;
    for fs in &per_file {
        let count = unseal_sites(fs, cindy_names.for_file(&fs.path))?;
        tracing::info!(
            file = %fs.path.display(),
            count,
            "unsealed secrets in source"
        );
        affected.push(fs.path.clone());
        total += count;
    }

    cargo_fmt(&affected);
    tracing::info!(
        count = total,
        "unsealed total secrets (re-run `cindy secret seal` to put them back)"
    );
    Ok(())
}

/// A source file plus every `Secret::sealed_b64(...)` call found in it.
/// Holds the file content the byte offsets were computed against, so
/// the rewrite phase can't race a concurrent edit.
struct FileSites {
    path: PathBuf,
    original: String,
    sites: Vec<SealedSite>,
}

fn collect_sealed_sites(path: &Path) -> eyre::Result<FileSites> {
    let original = std::fs::read_to_string(path)
        .with_context(|| format!("Reading source file {}", path.display()))?;
    let line_starts = compute_line_starts(&original);

    // A file that doesn't tokenize can't hold a sealed call worth
    // finding, and a single stray fixture with a syntax error must not
    // make `cindy secret unseal` impossible for the whole workspace.
    // Warn and skip; read failures stay hard errors.
    let tokens: proc_macro2::TokenStream = match original.parse() {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::warn!(
                "Skipping {}: doesn't tokenise as Rust ({e}), so it can't hold a \
                 `Secret::sealed_b64` call",
                path.display()
            );
            return Ok(FileSites {
                path: path.to_owned(),
                original,
                sites: Vec::new(),
            });
        }
    };

    let mut sites: Vec<SealedSite> = Vec::new();
    find_sealed_calls(&tokens, &original, &line_starts, &mut sites)
        .with_context(|| format!("Locating `Secret::sealed_b64` calls in {}", path.display()))?;
    Ok(FileSites {
        path: path.to_owned(),
        original,
        sites,
    })
}

fn unseal_sites(fs: &FileSites, cindy_name: &str) -> eyre::Result<usize> {
    let FileSites {
        path,
        original,
        sites,
    } = fs;

    let mut planned: Vec<(usize, usize, String)> = Vec::new();
    for site in sites {
        let key = keychain::get_vault_key(&site.vault).map_err(|e| {
            eyre::eyre!(
                "{}:{}:{}: loading the key for vault `{}`: {e}",
                path.display(),
                site.line,
                site.column,
                site.vault,
            )
        })?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(site.ciphertext_b64.as_bytes())
            .with_context(|| {
                format!(
                    "{}:{}:{}: ciphertext for vault `{}` is not valid base64",
                    path.display(),
                    site.line,
                    site.column,
                    site.vault,
                )
            })?;
        let plaintext = crypto::unseal(&key, &ciphertext).map_err(|e| {
            eyre::eyre!(
                "{}:{}:{}: decrypting vault `{}`: {e}",
                path.display(),
                site.line,
                site.column,
                site.vault,
            )
        })?;
        let payload: SealedPayload = postcard::from_bytes(&plaintext).map_err(|e| {
            eyre::eyre!(
                "{}:{}:{}: SealedPayload didn't deserialise for vault `{}`: {e}. \
                 This blob was probably produced by an older cindy version; \
                 rewrite it as `cindy::secret!(...)` by hand and re-run `cindy secret seal`.",
                path.display(),
                site.line,
                site.column,
                site.vault,
            )
        })?;

        let replacement = format!(
            "::{cindy_name}::secret!({:?}, {})",
            site.vault, payload.source
        );
        planned.push((site.byte_start, site.byte_end, replacement));
    }

    apply_planned_replacements(path, original, &mut planned)?;
    Ok(sites.len())
}

// ---------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------

/// Keep only the elements at `indices` (must be sorted ascending, as
/// produced by the picker), preserving order.
fn keep_indices<T>(items: Vec<T>, indices: &[usize]) -> Vec<T> {
    let set: std::collections::BTreeSet<usize> = indices.iter().copied().collect();
    items
        .into_iter()
        .enumerate()
        .filter_map(|(i, item)| set.contains(&i).then_some(item))
        .collect()
}

#[cfg(test)]
mod keep_indices_tests {
    use super::keep_indices;

    #[test]
    fn keeps_only_selected_preserving_order() {
        let v = vec!["a", "b", "c", "d"];
        assert_eq!(keep_indices(v, &[0, 2, 3]), vec!["a", "c", "d"]);
    }

    #[test]
    fn empty_selection_keeps_nothing() {
        let v = vec![1, 2, 3];
        assert!(keep_indices(v, &[]).is_empty());
    }

    #[test]
    fn out_of_range_indices_are_ignored() {
        let v = vec![1, 2];
        assert_eq!(keep_indices(v, &[1, 99]), vec![2]);
    }
}

#[cfg(test)]
mod site_snippet_tests {
    use super::{SealedSite, collect_sealed_sites, site_snippet};

    /// A file with a syntax error anywhere makes `unseal` skip it with
    /// a warning instead of failing the whole workspace walk.
    #[test]
    fn untokenisable_file_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("broken.rs");
        std::fs::write(&file, "fn broken( { this is not rust").unwrap();

        let collected = collect_sealed_sites(&file).unwrap();
        assert!(collected.sites.is_empty());
    }

    fn site(byte_start: usize, byte_end: usize) -> SealedSite {
        SealedSite {
            line: 1,
            column: 0,
            byte_start,
            byte_end,
            vault: "v".into(),
            ciphertext_b64: String::new(),
        }
    }

    #[test]
    fn elides_call_keeps_context() {
        let src = "fn x() {\n    password: ::cindy::Secret::sealed_b64(\"v\", \"QUJD\"),\n}\n";
        let start = src.find("::cindy").unwrap();
        let end = src.find("),").unwrap() + 1;
        assert_eq!(site_snippet(src, &site(start, end)), "password: …,");
    }

    #[test]
    fn multiline_call_drops_suffix() {
        let src = "x: ::cindy::Secret::sealed_b64(\n    \"v\",\n    \"QUJD\",\n),\n";
        let start = src.find("::cindy").unwrap();
        let end = src.rfind(')').unwrap() + 1;
        assert_eq!(site_snippet(src, &site(start, end)), "x: …");
    }
}

#[cfg(test)]
mod seal_unseal_roundtrip_tests {
    use super::*;

    /// Drive the full source-rewriting half of the seal/unseal workflow
    /// against a real file, with a real vault key and ciphertext: a
    /// `secret!` call gets spliced into `Secret::sealed_b64`, found back
    /// by the collector, and decrypted back into the original source
    /// tokens. This is the only code path that rewrites the user's
    /// source files and the last place the plaintext exists.
    #[test]
    fn seal_then_unseal_restores_the_source_call() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("playbook.rs");

        // The macro must sit at a known line/column for the seal record
        // to target it; putting it first on line 1 makes column 1.
        let source_tokens = "Creds { user: \"u\".into(), pw: \"p\".into() }";
        let original = format!("::cindy::secret!(\"rt-vault-x7\", {source_tokens});\n");
        std::fs::write(&file, &original).unwrap();

        // Build the ciphertext exactly the way the `secret!` macro's
        // serialize thunk (and thus the orchestrator's seal mode) does.
        let key = cindy::secret::crypto::generate_vault_key();
        let payload = cindy::secret::SealedPayload {
            value: postcard::to_allocvec(&("u", "p")).unwrap(),
            source: source_tokens.to_owned(),
        };
        let ciphertext =
            cindy::secret::crypto::seal(&key, &postcard::to_allocvec(&payload).unwrap()).unwrap();
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

        // Seal: splice the call into the sealed form.
        let record = SealRecord {
            file: file.display().to_string(),
            line: 1,
            column: 1,
            vault: "rt-vault-x7".to_owned(),
            ciphertext: ciphertext_b64.clone(),
        };
        rewrite_file_seal(&file, &[record], "cindy").unwrap();
        let sealed_source = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            sealed_source,
            format!("::cindy::Secret::sealed_b64(\"rt-vault-x7\", {ciphertext_b64:?});\n"),
        );

        // Unseal: find the sealed call back, decrypt, splice.
        let fs_sites = collect_sealed_sites(&file).unwrap();
        assert_eq!(fs_sites.sites.len(), 1);
        assert_eq!(fs_sites.sites[0].vault, "rt-vault-x7");
        assert_eq!(fs_sites.sites[0].ciphertext_b64, ciphertext_b64);

        let mut chain = std::collections::HashMap::new();
        chain.insert("rt-vault-x7".to_owned(), key);
        cindy::secret::keychain::install_keys(chain);

        let count = unseal_sites(&fs_sites, "cindy").unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("::cindy::secret!(\"rt-vault-x7\", {source_tokens});\n"),
        );
    }

    /// The done-when for the rename fix: against a real workspace whose
    /// member depends on cindy as `infra = { package = "cindy" }`, the
    /// rewriter resolves the local name from `cargo metadata` and the
    /// seal/unseal round-trip emits `::infra::` paths that actually
    /// compile in that workspace.
    #[test]
    fn round_trip_through_a_renamed_dependency() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        std::fs::write(
            ws.join("Cargo.toml"),
            "[package]\nname = \"playbook\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
             [dependencies]\ninfra = { version = \"0.3\", package = \"cindy\" }\n",
        )
        .unwrap();
        std::fs::create_dir(ws.join("src")).unwrap();
        let file = ws.join("src/main.rs");

        // The macro must sit at a known line/column; first on line 1.
        let source_tokens = "Creds { user: \"u\".into(), pw: \"p\".into() }";
        let original = format!("::infra::secret!(\"rt-vault-x8\", {source_tokens});\n");
        std::fs::write(&file, &original).unwrap();

        let meta = cargo_metadata::MetadataCommand::new()
            .no_deps()
            .current_dir(ws)
            .exec()
            .unwrap();
        let names = CindyNames::collect(&meta);
        assert_eq!(names.for_file(&file), "infra");
        // Outside every member: the fallback name.
        assert_eq!(names.for_file(Path::new("/nowhere/x.rs")), "cindy");

        let key = cindy::secret::crypto::generate_vault_key();
        let payload = cindy::secret::SealedPayload {
            value: postcard::to_allocvec(&("u", "p")).unwrap(),
            source: source_tokens.to_owned(),
        };
        let ciphertext =
            cindy::secret::crypto::seal(&key, &postcard::to_allocvec(&payload).unwrap()).unwrap();
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

        let record = SealRecord {
            file: file.display().to_string(),
            line: 1,
            column: 1,
            vault: "rt-vault-x8".to_owned(),
            ciphertext: ciphertext_b64.clone(),
        };
        let name = names.for_file(&file);
        rewrite_file_seal(&file, &[record], name).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("::infra::Secret::sealed_b64(\"rt-vault-x8\", {ciphertext_b64:?});\n"),
        );

        // The collector is path-liberal, so the renamed form is found
        // back regardless of prefix.
        let fs_sites = collect_sealed_sites(&file).unwrap();
        assert_eq!(fs_sites.sites.len(), 1);

        let mut chain = std::collections::HashMap::new();
        chain.insert("rt-vault-x8".to_owned(), key);
        cindy::secret::keychain::install_keys(chain);

        let count = unseal_sites(&fs_sites, names.for_file(&file)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("::infra::secret!(\"rt-vault-x8\", {source_tokens});\n"),
        );
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;

    fn seal_with(key: &cindy::secret::crypto::VaultKey, source_tokens: &str) -> String {
        let payload = cindy::secret::SealedPayload {
            value: postcard::to_allocvec(&("u", "p")).unwrap(),
            source: source_tokens.to_owned(),
        };
        let ciphertext =
            cindy::secret::crypto::seal(key, &postcard::to_allocvec(&payload).unwrap()).unwrap();
        base64::engine::general_purpose::STANDARD.encode(&ciphertext)
    }

    /// The core promise: after rotation the site's ciphertext opens
    /// under the new key, refuses the old one (by name — the leaked
    /// key is the whole point), and the unseal round-trip still
    /// restores the original source tokens.
    #[test]
    fn rotation_reseals_onto_the_new_key_and_old_key_cannot_read_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("playbook.rs");

        let source_tokens = "Creds { user: \"u\".into(), pw: \"p\".into() }";
        let old_key = cindy::secret::crypto::generate_vault_key();
        let old_b64 = seal_with(&old_key, source_tokens);
        std::fs::write(
            &file,
            format!("::cindy::Secret::sealed_b64(\"rt-rot-x9\", {old_b64:?});\n"),
        )
        .unwrap();

        let fs_sites = collect_sealed_sites(&file).unwrap();
        assert_eq!(fs_sites.sites.len(), 1);

        let new_key = cindy::secret::crypto::generate_vault_key();
        let (converged, resealed) =
            rotate_sites(&fs_sites, "rt-rot-x9", &new_key, &old_key, "cindy").unwrap();
        assert_eq!((converged, resealed), (0, 1));

        // The rewritten file is still a findable sealed call, and the
        // ciphertext is NEW (not a re-emission of the old b64).
        let after = collect_sealed_sites(&file).unwrap();
        assert_eq!(after.sites.len(), 1);
        assert_ne!(after.sites[0].ciphertext_b64, old_b64);

        let new_ct = base64::engine::general_purpose::STANDARD
            .decode(after.sites[0].ciphertext_b64.as_bytes())
            .unwrap();
        assert!(cindy::secret::crypto::unseal(&new_key, &new_ct).is_ok());
        let err = cindy::secret::crypto::unseal(&old_key, &new_ct).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("AEAD decryption failed"), "got: {msg}");
        assert!(!msg.contains("version"), "got: {msg}");

        // End to end: with the new key installed, unseal restores the
        // original source expression.
        let mut chain = std::collections::HashMap::new();
        chain.insert("rt-rot-x9".to_owned(), new_key);
        cindy::secret::keychain::install_keys(chain);
        let count = unseal_sites(&after, "cindy").unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("::cindy::secret!(\"rt-rot-x9\", {source_tokens});\n"),
        );
    }

    /// The resume path: a run interrupted mid-reseal leaves some sites
    /// on the new key and some on the old. A second pass must converge
    /// both without touching the already-done one.
    #[test]
    fn resumed_rotation_converges_mixed_sites() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("playbook.rs");

        let old_key = cindy::secret::crypto::generate_vault_key();
        let new_key = cindy::secret::crypto::generate_vault_key();
        let old_b64 = seal_with(&old_key, "1");
        let new_b64 = seal_with(&new_key, "2");
        std::fs::write(
            &file,
            format!(
                "a: ::cindy::Secret::sealed_b64(\"rt-rot-x10\", {old_b64:?});\n\
                 b: ::cindy::Secret::sealed_b64(\"rt-rot-x10\", {new_b64:?});\n"
            ),
        )
        .unwrap();

        let fs_sites = collect_sealed_sites(&file).unwrap();
        assert_eq!(fs_sites.sites.len(), 2);

        let (converged, resealed) =
            rotate_sites(&fs_sites, "rt-rot-x10", &new_key, &old_key, "cindy").unwrap();
        assert_eq!((converged, resealed), (1, 1));

        // Both sites now open under the new key, and the file still
        // holds two findable sealed calls.
        let after = collect_sealed_sites(&file).unwrap();
        assert_eq!(after.sites.len(), 2);
        for site in &after.sites {
            let ct = base64::engine::general_purpose::STANDARD
                .decode(site.ciphertext_b64.as_bytes())
                .unwrap();
            assert!(cindy::secret::crypto::unseal(&new_key, &ct).is_ok());
        }
    }

    /// Rotation is vault-scoped: a site of another vault in the same
    /// file must come through byte-for-byte identical.
    #[test]
    fn other_vaults_are_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("playbook.rs");

        let old_key = cindy::secret::crypto::generate_vault_key();
        let new_key = cindy::secret::crypto::generate_vault_key();
        let bystander_key = cindy::secret::crypto::generate_vault_key();
        let rotated_b64 = seal_with(&old_key, "1");
        let bystander_b64 = seal_with(&bystander_key, "2");
        std::fs::write(
            &file,
            format!(
                "a: ::cindy::Secret::sealed_b64(\"rt-rot-x11\", {rotated_b64:?});\n\
                 b: ::cindy::Secret::sealed_b64(\"rt-rot-bystander\", {bystander_b64:?});\n"
            ),
        )
        .unwrap();

        let fs_sites = collect_sealed_sites(&file).unwrap();
        let (_, resealed) =
            rotate_sites(&fs_sites, "rt-rot-x11", &new_key, &old_key, "cindy").unwrap();
        assert_eq!(resealed, 1);

        let after = collect_sealed_sites(&file).unwrap();
        let bystander = after
            .sites
            .iter()
            .find(|s| s.vault == "rt-rot-bystander")
            .unwrap();
        assert_eq!(bystander.ciphertext_b64, bystander_b64);
    }

    /// Key installation for rotation keeps the mode `vault create`
    /// writes — 0600, never wider.
    #[cfg(unix)]
    #[test]
    fn overwrite_keeps_key_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotated.key");
        let key = cindy::secret::crypto::generate_vault_key();
        write_vault_key_overwrite(&path, &key).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// Per-file line cache for building picker labels without re-reading
/// the same source file once per record.
#[derive(Default)]
struct SnippetCache {
    files: std::collections::HashMap<PathBuf, Vec<String>>,
}

impl SnippetCache {
    /// Trimmed, length-capped text of `line` (1-based) in `path`.
    fn line(&mut self, path: &Path, line: u32) -> String {
        let lines = self.files.entry(path.to_owned()).or_insert_with(|| {
            std::fs::read_to_string(path)
                .map(|c| c.lines().map(str::to_owned).collect())
                .unwrap_or_default()
        });
        let Some(text) = line.checked_sub(1).and_then(|i| lines.get(i as usize)) else {
            return String::new();
        };
        truncate_snippet(text)
    }
}

/// Trim and cap a single-line snippet for picker labels.
fn truncate_snippet(text: &str) -> String {
    const MAX: usize = 60;
    let trimmed = text.trim();
    match trimmed.char_indices().nth(MAX) {
        Some((byte, _)) => format!("{}…", &trimmed[..byte]),
        None => trimmed.to_owned(),
    }
}

/// The source line containing `site`, with the `Secret::sealed_b64(...)`
/// call itself elided so base64 ciphertext doesn't pollute fuzzy
/// matching — leaves surrounding context like `password: …,`.
fn site_snippet(original: &str, site: &SealedSite) -> String {
    let line_start = original[..site.byte_start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = original[site.byte_start..]
        .find('\n')
        .map_or(original.len(), |i| site.byte_start + i);

    let prefix = &original[line_start..site.byte_start];
    // The call may span multiple lines; only keep a suffix when it
    // ends on the same line it started.
    let suffix = if site.byte_end <= line_end {
        &original[site.byte_end..line_end]
    } else {
        ""
    };
    truncate_snippet(&format!("{prefix}…{suffix}"))
}

fn apply_planned_replacements(
    path: &Path,
    original: &str,
    planned: &mut [(usize, usize, String)],
) -> eyre::Result<()> {
    // Reverse byte order so earlier offsets stay stable while we
    // splice tail-first.
    planned.sort_by_key(|(s, _, _)| std::cmp::Reverse(*s));

    // Overlapping (or duplicate) ranges would splice into
    // already-replaced text and silently corrupt the file — refuse.
    // Duplicates can genuinely happen, e.g. the same file compiled in
    // twice via `include!`/`#[path]` producing two identical records.
    for pair in planned.windows(2) {
        let (later_start, _, _) = pair[0];
        let (_, earlier_end, _) = pair[1];
        if earlier_end > later_start {
            eyre::bail!(
                "planned rewrites in {} overlap (byte ranges ..{earlier_end} and {later_start}..); \
                 refusing to rewrite. Is the same source file compiled into the binary twice?",
                path.display(),
            );
        }
    }

    let mut new = original.to_owned();
    for (start, end, replacement) in planned.iter() {
        new.replace_range(*start..*end, replacement);
    }

    if new != original {
        // Write-to-temp + rename so a crash mid-write can't truncate the
        // user's source file (which, on seal, is the only place the
        // just-encrypted plaintext still exists).
        let dir = path.parent().unwrap_or(Path::new("."));
        let tmp = tempfile::NamedTempFile::new_in(dir)
            .with_context(|| format!("Creating temp file next to {}", path.display()))?;
        std::io::Write::write_all(&mut tmp.as_file(), new.as_bytes())
            .with_context(|| format!("Writing rewritten source for {}", path.display()))?;
        // Keep the original file's permissions — the temp file's 0600
        // would otherwise stick after the rename.
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = tmp.as_file().set_permissions(meta.permissions());
        }
        tmp.persist(path)
            .with_context(|| format!("Replacing {}", path.display()))?;
    }
    Ok(())
}

/// Recursively collect every `.rs` file under `root`, skipping
/// `target/` directories.
fn walk_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_recursive(root, &mut out);
    out
}

fn walk_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `entry.file_type()` doesn't follow symlinks — a symlinked
        // directory is skipped rather than recursed, so a link cycle
        // can't loop us forever.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if path.file_name().and_then(|s| s.to_str()) == Some("target") {
                continue;
            }
            walk_recursive(&path, out);
        } else if file_type.is_file() && path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// Best-effort `cargo fmt -- <files>`. Failures (rustfmt missing, the
/// user has unparseable code we just touched, …) are logged but don't
/// stop the run — the rewrite itself already landed.
fn cargo_fmt(files: &[PathBuf]) {
    if files.is_empty() {
        return;
    }
    // `cargo fmt -- <file>` forwards `<file>` to rustfmt directly,
    // bypassing cargo's "format the whole package" logic so we only
    // touch the files we rewrote.
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("fmt").arg("--");
    for f in files {
        cmd.arg(f);
    }
    match cmd.status() {
        Ok(s) if s.success() => {
            tracing::info!(count = files.len(), "ran `cargo fmt` on affected files");
        }
        Ok(s) => {
            tracing::warn!(
                "`cargo fmt` exited with {s:?}; rewritten files may be poorly formatted"
            );
        }
        Err(e) => {
            tracing::warn!("couldn't spawn `cargo fmt` ({e}); rewritten files left as-is");
        }
    }
}

fn compute_line_starts(s: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in s.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn line_col_to_byte(line_starts: &[usize], source: &str, line: u32, column: u32) -> Option<usize> {
    let line_idx = line.checked_sub(1)? as usize;
    let line_start = *line_starts.get(line_idx)?;
    let line_end = line_starts
        .get(line_idx + 1)
        .copied()
        .unwrap_or(source.len());
    let line_slice = source.get(line_start..line_end)?;

    let col_chars = column.checked_sub(1)? as usize;
    let mut chars_seen = 0;
    let mut byte_off = 0;
    for c in line_slice.chars() {
        if chars_seen == col_chars {
            return Some(line_start + byte_off);
        }
        chars_seen += 1;
        byte_off += c.len_utf8();
    }
    if chars_seen == col_chars {
        Some(line_start + byte_off)
    } else {
        None
    }
}

struct MacroSite {
    line: u32,
    column: u32,
    byte_start: usize,
    byte_end: usize,
}

struct SealedSite {
    line: u32,
    column: u32,
    byte_start: usize,
    byte_end: usize,
    vault: String,
    ciphertext_b64: String,
}

/// Convert a span's start/end (line, column) pair to byte offsets,
/// erroring instead of guessing: a miss here means our span arithmetic
/// disagrees with the file on disk, and proceeding with a fabricated
/// range could rewrite arbitrary source text.
fn span_to_byte_range(
    line_starts: &[usize],
    source: &str,
    start: (u32, u32),
    end: (u32, u32),
) -> eyre::Result<(usize, usize)> {
    let convert = |(line, column): (u32, u32)| {
        line_col_to_byte(line_starts, source, line, column).ok_or_else(|| {
            eyre::eyre!("couldn't map source position {line}:{column} back to a byte offset")
        })
    };
    Ok((convert(start)?, convert(end)?))
}

/// Walk `<path>secret!<group>` invocations including nested ones.
fn find_secret_macros(
    stream: &proc_macro2::TokenStream,
    source: &str,
    line_starts: &[usize],
    out: &mut Vec<MacroSite>,
) -> eyre::Result<()> {
    use proc_macro2::{Spacing, TokenTree};

    let trees: Vec<TokenTree> = stream.clone().into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        if let TokenTree::Ident(ident) = &trees[i]
            && ident == "secret"
            && let Some(TokenTree::Punct(bang)) = trees.get(i + 1)
            && bang.as_char() == '!'
            && let Some(TokenTree::Group(grp)) = trees.get(i + 2)
        {
            let mut path_start = i;
            while path_start >= 3 {
                if let Some(TokenTree::Punct(p2)) = trees.get(path_start - 1)
                    && p2.as_char() == ':'
                    && let Some(TokenTree::Punct(p1)) = trees.get(path_start - 2)
                    && p1.as_char() == ':'
                    && p1.spacing() == Spacing::Joint
                    && let Some(TokenTree::Ident(_)) = trees.get(path_start - 3)
                {
                    path_start -= 3;
                } else {
                    break;
                }
            }
            // Optional leading `::` (the seal/unseal step emits it,
            // and `column!()` at the call site includes its position).
            if path_start >= 2
                && let Some(TokenTree::Punct(c2)) = trees.get(path_start - 1)
                && c2.as_char() == ':'
                && let Some(TokenTree::Punct(c1)) = trees.get(path_start - 2)
                && c1.as_char() == ':'
                && c1.spacing() == Spacing::Joint
            {
                path_start -= 2;
            }

            let start_lc = trees[path_start].span().start();
            let close_lc = grp.span_close().end();
            let line = start_lc.line as u32;
            let column = start_lc.column as u32 + 1;
            let (byte_start, byte_end) = span_to_byte_range(
                line_starts,
                source,
                (line, column),
                (close_lc.line as u32, close_lc.column as u32 + 1),
            )?;

            out.push(MacroSite {
                line,
                column,
                byte_start,
                byte_end,
            });
            i += 3;
            continue;
        }

        if let TokenTree::Group(grp) = &trees[i] {
            find_secret_macros(&grp.stream(), source, line_starts, out)?;
        }
        i += 1;
    }
    Ok(())
}

/// Walk `<path>Secret::sealed_b64(<group>)` invocations including
/// nested ones. The group is expected to be `("<vault>", "<b64>")` —
/// any call that doesn't parse cleanly is silently skipped (probably
/// hand-written and not produced by `cindy secret seal`).
fn find_sealed_calls(
    stream: &proc_macro2::TokenStream,
    source: &str,
    line_starts: &[usize],
    out: &mut Vec<SealedSite>,
) -> eyre::Result<()> {
    use proc_macro2::{Spacing, TokenTree};

    let trees: Vec<TokenTree> = stream.clone().into_iter().collect();
    let mut i = 0;
    while i < trees.len() {
        // Need at least: Secret :: sealed_b64 ( ... )  (5 tokens).
        if let TokenTree::Ident(secret_ident) = &trees[i]
            && secret_ident == "Secret"
            && let Some(TokenTree::Punct(p1)) = trees.get(i + 1)
            && p1.as_char() == ':'
            && p1.spacing() == Spacing::Joint
            && let Some(TokenTree::Punct(p2)) = trees.get(i + 2)
            && p2.as_char() == ':'
            && let Some(TokenTree::Ident(method_ident)) = trees.get(i + 3)
            && method_ident == "sealed_b64"
            && let Some(TokenTree::Group(grp)) = trees.get(i + 4)
        {
            // Walk back over any path prefix: `(ident ::)*` before
            // `Secret`. Any of `::cindy::Secret`, `cindy::Secret`,
            // `crate::Secret`, etc. is fine.
            let mut path_start = i;
            while path_start >= 3 {
                if let Some(TokenTree::Punct(c2)) = trees.get(path_start - 1)
                    && c2.as_char() == ':'
                    && let Some(TokenTree::Punct(c1)) = trees.get(path_start - 2)
                    && c1.as_char() == ':'
                    && c1.spacing() == Spacing::Joint
                    && let Some(TokenTree::Ident(_)) = trees.get(path_start - 3)
                {
                    path_start -= 3;
                } else {
                    break;
                }
            }
            // Leading `::` is also legal (the seal step emits it).
            // Each `::` is two Joint puncts; allow one extra step.
            if path_start >= 2
                && let Some(TokenTree::Punct(c2)) = trees.get(path_start - 1)
                && c2.as_char() == ':'
                && let Some(TokenTree::Punct(c1)) = trees.get(path_start - 2)
                && c1.as_char() == ':'
                && c1.spacing() == Spacing::Joint
            {
                path_start -= 2;
            }

            if let Some((vault, ciphertext_b64)) = parse_two_string_literals(&grp.stream()) {
                let start_lc = trees[path_start].span().start();
                let close_lc = grp.span_close().end();
                let line = start_lc.line as u32;
                let column = start_lc.column as u32 + 1;
                let (byte_start, byte_end) = span_to_byte_range(
                    line_starts,
                    source,
                    (line, column),
                    (close_lc.line as u32, close_lc.column as u32 + 1),
                )?;

                out.push(SealedSite {
                    line,
                    column,
                    byte_start,
                    byte_end,
                    vault,
                    ciphertext_b64,
                });
                i += 5;
                continue;
            }
        }

        if let TokenTree::Group(grp) = &trees[i] {
            find_sealed_calls(&grp.stream(), source, line_starts, out)?;
        }
        i += 1;
    }
    Ok(())
}

/// Parse `("vault-literal", "ciphertext-literal")` out of a token
/// group. Returns `None` if the shape doesn't match — we'd rather
/// silently skip a stray `Secret::sealed_b64(...)` than crash.
fn parse_two_string_literals(stream: &proc_macro2::TokenStream) -> Option<(String, String)> {
    use syn::parse::Parser as _;

    let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
    let punct = parser.parse2(stream.clone()).ok()?;
    let args: Vec<&syn::Expr> = punct.iter().collect();
    if args.len() != 2 {
        return None;
    }
    let extract = |e: &syn::Expr| -> Option<String> {
        if let syn::Expr::Lit(lit) = e
            && let syn::Lit::Str(s) = &lit.lit
        {
            Some(s.value())
        } else {
            None
        }
    };
    Some((extract(args[0])?, extract(args[1])?))
}
