//! Download a file over HTTP(S) to a path on the remote machine.
//!
//! Idempotent when a [`checksum`](State::checksum) is supplied: if the
//! destination already exists and its digest matches, the download is
//! skipped. Without a checksum the file is (re)fetched only when it's
//! missing — to refresh a mutable URL, remove the file first
//! (`path::absent(dest)`) and fetch again.
//!
//! HTTP is performed with the pure-Rust [`ureq`] client over `rustls`
//! (no OpenSSL / system TLS), so the build stays free of C and dynamic
//! library dependencies.

use std::io::Read as _;
use std::path::PathBuf;

use sha2::Digest as _;

use crate as cindy;
use crate::Context;

/// A digest to verify a downloaded file against. Pairing the algorithm
/// with the expected hex string makes a fetch both *idempotent* (skip
/// when the on-disk file already matches) and *safe* (a corrupted or
/// tampered download is rejected).
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Checksum {
    Sha256(String),
    Sha512(String),
}

impl Checksum {
    /// Lower-cased expected hex digest.
    fn expected(&self) -> String {
        match self {
            Checksum::Sha256(h) | Checksum::Sha512(h) => h.trim().to_ascii_lowercase(),
        }
    }

    /// Reject a malformed expected digest *before* any download. A
    /// truncated copy-paste or a stray character would otherwise just
    /// "never match" — re-downloading every run and then failing with a
    /// checksum mismatch that hides the real problem.
    fn validate(&self) -> crate::Result<()> {
        let (want_len, algo) = match self {
            Checksum::Sha256(_) => (64, "sha256"),
            Checksum::Sha512(_) => (128, "sha512"),
        };
        let expected = self.expected();
        if expected.len() != want_len || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            crate::bail!(
                "malformed {algo} digest {expected:?}: expected {want_len} hex characters, \
                 got {} — check for truncation or stray characters",
                expected.len(),
            );
        }
        Ok(())
    }

    /// Compute this checksum's digest over `bytes`, as a hex string.
    fn digest(&self, bytes: &[u8]) -> String {
        match self {
            Checksum::Sha256(_) => hex(&sha2::Sha256::digest(bytes)),
            Checksum::Sha512(_) => hex(&sha2::Sha512::digest(bytes)),
        }
    }

    /// Does `bytes` match the expected digest?
    fn matches(&self, bytes: &[u8]) -> bool {
        self.digest(bytes) == self.expected()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Source URL (`http`/`https`).
    pub url: String,
    /// Destination path on the remote.
    pub dest: PathBuf,
    /// Optional digest to verify the download against and to make the
    /// task idempotent. `None` ⇒ skip only when the file already exists.
    pub checksum: Option<Checksum>,
    /// Owning user for the downloaded file. `None` ⇒ leave as-is.
    pub user: Option<String>,
    /// Owning group for the downloaded file. `None` ⇒ leave as-is.
    pub group: Option<String>,
    /// Mode to set on the downloaded file. `None` ⇒ leave the OS default.
    pub mode: Option<super::path::Mode>,
}

/// If the destination already holds satisfying content (readable
/// regular file whose checksum matches, or any readable file when no
/// checksum was given), return those bytes so the download can be
/// skipped. Owner/mode may still have drifted — the caller pushes the
/// bytes through `path` either way to reconcile.
///
/// There is deliberately no "force re-download" flag: with a checksum,
/// a stale file *is* re-fetched; without one, refreshing a mutable URL
/// is spelled out as `path::absent(dest)` followed by the fetch — two
/// visible steps instead of a boolean that flips this function's
/// meaning.
///
/// Any read failure — missing file, or the destination being a
/// directory/special file — means "not satisfied, download".
fn existing_matching_content(state: &State) -> Option<Vec<u8>> {
    let existing = std::fs::read(&state.dest).ok()?;
    match &state.checksum {
        Some(sum) if !sum.matches(&existing) => None,
        _ => Some(existing),
    }
}

/// `GET` the URL and return the full response body.
fn download(url: &str) -> crate::Result<Vec<u8>> {
    // Explicit timeouts — ureq's defaults are all `None`, so a
    // blackholed server or stalled transfer would otherwise hang the
    // play forever with no diagnostic.
    let agent = ureq::Agent::config_builder()
        .timeout_connect(Some(std::time::Duration::from_secs(30)))
        .timeout_global(Some(std::time::Duration::from_secs(60 * 60)))
        .build()
        .new_agent();
    let mut response = agent.get(url).call().context(format!("GET {url} failed"))?;

    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .context(format!("Reading response body from {url} failed"))?;
    Ok(body)
}

/// Download a file to the remote, verifying its checksum if given.
///
/// The download is fetched into memory and verified, then materialised
/// on disk by delegating to the [`path`](super::path) module: that's
/// what gives `fetch` correct file/dir/symlink transition handling,
/// ownership, and the same struct diff as every other builtin — without
/// reimplementing any of it here.
///
/// This is the full-control entry point taking a [`State`] (owner, mode,
/// …). For the common cases, prefer the intent-named helpers: [`url`],
/// [`verified`].
#[crate::remote]
pub fn fetch(state: State) -> crate::Result<super::Return> {
    apply(state)
}

// Intent-named helpers, each a single `#[crate::action]` fn whose body builds
// a `State` and calls `apply`. The macro generates the concrete `#[remote]`
// wire entry point, the orchestrator shim, and the in-process `::inner`.

/// Download `url` to `dest`, owned by the worker's identity at `0o644`.
/// Without a checksum the file is fetched only when missing. Orchestrator:
/// `url(url, dest).await?`.
#[crate::action]
pub fn url(url: impl Into<String>, dest: impl Into<PathBuf>) -> crate::Result<super::Return> {
    apply(State {
        url,
        dest,
        checksum: None,
        user: None,
        group: None,
        mode: None,
    })
}

/// Download `url` to `dest` and verify it against `checksum` — making the
/// fetch both idempotent (skip when the on-disk file already matches) and
/// safe (a corrupt/tampered download is rejected). Orchestrator:
/// `verified(url, dest, checksum).await?`.
#[crate::action]
pub fn verified(
    url: impl Into<String>,
    dest: impl Into<PathBuf>,
    checksum: impl Into<Checksum>,
) -> crate::Result<super::Return> {
    apply(State {
        url,
        dest,
        checksum: Some(checksum),
        user: None,
        group: None,
        mode: None,
    })
}

fn apply(state: State) -> crate::Result<super::Return> {
    if let Some(sum) = &state.checksum {
        sum.validate()?;
    }

    let body = match existing_matching_content(&state) {
        // Content already satisfied: skip the download, but still fall
        // through to `path` below so owner/mode drift on the existing
        // file is repaired instead of silently reported `Unchanged`.
        Some(existing) => existing,
        None => {
            eprintln!("fetch {} -> {}", state.url, state.dest.display());
            let body = download(&state.url)?;
            if let Some(sum) = &state.checksum
                && !sum.matches(&body)
            {
                crate::bail!(
                    "checksum mismatch for {}: expected {}, got {}",
                    state.url,
                    sum.expected(),
                    sum.digest(&body),
                );
            }
            body
        }
    };

    // Hand the bytes to the `path` module, which owns the on-disk
    // state-transition logic (and emits the diff). `path` requires a
    // total owner/mode spec; fetch's own owner/mode are optional
    // ("`None` ⇒ leave as-is"), so fill unspecified fields from the
    // existing file when there is one, else from the worker's identity
    // and a conventional `0o644`.
    let (user, group, mode) = match std::fs::metadata(&state.dest) {
        Ok(meta) => {
            use std::os::unix::fs::MetadataExt as _;
            (
                state.user.unwrap_or_else(|| super::name_of_uid(meta.uid())),
                state
                    .group
                    .unwrap_or_else(|| super::name_of_gid(meta.gid())),
                state
                    .mode
                    .unwrap_or(super::path::Mode::from_st_mode(meta.mode())),
            )
        }
        Err(_) => {
            let (user, group) = super::current_owner_names();
            (
                state.user.unwrap_or(user),
                state.group.unwrap_or(group),
                state.mode.unwrap_or(super::path::Mode(0o644)),
            )
        }
    };
    super::path::file_raw::inner(state.dest, body, user, group, mode)
}
