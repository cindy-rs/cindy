//! Download a file over HTTP(S) to a path on the remote machine.
//!
//! Idempotent when a [`checksum`](State::checksum) is supplied: if the
//! destination already exists and its digest matches, the download is
//! skipped. Without a checksum the file is (re)fetched only when it's
//! missing — to refresh a mutable URL, remove the file first
//! (`path::absent(dest)`) and fetch again.
//!
//! The body is **streamed** to the destination, never buffered whole.
//! The digest is computed as the bytes pass through and the file is
//! published only once it verifies, so a multi-gigabyte artefact costs a
//! fixed-size buffer rather than its own size in RAM on the target —
//! which matters, because the target is often the smallest machine in
//! the fleet. [`State::max_bytes`] bounds what a URL is allowed to
//! deliver at all.
//!
//! HTTP is performed with the pure-Rust [`ureq`] client over `rustls`
//! (no OpenSSL / system TLS), so the build stays free of C and dynamic
//! library dependencies.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use sha2::Digest as _;

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
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Ceiling on a downloaded body when [`State::max_bytes`] is `None`.
///
/// Streaming removed the memory blow-up but not the disk one: a
/// misconfigured URL, or a server that simply never stops sending, would
/// still fill the target's filesystem. 4 GiB is past any plausible
/// artefact while still being a bound.
const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Read buffer for the streaming digest of an on-disk file.
const DIGEST_CHUNK: usize = 64 * 1024;

/// How long the server gets to produce response *headers*. The body is
/// bounded by [`State::max_bytes`] rather than a clock, so that a slow
/// link doesn't fail a legitimately large artefact — but a blackholed
/// host still has to fail fast instead of hanging the play with no
/// diagnostic. [`State::timeout`] adds a hard end-to-end deadline when
/// that's what you want.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long the TCP/TLS connection setup gets.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Incremental digest for a [`Checksum`]'s algorithm, so a download is
/// verified from the same pass that writes it to disk instead of being
/// buffered first.
enum Hasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    fn for_checksum(sum: &Checksum) -> Self {
        match sum {
            Checksum::Sha256(_) => Self::Sha256(sha2::Sha256::new()),
            Checksum::Sha512(_) => Self::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }

    fn finish(self) -> String {
        match self {
            Self::Sha256(h) => hex(&h.finalize()),
            Self::Sha512(h) => hex(&h.finalize()),
        }
    }
}

/// A [`Read`](std::io::Read) adapter that digests every byte it passes
/// through. Wrapping the response body in this is what lets the verify
/// step happen without a second copy of the artefact anywhere.
struct Digesting<R> {
    inner: R,
    hasher: Option<Hasher>,
}

impl<R: std::io::Read> std::io::Read for Digesting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(&buf[..n]);
        }
        Ok(n)
    }
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
    /// Mode to set on the downloaded file. `None` ⇒ `0o644`.
    pub mode: Option<super::path::Mode>,
    /// Largest body this fetch will accept, in bytes. A declared
    /// `Content-Length` over the limit is rejected before any transfer;
    /// a server that lies about (or omits) the length is cut off once it
    /// exceeds the limit mid-stream, leaving the destination untouched.
    /// `None` ⇒ [`DEFAULT_MAX_BYTES`].
    pub max_bytes: Option<u64>,
    /// Hard end-to-end deadline for the whole fetch, DNS lookup to last
    /// byte. `None` (the default) lets a large artefact take as long as
    /// the link needs; the transfer is still bounded by
    /// [`max_bytes`](Self::max_bytes) and header retrieval by its own
    /// fixed timeout.
    pub timeout: Option<std::time::Duration>,
}

/// `url` with any `user:password@` userinfo replaced.
///
/// Log and error lines are forwarded to the operator's terminal and the
/// run view's scrollback verbatim, so a token embedded in the URL would
/// otherwise be on screen (and in any captured CI log) in the clear.
fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    let Some(scheme_end) = url.find("://") else {
        return std::borrow::Cow::Borrowed(url);
    };
    let authority_start = scheme_end + 3;
    // Userinfo, when present, ends at the first `@` *within the
    // authority*; a later `@` in the path or query is not credentials.
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| authority_start + i);
    let Some(at) = url[authority_start..authority_end].find('@') else {
        return std::borrow::Cow::Borrowed(url);
    };
    std::borrow::Cow::Owned(format!(
        "{}***@{}",
        &url[..authority_start],
        &url[authority_start + at + 1..]
    ))
}

/// Streaming digest of the file at `path` under `sum`'s algorithm, or
/// `None` if it can't be read (missing, a directory, permissions) —
/// which the caller reads as "not satisfied, download".
fn digest_file(path: &Path, sum: &Checksum) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Hasher::for_checksum(sum);
    let mut buf = vec![0u8; DIGEST_CHUNK];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(hasher.finish())
}

/// [`path`](super::path) requires a total owner/mode spec; fetch's own
/// are optional ("`None` ⇒ leave as-is"). Fill the unspecified fields
/// from the existing file when there is one, else from the worker's
/// identity and a conventional `0o644`.
fn desired_attrs(
    state: &State,
    existing: Option<&std::fs::Metadata>,
) -> (String, String, super::path::Mode) {
    match existing {
        Some(meta) => {
            use std::os::unix::fs::MetadataExt as _;
            (
                state
                    .user
                    .clone()
                    .unwrap_or_else(|| super::name_of_uid(meta.uid())),
                state
                    .group
                    .clone()
                    .unwrap_or_else(|| super::name_of_gid(meta.gid())),
                state
                    .mode
                    .unwrap_or(super::path::Mode::from_st_mode(meta.mode())),
            )
        }
        None => {
            let (user, group) = super::current_owner_names();
            (
                state.user.clone().unwrap_or(user),
                state.group.clone().unwrap_or(group),
                state.mode.unwrap_or(super::path::Mode(0o644)),
            )
        }
    }
}

/// HTTP agent for one fetch. ureq's timeout defaults are all `None`, so
/// without these a blackholed server would hang the play forever with no
/// diagnostic.
fn agent(timeout: Option<std::time::Duration>) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(HEADER_TIMEOUT))
        .timeout_global(timeout)
        .build()
        .new_agent()
}

/// Download a file to the remote, verifying its checksum if given.
///
/// The body streams into a temp file next to the destination, which the
/// [`path`](super::path) module then publishes with an atomic rename —
/// so `fetch` inherits correct file/dir/symlink transition handling,
/// ownership and durability without reimplementing any of it, and
/// without the artefact ever existing in memory.
///
/// This is the full-control entry point taking a [`State`] (owner, mode,
/// size limit, …). For the common cases, prefer the intent-named
/// helpers: [`url`], [`verified`].
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
        ..State::default()
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
        ..State::default()
    })
}

fn apply(state: State) -> crate::Result<super::Return> {
    if let Some(sum) = &state.checksum {
        sum.validate()?;
    }

    // Only a regular file can satisfy the destination. Anything else —
    // directory, symlink, special file — is what the atomic publish
    // below replaces, and its attributes are not inherited.
    let existing = std::fs::symlink_metadata(&state.dest)
        .ok()
        .filter(std::fs::Metadata::is_file);

    // Idempotency check that never loads the artefact: with a checksum,
    // stream-hash what's on disk; without one, existence is all we can
    // honestly check.
    let satisfied = existing.is_some()
        && match &state.checksum {
            Some(sum) => digest_file(&state.dest, sum).is_some_and(|have| have == sum.expected()),
            None => true,
        };

    let (user, group, mode) = desired_attrs(&state, existing.as_ref());

    if satisfied {
        // Content is already right, but owner/mode may have drifted —
        // reconcile those rather than reporting a blanket `Unchanged`.
        return super::path::reconcile_file_attrs(&state.dest, &user, &group, mode);
    }

    // Resolve the owner before the transfer, so a typo'd user fails in a
    // second instead of after a gigabyte has crossed the wire.
    let (uid, gid) = super::path::resolve_owner(&user, &group)?;
    let max = state.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let url = redact_url(&state.url);

    let _ = crate::diff::note(
        &mut std::io::stderr().lock(),
        &format!("~ {} <- {url}", state.dest.display()),
    );

    let mut response = agent(state.timeout)
        .get(&state.url)
        .call()
        .context(format!("GET {url} failed"))?;

    // Reject an over-sized artefact from the declared length before a
    // single body byte is transferred, when the server declares one.
    if let Some(len) = response.body().content_length()
        && len > max
    {
        crate::bail!(
            "{url} declares {len} bytes, over this fetch's {max}-byte limit \
             (raise `max_bytes` if that really is the artefact's size)"
        );
    }

    let mut digesting = Digesting {
        // `limit` errors on the read *past* its bound, so `max + 1`
        // makes `max_bytes` an inclusive ceiling instead of one byte
        // short of it.
        inner: response
            .body_mut()
            .with_config()
            .limit(max.saturating_add(1))
            .reader(),
        hasher: state.checksum.as_ref().map(Hasher::for_checksum),
    };

    let staged =
        super::path::stage_stream(&state.dest, &mut digesting, uid, gid, mode).context(format!(
            "streaming {url} to {} (max_bytes = {max})",
            state.dest.display()
        ))?;

    // Verify *before* publishing. A failed checksum must leave the
    // destination exactly as it was, so the staged temp file is dropped
    // — and unlinked — rather than renamed into place.
    if let (Some(sum), Some(hasher)) = (&state.checksum, digesting.hasher.take()) {
        let got = hasher.finish();
        if got != sum.expected() {
            crate::bail!(
                "checksum mismatch for {url}: expected {}, got {got} \
                 ({} bytes transferred; {} was left untouched)",
                sum.expected(),
                staged.written(),
                state.dest.display(),
            );
        }
    }

    staged.publish()?;
    Ok(super::Return::Changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = b"downloaded-by-cindy-fetch-module\n";
    /// `sha256sum` of [`BODY`], as an independent check that the
    /// streaming digest agrees with the reference implementation and not
    /// just with itself.
    const BODY_SHA256: &str = "779d665dc1671dd5c8a59c60849873195d031352e71c9d9c3f32193ed811395d";

    #[test]
    fn streaming_digest_matches_the_one_shot_digest() {
        // The whole point of `Digesting`/`digest_file` is that they
        // agree with hashing the buffer in one go — across a chunk
        // boundary, where an off-by-one in the adapter would show up.
        let big: Vec<u8> = (0..(DIGEST_CHUNK * 2 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        let want = hex(&sha2::Sha256::digest(&big));

        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("blob");
        std::fs::write(&p, &big).unwrap();
        assert_eq!(
            digest_file(&p, &Checksum::Sha256(String::new())).as_deref(),
            Some(want.as_str()),
        );

        let mut digesting = Digesting {
            inner: &big[..],
            hasher: Some(Hasher::for_checksum(&Checksum::Sha256(String::new()))),
        };
        let mut sink = Vec::new();
        std::io::copy(&mut digesting, &mut sink).unwrap();
        assert_eq!(sink, big, "the adapter must pass bytes through unchanged");
        assert_eq!(digesting.hasher.take().unwrap().finish(), want);
    }

    #[test]
    fn digest_file_agrees_with_sha256sum() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("blob");
        std::fs::write(&p, BODY).unwrap();
        assert_eq!(
            digest_file(&p, &Checksum::Sha256(String::new())).as_deref(),
            Some(BODY_SHA256),
        );
    }

    #[test]
    fn sha512_digest_path_is_wired_to_sha512() {
        let want = hex(&sha2::Sha512::digest(BODY));
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("blob");
        std::fs::write(&p, BODY).unwrap();
        assert_eq!(
            digest_file(&p, &Checksum::Sha512(String::new())).as_deref(),
            Some(want.as_str()),
        );
        assert_ne!(
            digest_file(&p, &Checksum::Sha256(String::new())).as_deref(),
            Some(want.as_str()),
        );
    }

    #[test]
    fn digest_file_reports_none_for_unreadable_destinations() {
        let tmp = tempfile::tempdir().unwrap();
        let sum = Checksum::Sha256(String::new());
        // Missing.
        assert!(digest_file(&tmp.path().join("nope"), &sum).is_none());
        // A directory is not a readable artefact either.
        assert!(digest_file(tmp.path(), &sum).is_none());
    }

    #[test]
    fn expected_digest_is_normalised_and_validated() {
        // Case and surrounding whitespace are tolerated…
        assert_eq!(
            Checksum::Sha256(format!("  {}  ", BODY_SHA256.to_uppercase())).expected(),
            BODY_SHA256,
        );
        assert!(Checksum::Sha256(BODY_SHA256.to_owned()).validate().is_ok());
        // …but a truncated or non-hex digest is rejected up front rather
        // than silently never matching.
        assert!(
            Checksum::Sha256(BODY_SHA256[..63].to_owned())
                .validate()
                .is_err()
        );
        assert!(
            Checksum::Sha256(BODY_SHA256.replace('d', "z"))
                .validate()
                .is_err()
        );
        // A sha256-length string in a Sha512 slot is a mixed-up algorithm.
        assert!(Checksum::Sha512(BODY_SHA256.to_owned()).validate().is_err());
    }

    #[test]
    fn url_userinfo_is_redacted_but_nothing_else_is() {
        let cases = [
            (
                "https://user:tok3n@example.com/a/b?x=1",
                "https://***@example.com/a/b?x=1",
            ),
            ("https://tok3n@example.com/a", "https://***@example.com/a"),
            // No userinfo: untouched, including an `@` further along.
            ("https://example.com/a@b", "https://example.com/a@b"),
            (
                "https://example.com/?to=a@b.com",
                "https://example.com/?to=a@b.com",
            ),
            ("https://example.com", "https://example.com"),
            // Not a URL at all: don't mangle it.
            ("example.com/a@b", "example.com/a@b"),
        ];
        for (raw, want) in cases {
            assert_eq!(redact_url(raw), want, "{raw}");
        }
    }
}
