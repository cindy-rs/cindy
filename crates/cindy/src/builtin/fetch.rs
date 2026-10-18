//! Download a file over HTTP(S) to a path on the remote machine.
//!
//! With a [`checksum`](State::checksum) an existing destination that
//! matches is left alone; without one, only a missing destination is
//! fetched (remove the file first to refresh a mutable URL).
//!
//! The body streams to disk and is digested on the way, then published
//! only once it verifies — a multi-gigabyte artefact costs a fixed
//! buffer, not its size in RAM on what is often the smallest machine in
//! the fleet.

use std::path::{Path, PathBuf};

use sha2::Digest as _;

use crate::Context;

/// Expected digest, as hex.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub enum Checksum {
    Sha256(String),
    Sha512(String),
}

impl Checksum {
    fn expected(&self) -> String {
        match self {
            Checksum::Sha256(h) | Checksum::Sha512(h) => h.trim().to_ascii_lowercase(),
        }
    }

    /// A truncated or mistyped digest would otherwise never match:
    /// re-download every run, then fail on a mismatch that hides the typo.
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

/// Past any plausible artefact, short of filling a disk with a server
/// that never stops sending.
const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

// ureq has no timeouts by default. The body is bounded by size, not a
// clock, so a slow link can still deliver a large artefact; a
// blackholed host fails on these.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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

/// Digests what passes through, so verifying needs no second copy.
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
    pub url: String,
    pub dest: PathBuf,
    /// `None` ⇒ an existing file counts as done.
    pub checksum: Option<Checksum>,
    /// `None` ⇒ the existing file's, else the worker's.
    pub user: Option<String>,
    /// `None` ⇒ the existing file's, else the worker's.
    pub group: Option<String>,
    /// `None` ⇒ the existing file's, else `0o644`.
    pub mode: Option<super::path::Mode>,
    /// Larger bodies are refused — up front from `Content-Length`, else
    /// once the stream passes it — leaving the destination untouched.
    /// `None` ⇒ 4 GiB.
    pub max_bytes: Option<u64>,
    /// Deadline for the whole fetch, connect to last byte. `None` lets
    /// a large artefact take as long as the link needs.
    pub timeout: Option<std::time::Duration>,
    /// Extra request headers (`Authorization: Bearer …`). Reveal the
    /// value from a [`Secret`](crate::secret::Secret) inside the remote
    /// fn; [`HeaderValue`] keeps it out of `Debug` output.
    pub headers: Vec<(String, HeaderValue)>,
}

/// A header value that `Debug`-prints as `Sensitive` — `http`'s own
/// redaction, which every value gets, credential or not. The newtype
/// exists only because `http::HeaderValue` has no serde impls.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderValue(ureq::http::HeaderValue);

impl HeaderValue {
    /// Refuses control characters and newlines (header injection).
    pub fn new(value: impl AsRef<[u8]>) -> crate::Result<Self> {
        let mut inner = ureq::http::HeaderValue::from_bytes(value.as_ref())
            .map_err(|e| crate::Error::msg(format!("invalid header value: {e}")))?;
        inner.set_sensitive(true);
        Ok(Self(inner))
    }

    fn as_str(&self) -> crate::Result<&str> {
        self.0
            .to_str()
            .map_err(|e| crate::Error::msg(format!("header value is not valid UTF-8: {e}")))
    }
}

impl std::fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl serde::Serialize for HeaderValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for HeaderValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let bytes = <Vec<u8> as serde::Deserialize>::deserialize(deserializer)?;
        // The sensitive flag doesn't travel; `new` sets it again.
        Self::new(&bytes).map_err(D::Error::custom)
    }
}

/// `url` with any `user:password@` replaced, for log and error lines.
fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    let Some(scheme_end) = url.find("://") else {
        return std::borrow::Cow::Borrowed(url);
    };
    let authority_start = scheme_end + 3;
    // Only an `@` inside the authority is userinfo.
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

/// `None` when the file can't be read, which means "download".
fn digest_file(path: &Path, sum: &Checksum) -> Option<String> {
    let mut reader = Digesting {
        inner: std::fs::File::open(path).ok()?,
        hasher: Some(Hasher::for_checksum(sum)),
    };
    std::io::copy(&mut reader, &mut std::io::sink()).ok()?;
    reader.hasher.map(Hasher::finish)
}

/// Fill fetch's optional owner/mode from the existing file, else the
/// worker and `0o644`, because `path` takes a total spec.
fn desired_attrs(
    state: &State,
    existing: Option<&std::fs::Metadata>,
) -> (super::path::Owner, super::path::Mode) {
    use std::os::unix::fs::MetadataExt as _;
    let (fallback, mode) = match existing {
        Some(meta) => (
            super::path::Owner {
                user: super::name_of_uid(meta.uid()),
                group: super::name_of_gid(meta.gid()),
            },
            super::path::Mode::from_st_mode(meta.mode()),
        ),
        None => (super::path::Owner::current(), super::path::Mode(0o644)),
    };
    (
        super::path::Owner {
            user: state.user.clone().unwrap_or(fallback.user),
            group: state.group.clone().unwrap_or(fallback.group),
        },
        state.mode.unwrap_or(mode),
    )
}

fn agent(timeout: Option<std::time::Duration>) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(HEADER_TIMEOUT))
        .timeout_global(timeout)
        .build()
        .new_agent()
}

/// The full-control entry point; [`url`] and [`verified`] cover the
/// common cases.
#[crate::remote]
pub fn fetch(state: State) -> crate::Result<super::Return> {
    apply(state)
}

/// Download `url` to `dest` if it is missing.
#[crate::action]
pub fn url(url: impl Into<String>, dest: impl Into<PathBuf>) -> crate::Result<super::Return> {
    apply(State {
        url,
        dest,
        ..State::default()
    })
}

/// Download `url` to `dest` unless it already matches `checksum`, and
/// refuse a download that doesn't.
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

    // Anything but a regular file gets replaced, attributes and all.
    let existing = std::fs::symlink_metadata(&state.dest)
        .ok()
        .filter(std::fs::Metadata::is_file);

    let satisfied = existing.is_some()
        && match &state.checksum {
            Some(sum) => digest_file(&state.dest, sum).is_some_and(|have| have == sum.expected()),
            None => true,
        };

    let (owner, mode) = desired_attrs(&state, existing.as_ref());

    if satisfied {
        // The content is right; owner and mode may still have drifted.
        if crate::dry_run() {
            let attrs_ok = super::path::file_attrs_satisfied(&state.dest, &owner, mode);
            return Ok(super::Return::from_changed(!attrs_ok));
        }
        return super::path::reconcile_file_attrs(&state.dest, &owner, mode);
    }

    if crate::dry_run() {
        return Ok(super::Return::Changed);
    }

    let (uid, gid) = owner.resolve()?;
    let max = state.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let url = redact_url(&state.url);

    let _ = crate::diff::note(
        &mut std::io::stderr().lock(),
        &format!("~ {} <- {url}", state.dest.display()),
    );

    let mut request = agent(state.timeout).get(&state.url);
    for (name, value) in &state.headers {
        request = request.header(name.as_str(), value.as_str()?);
    }
    let mut response = request.call().context(format!("GET {url} failed"))?;

    if let Some(len) = response.body().content_length()
        && len > max
    {
        crate::bail!(
            "{url} declares {len} bytes, over this fetch's {max}-byte limit \
             (raise `max_bytes` if that really is the artefact's size)"
        );
    }

    let mut digesting = Digesting {
        // `limit` fails the read past its bound: `+ 1` makes it inclusive.
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

    // A mismatch drops (and so unlinks) the staged file unpublished.
    if let (Some(sum), Some(hasher)) = (&state.checksum, digesting.hasher.take()) {
        let got = hasher.finish();
        if got != sum.expected() {
            crate::bail!(
                "checksum mismatch for {url}: expected {}, got {got} \
                 ({} bytes transferred; {} was left untouched)",
                sum.expected(),
                staged.written()?,
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
    /// From `sha256sum`, so the digest is checked against more than itself.
    const BODY_SHA256: &str = "779d665dc1671dd5c8a59c60849873195d031352e71c9d9c3f32193ed811395d";

    #[test]
    fn streaming_digest_matches_the_one_shot_digest() {
        // Spans several `io::copy` buffers.
        let big: Vec<u8> = (0..(64 * 1024 * 2 + 7)).map(|i| (i % 251) as u8).collect();
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
        assert!(digest_file(&tmp.path().join("nope"), &sum).is_none());
        assert!(digest_file(tmp.path(), &sum).is_none());
    }

    #[test]
    fn expected_digest_is_normalised_and_validated() {
        assert_eq!(
            Checksum::Sha256(format!("  {}  ", BODY_SHA256.to_uppercase())).expected(),
            BODY_SHA256,
        );
        assert!(Checksum::Sha256(BODY_SHA256.to_owned()).validate().is_ok());
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
        assert!(Checksum::Sha512(BODY_SHA256.to_owned()).validate().is_err());
    }

    #[test]
    fn header_values_never_debug_print_themselves() {
        let state = State {
            url: "https://example.com/a".into(),
            headers: vec![(
                "Authorization".to_owned(),
                HeaderValue::new("Bearer s3kr1t-token").unwrap(),
            )],
            ..State::default()
        };
        let rendered = format!("{state:?}");
        assert!(!rendered.contains("s3kr1t-token"), "{rendered}");
        assert!(!rendered.contains("Bearer"), "{rendered}");
        assert!(rendered.contains("Authorization"), "{rendered}");
        assert!(rendered.contains("Sensitive"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
    }

    #[test]
    fn redaction_survives_the_rpc_wire() {
        let before = HeaderValue::new("Bearer s3kr1t-token").unwrap();
        let bytes = postcard::to_allocvec(&before).unwrap();
        let after: HeaderValue = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(after, before, "value must round-trip intact");
        assert_eq!(format!("{after:?}"), "Sensitive");
        assert_eq!(after.as_str().unwrap(), "Bearer s3kr1t-token");
    }

    #[test]
    fn header_values_reject_injection_shapes() {
        assert!(HeaderValue::new("ok").is_ok());
        assert!(HeaderValue::new("bad\r\nX-Evil: 1").is_err());
        assert!(HeaderValue::new("bad\nvalue").is_err());
        assert!(HeaderValue::new("bad\0value").is_err());
    }

    #[test]
    fn url_userinfo_is_redacted_but_nothing_else_is() {
        let cases = [
            (
                "https://user:tok3n@example.com/a/b?x=1",
                "https://***@example.com/a/b?x=1",
            ),
            ("https://tok3n@example.com/a", "https://***@example.com/a"),
            ("https://example.com/a@b", "https://example.com/a@b"),
            (
                "https://example.com/?to=a@b.com",
                "https://example.com/?to=a@b.com",
            ),
            ("https://example.com", "https://example.com"),
            ("example.com/a@b", "example.com/a@b"),
        ];
        for (raw, want) in cases {
            assert_eq!(redact_url(raw), want, "{raw}");
        }
    }
}
