pub mod archive;
pub mod command;
pub mod compress;
pub mod debian;
pub mod decompress;
pub mod fetch;
pub mod group;
pub mod path;
pub mod systemd;
pub mod unarchive;
pub mod user;

/// A stream compression codec, independent of any container format.
///
/// This is the compression *layer* — what wraps a byte stream — as
/// opposed to [`Format`], which is the archive *container*. The
/// [`compress`] and [`decompress`] modules operate purely on this, and
/// [`archive`]/[`unarchive`] reuse them via `compress::compress::inner`
/// / `decompress::bounded` for the tar-based formats.
///
/// Every codec is pure Rust (no C, no FFI): `flate2`/miniz_oxide for
/// gzip, `lzma-rs` for xz, `ruzstd` for zstd.
#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Codec {
    /// No compression — bytes pass through unchanged.
    Store,
    /// gzip (RFC 1952).
    Gzip,
    /// xz / LZMA2.
    Xz,
    /// Zstandard. **Compression** uses the pure-Rust `ruzstd` encoder,
    /// which currently emits the "fastest" level only.
    Zstd,
}

/// Archive container + compression format, shared by [`archive`] and
/// [`unarchive`].
///
/// Every variant is handled by a pure-Rust codec (no C, no FFI):
/// `tar` for tarballs, `flate2`/miniz_oxide for gzip, `lzma-rs` for xz,
/// `ruzstd` for zstd, `zip`, and `sevenz-rust2` for 7z.
///
/// The tar family is modelled as `Tar(Option<Codec>)` — a tar byte
/// stream optionally wrapped in a compression layer — rather than one
/// variant per `.tar.*` combination. That makes "tar with codec X"
/// total over `Codec` (no per-extension enum explosion) and lets the
/// archive/unarchive code branch on "tar vs container" without an
/// unreachable arm. `Zip` and `SevenZ` are containers with their own
/// per-entry compression, so they carry no [`Codec`].
#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Format {
    /// A tar stream, optionally compressed. `Tar(None)` is a plain
    /// `.tar`; `Tar(Some(Codec::Gzip))` is `.tar.gz`, and so on.
    /// `Tar(Some(Codec::Store))` is equivalent to `Tar(None)`.
    Tar(Option<Codec>),
    /// ZIP archive (`.zip`).
    Zip,
    /// 7-Zip archive (`.7z`).
    SevenZ,
}

impl Format {
    /// Infer the format from a file name's extension(s).
    ///
    /// Recognises the double extensions (`.tar.gz` …) before the single
    /// ones so `archive.tar.gz` isn't misread as a bare gzip stream.
    pub fn from_path(path: &std::path::Path) -> crate::Result<Self> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let format = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            Self::Tar(Some(Codec::Gzip))
        } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
            Self::Tar(Some(Codec::Xz))
        } else if name.ends_with(".tar.zst") || name.ends_with(".tzst") {
            Self::Tar(Some(Codec::Zstd))
        } else if name.ends_with(".tar") {
            Self::Tar(None)
        } else if name.ends_with(".zip") {
            Self::Zip
        } else if name.ends_with(".7z") {
            Self::SevenZ
        } else {
            crate::bail!(
                "couldn't infer archive format from {:?}; set `format` explicitly",
                path
            );
        };
        Ok(format)
    }
}

#[crate::wire]
pub enum Return {
    Unchanged,
    Changed,
}
impl Return {
    pub fn changed(&self) -> bool {
        matches!(self, Self::Changed)
    }

    /// Pick the variant from a "did anything change?" flag, so callers
    /// don't repeat the `if changed { Changed } else { Unchanged }`
    /// dance.
    pub fn from_changed(changed: bool) -> Self {
        if changed {
            Self::Changed
        } else {
            Self::Unchanged
        }
    }
}

/// The user and group names the worker process currently runs as.
///
/// Used by builtins that delegate to [`path`] (which requires a total
/// owner) but whose own owner inputs are optional — an unspecified
/// owner falls back to "whoever is running this". Falls back to the
/// numeric id as a string if the id has no NSS entry.
pub fn current_owner_names() -> (String, String) {
    (
        name_of_uid(nix::unistd::getuid().as_raw()),
        name_of_gid(nix::unistd::getgid().as_raw()),
    )
}

/// Resolve a uid to its user name, falling back to the numeric id as a
/// string when it has no NSS entry.
pub(crate) fn name_of_uid(uid: u32) -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string())
}

/// Resolve a gid to its group name, falling back to the numeric id as a
/// string when it has no NSS entry.
pub(crate) fn name_of_gid(gid: u32) -> String {
    nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| gid.to_string())
}

/// Read a numeric `key` from `/etc/login.defs` (e.g. `SYS_UID_MAX`),
/// tolerating a trailing comment on the line. `default` is returned
/// when the file is absent or the key unparseable.
///
/// Shared by the `user`/`group` builtins so their notion of a "system"
/// id range matches what `useradd`/`groupadd --system` would do.
pub(crate) fn login_defs_value(key: &str, default: u32) -> u32 {
    let Ok(contents) = std::fs::read_to_string("/etc/login.defs") else {
        return default;
    };
    contents
        .lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix(key)?;
            // Require a separator so `SYS_UID_MAX` can't match a longer
            // key it happens to prefix.
            if !rest.starts_with([' ', '\t']) {
                return None;
            }
            rest.split(['#', ' ', '\t'])
                .find(|s| !s.is_empty())?
                .parse::<u32>()
                .ok()
        })
        .unwrap_or(default)
}

/// Run a [`Command`](std::process::Command) to completion, returning an
/// error that includes the combined stdout+stderr if it exits non-zero.
///
/// Shared by the builtins that drive an external tool (`apt-get`,
/// `useradd`, `groupadd`, …) where a non-zero exit is always a failure
/// we want to surface verbatim.
pub(crate) fn run_check(cmd: &mut std::process::Command) -> crate::Result<()> {
    use crate::Context as _;

    let out = cmd
        .output()
        .context(format!("Failed to spawn {:?}", cmd.get_program()))?;
    if !out.status.success() {
        crate::bail!(
            "{:?} failed with {:?}:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            cmd.get_program(),
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    Ok(())
}

/// Attempts (including the first) before a lock-contended shadow-utils
/// call is reported as a failure.
const LOCK_ATTEMPTS: u32 = 8;

/// First backoff step; doubles each attempt up to [`LOCK_BACKOFF_CAP`].
const LOCK_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_millis(100);

/// Ceiling on a single backoff step, so eight attempts land around ten
/// seconds rather than growing unboundedly.
const LOCK_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(2);

/// Does this output look like the tool telling us its global lock was
/// already taken?
///
/// Matched on the tools' own words rather than their exit codes, which
/// are far too coarse: `useradd` uses exit 1 for *any* "can't update
/// password file" condition, including a read-only filesystem or a
/// corrupt file, and retrying those only delays the report.
///
/// Two families of phrasing, because two families of tool serialise on a
/// global lock:
///
/// - shadow-utils (`useradd`, `usermod`, `groupadd`, …):
///   `cannot lock /etc/passwd; try again later.`, and the `/etc/group`,
///   `/etc/shadow`, `/etc/gshadow` variants.
/// - apt's own tools (`apt-mark`), which never say "cannot lock":
///   `Could not get lock /var/lib/dpkg/lock-frontend`,
///   `Unable to acquire the dpkg frontend lock`, and older apt's
///   `open (11: Resource temporarily unavailable)`.
fn is_lock_contention(stderr: &str) -> bool {
    const MARKERS: [&str; 5] = [
        // shadow-utils
        "cannot lock",
        "try again later",
        // apt
        "could not get lock",
        "unable to acquire the dpkg frontend lock",
        "temporarily unavailable",
    ];
    let lowered = stderr.to_ascii_lowercase();
    MARKERS.iter().any(|m| lowered.contains(m))
}

/// Pseudo-random fraction of `step` to add as jitter.
///
/// Two `cindy` runs that collide would otherwise back off in lockstep
/// and keep colliding. The clock's sub-second component decorrelates
/// retries within one process; the pid decorrelates them between
/// processes — which is exactly the case here, since the contender is
/// another operator's worker on the same host. Not worth a `rand`
/// dependency in the framework crate for this.
fn backoff_jitter(step: std::time::Duration) -> std::time::Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    let spread = (nanos ^ u64::from(std::process::id())) % 1000;
    step.mul_f64(spread as f64 / 1000.0)
}

/// Like [`run_check`], but retries while the tool reports that it
/// couldn't take its global lock.
///
/// `useradd`/`usermod`/`groupadd`/… serialise on `/etc/passwd` and
/// `/etc/group` through `lckpwdf(3)` and, on contention, **fail fast** —
/// they never wait, and shadow-utils offers no timeout flag to make them
/// (unlike apt, which has `DPkg::Lock::Timeout`). So two concurrent
/// `cindy` runs against one host — two engineers deploying at once, or
/// one play's own `join!`ed user tasks — used to surface as a hard play
/// failure with a confusing message.
///
/// Retrying is the correct response precisely *because* the tool fails
/// fast: the lock is held only for the duration of one invocation,
/// typically well under a second. Anything that isn't lock contention
/// fails on the first attempt, so a genuine error is still reported
/// immediately rather than eight backoffs later.
pub(crate) fn run_check_retry_locks(cmd: &mut std::process::Command) -> crate::Result<()> {
    use crate::Context as _;

    let mut step = LOCK_BACKOFF_BASE;
    for attempt in 1..=LOCK_ATTEMPTS {
        let out = cmd
            .output()
            .context(format!("Failed to spawn {:?}", cmd.get_program()))?;
        if out.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&out.stderr);
        if !is_lock_contention(&stderr) || attempt == LOCK_ATTEMPTS {
            crate::bail!(
                "{:?} failed with {:?}{}:\n--- stdout ---\n{}\n--- stderr ---\n{stderr}",
                cmd.get_program(),
                out.status,
                if attempt > 1 {
                    format!(" after {attempt} attempts (the lock stayed held)")
                } else {
                    String::new()
                },
                String::from_utf8_lossy(&out.stdout),
            );
        }

        std::thread::sleep(step + backoff_jitter(step));
        step = (step * 2).min(LOCK_BACKOFF_CAP);
    }
    // The loop either returns or bails on its final attempt.
    unreachable!("the retry loop returns or bails on attempt {LOCK_ATTEMPTS}")
}

/// Did this create failure mean "another agent won the race to create
/// it"?
///
/// `run_check_retry_locks` handles two cindy runs colliding on the
/// shadow-utils *lock*; this is the other race — both runs observe the
/// account absent, both spawn `useradd`/`groupadd`, and the loser is
/// told `user 'bob' already exists` / `group 'web' already exists`
/// (or, checking the GID first, `GID '2000' already in use`). The
/// winner having created the desired account is the desired end
/// state, not an error, so callers re-observe and reconcile.
///
/// The wording match is only a pre-filter: a false positive costs the
/// caller one re-observation, after which a still-absent account
/// propagates the original error. A false negative just reports a
/// race the caller would have survived — failure is loud either way.
fn is_create_race(err: &impl std::fmt::Display) -> bool {
    let msg = err.to_string();
    msg.contains("already exists") || msg.contains("already in use")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(stderr: &str) -> crate::Result<()> {
        crate::bail!("\"useradd\" failed:\n--- stderr ---\n{stderr}")
    }

    #[test]
    fn create_races_are_recognised_by_the_tools_own_words() {
        assert!(is_create_race(
            &failure("useradd: user 'bob' already exists\n").unwrap_err()
        ));
        assert!(is_create_race(
            &failure("groupadd: group 'web' already exists\n").unwrap_err()
        ));
        // `groupadd --gid` can check GID availability before the name.
        assert!(is_create_race(
            &failure("groupadd: GID '2000' already in use\n").unwrap_err()
        ));
    }

    #[test]
    fn lock_contention_and_genuine_failures_are_not_create_races() {
        // Contention has its own retry path in run_check_retry_locks.
        assert!(!is_create_race(
            &failure("useradd: cannot lock /etc/passwd; try again later.").unwrap_err()
        ));
        assert!(!is_create_race(
            &failure("useradd: cannot create directory /home/bob").unwrap_err()
        ));
        assert!(!is_create_race(
            &failure("useradd: invalid user name 'x y'").unwrap_err()
        ));
    }
}
