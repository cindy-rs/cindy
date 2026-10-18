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

/// A stream compression layer, independent of any container.
#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Codec {
    Store,
    Gzip,
    Xz,
    /// The pure-Rust encoder only emits its "fastest" level.
    Zstd,
}

/// An archive container. Tar is `Tar(Option<Codec>)` rather than one
/// variant per `.tar.*`, so "tar with codec X" is total over [`Codec`];
/// zip and 7z compress per entry and carry none.
#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Format {
    /// `Tar(Some(Codec::Store))` is the same as `Tar(None)`.
    Tar(Option<Codec>),
    Zip,
    SevenZ,
}

impl Format {
    /// Infer the format from a file name's extension.
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

#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Return {
    Unchanged,
    Changed,
}

impl Return {
    pub fn changed(&self) -> bool {
        *self == Self::Changed
    }

    pub fn from_changed(changed: bool) -> Self {
        if changed {
            Self::Changed
        } else {
            Self::Unchanged
        }
    }
}

/// The user and group the worker runs as.
pub fn current_owner_names() -> (String, String) {
    let path::Owner { user, group } = path::Owner::current();
    (user, group)
}

/// The user name, or the number itself when it has no NSS entry.
pub(crate) fn name_of_uid(uid: u32) -> String {
    nix::unistd::User::from_uid(uid.into())
        .ok()
        .flatten()
        .map_or_else(|| uid.to_string(), |u| u.name)
}

/// The group name, or the number itself when it has no NSS entry.
pub(crate) fn name_of_gid(gid: u32) -> String {
    nix::unistd::Group::from_gid(gid.into())
        .ok()
        .flatten()
        .map_or_else(|| gid.to_string(), |g| g.name)
}

/// A numeric `/etc/login.defs` key (`SYS_UID_MAX`, …), so the user and
/// group builtins agree with `useradd --system` on the system id range.
pub(crate) fn login_defs_value(key: &str, default: u32) -> u32 {
    let Ok(contents) = std::fs::read_to_string("/etc/login.defs") else {
        return default;
    };
    contents
        .lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix(key)?;
            // A separator, so `SYS_UID_MAX` can't match a longer key.
            if !rest.starts_with([' ', '\t']) {
                return None;
            }
            rest.split(['#', ' ', '\t'])
                .find(|s| !s.is_empty())?
                .parse()
                .ok()
        })
        .unwrap_or(default)
}

fn spawn(cmd: &mut std::process::Command) -> crate::Result<std::process::Output> {
    use crate::Context as _;
    cmd.output()
        .context(format!("Failed to spawn {:?}", cmd.get_program()))
}

fn failure(cmd: &std::process::Command, out: &std::process::Output, after: &str) -> crate::Error {
    crate::anyhow!(
        "{:?} failed with {:?}{after}:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        cmd.get_program(),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    )
}

/// Run a tool to completion; a non-zero exit fails with its output.
pub(crate) fn run_check(cmd: &mut std::process::Command) -> crate::Result<()> {
    let out = spawn(cmd)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(failure(cmd, &out, ""))
    }
}

const LOCK_ATTEMPTS: u32 = 8;
const LOCK_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_millis(100);
/// Caps one step, so all attempts together stay around ten seconds.
const LOCK_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(2);

/// Did the tool fail because its global lock was taken? Matched on its
/// words: exit codes are too coarse (`useradd` exits 1 for any "can't
/// update password file", read-only filesystem included).
fn is_lock_contention(stderr: &str) -> bool {
    const MARKERS: [&str; 5] = [
        // shadow-utils: `cannot lock /etc/passwd; try again later.`
        "cannot lock",
        "try again later",
        // apt-mark, current and older apt
        "could not get lock",
        "unable to acquire the dpkg frontend lock",
        "temporarily unavailable",
    ];
    let lowered = stderr.to_ascii_lowercase();
    MARKERS.iter().any(|m| lowered.contains(m))
}

/// Up to one more `step`, so two colliding runs — usually two workers
/// on one host, hence the pid — don't retry in lockstep. Not worth a
/// `rand` dependency.
fn backoff_jitter(step: std::time::Duration) -> std::time::Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    let spread = (nanos ^ u64::from(std::process::id())) % 1000;
    step.mul_f64(spread as f64 / 1000.0)
}

/// [`run_check`], retrying while the tool reports lock contention.
///
/// shadow-utils (`useradd`, `groupadd`, …) fail fast on a held
/// `lckpwdf(3)` lock and have no wait flag (apt has
/// `DPkg::Lock::Timeout`), so two concurrent runs — or one play's own
/// `join!`ed user tasks — would otherwise fail the play. The lock is
/// held for one invocation, so retrying works; any other failure is
/// reported on the first attempt.
pub(crate) fn run_check_retry_locks(cmd: &mut std::process::Command) -> crate::Result<()> {
    let mut step = LOCK_BACKOFF_BASE;
    let mut attempt = 1;
    loop {
        let out = spawn(cmd)?;
        if out.status.success() {
            return Ok(());
        }
        if !is_lock_contention(&String::from_utf8_lossy(&out.stderr)) {
            return Err(failure(cmd, &out, ""));
        }
        if attempt == LOCK_ATTEMPTS {
            let after = format!(" after {attempt} attempts (the lock stayed held)");
            return Err(failure(cmd, &out, &after));
        }
        std::thread::sleep(step + backoff_jitter(step));
        step = (step * 2).min(LOCK_BACKOFF_CAP);
        attempt += 1;
    }
}

/// Did a create fail because a concurrent run created it first
/// (`user 'bob' already exists`, `GID '2000' already in use`)? Callers
/// re-observe and reconcile, so a false positive costs one lookup and a
/// false negative one loud failure.
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
        assert!(is_create_race(
            &failure("groupadd: GID '2000' already in use\n").unwrap_err()
        ));
    }

    #[test]
    fn lock_contention_and_genuine_failures_are_not_create_races() {
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
