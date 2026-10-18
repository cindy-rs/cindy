//! One destination path: a file with given contents, a directory, a
//! symlink, or nothing.
//!
//! The spec is total — owner and mode are required, there is no "leave
//! as-is" — so a converged path is fully described by the call that
//! created it. Links carry no mode (Linux ignores symlink permissions).

use std::fmt;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid};

use crate::Context;

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::__reexports::serde")]
pub struct Mode(pub(crate) u32);

impl Mode {
    /// The permission bits of an `st_mode`, which also carries file-type
    /// bits. Masking is right for OS metadata; user input goes through
    /// `try_from`, where stray bits mean a typo.
    pub const fn from_st_mode(st_mode: u32) -> Self {
        Mode(st_mode & 0o7777)
    }

    fn nix(self) -> nix::sys::stat::Mode {
        nix::sys::stat::Mode::from_bits_truncate(self.0)
    }
}

// No `From<u32>`: it would make std derive an infallible `TryFrom`
// that conflicts with this one, and would have to mask or panic.
impl TryFrom<u32> for Mode {
    type Error = crate::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value & !0o7777 != 0 {
            crate::bail!(
                "invalid file mode 0o{value:o} ({value}): bits outside 0o7777. \
                 Did you forget the `0o` prefix on an octal literal?",
            );
        }
        Ok(Mode(value))
    }
}

impl From<Mode> for std::fs::Permissions {
    fn from(Mode(value): Mode) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::Permissions::from_mode(value)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0o{:o}", self.0)
    }
}

impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::__reexports::serde")]
pub(crate) struct Owner {
    pub(crate) user: String,
    pub(crate) group: String,
}

impl Owner {
    #[cfg(test)]
    fn new(user: impl Into<String>, group: impl Into<String>) -> Self {
        Owner {
            user: user.into(),
            group: group.into(),
        }
    }

    /// Whoever the worker runs as.
    pub(crate) fn current() -> Self {
        Owner {
            user: super::name_of_uid(nix::unistd::getuid().as_raw()),
            group: super::name_of_gid(nix::unistd::getgid().as_raw()),
        }
    }

    /// Callers resolve before anything destructive or expensive, so a
    /// typo'd name fails the call while nothing has happened yet.
    pub(crate) fn resolve(&self) -> crate::Result<(Uid, Gid)> {
        let uid = match nix::unistd::User::from_name(&self.user) {
            Ok(Some(user)) => user.uid,
            Ok(None) => crate::bail!("no such user: {}", self.user),
            Err(e) => crate::bail!("user lookup for {:?} failed: {e}", self.user),
        };
        let gid = match nix::unistd::Group::from_name(&self.group) {
            Ok(Some(group)) => group.gid,
            Ok(None) => crate::bail!("no such group: {}", self.group),
            Err(e) => crate::bail!("group lookup for {:?} failed: {e}", self.group),
        };
        Ok((uid, gid))
    }
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.user, self.group)
    }
}

/// File content whose `Debug` makes a readable diff: text line by line,
/// binary as a size.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::__reexports::serde", transparent)]
struct Content(Vec<u8>);

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(text) = std::str::from_utf8(&self.0) else {
            return write!(f, "<binary, {} bytes>", self.0.len());
        };
        f.write_str("(\n")?;
        for line in text.lines() {
            writeln!(f, "    {line}")?;
        }
        if !text.is_empty() && !text.ends_with('\n') {
            f.write_str("    \\ no newline at end\n")?;
        }
        f.write_str(")")
    }
}

#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
enum Kind {
    /// Nothing at the path; an existing directory goes recursively.
    Absent,
    /// Replacing a directory deletes its contents.
    File {
        content: Content,
        owner: Owner,
        mode: Mode,
    },
    /// Only the directory itself; its contents are left alone.
    Directory {
        owner: Owner,
        mode: Mode,
    },
    Link {
        target: PathBuf,
        owner: Owner,
    },
}

#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
struct State {
    destination: PathBuf,
    kind: Kind,
}

impl crate::Diff for State {}

#[crate::action]
pub fn file(
    destination: impl Into<PathBuf>,
    content: impl Into<Vec<u8>>,
    user: impl Into<String>,
    group: impl Into<String>,
    mode: impl Into<Mode>,
) -> crate::Result<super::Return> {
    apply(State {
        destination,
        kind: Kind::File {
            content: Content(content),
            owner: Owner { user, group },
            mode,
        },
    })
}

#[crate::action]
pub fn directory(
    destination: impl Into<PathBuf>,
    user: impl Into<String>,
    group: impl Into<String>,
    mode: impl Into<Mode>,
) -> crate::Result<super::Return> {
    apply(State {
        destination,
        kind: Kind::Directory {
            owner: Owner { user, group },
            mode,
        },
    })
}

#[crate::action]
pub fn link(
    destination: impl Into<PathBuf>,
    target: impl Into<PathBuf>,
    user: impl Into<String>,
    group: impl Into<String>,
) -> crate::Result<super::Return> {
    apply(State {
        destination,
        kind: Kind::Link {
            target,
            owner: Owner { user, group },
        },
    })
}

#[crate::action]
pub fn absent(destination: impl Into<PathBuf>) -> crate::Result<super::Return> {
    apply(State {
        destination,
        kind: Kind::Absent,
    })
}

/// What is at the path now. File content isn't read until a comparison
/// or a diff needs it.
enum Observed {
    Absent,
    File {
        owner: Owner,
        mode: Mode,
    },
    Directory {
        owner: Owner,
        mode: Mode,
    },
    Link {
        target: PathBuf,
        owner: Owner,
    },
    /// Socket, FIFO or device: can be removed, never managed.
    Special,
}

impl Observed {
    fn read(path: &Path) -> crate::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;

        let md = match std::fs::symlink_metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Observed::Absent),
            Err(e) => return Err(e).context(format!("Couldn't stat {}", path.display())),
        };
        let owner = Owner {
            user: super::name_of_uid(md.uid()),
            group: super::name_of_gid(md.gid()),
        };
        let mode = Mode::from_st_mode(md.mode());
        let ft = md.file_type();
        Ok(if ft.is_file() {
            Observed::File { owner, mode }
        } else if ft.is_dir() {
            Observed::Directory { owner, mode }
        } else if ft.is_symlink() {
            let target = std::fs::read_link(path)
                .context(format!("Couldn't read symlink {}", path.display()))?;
            Observed::Link { target, owner }
        } else {
            Observed::Special
        })
    }

    fn satisfies(&self, desired: &State) -> bool {
        match (self, &desired.kind) {
            (Observed::Absent, Kind::Absent) => true,
            (
                Observed::File { owner, mode },
                Kind::File {
                    content,
                    owner: o,
                    mode: m,
                },
            ) => {
                owner == o
                    && mode == m
                    && std::fs::read(&desired.destination).is_ok_and(|have| have == content.0)
            }
            (Observed::Directory { owner, mode }, Kind::Directory { owner: o, mode: m }) => {
                owner == o && mode == m
            }
            (
                Observed::Link { target, owner },
                Kind::Link {
                    target: t,
                    owner: o,
                },
            ) => target == t && owner == o,
            _ => false,
        }
    }

    /// The observation as a `Kind`, for the diff's old side.
    fn as_kind(&self, path: &Path) -> Kind {
        match self {
            Observed::Absent | Observed::Special => Kind::Absent,
            Observed::File { owner, mode } => Kind::File {
                content: Content(std::fs::read(path).unwrap_or_default()),
                owner: owner.clone(),
                mode: *mode,
            },
            Observed::Directory { owner, mode } => Kind::Directory {
                owner: owner.clone(),
                mode: *mode,
            },
            Observed::Link { target, owner } => Kind::Link {
                target: target.clone(),
                owner: owner.clone(),
            },
        }
    }

    fn remove(&self, path: &Path) -> crate::Result<()> {
        match self {
            Observed::Absent => Ok(()),
            Observed::Directory { .. } => std::fs::remove_dir_all(path)
                .context(format!("Couldn't remove directory {}", path.display())),
            _ => std::fs::remove_file(path).context(format!("Couldn't remove {}", path.display())),
        }
    }
}

fn apply(state: State) -> crate::Result<super::Return> {
    let dest = &state.destination;
    let old = Observed::read(dest)?;

    if let Observed::Special = old {
        if state.kind != Kind::Absent {
            crate::bail!(
                "{} is a special file (socket, FIFO, or device); refusing to manage it",
                dest.display()
            );
        }
        let _ = crate::diff::note(
            &mut std::io::stderr().lock(),
            &format!("- {} (special file)", dest.display()),
        );
    } else {
        if old.satisfies(&state) {
            return Ok(super::Return::Unchanged);
        }
        let old_view = State {
            destination: dest.clone(),
            kind: old.as_kind(dest),
        };
        let _ = crate::Diff::diff(&old_view, &state, &mut std::io::stderr().lock());
    }
    if crate::dry_run() {
        return Ok(super::Return::Changed);
    }

    match &state.kind {
        Kind::Absent => old.remove(dest)?,
        Kind::File {
            content,
            owner,
            mode,
        } => {
            let (uid, gid) = owner.resolve()?;
            let staged = stage_stream(dest, &mut &content.0[..], uid, gid, *mode)?;
            // rename(2) replaces a file or symlink, but not a directory.
            if let Observed::Directory { .. } = old {
                old.remove(dest)?;
            }
            staged.publish()?;
        }
        Kind::Directory { owner, mode } => {
            let (uid, gid) = owner.resolve()?;
            if !matches!(old, Observed::Directory { .. }) {
                old.remove(dest)?;
                std::fs::create_dir(dest).context("Couldn't create directory")?;
            }
            apply_attrs_nofollow(dest, uid, gid, *mode, true)?;
        }
        Kind::Link { target, owner } => {
            let (uid, gid) = owner.resolve()?;
            old.remove(dest)?;
            std::os::unix::fs::symlink(target, dest).context("Couldn't create symbolic link")?;
            nix::unistd::fchownat(
                nix::fcntl::AT_FDCWD,
                dest,
                Some(uid),
                Some(gid),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .context("Couldn't change ownership of symbolic link")?;
        }
    }
    Ok(super::Return::Changed)
}

/// chown + chmod through an `O_NOFOLLOW` fd, so a path swapped for a
/// symlink since it was observed fails the open instead of redirecting
/// the change onto the link's target.
fn apply_attrs_nofollow(
    path: &Path,
    uid: Uid,
    gid: Gid,
    mode: Mode,
    expect_dir: bool,
) -> crate::Result<()> {
    use nix::fcntl::OFlag;

    let mut flags = OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC;
    if expect_dir {
        flags |= OFlag::O_DIRECTORY;
    }
    let fd = nix::fcntl::open(path, flags, nix::sys::stat::Mode::empty()).context(format!(
        "Couldn't open {} (O_NOFOLLOW) to set attributes",
        path.display()
    ))?;
    nix::unistd::fchown(&fd, Some(uid), Some(gid))
        .context(format!("Couldn't change ownership of {}", path.display()))?;
    nix::sys::stat::fchmod(&fd, mode.nix())
        .context(format!("Couldn't set permissions of {}", path.display()))
}

/// Would [`reconcile_file_attrs`] leave the file alone? Metadata only,
/// so check mode can ask it.
pub(crate) fn file_attrs_satisfied(path: &Path, owner: &Owner, mode: Mode) -> bool {
    matches!(Observed::read(path), Ok(Observed::File { owner: o, mode: m }) if o == *owner && m == mode)
}

/// Owner and mode of an existing file, leaving its content alone — for
/// builtins that put the content there themselves (`fetch` streams it).
pub(crate) fn reconcile_file_attrs(
    path: &Path,
    owner: &Owner,
    mode: Mode,
) -> crate::Result<super::Return> {
    let old = Observed::read(path)?;
    let Observed::File {
        owner: old_owner,
        mode: old_mode,
    } = &old
    else {
        crate::bail!("{} is not a regular file", path.display());
    };
    if old_owner == owner && *old_mode == mode {
        return Ok(super::Return::Unchanged);
    }
    let (uid, gid) = owner.resolve()?;
    // A note, not a `State` diff: that would read the content in.
    let _ = crate::diff::note(
        &mut std::io::stderr().lock(),
        &format!(
            "~ {} {owner:?} {mode} (was {old_owner:?} {old_mode})",
            path.display()
        ),
    );
    apply_attrs_nofollow(path, uid, gid, mode, false)?;
    Ok(super::Return::Changed)
}

/// The directory `path` lives in, `.` for a bare file name.
pub(crate) fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// A complete, correctly owned temp file next to its destination,
/// waiting to be renamed over it. Dropping it instead of publishing
/// unlinks it, so a caller can verify what it streamed (a checksum)
/// before anything becomes visible.
pub(crate) struct Staged {
    tmp: tempfile::NamedTempFile,
    destination: PathBuf,
}

impl Staged {
    pub(crate) fn written(&self) -> crate::Result<u64> {
        Ok(self
            .tmp
            .as_file()
            .metadata()
            .context("Couldn't stat the temporary file")?
            .len())
    }

    /// Rename over the destination, and make the rename durable.
    pub(crate) fn publish(self) -> crate::Result<()> {
        self.tmp
            .persist(&self.destination)
            .context("Couldn't persist the temporary file")?;
        let dir = parent_dir(&self.destination);
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .context(format!("Couldn't fsync directory {}", dir.display()))
    }
}

/// A staged file being written. It starts at `0o000` and gets its owner
/// and mode through its fd in [`finish`](Self::finish), so it is never
/// visible with the wrong attributes and there is no path-based chown
/// to race.
pub(crate) struct StagedWriter {
    tmp: tempfile::NamedTempFile,
    destination: PathBuf,
    uid: Uid,
    gid: Gid,
    mode: Mode,
}

impl StagedWriter {
    pub(crate) fn create(
        destination: &Path,
        uid: Uid,
        gid: Gid,
        mode: Mode,
    ) -> crate::Result<Self> {
        let tmp = tempfile::Builder::new()
            .permissions(Mode(0).into())
            .prefix(".cindy.")
            // Same directory, so the final rename never crosses filesystems.
            .tempfile_in(parent_dir(destination))
            .context("Couldn't create temporary file")?;
        Ok(Self {
            tmp,
            destination: destination.to_path_buf(),
            uid,
            gid,
            mode,
        })
    }

    pub(crate) fn as_file_mut(&mut self) -> &mut std::fs::File {
        self.tmp.as_file_mut()
    }

    pub(crate) fn finish(self) -> crate::Result<Staged> {
        let file = self.tmp.as_file();
        nix::unistd::fchown(file, Some(self.uid), Some(self.gid))
            .context("Couldn't change ownership of the temporary file")?;
        nix::sys::stat::fchmod(file, self.mode.nix())
            .context("Couldn't set permissions of the temporary file")?;
        // `persist` doesn't fsync, and a crash after the rename must not
        // leave a partial file at the destination.
        file.sync_all()
            .context("Couldn't fsync the temporary file before rename")?;
        Ok(Staged {
            tmp: self.tmp,
            destination: self.destination,
        })
    }
}

/// Stream `reader` into a staged file — content larger than the
/// target's RAM never has to be in memory.
pub(crate) fn stage_stream(
    destination: &Path,
    reader: &mut dyn std::io::Read,
    uid: Uid,
    gid: Gid,
    mode: Mode,
) -> crate::Result<Staged> {
    let mut writer = StagedWriter::create(destination, uid, gid, mode)?;
    std::io::copy(reader, writer.as_file_mut()).context("Couldn't write the temporary file")?;
    writer.finish()
}

/// A scratch file for data too big for RAM that is never published
/// (codec spill). Unlinked on drop; `0o600`, since it is reopened by path.
pub(crate) fn spill_in(parent: &Path) -> crate::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(".cindy.")
        .tempfile_in(parent)
        .context("Couldn't create a spill file")
}

/// Publish a file whose content `fill` builds (an archive). Nothing is
/// compared — the content didn't exist before — so the caller owns the
/// `Changed` verdict. If `fill` fails, nothing is published.
pub(crate) fn file_from_writer(
    destination: &Path,
    owner: &Owner,
    mode: Mode,
    fill: impl FnOnce(&mut StagedWriter) -> crate::Result<()>,
) -> crate::Result<()> {
    let (uid, gid) = owner.resolve()?;
    let mut staged = StagedWriter::create(destination, uid, gid, mode)?;
    fill(&mut staged)?;
    let staged = staged.finish()?;
    // rename(2) can't replace a directory. Cleared only now that the
    // new content exists, so a failed build leaves the old tree.
    if let old @ Observed::Directory { .. } = Observed::read(destination)? {
        old.remove(destination)?;
    }
    staged.publish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Owner {
        Owner::current()
    }

    #[test]
    fn file_attrs_satisfied_reads_without_applying() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("attr-probe");
        std::fs::write(&file, b"content").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(file_attrs_satisfied(&file, &owner(), Mode(0o600)));
        assert!(!file_attrs_satisfied(&file, &owner(), Mode(0o644)));
        assert!(!file_attrs_satisfied(
            &tmp.path().join("missing"),
            &owner(),
            Mode(0o600)
        ));
    }

    /// postcard isn't self-describing: a `#[serde(flatten)]` anywhere in
    /// `State` would compile and fail on the wire.
    #[test]
    fn state_postcard_roundtrips_every_variant() {
        let owner = Owner::new("alice", "users");
        let kinds = [
            Kind::Absent,
            Kind::File {
                content: Content(b"\x00\x01binary".to_vec()),
                owner: owner.clone(),
                mode: Mode(0o640),
            },
            Kind::Directory {
                owner: owner.clone(),
                mode: Mode(0o750),
            },
            Kind::Link {
                target: "/tmp/target".into(),
                owner,
            },
        ];
        for kind in kinds {
            let s = State {
                destination: "/tmp/x".into(),
                kind,
            };
            let bytes = postcard::to_allocvec(&s).unwrap();
            assert_eq!(s, postcard::from_bytes::<State>(&bytes).unwrap());
        }
    }

    #[test]
    fn diff_shows_text_content_by_line_and_owner_compactly() {
        let state = |content: &[u8]| State {
            destination: "/etc/motd".into(),
            kind: Kind::File {
                content: Content(content.to_vec()),
                owner: Owner::new("root", "root"),
                mode: Mode(0o644),
            },
        };
        let mut out = Vec::new();
        crate::Diff::diff(&state(b"hello\nold\n"), &state(b"hello\nnew\n"), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("-            old"), "{out}");
        assert!(out.contains("+            new"), "{out}");
        assert!(
            !out.contains("hello\\n"),
            "content rendered as one string: {out}"
        );

        assert!(out.contains("mode: 0o644"), "{out}");
        assert_eq!(format!("{:?}", Owner::new("root", "wheel")), "root:wheel");
        assert_eq!(format!("{:?}", Content(vec![0xff, 0])), "<binary, 2 bytes>");
    }

    #[test]
    fn file_lifecycle_on_disk() {
        let Owner { user: u, group: g } = owner();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("f");
        let file = |content: &[u8], mode| {
            file_raw::inner(
                p.clone(),
                content.to_vec(),
                u.clone(),
                g.clone(),
                Mode(mode),
            )
            .unwrap()
            .changed()
        };

        assert!(file(b"one", 0o644));
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        assert!(!file(b"one", 0o644), "re-run must be Unchanged");
        assert!(file(b"two", 0o644));
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert!(file(b"two", 0o600), "mode alone must be Changed");

        assert!(
            directory_raw::inner(p.clone(), u.clone(), g.clone(), Mode(0o755))
                .unwrap()
                .changed()
        );
        assert!(p.is_dir());

        assert!(absent_raw::inner(p.clone()).unwrap().changed());
        assert!(!p.exists());
        assert!(!absent_raw::inner(p.clone()).unwrap().changed());
    }

    #[test]
    fn dir_to_file_replacement_clears_tree() {
        let Owner { user, group } = owner();
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("inner"), b"x").unwrap();

        let r = file_raw::inner(d.clone(), b"now a file".to_vec(), user, group, Mode(0o600));
        assert!(r.unwrap().changed());
        assert_eq!(std::fs::read(&d).unwrap(), b"now a file");
    }

    #[test]
    fn a_special_file_can_be_removed_but_not_managed() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let Owner { user, group } = owner();

        let err = file_raw::inner(fifo.clone(), vec![], user, group, Mode(0o600)).unwrap_err();
        assert!(err.to_string().contains("special file"), "{err}");
        assert!(absent_raw::inner(fifo.clone()).unwrap().changed());
        assert!(std::fs::symlink_metadata(&fifo).is_err());
    }
}
