//! Manage a single destination path on the remote machine: a regular
//! file with given contents, a directory, a symbolic link, or its
//! absence. Idempotent — it reads the current on-disk state and only
//! acts (reporting `Return::Changed`) when reality differs from what was
//! requested.
//!
//! Use the [`file`], [`directory`], [`link`] and [`absent`] functions.
//! Each is a remote entry point: call `file(..).await?` from the
//! orchestrator, or `file::inner(..)?` from another `#[remote]` builtin
//! on the worker. Ownership and mode are **required** — this is a total,
//! declarative spec, not a partial set of opinions, so there is no
//! "leave as-is". Illegal combinations can't be expressed: a link
//! carries no `mode` (the Linux kernel ignores symlink permissions),
//! and an absent path carries nothing.

use crate::Context;

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub struct Mode(pub(crate) u32);
impl From<Mode> for std::fs::Permissions {
    fn from(Mode(value): Mode) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::Permissions::from_mode(value)
    }
}
impl Mode {
    /// Extract the permission bits from a raw `st_mode` (which also
    /// carries file-type bits above `0o7777`). Total — masking is the
    /// *correct* interpretation of OS metadata, unlike user input,
    /// where out-of-range bits mean a typo and must be rejected
    /// (`Mode::try_from`).
    pub const fn from_st_mode(st_mode: u32) -> Self {
        Mode(st_mode & 0o7777)
    }
}

impl TryFrom<u32> for Mode {
    type Error = anyhow_serde::Error;

    /// The one way to build a `Mode` from a number:
    /// `Mode::try_from(0o644)?`. (There is deliberately no `From<u32>`:
    /// it couldn't coexist with this impl — std's blanket impl would
    /// derive a conflicting infallible `TryFrom` — and an unchecked
    /// conversion would either silently mask a typo'd mode or panic.)
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

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0o{:o}", self.0)
    }
}

/// Desired state of the destination path (internal; built by the
/// [`file`]/[`directory`]/[`link`]/[`absent`] entry points).
///
/// Ownership and mode are **required** on every variant they apply to:
/// this is a total, declarative spec ("this file *is* root:root 0644"),
/// not a partial set of opinions. There is no "leave as-is" — stating a
/// path means stating who owns it and how it's permissioned, which is
/// what keeps drift from creeping in through unspecified attributes. The
/// fields live directly on the variants, so illegal combinations can't
/// be expressed: `Link` has no `mode` (the Linux kernel ignores symlink
/// permissions) and `Absent` carries nothing.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
enum Kind {
    /// Ensure nothing exists at the destination. An existing file,
    /// symlink, or **directory** (recursively, contents and all) is
    /// removed.
    Absent,
    /// A regular file with exactly `content`, owned by `user`:`group`
    /// at `mode`. Replacing an existing **directory** with a file
    /// deletes that directory's contents.
    File {
        content: Vec<u8>,
        user: String,
        group: String,
        mode: Mode,
    },
    /// A directory owned by `user`:`group` at `mode`. Only the directory
    /// itself is managed; its contents are not touched beyond creating
    /// the directory.
    Directory {
        user: String,
        group: String,
        mode: Mode,
    },
    /// A symbolic link to `target`, owned by `user`:`group` (via
    /// `lchown`). No `mode`: the Linux kernel does not honour symlink
    /// permission bits.
    Link {
        target: PathBuf,
        user: String,
        group: String,
    },
}

/// Fully-specified desired state, built internally by the [`file`],
/// [`directory`], [`link`] and [`absent`] entry points and applied by
/// [`apply`]. Not part of the public API — callers use those functions.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
struct State {
    destination: PathBuf,
    kind: Kind,
}

// Each entry point is a single `#[crate::action]` fn: it has ergonomic
// `impl Into<..>` arguments and a body that builds a `State` and calls
// `apply`. The macro generates from it the concrete `#[remote]` `*_raw` fn
// (the wire-level entry point), the orchestrator shim (`file(..).await?`),
// and the in-process `file::inner(..)` used worker-side / for local action.

/// Manage a regular file with the given contents, owned by `user`:`group`
/// at `mode`. Orchestrator: `file(..).await?` (acts on the remote worker).
/// Local/worker-side: `file::inner(..)?` (acts in-process, no RPC).
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
            content,
            user,
            group,
            mode,
        },
    })
}

/// Manage a directory owned by `user`:`group` at `mode`. Orchestrator:
/// `directory(..).await?`. Local/worker-side: `directory::inner(..)?`.
#[crate::action]
pub fn directory(
    destination: impl Into<PathBuf>,
    user: impl Into<String>,
    group: impl Into<String>,
    mode: impl Into<Mode>,
) -> crate::Result<super::Return> {
    apply(State {
        destination,
        kind: Kind::Directory { user, group, mode },
    })
}

/// Manage a symbolic link to `target`, owned by `user`:`group`.
/// Orchestrator: `link(..).await?`. Local/worker-side: `link::inner(..)?`.
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
            user,
            group,
        },
    })
}

/// Ensure nothing exists at `destination`. Orchestrator: `absent(..).await?`.
/// Local/worker-side: `absent::inner(..)?`.
#[crate::action]
pub fn absent(destination: impl Into<PathBuf>) -> crate::Result<super::Return> {
    apply(State {
        destination,
        kind: Kind::Absent,
    })
}

/// Custom diff for `State`: like the default `{:#?}` renderer except
/// `Kind::File` content is unwrapped — UTF-8 shown inline so the line
/// diff is meaningful, non-UTF-8 collapsed to `<binary, N bytes>`.
impl crate::Diff for State {
    fn diff(&self, new: &Self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        crate::diff::text_diff(&render_state(self), &render_state(new), out)
    }
}

fn render_owner(out: &mut String, user: &str, group: &str) {
    use std::fmt::Write as _;
    writeln!(out, "        user: {user:?},").unwrap();
    writeln!(out, "        group: {group:?},").unwrap();
}

fn render_state(s: &State) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    writeln!(out, "State {{").unwrap();
    writeln!(out, "    destination: {:?},", s.destination).unwrap();
    match &s.kind {
        Kind::Absent => writeln!(out, "    kind: Absent,").unwrap(),
        Kind::Directory { user, group, mode } => {
            writeln!(out, "    kind: Directory {{").unwrap();
            render_owner(&mut out, user, group);
            writeln!(out, "        mode: {mode},").unwrap();
            writeln!(out, "    }},").unwrap();
        }
        Kind::Link {
            target,
            user,
            group,
        } => {
            writeln!(out, "    kind: Link {{").unwrap();
            writeln!(out, "        target: {target:?},").unwrap();
            render_owner(&mut out, user, group);
            writeln!(out, "    }},").unwrap();
        }
        Kind::File {
            content,
            user,
            group,
            mode,
        } => {
            writeln!(out, "    kind: File {{").unwrap();
            match std::str::from_utf8(content) {
                Ok(text) => {
                    writeln!(out, "        content: (").unwrap();
                    // `split_inclusive` keeps trailing newlines so a final
                    // unterminated line still renders correctly.
                    for line in text.split_inclusive('\n') {
                        write!(out, "            {line}").unwrap();
                        if !line.ends_with('\n') {
                            out.push('\n');
                        }
                    }
                    writeln!(out, "        ),").unwrap();
                }
                Err(_) => {
                    writeln!(out, "        content: <binary, {} bytes>,", content.len()).unwrap()
                }
            }
            render_owner(&mut out, user, group);
            writeln!(out, "        mode: {mode},").unwrap();
            writeln!(out, "    }},").unwrap();
        }
    }
    writeln!(out, "}}").unwrap();
    out
}

/// The kind of thing currently at the destination, **without** the file
/// content (which is read lazily, only when a `File`-vs-`File`
/// comparison actually needs it — see [`file_matches`]).
#[derive(Clone, PartialEq, Eq)]
enum ObservedKind {
    Absent,
    File,
    Directory,
    Link(PathBuf),
}

/// Snapshot of the on-disk state at the destination path, sans file
/// content. `destination` is omitted; the caller already has it.
///
/// `user`/`group` are the resolved owner names (always present for an
/// existing path); `mode` is `None` only for symlinks (meaningless) and
/// `Absent`. This is the *observed* reality, so unlike the total
/// desired `Kind` it can't always be a complete picture.
struct OldState {
    kind: ObservedKind,
    user: String,
    group: String,
    mode: Option<Mode>,
}

impl OldState {
    /// Build a `Kind`-shaped view of this snapshot for diffing. Reads
    /// the file content (for `File`) so the diff can show it; this is
    /// the only place the bytes are loaded for rendering, and only when
    /// we're about to print a diff.
    fn to_kind(&self, destination: &Path) -> Kind {
        match &self.kind {
            ObservedKind::Absent => Kind::Absent,
            ObservedKind::Directory => Kind::Directory {
                user: self.user.clone(),
                group: self.group.clone(),
                mode: self.mode.unwrap_or(Mode(0)),
            },
            ObservedKind::Link(target) => Kind::Link {
                target: target.clone(),
                user: self.user.clone(),
                group: self.group.clone(),
            },
            ObservedKind::File => Kind::File {
                content: std::fs::read(destination).unwrap_or_default(),
                user: self.user.clone(),
                group: self.group.clone(),
                mode: self.mode.unwrap_or(Mode(0)),
            },
        }
    }
}

use super::{name_of_gid, name_of_uid};

/// Capture the destination's current state *without* reading any file
/// content — only metadata and (for symlinks) the link target. The
/// content is read lazily later, and only if it's actually compared.
fn capture_old_state(path: &Path) -> crate::Result<OldState> {
    use std::os::linux::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OldState {
                kind: ObservedKind::Absent,
                user: String::new(),
                group: String::new(),
                mode: None,
            });
        }
        Err(e) => return Err(e).context(format!("Couldn't stat {}", path.display())),
    };

    let ft = md.file_type();
    let kind = if ft.is_file() {
        ObservedKind::File
    } else if ft.is_dir() {
        ObservedKind::Directory
    } else if ft.is_symlink() {
        ObservedKind::Link(
            std::fs::read_link(path)
                .context(format!("Couldn't read symlink {}", path.display()))?,
        )
    } else {
        crate::bail!(
            "{} is a special file (socket, FIFO, or device); refusing to manage it",
            path.display()
        );
    };

    let mode = if matches!(kind, ObservedKind::Link(_)) {
        None
    } else {
        // `st_mode` carries file-type bits above the permission range;
        // mask them off before the (now strict) `Mode` conversion.
        Some(Mode::from_st_mode(md.permissions().mode()))
    };

    Ok(OldState {
        kind,
        user: name_of_uid(md.st_uid()),
        group: name_of_gid(md.st_gid()),
        mode,
    })
}

/// Remove the existing entry at `path`, choosing the syscall for its kind.
fn remove_existing(path: &Path, kind: &ObservedKind) -> crate::Result<()> {
    match kind {
        ObservedKind::Absent => Ok(()),
        ObservedKind::File | ObservedKind::Link(_) => std::fs::remove_file(path).context(format!(
            "Couldn't remove file or symlink {}",
            path.display()
        )),
        ObservedKind::Directory => std::fs::remove_dir_all(path)
            .context(format!("Couldn't remove directory {}", path.display())),
    }
}

/// `true` when the observed owner matches the desired owner exactly.
/// Owner/group are total in the desired state — there is no "don't
/// care" — so this is plain equality.
fn owner_matches(old: &OldState, user: &str, group: &str) -> bool {
    old.user == user && old.group == group
}

/// The comparison half of [`reconcile_file_attrs`]: would it leave the
/// file's attributes alone? Pure metadata — no content, no mutation.
fn attrs_match(old: &OldState, user: &str, group: &str, mode: Mode) -> bool {
    owner_matches(old, user, group) && old.mode == Some(mode)
}

/// Would [`reconcile_file_attrs`] report `Unchanged` for this file?
/// Extracted so check mode can ask the attr-drift question without
/// applying anything — the answer is stat-level reads (owner names +
/// mode), never content.
pub(crate) fn file_attrs_satisfied(path: &Path, user: &str, group: &str, mode: Mode) -> bool {
    capture_old_state(path).is_ok_and(|old| attrs_match(&old, user, group, mode))
}

/// `true` when the on-disk file's content equals `want`. Reads the file
/// here — the one place content is loaded for comparison, and only when
/// both sides are regular files.
fn file_matches(path: &Path, want: &[u8]) -> bool {
    match std::fs::read(path) {
        Ok(have) => have == want,
        Err(_) => false,
    }
}

/// Returns `true` when the on-disk state already satisfies `desired`.
fn state_matches(old: &OldState, desired: &State) -> bool {
    match (&old.kind, &desired.kind) {
        (ObservedKind::Absent, Kind::Absent) => true,
        (_, Kind::Absent) | (ObservedKind::Absent, _) => false,

        (
            ObservedKind::File,
            Kind::File {
                content,
                user,
                group,
                mode,
            },
        ) => {
            owner_matches(old, user, group)
                && old.mode == Some(*mode)
                && file_matches(&desired.destination, content)
        }
        (ObservedKind::Directory, Kind::Directory { user, group, mode }) => {
            owner_matches(old, user, group) && old.mode == Some(*mode)
        }
        (
            ObservedKind::Link(have_target),
            Kind::Link {
                target,
                user,
                group,
            },
        ) => have_target == target && owner_matches(old, user, group),
        // Kind mismatch (file vs dir vs link).
        _ => false,
    }
}

fn resolve_uid(name: &str) -> crate::Result<nix::unistd::Uid> {
    match nix::unistd::User::from_name(name) {
        Ok(Some(user)) => Ok(user.uid),
        Ok(None) => crate::bail!("no such user: {name}"),
        Err(e) => crate::bail!("user lookup for {name:?} failed: {e}"),
    }
}

fn resolve_gid(name: &str) -> crate::Result<nix::unistd::Gid> {
    match nix::unistd::Group::from_name(name) {
        Ok(Some(group)) => Ok(group.gid),
        Ok(None) => crate::bail!("no such group: {name}"),
        Err(e) => crate::bail!("group lookup for {name:?} failed: {e}"),
    }
}

/// Resolve a `user`:`group` name pair to numeric ids, erroring on either
/// miss.
///
/// Exposed in-crate so callers that don't go through [`apply`] (e.g.
/// [`fetch`](super::fetch)) resolve the owner up front — a typo'd user
/// must fail the call before anything destructive or expensive happens,
/// not after.
pub(crate) fn resolve_owner(
    user: &str,
    group: &str,
) -> crate::Result<(nix::unistd::Uid, nix::unistd::Gid)> {
    Ok((resolve_uid(user)?, resolve_gid(group)?))
}

/// fsync the directory containing `path` so a preceding `rename(2)`
/// (the file write's atomic publish) survives power-loss. The file's
/// own data was already fsynced before the rename; this makes the
/// *directory entry* durable too.
fn fsync_parent(path: &Path) -> crate::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    let f =
        std::fs::File::open(dir).context(format!("Couldn't open {} to fsync", dir.display()))?;
    f.sync_all()
        .context(format!("Couldn't fsync directory {}", dir.display()))
}

/// Apply ownership + mode to an **existing** path without following
/// symlinks, closing the TOCTOU window where the target could be
/// swapped for a symlink between the observation and the chown/chmod.
///
/// Opens with `O_NOFOLLOW` (plus `O_DIRECTORY` when `expect_dir`), so a
/// symlink swap makes the *open* fail instead of silently redirecting
/// the operation onto the link's target, then acts on that fd with
/// `fchown`/`fchmod`.
fn apply_attrs_nofollow(
    path: &Path,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
    mode: Mode,
    expect_dir: bool,
) -> crate::Result<()> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::{Mode as NixMode, fchmod};

    let mut flags = OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC;
    if expect_dir {
        flags |= OFlag::O_DIRECTORY;
    }

    let fd = open(path, flags, NixMode::empty()).context(format!(
        "Couldn't open {} (O_NOFOLLOW) to set attributes",
        path.display()
    ))?;

    nix::unistd::fchown(&fd, Some(uid), Some(gid))
        .context(format!("Couldn't change ownership of {}", path.display()))?;
    fchmod(&fd, NixMode::from_bits_truncate(mode.0))
        .context(format!("Couldn't set permissions of {}", path.display()))?;
    Ok(())
}

/// A fully written, correctly owned temp file waiting to be renamed over
/// its destination.
///
/// Splitting the write from the rename is what lets a caller check the
/// bytes it just streamed — a digest it could only compute *while*
/// streaming — before anything becomes visible at the destination. Drop
/// it instead of calling [`Staged::publish`] and the temp file is
/// unlinked, leaving the destination exactly as it was.
pub(crate) struct Staged {
    tmp: tempfile::NamedTempFile,
    destination: PathBuf,
    written: u64,
}

impl Staged {
    /// Bytes written into the staged file.
    pub(crate) fn written(&self) -> u64 {
        self.written
    }

    /// Rename the staged file over its destination, and make the rename
    /// itself durable.
    pub(crate) fn publish(self) -> crate::Result<()> {
        self.tmp
            .persist(&self.destination)
            .context("Couldn't persist the temporary file")?;
        fsync_parent(&self.destination)
    }
}

/// Stream `reader` into a temp file alongside `destination`, owned by
/// `uid`:`gid` at `mode`, ready to be published.
///
/// The content never has to exist in memory all at once, which is what
/// lets [`fetch`](super::fetch) handle an artefact larger than the
/// target's RAM. The temp file starts at `0o000` and takes its ownership
/// and mode through its own *file descriptor*, so it appears at
/// `destination` already correct — there is no window where it is
/// visible with the wrong attributes, and no path-based `chown`/`chmod`
/// for anything to race.
pub(crate) fn stage_stream(
    destination: &Path,
    reader: &mut dyn std::io::Read,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
    mode: Mode,
) -> crate::Result<Staged> {
    let mut tmp = new_staged_tempfile(destination)?;

    std::io::copy(reader, &mut tmp).context("Couldn't write the temporary file")?;

    finalise_staged(tmp, destination, uid, gid, mode)
}

/// A scratch temp file in `parent`, for bulk data that must not live
/// in RAM but is never published — codec spill files. `0o600`, because
/// unlike a staged publish it is reopened *by path*. Auto-unlinked on
/// drop.
pub(crate) fn spill_in(parent: &Path) -> crate::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(".cindy.")
        .tempfile_in(parent)
        .context("Couldn't create a spill file")
}

/// A staging temp file the way every cindy publish wants it: hidden
/// (`.cindy.` prefix), mode `0o000` until its real attributes arrive
/// via its fd, living in the destination's own directory so the final
/// `rename(2)` never crosses a filesystem.
fn new_staged_tempfile(destination: &Path) -> crate::Result<tempfile::NamedTempFile> {
    let parent_raw = destination
        .parent()
        .context("Parent directory unavailable")?;
    let parent = if parent_raw.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent_raw
    };

    tempfile::Builder::new()
        .permissions(Mode(0o0000).into())
        .prefix(".cindy.")
        .tempfile_in(parent)
        .context("Couldn't create temporary file")
}

/// Apply ownership and mode to a staged temp file through its fd, fsync
/// it, and wrap it as a [`Staged`] ready to publish. Shared by
/// [`stage_stream`] (reader side) and [`StagedWriter::finish`] (writer
/// side).
fn finalise_staged(
    tmp: tempfile::NamedTempFile,
    destination: &Path,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
    mode: Mode,
) -> crate::Result<Staged> {
    nix::unistd::fchown(tmp.as_file(), Some(uid), Some(gid))
        .context("Couldn't change ownership of the temporary file")?;
    nix::sys::stat::fchmod(
        tmp.as_file(),
        nix::sys::stat::Mode::from_bits_truncate(mode.0),
    )
    .context("Couldn't set permissions of the temporary file")?;

    // Flush the data *and* the attribute change before the rename:
    // otherwise a crash after rename(2) but before write-back can leave
    // a zero-length or partial file at `destination`. `persist` does not
    // fsync for us.
    tmp.as_file()
        .sync_all()
        .context("Couldn't fsync the temporary file before rename")?;

    let written = tmp
        .as_file()
        .metadata()
        .context("Couldn't stat the temporary file")?
        .len();

    Ok(Staged {
        tmp,
        destination: destination.to_path_buf(),
        written,
    })
}

/// A staged temp file **open for writing**, for callers that *build*
/// content rather than copy it — the write-side counterpart of
/// [`stage_stream`]. Archive writers, compression encoders and friends
/// stream into [`as_file_mut`](Self::as_file_mut); [`Self::finish`]
/// then applies ownership/mode over the fd and hands back a [`Staged`]
/// to publish. If the builder errors part-way, dropping the
/// `StagedWriter` unlinks the temp file and the destination keeps
/// whatever it had.
pub(crate) struct StagedWriter {
    tmp: tempfile::NamedTempFile,
    destination: PathBuf,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
    mode: Mode,
}

impl StagedWriter {
    /// Create a `0o000` temp file alongside `destination`, to be filled
    /// by the caller and published over `destination`.
    pub(crate) fn create(
        destination: &Path,
        uid: nix::unistd::Uid,
        gid: nix::unistd::Gid,
        mode: Mode,
    ) -> crate::Result<Self> {
        Ok(Self {
            tmp: new_staged_tempfile(destination)?,
            destination: destination.to_path_buf(),
            uid,
            gid,
            mode,
        })
    }

    /// The staged file, open for writing — hand this to the builder.
    pub(crate) fn as_file_mut(&mut self) -> &mut std::fs::File {
        self.tmp.as_file_mut()
    }

    /// Seal the staged file: attributes via its fd, fsync, and a
    /// [`Staged`] whose `publish` renames it over the destination.
    pub(crate) fn finish(self) -> crate::Result<Staged> {
        finalise_staged(self.tmp, &self.destination, self.uid, self.gid, self.mode)
    }
}

/// Publish a file at `destination` whose content the caller **builds**
/// into a staged temp file, the way [`stage_stream`] publishes content
/// it copies from a reader. Shares the destination-transition semantics
/// of [`apply`]'s `Kind::File`: an existing file or symlink is replaced
/// atomically by the rename, an existing directory is cleared first.
///
/// Unlike [`apply`], content is never read back or compared — the
/// caller streams bytes that did not exist before it ran (an archive
/// build), so there is nothing to diff against and the caller owns the
/// `Changed` verdict. If `fill` errors, nothing is published.
pub(crate) fn file_from_writer(
    destination: &Path,
    user: &str,
    group: &str,
    mode: Mode,
    fill: impl FnOnce(&mut StagedWriter) -> crate::Result<()>,
) -> crate::Result<()> {
    // Resolve the owner before anything destructive, mirroring `apply`.
    let (uid, gid) = resolve_owner(user, group)?;

    // `Staged::publish`'s rename(2) replaces an existing file or
    // symlink atomically. The one thing rename can't replace is a
    // directory, so pre-clear that case.
    if std::fs::symlink_metadata(destination)
        .map(|md| md.is_dir())
        .unwrap_or(false)
    {
        remove_existing(destination, &ObservedKind::Directory)?;
    }

    let mut staged = StagedWriter::create(destination, uid, gid, mode)?;
    fill(&mut staged)?;
    staged.finish()?.publish()
}

/// Reconcile only ownership and mode on the regular file at `path`,
/// leaving its content alone.
///
/// For builtins that establish content by other means — [`fetch`]
/// streams it, and can't hand the bytes to [`apply`] without buffering
/// the whole artefact — but still want this module's total owner/mode
/// guarantee. Reports `Unchanged` when both already match, so a
/// satisfied download doesn't claim work it didn't do.
///
/// [`fetch`]: super::fetch
pub(crate) fn reconcile_file_attrs(
    path: &Path,
    user: &str,
    group: &str,
    mode: Mode,
) -> crate::Result<super::Return> {
    let old = capture_old_state(path)?;
    if attrs_match(&old, user, group, mode) {
        return Ok(super::Return::Unchanged);
    }

    let (uid, gid) = resolve_owner(user, group)?;
    // A one-line note rather than a `State` diff: rendering the `File`
    // variant would mean reading the content this function exists to
    // avoid loading.
    let _ = crate::diff::note(
        &mut std::io::stderr().lock(),
        &format!(
            "~ {} {user}:{group} {mode} (was {}:{} {})",
            path.display(),
            old.user,
            old.group,
            old.mode.map_or_else(|| "?".to_owned(), |m| m.to_string()),
        ),
    );
    apply_attrs_nofollow(path, uid, gid, mode, false)?;
    Ok(super::Return::Changed)
}

/// Apply a fully-specified `State` to the destination on the worker.
///
/// This is the shared worker-side executor behind the [`file`],
/// [`directory`], [`link`] and [`absent`] remote functions — it is not
/// itself a remote fn (those are), just the body they all funnel into
/// once they've built their `State`. Idempotent: reads the current
/// on-disk state and only acts (reporting `Return::Changed`) when
/// reality differs.
fn apply(state: State) -> crate::Result<super::Return> {
    // `capture_old_state` refuses special files (sockets, FIFOs,
    // devices) because we can't *manage* one — but ensuring one is
    // `Absent` is legitimate cleanup (e.g. a stale `.sock`). Handle
    // that case before the general capture would bail.
    if matches!(state.kind, Kind::Absent)
        && let Ok(md) = std::fs::symlink_metadata(&state.destination)
    {
        let ft = md.file_type();
        if !ft.is_file() && !ft.is_dir() && !ft.is_symlink() {
            eprintln!("removing special file {}", state.destination.display());
            if crate::dry_run() {
                return Ok(super::Return::Changed);
            }
            std::fs::remove_file(&state.destination).context(format!(
                "Couldn't remove special file {}",
                state.destination.display()
            ))?;
            return Ok(super::Return::Changed);
        }
    }

    let old = capture_old_state(&state.destination)?;

    if state_matches(&old, &state) {
        return Ok(super::Return::Unchanged);
    }

    // Show what we're about to change. Diff output is informational;
    // errors writing to stderr are deliberately ignored.
    let old_view = State {
        destination: state.destination.clone(),
        kind: old.to_kind(&state.destination),
    };
    let _ = <State as crate::Diff>::diff(&old_view, &state, &mut std::io::stderr().lock());

    // Check mode: the diff above is the report. `state_matches` has
    // already returned `Unchanged` for converged requests, so anything
    // reaching here would have been applied — say so and stop.
    if crate::dry_run() {
        return Ok(super::Return::Changed);
    }

    match &state.kind {
        Kind::Absent => {
            remove_existing(&state.destination, &old.kind)?;
        }

        Kind::File {
            content,
            user,
            group,
            mode,
        } => {
            // Resolve the owner before anything destructive: a typo'd
            // user must fail the call, not leave the directory cleared
            // below already gone.
            let (new_uid, new_gid) = resolve_owner(user, group)?;

            // `Staged::publish`'s rename(2) replaces an existing file
            // or symlink atomically. The one thing rename can't replace
            // is a directory, so pre-clear that case.
            if matches!(old.kind, ObservedKind::Directory) {
                remove_existing(&state.destination, &old.kind)?;
            }

            // The in-memory content is just a reader here, so the write,
            // the fd-based attribute application, the fsyncs and the
            // atomic publish are shared verbatim with the streaming
            // callers (see `stage_stream`).
            stage_stream(
                &state.destination,
                &mut &content[..],
                new_uid,
                new_gid,
                *mode,
            )?
            .publish()?;
        }

        Kind::Directory { user, group, mode } => {
            let (new_uid, new_gid) = resolve_owner(user, group)?;

            match old.kind {
                ObservedKind::Directory => {
                    // Already a directory; only attributes may change.
                }
                ObservedKind::Absent => {
                    std::fs::create_dir(&state.destination).context("Couldn't create directory")?;
                }
                ref other => {
                    remove_existing(&state.destination, other)?;
                    std::fs::create_dir(&state.destination).context("Couldn't create directory")?;
                }
            }

            // Apply ownership/mode via an O_NOFOLLOW fd so a symlink
            // swap between the create above and now can't redirect the
            // chown/chmod onto an attacker-chosen target.
            apply_attrs_nofollow(&state.destination, new_uid, new_gid, *mode, true)?;
        }

        Kind::Link {
            target,
            user,
            group,
        } => {
            let (new_uid, new_gid) = resolve_owner(user, group)?;

            if !matches!(old.kind, ObservedKind::Absent) {
                remove_existing(&state.destination, &old.kind)?;
            }

            std::os::unix::fs::symlink(target, &state.destination)
                .context("Couldn't create symbolic link")?;
            nix::unistd::fchownat(
                nix::fcntl::AT_FDCWD,
                &state.destination,
                Some(new_uid),
                Some(new_gid),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .context("Couldn't change ownership of symbolic link")?;
            // `mode` is intentionally absent on `Kind::Link`: the Linux
            // kernel does not honour symlink permission bits.
        }
    }

    Ok(super::Return::Changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user/group names the test process actually runs as, so the
    /// `resolve_uid`/`resolve_gid` lookups succeed regardless of CI uid.
    fn current_owner() -> (String, String) {
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();
        let user = nix::unistd::User::from_uid(uid)
            .unwrap()
            .expect("current uid has a passwd entry")
            .name;
        let group = nix::unistd::Group::from_gid(gid)
            .unwrap()
            .expect("current gid has a group entry")
            .name;
        (user, group)
    }

    /// The pure predicate behind `reconcile_file_attrs`'s `Unchanged`
    /// path — and behind fetch's check-mode attr report. Owner drift
    /// can't be arranged without root, but mode drift can, and absence
    /// is the other failure shape.
    #[test]
    fn file_attrs_satisfied_reads_without_applying() {
        use std::os::unix::fs::PermissionsExt as _;

        let (user, group) = current_owner();
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = tmp.path().join("attr-probe");
        std::fs::write(&file, b"content").expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");

        // Matching attrs: satisfied.
        assert!(file_attrs_satisfied(&file, &user, &group, Mode(0o600)));
        // Mode drift: not satisfied — this is the drift check mode
        // must not paper over with `Unchanged`.
        assert!(!file_attrs_satisfied(&file, &user, &group, Mode(0o644)));
        // Absent: not satisfied.
        assert!(!file_attrs_satisfied(
            &tmp.path().join("missing"),
            &user,
            &group,
            Mode(0o600)
        ));
    }

    /// `State` is reconstructed on the worker from the remote-fn args
    /// (postcard). Postcard is not self-describing, so any
    /// `#[serde(flatten)]` (or other map/any-based) construct in `State`
    /// / `Kind` silently breaks at runtime while still compiling. This
    /// guards every variant against that.
    #[test]
    fn state_postcard_roundtrips_every_variant() {
        let cases = [
            State {
                destination: "/tmp/x".into(),
                kind: Kind::Absent,
            },
            State {
                destination: "/tmp/x".into(),
                kind: Kind::File {
                    content: b"\x00\x01binary".to_vec(),
                    user: "alice".into(),
                    group: "users".into(),
                    mode: Mode(0o640),
                },
            },
            State {
                destination: "/tmp/d".into(),
                kind: Kind::Directory {
                    user: "alice".into(),
                    group: "users".into(),
                    mode: Mode(0o750),
                },
            },
            State {
                destination: "/tmp/l".into(),
                kind: Kind::Link {
                    target: "/tmp/target".into(),
                    user: "bob".into(),
                    group: "staff".into(),
                },
            },
        ];
        for s in cases {
            let bytes = postcard::to_allocvec(&s).expect("postcard serialise");
            let back: State = postcard::from_bytes(&bytes).expect("postcard deserialise");
            assert_eq!(s, back, "roundtrip mismatch");
        }
    }

    /// End-to-end against a real temp dir, driving the worker-side
    /// `*::inner` entry points: create file → idempotent re-run →
    /// content change → mode change → replace with dir → make absent.
    #[test]
    fn file_lifecycle_on_disk() {
        let (u, g) = current_owner();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("f");

        // Create.
        let r = file_raw::inner(
            p.clone(),
            b"one".to_vec(),
            u.clone(),
            g.clone(),
            Mode(0o644),
        )
        .unwrap();
        assert!(r.changed());
        assert_eq!(std::fs::read(&p).unwrap(), b"one");

        // Idempotent: same content + owner + mode → Unchanged.
        let r = file_raw::inner(
            p.clone(),
            b"one".to_vec(),
            u.clone(),
            g.clone(),
            Mode(0o644),
        )
        .unwrap();
        assert!(!r.changed());

        // Content change → Changed.
        let r = file_raw::inner(
            p.clone(),
            b"two".to_vec(),
            u.clone(),
            g.clone(),
            Mode(0o644),
        )
        .unwrap();
        assert!(r.changed());
        assert_eq!(std::fs::read(&p).unwrap(), b"two");

        // Mode change alone → Changed.
        let r = file_raw::inner(
            p.clone(),
            b"two".to_vec(),
            u.clone(),
            g.clone(),
            Mode(0o600),
        )
        .unwrap();
        assert!(r.changed());

        // Replace file with a directory.
        let r = directory_raw::inner(p.clone(), u.clone(), g.clone(), Mode(0o755)).unwrap();
        assert!(r.changed());
        assert!(p.is_dir());

        // Make absent (recursively removes the dir).
        let r = absent_raw::inner(p.clone()).unwrap();
        assert!(r.changed());
        assert!(!p.exists());

        // Absent is idempotent.
        let r = absent_raw::inner(p.clone()).unwrap();
        assert!(!r.changed());
    }

    /// Replacing a non-empty directory with a file deletes the tree, and
    /// the new file lands with the requested contents.
    #[test]
    fn dir_to_file_replacement_clears_tree() {
        let (u, g) = current_owner();
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("inner"), b"x").unwrap();

        let r = file_raw::inner(d.clone(), b"now a file".to_vec(), u, g, Mode(0o600)).unwrap();
        assert!(r.changed());
        assert!(d.is_file());
        assert_eq!(std::fs::read(&d).unwrap(), b"now a file");
    }
}
