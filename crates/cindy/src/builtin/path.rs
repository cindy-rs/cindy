//! Manage a single destination path on the remote machine: a regular
//! file with given contents, a directory, a symbolic link, or its
//! absence. Idempotent — it reads the current on-disk state and only
//! acts (reporting `Return::Changed`) when reality differs from what was
//! requested.
//!
//! Use the [`file`], [`template`], [`directory`], [`link`] and
//! [`absent`] functions. Each is a remote entry point: call
//! `file(..).await?` from the orchestrator, or `file::inner(..)?` from
//! another `#[remote]` builtin on the worker. Ownership and mode are
//! **required** — this is a total, declarative spec, not a partial set
//! of opinions, so there is no "leave as-is". Illegal combinations can't
//! be expressed: a link carries no `mode` (the Linux kernel ignores
//! symlink permissions), and an absent path carries nothing.
//!
//! # Files that contain secrets
//!
//! Reach for [`template`] rather than [`file`] whenever the content can
//! hold a secret. It is the one entry point that renders the content
//! itself, and rendering is the only moment at which cindy can tell
//! which bytes are secret — so it is the only path on which a diff can
//! be redacted. Put the `Secret<T>` in the template; there is nothing to
//! annotate and no `.reveal()` to call.
//!
//! The diff is asymmetric by necessity. cindy renders the *new* content,
//! so it knows exactly what to hide there. It knows nothing about the
//! bytes already on disk, so those are shown only when no secret is
//! involved at all — see [`old_content_view`].

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

/// The bytes to write to a file, plus — when they were produced from a
/// template containing secrets — the redacted rendering that every diff
/// is built from instead.
///
/// Built by `Into` from plain bytes or a string, in which case there is
/// nothing to redact and the diff behaves exactly as it always has; or
/// by [`Content::render`], which renders a template twice and keeps both
/// results. Only the second ever reaches a diff, stderr, or the run
/// view.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub struct Content {
    /// What gets written to the destination.
    bytes: Vec<u8>,
    /// The rendering safe to print. `None` when the content came from
    /// plain bytes, or from a template that turned out to hold no
    /// secrets — then `bytes` is its own safe rendering.
    redacted: Option<String>,
}

impl Content {
    /// Render `template` twice — once for real, once with every
    /// `Secret<T>` collapsed to `***` — keeping the real bytes to write
    /// and the redacted text to diff.
    ///
    /// When the two passes come out identical the template held no
    /// secrets, and the redacted rendering is dropped: there is nothing
    /// to hide, so the file diffs in full like any other.
    pub fn render(template: &impl crate::secret::Render) -> crate::Result<Self> {
        let (real, redacted) = crate::secret::render_both(template)?;
        let sensitive = real != redacted;
        Ok(Self {
            bytes: real.into_bytes(),
            redacted: sensitive.then_some(redacted),
        })
    }

    /// `true` when this content holds at least one secret, so its bytes
    /// must never be rendered.
    fn is_sensitive(&self) -> bool {
        self.redacted.is_some()
    }

    /// How this content should be rendered in a diff.
    fn view(&self) -> ContentView<'_> {
        match &self.redacted {
            Some(text) => ContentView::Redacted(text),
            None => ContentView::Bytes(&self.bytes),
        }
    }
}

impl From<Vec<u8>> for Content {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            redacted: None,
        }
    }
}

impl From<&[u8]> for Content {
    fn from(bytes: &[u8]) -> Self {
        bytes.to_vec().into()
    }
}

impl<const N: usize> From<&[u8; N]> for Content {
    fn from(bytes: &[u8; N]) -> Self {
        bytes.as_slice().into()
    }
}

impl From<String> for Content {
    fn from(text: String) -> Self {
        text.into_bytes().into()
    }
}

impl From<&str> for Content {
    fn from(text: &str) -> Self {
        text.as_bytes().into()
    }
}

/// How one side of a diff renders a file's content.
enum ContentView<'a> {
    /// Show the bytes: inline when UTF-8, a byte count otherwise.
    Bytes(&'a [u8]),
    /// Show this text in place of the bytes — the redacted rendering of
    /// content that contains secrets.
    Redacted(&'a str),
    /// Show only a size. cindy has no redaction rendering for these
    /// bytes and therefore can't prove printing them is safe.
    Withheld(u64),
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
        content: Content,
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
    content: impl Into<Content>,
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

/// Manage a regular file whose content comes from a **template**.
///
/// This is the entry point to use whenever the content can contain a
/// secret, and it is the only one on which cindy can redact a diff.
/// Put the `Secret<T>` straight into the template — there is no
/// `.reveal()` on this path, and nothing to mark up:
///
/// ```rust,ignore
/// #[derive(askama::Template)]
/// #[template(path = "app.conf")]
/// struct AppConf<'a> {
///     password: &'a cindy::Secret<String>,
///     port: u16,
/// }
///
/// path::template("/etc/app.conf", &AppConf { password: &pw, port: 8080 },
///                &user, &group, mode).await?;
/// ```
///
/// The template is rendered twice: once for the bytes written to the
/// target, and once with every secret collapsed to `***` for the diff.
/// So `port = 8080` stays fully visible and diffable while
/// `password = ***` does not, and the plaintext never reaches stderr,
/// the run view, or a CI log.
///
/// Rendering happens where this is called — the orchestrator for
/// `template(..).await`, the worker for `template::inner(..)` — because
/// only there does the template still exist as structure. What crosses
/// the wire is both renderings, never the template.
///
/// Written out by hand rather than with `#[crate::action]`: the
/// ergonomic layer has to *render* rather than `.into()`, which is more
/// than that macro generates.
#[cfg(feature = "orchestrator")]
pub async fn template(
    destination: impl Into<PathBuf>,
    template: &impl crate::secret::Render,
    user: impl Into<String>,
    group: impl Into<String>,
    mode: impl Into<Mode>,
) -> crate::Result<super::Return> {
    file(
        destination.into(),
        Content::render(template)?,
        user.into(),
        group.into(),
        mode.into(),
    )
    .await
}

/// In-process counterpart of [`template`], mirroring the `::inner`
/// convention `#[crate::action]` establishes for every other entry
/// point: it acts on the machine it runs on, with no RPC.
#[allow(non_camel_case_types)]
pub enum template {}

impl template {
    pub fn inner(
        destination: impl Into<PathBuf>,
        template: &impl crate::secret::Render,
        user: impl Into<String>,
        group: impl Into<String>,
        mode: impl Into<Mode>,
    ) -> crate::Result<super::Return> {
        file::inner(
            destination.into(),
            Content::render(template)?,
            user.into(),
            group.into(),
            mode.into(),
        )
    }
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

fn render_owner(out: &mut String, user: &str, group: &str) {
    use std::fmt::Write as _;
    writeln!(out, "        user: {user:?},").unwrap();
    writeln!(out, "        group: {group:?},").unwrap();
}

/// Render a file's content for the diff, honouring what the caller
/// decided may be shown.
fn render_content(out: &mut String, view: ContentView<'_>) {
    use std::fmt::Write as _;

    let text = match view {
        ContentView::Bytes(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                writeln!(out, "        content: <binary, {} bytes>,", bytes.len()).unwrap();
                return;
            }
        },
        ContentView::Redacted(text) => text,
        ContentView::Withheld(len) => {
            writeln!(
                out,
                "        content: <{len} bytes withheld: cindy cannot show content it \
                 didn't render, and the new content holds a secret>,"
            )
            .unwrap();
            return;
        }
    };

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

/// Render one side of the diff. `file_content` decides what a
/// `Kind::File`'s bytes turn into — the two sides are rendered with
/// different rules, which is why this isn't a `Diff` impl on `State`.
fn render_state(s: &State, file_content: ContentView<'_>) -> String {
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
            user, group, mode, ..
        } => {
            writeln!(out, "    kind: File {{").unwrap();
            render_content(&mut out, file_content);
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
    /// Build a `Kind`-shaped view of this snapshot for diffing.
    ///
    /// The content is left empty: whether the old bytes may be *shown*
    /// is a separate decision (see [`old_content_view`]), and this shape
    /// only carries the structural side — kind, owner, mode.
    fn to_kind(&self) -> Kind {
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
                content: Content::from(Vec::new()),
                user: self.user.clone(),
                group: self.group.clone(),
                mode: self.mode.unwrap_or(Mode(0)),
            },
        }
    }
}

/// Decide what the diff may show of the content already on disk.
///
/// cindy renders the *new* content itself, so it knows exactly which of
/// those bytes are secret. It knows nothing of the kind about bytes that
/// were already there — they could be last run's output, a hand edit, or
/// a file it has never seen. So the old content is shown only when
/// there is no secret in play at all:
///
///   * new state is a `File` with plain content ⇒ show the old bytes,
///     exactly as cindy always has;
///   * new state is a `File` whose content holds a secret ⇒ withhold,
///     because the old file is almost certainly the previous render of
///     the same template and therefore holds the previous secret;
///   * new state is *not* a `File` (`absent`, or replacement by a
///     directory or symlink) ⇒ withhold, because there is no rendering
///     to compare against and no way to tell whether those bytes are
///     sensitive.
///
/// The last case costs a content diff on the deletion of an ordinary
/// file. That is the deliberate trade: a deletion's content is going
/// away regardless, and the alternative is printing a private key
/// because someone ran `path::absent` on it.
fn old_content_view<'a>(
    old: &OldState,
    destination: &Path,
    new: &Kind,
    scratch: &'a mut Vec<u8>,
) -> ContentView<'a> {
    if !matches!(old.kind, ObservedKind::File) {
        // No content on this side at all.
        return ContentView::Bytes(&[]);
    }
    let plain_file_replacement =
        matches!(new, Kind::File { content, .. } if !content.is_sensitive());
    if plain_file_replacement {
        *scratch = std::fs::read(destination).unwrap_or_default();
        ContentView::Bytes(scratch)
    } else {
        let len = std::fs::metadata(destination).map(|m| m.len()).unwrap_or(0);
        ContentView::Withheld(len)
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
                && file_matches(&desired.destination, &content.bytes)
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
    let parent_raw = destination
        .parent()
        .context("Parent directory unavailable")?;
    let parent = if parent_raw.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent_raw
    };

    let mut tmp = tempfile::Builder::new()
        .permissions(Mode(0o0000).into())
        .prefix(".cindy.")
        .tempfile_in(parent)
        .context("Couldn't create temporary file")?;

    let written = std::io::copy(reader, &mut tmp).context("Couldn't write the temporary file")?;

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

    Ok(Staged {
        tmp,
        destination: destination.to_path_buf(),
        written,
    })
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
    if owner_matches(&old, user, group) && old.mode == Some(mode) {
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
    //
    // The two sides are rendered under different rules: the new content
    // is ours, so we know what in it is secret and can show a redacted
    // rendering of it; the old content is not, so it is shown only when
    // no secret is involved at all (see `old_content_view`).
    let old_view = State {
        destination: state.destination.clone(),
        kind: old.to_kind(),
    };
    let mut old_bytes = Vec::new();
    let old_content = old_content_view(&old, &state.destination, &state.kind, &mut old_bytes);
    let new_content = match &state.kind {
        Kind::File { content, .. } => content.view(),
        _ => ContentView::Bytes(&[]),
    };
    let _ = crate::diff::text_diff(
        &render_state(&old_view, old_content),
        &render_state(&state, new_content),
        &mut std::io::stderr().lock(),
    );

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
                &mut &content.bytes[..],
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
                    content: b"\x00\x01binary".to_vec().into(),
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
            b"one".to_vec().into(),
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
            b"one".to_vec().into(),
            u.clone(),
            g.clone(),
            Mode(0o644),
        )
        .unwrap();
        assert!(!r.changed());

        // Content change → Changed.
        let r = file_raw::inner(
            p.clone(),
            b"two".to_vec().into(),
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
            b"two".to_vec().into(),
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

    /// A template holding a secret must produce the real bytes on disk
    /// and a redacted rendering for the diff — with the plaintext absent
    /// from everything the operator can see.
    #[test]
    fn a_secret_bearing_template_writes_real_bytes_and_diffs_redacted() {
        use crate::secret::{crypto, keychain};

        // Install a vault key and seal a password under it, the way
        // `cindy secret seal` would.
        let key = crypto::generate_vault_key();
        let payload = crate::secret::SealedPayload {
            value: postcard::to_allocvec("hunter2").unwrap(),
            source: "\"hunter2\"".to_owned(),
        };
        let ciphertext = crypto::seal(&key, &postcard::to_allocvec(&payload).unwrap()).unwrap();
        let mut chain = std::collections::HashMap::new();
        chain.insert("tmpl-vault".to_owned(), key);
        keychain::install_keys(chain);
        let pw: crate::Secret<String> = crate::Secret::sealed("tmpl-vault", ciphertext);

        /// Stands in for an askama template: the `Display` of a
        /// `Secret<T>` is all the real thing relies on, so this exercises
        /// the same path without the derive.
        struct Conf<'a> {
            password: &'a crate::Secret<String>,
            port: u16,
        }
        impl crate::secret::Render for Conf<'_> {
            fn render(&self) -> crate::Result<String> {
                Ok(format!(
                    "port = {}\npassword = {}\n",
                    self.port, self.password
                ))
            }
        }

        let content = Content::render(&Conf {
            password: &pw,
            port: 8080,
        })
        .unwrap();

        // The bytes destined for disk carry the plaintext…
        assert_eq!(
            String::from_utf8(content.bytes.clone()).unwrap(),
            "port = 8080\npassword = hunter2\n"
        );
        // …and the rendering the diff uses does not.
        assert!(content.is_sensitive());
        let redacted = content.redacted.clone().unwrap();
        assert_eq!(redacted, "port = 8080\npassword = ***\n");
        assert!(!redacted.contains("hunter2"));

        // The diff render of this side must show the redaction, never
        // the bytes.
        let state = State {
            destination: "/tmp/conf".into(),
            kind: Kind::File {
                content: content.clone(),
                user: "root".into(),
                group: "root".into(),
                mode: Mode(0o600),
            },
        };
        let rendered = render_state(&state, content.view());
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("password = ***"), "{rendered}");
        // The non-secret part stays fully visible and diffable — that is
        // the whole point of redacting per-secret rather than per-file.
        assert!(rendered.contains("port = 8080"), "{rendered}");
    }

    /// The claim the `askama` feature exists to make: an *ordinary*
    /// askama template with a `Secret<T>` field, handed to cindy with no
    /// annotation, marking, or `.reveal()`, redacts itself.
    ///
    /// Worth a test with the real derive rather than a hand-rolled
    /// `Render` impl, because what makes this work is askama emitting a
    /// `Display` call for `{{ password }}` — if it ever used `Debug`, or
    /// took a `&str` by some other route, the redaction would quietly
    /// stop happening.
    #[cfg(feature = "askama")]
    #[test]
    fn an_ordinary_askama_template_redacts_itself() {
        use crate::secret::{crypto, keychain};

        #[derive(askama::Template)]
        #[template(source = "port = {{ port }}\npassword = {{ password }}\n", ext = "txt")]
        struct AppConf<'a> {
            password: &'a crate::Secret<String>,
            port: u16,
        }

        let key = crypto::generate_vault_key();
        let payload = crate::secret::SealedPayload {
            value: postcard::to_allocvec("s3kr1t").unwrap(),
            source: "\"s3kr1t\"".to_owned(),
        };
        let ciphertext = crypto::seal(&key, &postcard::to_allocvec(&payload).unwrap()).unwrap();
        let mut chain = std::collections::HashMap::new();
        chain.insert("askama-vault".to_owned(), key);
        keychain::install_keys(chain);

        let pw: crate::Secret<String> = crate::Secret::sealed("askama-vault", ciphertext);
        let content = Content::render(&AppConf {
            password: &pw,
            port: 443,
        })
        .unwrap();

        assert_eq!(
            String::from_utf8(content.bytes.clone()).unwrap(),
            "port = 443\npassword = s3kr1t\n"
        );
        assert_eq!(
            content.redacted.as_deref(),
            Some("port = 443\npassword = ***\n")
        );

        // And the diff rendering — the only thing the operator sees.
        let rendered = render_state(
            &State {
                destination: "/etc/app.conf".into(),
                kind: Kind::File {
                    content: content.clone(),
                    user: "root".into(),
                    group: "root".into(),
                    mode: Mode(0o600),
                },
            },
            content.view(),
        );
        assert!(!rendered.contains("s3kr1t"), "{rendered}");
        assert!(rendered.contains("port = 443"), "{rendered}");
    }

    /// A template with no secrets in it must behave exactly as plain
    /// content does: no redacted rendering, full diff on both sides.
    #[test]
    fn a_plain_template_is_not_treated_as_sensitive() {
        struct Conf;
        impl crate::secret::Render for Conf {
            fn render(&self) -> crate::Result<String> {
                Ok("listen = 8080\n".to_owned())
            }
        }
        let content = Content::render(&Conf).unwrap();
        assert!(!content.is_sensitive());
        assert_eq!(content.bytes, b"listen = 8080\n");
    }

    /// Outside a render pass a `Secret` must not produce plaintext — the
    /// safety net for a playbook that builds content by hand instead of
    /// going through `template`. The result is a visibly wrong file, not
    /// a leaked diff.
    #[test]
    fn a_secret_outside_a_render_pass_renders_as_a_placeholder() {
        let s: crate::Secret<String> = crate::Secret::sealed("v", vec![1, 2, 3]);
        assert_eq!(format!("{s}"), "<secret vault=v>");
        let plain = crate::Secret::new("hunter2".to_owned());
        assert_eq!(format!("{plain}"), "<secret plain>");
        assert!(!format!("{plain}").contains("hunter2"));
    }

    /// The old side of a diff is only shown when no secret is in play.
    #[test]
    fn old_content_is_withheld_whenever_a_secret_is_involved() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("f");
        std::fs::write(&p, b"old contents here").unwrap();
        let old = capture_old_state(&p).unwrap();

        let owner = || ("root".to_owned(), "root".to_owned());
        let plain = Kind::File {
            content: Content::from("new".to_owned()),
            user: owner().0,
            group: owner().1,
            mode: Mode(0o644),
        };
        let sensitive = Kind::File {
            content: Content {
                bytes: b"pw = hunter2\n".to_vec(),
                redacted: Some("pw = ***\n".to_owned()),
            },
            user: owner().0,
            group: owner().1,
            mode: Mode(0o644),
        };

        // Plain replacement: the old bytes are shown, as always.
        let mut scratch = Vec::new();
        assert!(matches!(
            old_content_view(&old, &p, &plain, &mut scratch),
            ContentView::Bytes(b) if b == b"old contents here"
        ));

        // Secret-bearing replacement: withheld, because the old file is
        // very likely the previous render of the same template — and so
        // holds the previous secret.
        let mut scratch = Vec::new();
        assert!(matches!(
            old_content_view(&old, &p, &sensitive, &mut scratch),
            ContentView::Withheld(17)
        ));

        // No new rendering at all (deletion, or replacement by a
        // directory/symlink): withheld, since nothing says those bytes
        // are safe to print.
        let mut scratch = Vec::new();
        assert!(matches!(
            old_content_view(&old, &p, &Kind::Absent, &mut scratch),
            ContentView::Withheld(17)
        ));
        let mut scratch = Vec::new();
        assert!(matches!(
            old_content_view(
                &old,
                &p,
                &Kind::Directory {
                    user: owner().0,
                    group: owner().1,
                    mode: Mode(0o755)
                },
                &mut scratch
            ),
            ContentView::Withheld(17)
        ));
    }

    /// A panic inside a render must not leave the real-secret render mode
    /// set on the thread: the next redacted render on a reused tokio
    /// worker thread would otherwise emit plaintext into a diff.
    #[test]
    fn a_panicking_render_does_not_leak_real_mode_to_the_next_render() {
        struct Boom;
        impl crate::secret::Render for Boom {
            fn render(&self) -> crate::Result<String> {
                panic!("render blew up");
            }
        }
        let caught = std::panic::catch_unwind(|| Content::render(&Boom));
        assert!(caught.is_err(), "the panic must propagate");

        // Mode restored: a secret rendered now is redacted, not real.
        let s: crate::Secret<String> = crate::Secret::sealed("v", vec![1, 2, 3]);
        assert_eq!(format!("{s}"), "<secret vault=v>");
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

        let r =
            file_raw::inner(d.clone(), b"now a file".to_vec().into(), u, g, Mode(0o600)).unwrap();
        assert!(r.changed());
        assert!(d.is_file());
        assert_eq!(std::fs::read(&d).unwrap(), b"now a file");
    }
}
