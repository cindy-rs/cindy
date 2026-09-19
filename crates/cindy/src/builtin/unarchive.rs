//! Extract an archive into a directory on the remote machine.
//!
//! Supports tar (plain / gzip / xz / zstd), zip and 7z, all through
//! pure-Rust codecs. The source [`Format`] is inferred from the
//! archive's extension unless given explicitly.
//!
//! Extraction is **not** strictly idempotent: it always unpacks and
//! reports [`Return::Changed`] (it can't cheaply prove the destination
//! already holds an identical tree).

use std::path::{Path, PathBuf};

use crate::Context;

use super::Format;

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Archive file to extract.
    pub src: PathBuf,
    /// Directory to extract into (created if missing).
    pub dest: PathBuf,
    /// Archive format. `None` ⇒ infer from `src`'s extension.
    pub format: Option<Format>,
    /// Ceiling on the *decompressed* size of a compressed tar
    /// (`*.tar.gz` etc.), rejected with an error naming this knob.
    /// Bounds the worker's memory against a crafted archive —
    /// decompression is multiplication, and the worker holds the
    /// expanded stream in memory. `None` ⇒
    /// [`decompress::DEFAULT_MAX_BYTES`](super::decompress::DEFAULT_MAX_BYTES),
    /// the same default `fetch` applies to what it stages.
    pub max_bytes: Option<u64>,
}

/// How an archive entry compares to what's already at the destination.
///
/// The comparison is deliberately cheap — existence and (for files)
/// byte size — rather than a full content hash. It's a human-facing
/// summary, not a correctness gate, so a same-size-different-content
/// edit reading as `Unchanged` is an acceptable trade for not hashing
/// every entry of a large archive.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryStatus {
    /// No file/dir exists at the destination path yet.
    Added,
    /// A file exists but its size differs from the archived entry.
    Changed,
    /// Already present at the same size (or an existing directory).
    Unchanged,
}

/// One archive entry's metadata, format-agnostic, used for the summary.
struct Entry {
    /// Path relative to the archive root.
    path: PathBuf,
    is_dir: bool,
    /// Uncompressed size (meaningless for directories).
    size: u64,
}

impl Entry {
    /// Classify this entry against the on-disk destination tree.
    fn status(&self, dest: &Path) -> EntryStatus {
        let target = dest.join(&self.path);
        match std::fs::symlink_metadata(&target) {
            Err(_) => EntryStatus::Added,
            Ok(_) if self.is_dir => EntryStatus::Unchanged,
            Ok(meta) if meta.is_file() && meta.len() == self.size => EntryStatus::Unchanged,
            Ok(_) => EntryStatus::Changed,
        }
    }
}

/// Maximum number of changed/added entries to name individually before
/// collapsing the rest into a "… and N more" line, so extracting a
/// huge archive doesn't flood stderr.
const SUMMARY_LIST_CAP: usize = 20;

/// Render a compact, `path`-style summary of what the extraction will
/// change at `dest`, to stderr (informational; ignore write errors).
///
/// Lines are prefixed `+` (added), `~` (changed) and counted; unchanged
/// entries are tallied but not listed. This is the archive-appropriate
/// granularity: per-entry visibility without a full `path` struct diff
/// for every one of potentially thousands of files.
fn render_summary(entries: &[Entry], dest: &Path) {
    let mut added = 0usize;
    let mut changed = 0usize;
    let mut unchanged = 0usize;
    let mut listed = 0usize;

    for entry in entries {
        let (mark, count) = match entry.status(dest) {
            EntryStatus::Added => ('+', &mut added),
            EntryStatus::Changed => ('~', &mut changed),
            EntryStatus::Unchanged => {
                unchanged += 1;
                continue;
            }
        };
        *count += 1;
        if listed < SUMMARY_LIST_CAP {
            eprintln!("  {mark} {}", entry.path.display());
            listed += 1;
        }
    }

    let extra = added + changed - listed;
    if extra > 0 {
        eprintln!("  … and {extra} more");
    }
    eprintln!("  {added} added, {changed} changed, {unchanged} unchanged");
}

/// List a tar stream's entries (paths + sizes + dir flags) without
/// extracting them.
fn list_tar(tar_bytes: &[u8]) -> crate::Result<Vec<Entry>> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut out = Vec::new();
    for entry in archive.entries().context("Couldn't read tar entries")? {
        let entry = entry.context("Couldn't read a tar entry")?;
        let path = entry.path().context("tar entry has no path")?.into_owned();
        let is_dir = entry.header().entry_type().is_dir();
        out.push(Entry {
            path,
            is_dir,
            size: entry.size(),
        });
    }
    Ok(out)
}

/// List a ZIP archive's entries without extracting them.
fn list_zip(src: &Path) -> crate::Result<Vec<Entry>> {
    let file = std::fs::File::open(src).context(format!("Couldn't open {}", src.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).context(format!("Couldn't open zip {}", src.display()))?;
    let mut out = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let f = archive.by_index(i).context("Couldn't read a zip entry")?;
        out.push(Entry {
            path: PathBuf::from(f.name()),
            is_dir: f.is_dir(),
            size: f.size(),
        });
    }
    Ok(out)
}

/// List a 7z archive's entries (header only, no decompression).
fn list_7z(src: &Path) -> crate::Result<Vec<Entry>> {
    let archive = sevenz_rust2::Archive::open(src)
        .map_err(|e| anyhow_serde::Error::msg(format!("Couldn't read 7z header: {e}")))?;
    Ok(archive
        .files
        .iter()
        .map(|f| Entry {
            path: PathBuf::from(f.name()),
            is_dir: f.is_directory(),
            size: f.size(),
        })
        .collect())
}

/// Unpack a raw tar byte stream into `dest`.
fn extract_tar(tar_bytes: &[u8], dest: &Path) -> crate::Result<()> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    archive
        .unpack(dest)
        .context(format!("Couldn't unpack tar into {}", dest.display()))
}

/// Extract a ZIP archive into `dest`.
fn extract_zip(src: &Path, dest: &Path) -> crate::Result<()> {
    let file = std::fs::File::open(src).context(format!("Couldn't open {}", src.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).context(format!("Couldn't open zip {}", src.display()))?;
    archive
        .extract(dest)
        .context(format!("Couldn't extract zip into {}", dest.display()))
}

/// Extract a 7z archive into `dest`.
///
/// `sevenz_rust2::decompress_file` joins each entry name onto `dest`
/// with no sanitisation, so a crafted archive with `../`-laden or
/// absolute entry names could write anywhere the worker (often root)
/// can (zip-slip). The tar and zip crates guard this themselves; here
/// we enforce the same rule by hand: every component of the entry name
/// must be a normal path segment.
fn extract_7z(src: &Path, dest: &Path) -> crate::Result<()> {
    sevenz_rust2::decompress_file_with_extract_fn(src, dest, |entry, reader, _| {
        let rel = Path::new(entry.name());
        let safe = rel.components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        });
        if !safe {
            return Err(sevenz_rust2::Error::Other(
                format!(
                    "7z entry {:?} has an unsafe path (absolute or contains `..`)",
                    entry.name()
                )
                .into(),
            ));
        }
        sevenz_rust2::default_entry_extract_fn(entry, reader, &dest.join(rel))
    })
    .context(format!(
        "Couldn't extract 7z {} into {}",
        src.display(),
        dest.display()
    ))
}

/// Extract an archive into a directory on the remote machine.
///
/// This is the full-control entry point taking a [`State`] (explicit
/// `format`). For the common case, prefer [`extract`], which infers the
/// format from the source's extension.
#[crate::remote]
pub fn unarchive(state: State) -> crate::Result<super::Return> {
    apply(state)
}

/// Extract the archive at `src` into the directory `dest` (created if
/// missing), inferring the format from `src`'s extension. Orchestrator:
/// `extract(src, dest).await?`.
#[crate::action]
pub fn extract(src: impl Into<PathBuf>, dest: impl Into<PathBuf>) -> crate::Result<super::Return> {
    apply(State {
        src,
        dest,
        format: None,
        max_bytes: None,
    })
}

/// Establish the destination directory. An *existing* directory is
/// left completely alone — the caller said "extract here", not "and
/// also chown/chmod the directory", so rewriting its owner/mode to
/// our defaults would be a destructive side effect nobody asked for.
/// Only when `dest` is missing (or a stale file/symlink is in the
/// way) do we go through the `path` module, which handles the
/// transition and emits the diff, creating the dir as the worker's
/// identity at a conventional `0o755`.
fn establish_dest(dest: &Path) -> crate::Result<()> {
    match std::fs::symlink_metadata(dest) {
        Ok(meta) if meta.is_dir() => {}
        _ => {
            let (user, group) = super::current_owner_names();
            super::path::directory_raw::inner(
                dest.to_path_buf(),
                user,
                group,
                super::path::Mode(0o755),
            )?;
        }
    }
    Ok(())
}

fn apply(state: State) -> crate::Result<super::Return> {
    let format = match state.format {
        Some(f) => f,
        None => Format::from_path(&state.src)?,
    };

    eprintln!(
        "unarchive {} -> {} ({:?})",
        state.src.display(),
        state.dest.display(),
        format,
    );

    // Read and decode the archive *before* touching the destination, so
    // an unreadable or corrupt source errors without leaving a
    // half-prepared destination directory behind.
    match format {
        Format::Tar(codec) => {
            let raw = std::fs::read(&state.src)
                .context(format!("Couldn't read {}", state.src.display()))?;
            let tar_bytes = super::decompress::bounded(
                raw,
                codec.unwrap_or(super::Codec::Store),
                state
                    .max_bytes
                    .unwrap_or(super::decompress::DEFAULT_MAX_BYTES),
            )?;
            let entries = list_tar(&tar_bytes)?;
            if crate::dry_run() {
                render_summary(&entries, &state.dest);
                return Ok(super::Return::Changed);
            }
            establish_dest(&state.dest)?;
            render_summary(&entries, &state.dest);
            extract_tar(&tar_bytes, &state.dest)?;
        }
        Format::Zip => {
            let entries = list_zip(&state.src)?;
            if crate::dry_run() {
                render_summary(&entries, &state.dest);
                return Ok(super::Return::Changed);
            }
            establish_dest(&state.dest)?;
            render_summary(&entries, &state.dest);
            extract_zip(&state.src, &state.dest)?;
        }
        Format::SevenZ => {
            let entries = list_7z(&state.src)?;
            if crate::dry_run() {
                render_summary(&entries, &state.dest);
                return Ok(super::Return::Changed);
            }
            establish_dest(&state.dest)?;
            render_summary(&entries, &state.dest);
            extract_7z(&state.src, &state.dest)?;
        }
    }

    Ok(super::Return::Changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::{Format, archive};

    /// Lay out a small source tree, archive it, extract it, and assert
    /// the bytes survive the round-trip — for every supported format.
    fn round_trip(format: Format, ext: &str) {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("payload");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello world").unwrap();
        std::fs::write(src.join("nested/b.bin"), [0u8, 1, 2, 3, 255]).unwrap();

        let archive_path = tmp.path().join(format!("out{ext}"));
        let changed = archive::archive::inner(archive::State {
            sources: vec![src.clone()],
            dest: archive_path.clone(),
            format: Some(format),
            // The `path` module (which archive delegates the write to)
            // creates files `0o000` by default; we need to read this
            // back via unarchive, so request a readable mode.
            mode: Some(crate::builtin::path::Mode(0o644)),
        })
        .unwrap_or_else(|e| panic!("archive {format:?} failed: {e}"));
        assert!(changed.changed(), "archive should report Changed");
        assert!(archive_path.exists(), "archive file should exist");

        let out = tmp.path().join("extracted");
        unarchive::inner(State {
            src: archive_path,
            dest: out.clone(),
            format: Some(format),
            max_bytes: None,
        })
        .unwrap_or_else(|e| panic!("unarchive {format:?} failed: {e}"));

        let a = std::fs::read(out.join("payload/a.txt"))
            .unwrap_or_else(|e| panic!("missing a.txt for {format:?}: {e}"));
        assert_eq!(a, b"hello world", "a.txt content mismatch for {format:?}");
        let b = std::fs::read(out.join("payload/nested/b.bin"))
            .unwrap_or_else(|e| panic!("missing b.bin for {format:?}: {e}"));
        assert_eq!(
            b,
            [0u8, 1, 2, 3, 255],
            "b.bin content mismatch for {format:?}"
        );
    }

    #[test]
    fn round_trip_tar() {
        round_trip(Format::Tar(None), ".tar");
    }

    #[test]
    fn round_trip_tar_gz() {
        round_trip(Format::Tar(Some(crate::builtin::Codec::Gzip)), ".tar.gz");
    }

    #[test]
    fn round_trip_tar_xz() {
        round_trip(Format::Tar(Some(crate::builtin::Codec::Xz)), ".tar.xz");
    }

    #[test]
    fn round_trip_tar_zst() {
        round_trip(Format::Tar(Some(crate::builtin::Codec::Zstd)), ".tar.zst");
    }

    #[test]
    fn round_trip_zip() {
        round_trip(Format::Zip, ".zip");
    }

    #[test]
    fn round_trip_7z() {
        round_trip(Format::SevenZ, ".7z");
    }

    #[test]
    fn entry_status_classification() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path();
        std::fs::write(dest.join("same.txt"), b"1234").unwrap();
        std::fs::write(dest.join("resized.txt"), b"12").unwrap();
        std::fs::create_dir(dest.join("adir")).unwrap();

        // Absent at destination → Added.
        let added = Entry {
            path: "new.txt".into(),
            is_dir: false,
            size: 9,
        };
        assert!(matches!(added.status(dest), EntryStatus::Added));

        // Present, same size → Unchanged.
        let same = Entry {
            path: "same.txt".into(),
            is_dir: false,
            size: 4,
        };
        assert!(matches!(same.status(dest), EntryStatus::Unchanged));

        // Present, different size → Changed.
        let resized = Entry {
            path: "resized.txt".into(),
            is_dir: false,
            size: 99,
        };
        assert!(matches!(resized.status(dest), EntryStatus::Changed));

        // Existing directory → Unchanged.
        let adir = Entry {
            path: "adir".into(),
            is_dir: true,
            size: 0,
        };
        assert!(matches!(adir.status(dest), EntryStatus::Unchanged));
    }

    /// Symlinks survive a tar/zip round-trip as symlinks (not
    /// dereferenced copies), and dangling links don't fail the archive.
    fn symlink_round_trip(format: Format, ext: &str) {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("payload");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("real.txt"), b"content").unwrap();
        std::os::unix::fs::symlink("real.txt", src.join("alias")).unwrap();
        std::os::unix::fs::symlink("nowhere", src.join("dangling")).unwrap();

        let archive_path = tmp.path().join(format!("out{ext}"));
        archive::archive::inner(archive::State {
            sources: vec![src.clone()],
            dest: archive_path.clone(),
            format: Some(format),
            mode: Some(crate::builtin::path::Mode(0o644)),
        })
        .unwrap_or_else(|e| panic!("archive {format:?} failed: {e}"));

        let out = tmp.path().join("extracted");
        unarchive::inner(State {
            src: archive_path,
            dest: out.clone(),
            format: Some(format),
            max_bytes: None,
        })
        .unwrap_or_else(|e| panic!("unarchive {format:?} failed: {e}"));

        let alias = out.join("payload/alias");
        let meta = std::fs::symlink_metadata(&alias)
            .unwrap_or_else(|e| panic!("alias missing for {format:?}: {e}"));
        assert!(
            meta.file_type().is_symlink(),
            "alias should still be a symlink for {format:?}"
        );
        assert_eq!(
            std::fs::read_link(&alias).unwrap(),
            std::path::PathBuf::from("real.txt"),
        );
        // And the dangling link came along without an error.
        assert!(
            std::fs::symlink_metadata(out.join("payload/dangling"))
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false),
            "dangling symlink should be preserved for {format:?}"
        );
    }

    #[test]
    fn symlinks_preserved_tar_gz() {
        symlink_round_trip(Format::Tar(Some(crate::builtin::Codec::Gzip)), ".tar.gz");
    }

    #[test]
    fn symlinks_preserved_zip() {
        symlink_round_trip(Format::Zip, ".zip");
    }

    #[test]
    fn seven_z_rejects_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("payload");
        std::fs::create_dir_all(&src).unwrap();
        std::os::unix::fs::symlink("x", src.join("link")).unwrap();

        let err = archive::archive::inner(archive::State {
            sources: vec![src],
            dest: tmp.path().join("out.7z"),
            format: Some(Format::SevenZ),
            mode: None,
        })
        .expect_err("7z archive of a symlink should fail");
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    /// An existing destination directory keeps its mode: extraction only
    /// creates the directory when missing, never rewrites its attributes.
    #[test]
    fn existing_dest_dir_attrs_untouched() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("payload");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"x").unwrap();
        let archive_path = tmp.path().join("out.tar");
        archive::archive::inner(archive::State {
            sources: vec![src],
            dest: archive_path.clone(),
            format: None,
            mode: Some(crate::builtin::path::Mode(0o644)),
        })
        .unwrap();

        let dest = tmp.path().join("existing");
        std::fs::create_dir(&dest).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o750)).unwrap();

        unarchive::inner(State {
            src: archive_path,
            dest: dest.clone(),
            format: None,
            max_bytes: None,
        })
        .unwrap();

        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o750, "existing dest dir mode must be preserved");
    }

    #[test]
    fn format_inference() {
        use crate::builtin::Codec;
        let cases = [
            ("x.tar", Format::Tar(None)),
            ("x.tar.gz", Format::Tar(Some(Codec::Gzip))),
            ("x.tgz", Format::Tar(Some(Codec::Gzip))),
            ("x.tar.xz", Format::Tar(Some(Codec::Xz))),
            ("x.tar.zst", Format::Tar(Some(Codec::Zstd))),
            ("x.zip", Format::Zip),
            ("x.7z", Format::SevenZ),
        ];
        for (name, want) in cases {
            assert_eq!(Format::from_path(std::path::Path::new(name)).unwrap(), want);
        }
        assert!(Format::from_path(std::path::Path::new("x.rar")).is_err());
    }
}
