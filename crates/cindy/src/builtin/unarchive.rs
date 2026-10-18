//! Extract an archive into a directory on the remote machine.
//!
//! Not idempotent: it can't cheaply prove the destination already holds
//! the same tree, so it always extracts and reports `Changed` — with a
//! per-entry summary of what is new or different.

use std::io::BufReader;
use std::path::{Path, PathBuf};

use crate::Context;

use super::decompress::{BoundedReader, LimitExceeded};
use super::{Codec, Format};

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    pub src: PathBuf,
    /// Created if missing; an existing directory's own owner and mode
    /// are left alone.
    pub dest: PathBuf,
    /// `None` ⇒ inferred from `src`'s extension.
    pub format: Option<Format>,
    /// Ceiling on a compressed tar's expanded size. `None` ⇒ 4 GiB.
    pub max_bytes: Option<u64>,
}

/// The full-control entry point; [`extract`] infers the format.
#[crate::remote]
pub fn unarchive(state: State) -> crate::Result<super::Return> {
    apply(state)
}

#[crate::action]
pub fn extract(src: impl Into<PathBuf>, dest: impl Into<PathBuf>) -> crate::Result<super::Return> {
    apply(State {
        src,
        dest,
        format: None,
        max_bytes: None,
    })
}

fn apply(state: State) -> crate::Result<super::Return> {
    let format = match state.format {
        Some(f) => f,
        None => Format::from_path(&state.src)?,
    };
    let _ = crate::diff::note(
        &mut std::io::stderr().lock(),
        &format!(
            "~ {} <- {} ({format:?})",
            state.dest.display(),
            state.src.display()
        ),
    );

    let archive = Archive::open(&state, format)?;
    // Listing first also trips the decompression ceiling before the
    // destination is touched.
    match archive.list()? {
        Some(entries) => render_summary(&entries, &state.dest),
        None => eprintln!("  (entries not listed: listing would decompress to disk under --check)"),
    }
    if crate::dry_run() {
        return Ok(super::Return::Changed);
    }
    if !std::fs::symlink_metadata(&state.dest).is_ok_and(|md| md.is_dir()) {
        let super::path::Owner { user, group } = super::path::Owner::current();
        super::path::directory_raw::inner(
            state.dest.clone(),
            user,
            group,
            super::path::Mode(0o755),
        )?;
    }
    archive.extract(&state.dest)?;
    Ok(super::Return::Changed)
}

enum Archive<'a> {
    Tar(Tar<'a>),
    Zip(&'a Path),
    SevenZ(&'a Path),
}

struct Tar<'a> {
    src: &'a Path,
    codec: Codec,
    max_bytes: u64,
    /// xz and zstd are expanded once into here: they have no decoder
    /// usable as a `Read`, and listing and extracting each need a pass.
    /// Never created under `--check`.
    spill: Option<tempfile::NamedTempFile>,
}

impl Tar<'_> {
    /// `None` when that would take a spill `--check` didn't create.
    fn stream(&self) -> crate::Result<Option<Box<dyn std::io::Read + '_>>> {
        Ok(Some(match (self.codec, &self.spill) {
            (Codec::Store, _) => Box::new(BufReader::new(open(self.src)?)),
            (Codec::Gzip, _) => Box::new(BoundedReader::new(
                flate2::read::MultiGzDecoder::new(BufReader::new(open(self.src)?)),
                Codec::Gzip,
                self.max_bytes,
            )),
            (Codec::Xz | Codec::Zstd, Some(spill)) => Box::new(open(spill.path())?),
            (Codec::Xz | Codec::Zstd, None) => return Ok(None),
        }))
    }
}

impl<'a> Archive<'a> {
    fn open(state: &'a State, format: Format) -> crate::Result<Self> {
        let src = state.src.as_path();
        let codec = match format {
            Format::Zip => return Ok(Archive::Zip(src)),
            Format::SevenZ => return Ok(Archive::SevenZ(src)),
            Format::Tar(codec) => codec.unwrap_or(Codec::Store),
        };
        let max_bytes = state.max_bytes.unwrap_or(super::DEFAULT_MAX_BYTES);
        let spill = if matches!(codec, Codec::Xz | Codec::Zstd) && !crate::dry_run() {
            let parent = state.dest.parent().filter(|p| p.is_dir());
            let mut spill = super::path::spill_in(parent.unwrap_or(&std::env::temp_dir()))?;
            super::decompress::decompress_into(
                codec,
                &mut BufReader::new(open(src)?),
                max_bytes,
                spill.as_file_mut(),
            )?;
            Some(spill)
        } else {
            None
        };
        Ok(Archive::Tar(Tar {
            src,
            codec,
            max_bytes,
            spill,
        }))
    }

    /// `None` when listing would mean decompressing to disk under
    /// `--check`.
    fn list(&self) -> crate::Result<Option<Vec<Entry>>> {
        match self {
            Archive::Tar(tar) => {
                let Some(stream) = tar.stream()? else {
                    return Ok(None);
                };
                let mut tar = tar::Archive::new(stream);
                let mut out = Vec::new();
                for entry in tar.entries().context("Couldn't read tar entries")? {
                    let entry = entry.map_err(|e| tar_error(e, "Couldn't read a tar entry"))?;
                    out.push(Entry {
                        path: entry.path().context("tar entry has no path")?.into_owned(),
                        is_dir: entry.header().entry_type().is_dir(),
                        size: entry.size(),
                    });
                }
                Ok(Some(out))
            }
            Archive::Zip(src) => {
                let mut zip = open_zip(src)?;
                (0..zip.len())
                    .map(|i| {
                        let f = zip.by_index(i).context("Couldn't read a zip entry")?;
                        let name = f.name().context("Couldn't decode a zip entry's name")?;
                        Ok(Entry {
                            path: PathBuf::from(&*name),
                            is_dir: f.is_dir(),
                            size: f.size(),
                        })
                    })
                    .collect::<crate::Result<_>>()
                    .map(Some)
            }
            Archive::SevenZ(src) => {
                let archive = sevenz_rust2::Archive::open(src)
                    .map_err(|e| crate::anyhow!("Couldn't read 7z header: {e}"))?;
                Ok(Some(
                    archive
                        .files
                        .iter()
                        .map(|f| Entry {
                            path: PathBuf::from(f.name()),
                            is_dir: f.is_directory(),
                            size: f.size(),
                        })
                        .collect(),
                ))
            }
        }
    }

    fn extract(&self, dest: &Path) -> crate::Result<()> {
        match self {
            Archive::Tar(tar) => {
                let stream = tar
                    .stream()?
                    .context("tar extraction without its spill file")?;
                tar::Archive::new(stream).unpack(dest).map_err(|e| {
                    tar_error(e, format!("Couldn't unpack tar into {}", dest.display()))
                })
            }
            Archive::Zip(src) => open_zip(src)?
                .extract(dest)
                .context(format!("Couldn't extract zip into {}", dest.display())),
            Archive::SevenZ(src) => extract_7z(src, dest),
        }
    }
}

fn open(path: &Path) -> crate::Result<std::fs::File> {
    std::fs::File::open(path).context(format!("Couldn't open {}", path.display()))
}

fn open_zip(src: &Path) -> crate::Result<zip::ZipArchive<std::fs::File>> {
    zip::ZipArchive::new(open(src)?).context(format!("Couldn't open zip {}", src.display()))
}

/// The decompression ceiling, if tar's error wraps it, rather than
/// tar's own message: the knob's name is what the operator needs.
fn tar_error(
    e: std::io::Error,
    what: impl std::fmt::Display + Send + Sync + 'static,
) -> crate::Error {
    match LimitExceeded::find(&e) {
        Some(limit) => limit.into(),
        None => crate::Error::from(e).context(what),
    }
}

/// `sevenz_rust2` joins entry names onto `dest` unchecked, so a `../`
/// or absolute name could write anywhere the worker (often root) can;
/// tar and zip guard this themselves.
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

struct Entry {
    /// Relative to the archive root.
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

/// Existence and size only — a summary for a human, not a correctness
/// gate, so not worth hashing every entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EntryStatus {
    Added,
    Changed,
    Unchanged,
}

impl Entry {
    fn status(&self, dest: &Path) -> EntryStatus {
        match std::fs::symlink_metadata(dest.join(&self.path)) {
            Err(_) => EntryStatus::Added,
            Ok(_) if self.is_dir => EntryStatus::Unchanged,
            Ok(meta) if meta.is_file() && meta.len() == self.size => EntryStatus::Unchanged,
            Ok(_) => EntryStatus::Changed,
        }
    }
}

/// Entries listed individually before the rest collapse into a count.
const SUMMARY_LIST_CAP: usize = 20;

fn render_summary(entries: &[Entry], dest: &Path) {
    let (mut added, mut changed, mut unchanged) = (0usize, 0usize, 0usize);
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
        if added + changed <= SUMMARY_LIST_CAP {
            eprintln!("  {mark} {}", entry.path.display());
        }
    }
    if let Some(extra) = (added + changed)
        .checked_sub(SUMMARY_LIST_CAP)
        .filter(|&n| n > 0)
    {
        eprintln!("  … and {extra} more");
    }
    eprintln!("  {added} added, {changed} changed, {unchanged} unchanged");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::{Format, archive};

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

        let added = Entry {
            path: "new.txt".into(),
            is_dir: false,
            size: 9,
        };
        assert_eq!(added.status(dest), EntryStatus::Added);

        let same = Entry {
            path: "same.txt".into(),
            is_dir: false,
            size: 4,
        };
        assert_eq!(same.status(dest), EntryStatus::Unchanged);

        let resized = Entry {
            path: "resized.txt".into(),
            is_dir: false,
            size: 99,
        };
        assert_eq!(resized.status(dest), EntryStatus::Changed);

        let adir = Entry {
            path: "adir".into(),
            is_dir: true,
            size: 0,
        };
        assert_eq!(adir.status(dest), EntryStatus::Unchanged);
    }

    /// Stored as symlinks, not dereferenced; dangling ones too.
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
    fn streaming_ceiling_is_a_named_error() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("payload");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("big.bin"), [0u8; 256 * 1024]).unwrap();

        let archive_path = tmp.path().join("out.tar.gz");
        archive::archive::inner(archive::State {
            sources: vec![src],
            dest: archive_path.clone(),
            format: Some(Format::Tar(Some(crate::builtin::Codec::Gzip))),
            mode: Some(crate::builtin::path::Mode(0o644)),
        })
        .unwrap();

        let out = tmp.path().join("extracted");
        let err = unarchive::inner(State {
            src: archive_path,
            dest: out.clone(),
            format: Some(Format::Tar(Some(crate::builtin::Codec::Gzip))),
            max_bytes: Some(64 * 1024),
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("gzip"), "{msg}");
        assert!(msg.contains("max_bytes"), "{msg}");
        assert!(!msg.contains("store"), "{msg}");

        assert!(
            !out.exists(),
            "an over-limit extraction must not create the destination"
        );
    }

    #[test]
    fn streaming_ceiling_bites_through_the_spill_path() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("payload");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("big.bin"), [0u8; 256 * 1024]).unwrap();

        let archive_path = tmp.path().join("out.tar.xz");
        archive::archive::inner(archive::State {
            sources: vec![src],
            dest: archive_path.clone(),
            format: Some(Format::Tar(Some(crate::builtin::Codec::Xz))),
            mode: Some(crate::builtin::path::Mode(0o644)),
        })
        .unwrap();

        let err = unarchive::inner(State {
            src: archive_path,
            dest: tmp.path().join("extracted"),
            format: Some(Format::Tar(Some(crate::builtin::Codec::Xz))),
            max_bytes: Some(64 * 1024),
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("xz"), "{msg}");
        assert!(msg.contains("max_bytes"), "{msg}");
    }

    #[test]
    fn archive_replaces_a_directory_at_the_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("payload");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"x").unwrap();

        let dest = tmp.path().join("out.tar");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("stale.txt"), b"stale").unwrap();

        archive::archive::inner(archive::State {
            sources: vec![src],
            dest: dest.clone(),
            format: Some(Format::Tar(None)),
            mode: Some(crate::builtin::path::Mode(0o644)),
        })
        .unwrap();

        let meta = std::fs::symlink_metadata(&dest).unwrap();
        assert!(meta.is_file(), "dest must now be the archive file");
        assert!(
            !dest.join("stale.txt").exists(),
            "the replaced directory's contents must be gone"
        );
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
