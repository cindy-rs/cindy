//! Create an archive from a set of source paths on the remote machine.
//!
//! Supports tar (plain / gzip / xz / zstd), zip and 7z, all through
//! pure-Rust codecs. The output [`Format`] is inferred from the
//! destination's extension unless given explicitly.
//!
//! This module is **not idempotent**: archives embed timestamps and
//! ordering, so re-running always rewrites the destination and reports
//! [`Return::Changed`].

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::Context;

use super::Format;

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Files and/or directories to put into the archive. Directories
    /// are added recursively.
    pub sources: Vec<PathBuf>,
    /// Destination archive path.
    pub dest: PathBuf,
    /// Archive format. `None` ⇒ infer from `dest`'s extension.
    pub format: Option<Format>,
    /// Mode to set on the produced archive. `None` ⇒ `0o644`.
    pub mode: Option<super::path::Mode>,
}

/// The name a source path is stored under inside the archive: its final
/// component (so `/var/log/app` is archived as `app/…`), matching the
/// intuition of `tar -C parent -c name`.
fn entry_name(path: &Path) -> crate::Result<&Path> {
    path.file_name()
        .map(Path::new)
        .context(format!("source path {} has no file name", path.display()))
}

/// Append one source (file or directory, recursively) to a tar builder.
fn append_to_tar<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
) -> crate::Result<()> {
    let name = entry_name(source)?;
    let meta =
        std::fs::symlink_metadata(source).context(format!("Couldn't stat {}", source.display()))?;
    if meta.is_dir() {
        builder.append_dir_all(name, source).context(format!(
            "Couldn't add directory {} to archive",
            source.display()
        ))
    } else {
        builder
            .append_path_with_name(source, name)
            .context(format!("Couldn't add file {} to archive", source.display()))
    }
}

/// Build the tar byte stream for all sources in memory.
fn build_tar(sources: &[PathBuf]) -> crate::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    // Store symlinks *as* symlinks (like `tar(1)` without `-h`). The
    // crate's default is to follow them, which dereferences link farms,
    // fails outright on a dangling link, and recurses forever on a
    // link cycle.
    builder.follow_symlinks(false);
    for source in sources {
        append_to_tar(&mut builder, source)?;
    }
    builder
        .into_inner()
        .context("Couldn't finalise the tar stream")
}

/// Build a ZIP archive in memory.
fn build_zip(sources: &[PathBuf]) -> crate::Result<Vec<u8>> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options: zip::write::FileOptions<()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for source in sources {
        add_to_zip(&mut zip, source, entry_name(source)?, options)?;
    }
    let cursor = zip.finish().context("Couldn't finalise the zip archive")?;
    Ok(cursor.into_inner())
}

/// Recursively add a path to a ZIP under `name`.
fn add_to_zip<W: std::io::Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    source: &Path,
    name: &Path,
    options: zip::write::FileOptions<()>,
) -> crate::Result<()> {
    let name_str = name.to_string_lossy().into_owned();
    let meta =
        std::fs::symlink_metadata(source).context(format!("Couldn't stat {}", source.display()))?;

    if meta.is_symlink() {
        // Preserve symlinks as symlinks, matching the tar behaviour.
        let target = std::fs::read_link(source)
            .context(format!("Couldn't read symlink {}", source.display()))?;
        zip.add_symlink_from_path(name, &target, options)
            .context(format!("Couldn't add symlink {name_str} to zip"))?;
    } else if meta.is_dir() {
        zip.add_directory(format!("{name_str}/"), options)
            .context(format!("Couldn't add dir {name_str} to zip"))?;
        for entry in
            std::fs::read_dir(source).context(format!("Couldn't read dir {}", source.display()))?
        {
            let entry = entry.context("Couldn't read directory entry")?;
            add_to_zip(zip, &entry.path(), &name.join(entry.file_name()), options)?;
        }
    } else {
        // Preserve unix permissions like the tar writer does, so an
        // extracted zip tree keeps its exec bits.
        #[cfg(unix)]
        let options =
            options.unix_permissions(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
        zip.start_file(name_str.clone(), options)
            .context(format!("Couldn't start zip entry {name_str}"))?;
        let bytes = std::fs::read(source).context(format!("Couldn't read {}", source.display()))?;
        zip.write_all(&bytes)
            .context(format!("Couldn't write zip entry {name_str}"))?;
    }
    Ok(())
}

/// Recursively add a path to a 7z writer under `name` (base-name
/// relative, matching the tar/zip layout).
fn add_to_7z<W: std::io::Write + std::io::Seek>(
    writer: &mut sevenz_rust2::ArchiveWriter<W>,
    source: &Path,
    name: &Path,
) -> crate::Result<()> {
    let name_str = name.to_string_lossy().into_owned();
    let meta =
        std::fs::symlink_metadata(source).context(format!("Couldn't stat {}", source.display()))?;

    if meta.is_symlink() {
        // `sevenz-rust2` has no symlink-entry support; silently
        // dereferencing (or dying on a dangling link) would be worse
        // than saying so.
        crate::bail!(
            "{} is a symlink; the 7z writer can't represent symlinks — \
             use a tar or zip archive for trees containing them",
            source.display(),
        );
    }

    if meta.is_dir() {
        let entry = sevenz_rust2::ArchiveEntry::from_path(source, name_str);
        writer
            .push_archive_entry::<&[u8]>(entry, None)
            .context(format!("Couldn't add dir {} to 7z", source.display()))?;
        for entry in
            std::fs::read_dir(source).context(format!("Couldn't read dir {}", source.display()))?
        {
            let entry = entry.context("Couldn't read directory entry")?;
            add_to_7z(writer, &entry.path(), &name.join(entry.file_name()))?;
        }
    } else {
        let file =
            std::fs::File::open(source).context(format!("Couldn't open {}", source.display()))?;
        let entry = sevenz_rust2::ArchiveEntry::from_path(source, name_str);
        writer
            .push_archive_entry(entry, Some(file))
            .context(format!("Couldn't add file {} to 7z", source.display()))?;
    }
    Ok(())
}

/// Build a 7z archive in memory.
fn build_7z(sources: &[PathBuf]) -> crate::Result<Vec<u8>> {
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut writer =
        sevenz_rust2::ArchiveWriter::new(&mut buf).context("Couldn't create the 7z writer")?;
    for source in sources {
        add_to_7z(&mut writer, source, entry_name(source)?)?;
    }
    writer
        .finish()
        .context("Couldn't finalise the 7z archive")?;
    Ok(buf.into_inner())
}

/// Create an archive on the remote machine.
///
/// This is the full-control entry point taking a [`State`] (explicit
/// `format`, `mode`). For the common case, prefer [`create`], which infers
/// the format from the destination's extension.
#[crate::remote]
pub fn archive(state: State) -> crate::Result<super::Return> {
    apply(state)
}

/// Create an archive at `dest` from `sources`, inferring the format from
/// `dest`'s extension and using the OS-default mode. Orchestrator:
/// `create(sources, dest).await?`.
#[crate::action]
pub fn create(
    sources: impl Into<Vec<PathBuf>>,
    dest: impl Into<PathBuf>,
) -> crate::Result<super::Return> {
    apply(State {
        sources,
        dest,
        format: None,
        mode: None,
    })
}

/// Two sources with the same final path component would silently
/// overwrite each other's entries in the archive — the full paths
/// differ, so the collision is invisible until extraction yields one
/// tree where two were expected. Reject it up front, naming both
/// offenders.
fn check_unique_entry_names(sources: &[PathBuf]) -> crate::Result<()> {
    let mut seen: std::collections::HashMap<&Path, &Path> = std::collections::HashMap::new();
    for source in sources {
        if let Some(first) = seen.insert(entry_name(source)?, source) {
            crate::bail!(
                "sources {} and {} both archive as `{}` — an entry name is its \
                 source's final path component; archive them via a parent directory \
                 or rename one",
                first.display(),
                source.display(),
                entry_name(source)?.display()
            );
        }
    }
    Ok(())
}

fn apply(state: State) -> crate::Result<super::Return> {
    if state.sources.is_empty() {
        crate::bail!("`archive` needs at least one source path");
    }
    check_unique_entry_names(&state.sources)?;

    let format = match state.format {
        Some(f) => f,
        None => Format::from_path(&state.dest)?,
    };

    eprintln!(
        "archive {} source(s) -> {} ({:?})",
        state.sources.len(),
        state.dest.display(),
        format,
    );

    let bytes = match format {
        // Tar-based: build the tar stream, then hand it to the
        // `compress` module's codec (no codec logic lives here).
        // `None` means an uncompressed tar (== `Codec::Store`).
        Format::Tar(codec) => {
            let tar_bytes = build_tar(&state.sources)?;
            super::compress::compress::inner(tar_bytes, codec.unwrap_or(super::Codec::Store))?
        }
        // Container formats carry their own per-entry compression.
        Format::Zip => build_zip(&state.sources)?,
        Format::SevenZ => build_7z(&state.sources)?,
    };

    // Check mode: building the bytes is pure computation, but whether
    // the destination would change is `path::file`'s comparison, which
    // needs the bytes. Report the conservative `Changed`.
    if crate::dry_run() {
        return Ok(super::Return::Changed);
    }

    // Materialise the archive via the `path` module: it owns the
    // on-disk state-transition logic (replacing an existing file, dir,
    // or symlink at `dest`) and emits the diff.
    // `path` requires a total owner/mode; archive only carries an
    // optional mode, so default the owner to the worker's identity and
    // an unspecified mode to `0o644`.
    let (user, group) = super::current_owner_names();
    super::path::file_raw::inner(
        state.dest,
        bytes,
        user,
        group,
        state.mode.unwrap_or(super::path::Mode(0o644)),
    )?;
    Ok(super::Return::Changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srcs(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn colliding_entry_names_are_rejected_up_front() {
        // The exact scenario from the plan: different directories,
        // same basename — the second entry would silently clobber the
        // first inside the archive.
        let err = check_unique_entry_names(&srcs(&["/a/conf", "/b/conf"])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/a/conf"), "{msg}");
        assert!(msg.contains("/b/conf"), "{msg}");
        assert!(msg.contains("`conf`"), "{msg}");

        assert!(check_unique_entry_names(&srcs(&["/a/conf", "/a/conf.d"])).is_ok());
        assert!(check_unique_entry_names(&srcs(&["/a/conf", "/b/other"])).is_ok());
        assert!(check_unique_entry_names(&srcs(&["/only/one"])).is_ok());
    }
}
