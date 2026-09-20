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

/// Build the tar byte stream for all sources straight into the staged
/// destination, compressed as it goes.
///
/// `Store` and `Gzip` stream end-to-end: the tar writer's output goes
/// directly through the codec encoder into the staged file. `Xz` and
/// `Zstd` have no write-side streaming encoder in their pure-Rust
/// implementations (see `compress_into`), so the raw tar spills to an
/// intermediate temp file in the destination's directory and is
/// compressed from there — memory stays flat either way, only the
/// tar's own buffers resident.
fn build_tar_into(
    codec: super::Codec,
    staged: &mut super::path::StagedWriter,
    dest_parent: &Path,
    sources: &[PathBuf],
) -> crate::Result<()> {
    // Store symlinks *as* symlinks (like `tar(1)` without `-h`). The
    // crate's default is to follow them, which dereferences link farms,
    // fails outright on a dangling link, and recurses forever on a
    // link cycle. Returns the builder's inner writer so the caller can
    // finish an encoder wrapped around it.
    fn fill<W: std::io::Write>(
        mut builder: tar::Builder<W>,
        sources: &[PathBuf],
    ) -> crate::Result<W> {
        builder.follow_symlinks(false);
        for source in sources {
            append_to_tar(&mut builder, source)?;
        }
        builder
            .into_inner()
            .context("Couldn't finalise the tar stream")
    }

    match codec {
        super::Codec::Store => {
            fill(tar::Builder::new(staged.as_file_mut()), sources)?;
        }
        super::Codec::Gzip => {
            let enc =
                flate2::write::GzEncoder::new(staged.as_file_mut(), flate2::Compression::default());
            fill(tar::Builder::new(enc), sources)?
                .finish()
                .context("gzip finalisation failed")?;
        }
        super::Codec::Xz | super::Codec::Zstd => {
            let mut spill = super::path::spill_in(dest_parent)?;
            fill(tar::Builder::new(spill.as_file_mut()), sources)?;
            let mut spill_file =
                std::fs::File::open(spill.path()).context("Couldn't reopen the tar spill file")?;
            super::compress::compress_into(codec, &mut spill_file, staged.as_file_mut())?;
        }
    }
    Ok(())
}

/// Build a ZIP archive straight into the staged destination.
fn build_zip_into(
    staged: &mut super::path::StagedWriter,
    sources: &[PathBuf],
) -> crate::Result<()> {
    let mut zip = zip::ZipWriter::new(staged.as_file_mut());
    let options: zip::write::FileOptions<()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for source in sources {
        add_to_zip(&mut zip, source, entry_name(source)?, options)?;
    }
    zip.finish().context("Couldn't finalise the zip archive")?;
    Ok(())
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

/// Build a 7z archive straight into the staged destination.
fn build_7z_into(staged: &mut super::path::StagedWriter, sources: &[PathBuf]) -> crate::Result<()> {
    let mut writer = sevenz_rust2::ArchiveWriter::new(staged.as_file_mut())
        .context("Couldn't create the 7z writer")?;
    for source in sources {
        add_to_7z(&mut writer, source, entry_name(source)?)?;
    }
    writer
        .finish()
        .context("Couldn't finalise the 7z archive")?;
    Ok(())
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

    let _ = crate::diff::note(
        &mut std::io::stderr().lock(),
        &format!(
            "~ {} ({format:?}, {} source(s))",
            state.dest.display(),
            state.sources.len(),
        ),
    );

    // Check mode: archives embed timestamps and ordering, so the
    // destination never converges and `Changed` is always the honest
    // verdict. Say so *without* building anything — a check run must
    // not even stage a temp file.
    if crate::dry_run() {
        return Ok(super::Return::Changed);
    }

    // Materialise the archive by streaming it into a staged temp file
    // next to the destination and publishing via the `path` module's
    // rename — the same shape `fetch` got. The whole build is
    // O(buffers) in memory regardless of tree size; the old
    // build-to-`Vec` path held the entire archive (and, for tar, the
    // uncompressed stream *and* the compressed output) in RAM.
    // `path` requires a total owner/mode; archive only carries an
    // optional mode, so default the owner to the worker's identity and
    // an unspecified mode to `0o644`.
    let (user, group) = super::current_owner_names();
    let mode = state.mode.unwrap_or(super::path::Mode(0o644));
    match format {
        // Tar-based: build the tar stream through the `compress`
        // module's codec (no codec logic lives here). `None` means an
        // uncompressed tar (== `Codec::Store`).
        Format::Tar(codec) => {
            super::path::file_from_writer(&state.dest, &user, &group, mode, |staged| {
                build_tar_into(
                    codec.unwrap_or(super::Codec::Store),
                    staged,
                    state
                        .dest
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| std::path::Path::new(".")),
                    &state.sources,
                )
            })?
        }
        // Container formats carry their own per-entry compression.
        Format::Zip => super::path::file_from_writer(&state.dest, &user, &group, mode, |staged| {
            build_zip_into(staged, &state.sources)
        })?,
        Format::SevenZ => {
            super::path::file_from_writer(&state.dest, &user, &group, mode, |staged| {
                build_7z_into(staged, &state.sources)
            })?
        }
    }
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
