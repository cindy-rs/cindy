//! Create an archive from source paths on the remote machine.
//!
//! Not idempotent: archives embed timestamps, so a rebuild always
//! rewrites the destination and reports `Changed`.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::Context;

use super::path::{Owner, StagedWriter};
use super::{Codec, Format};

#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Each is stored under its final path component; directories
    /// recursively, symlinks as symlinks.
    pub sources: Vec<PathBuf>,
    pub dest: PathBuf,
    /// `None` ⇒ inferred from `dest`'s extension.
    pub format: Option<Format>,
    /// `None` ⇒ `0o644`.
    pub mode: Option<super::path::Mode>,
}

/// The full-control entry point; [`create`] infers the format.
#[crate::remote]
pub fn archive(state: State) -> crate::Result<super::Return> {
    apply(state)
}

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
    if crate::dry_run() {
        return Ok(super::Return::Changed);
    }

    let mode = state.mode.unwrap_or(super::path::Mode(0o644));
    super::path::file_from_writer(
        &state.dest,
        &Owner::current(),
        mode,
        |staged| match format {
            Format::Tar(codec) => build_tar(codec.unwrap_or(Codec::Store), staged, &state),
            Format::Zip => build_zip(staged, &state),
            Format::SevenZ => build_7z(staged, &state),
        },
    )?;
    Ok(super::Return::Changed)
}

/// Two sources with one final component would silently clobber each
/// other inside the archive.
fn check_unique_entry_names(sources: &[PathBuf]) -> crate::Result<()> {
    let mut seen = std::collections::HashMap::new();
    for source in sources {
        let name = entry_name(source)?;
        if let Some(first) = seen.insert(name, source) {
            crate::bail!(
                "sources {} and {} both archive as `{}` — an entry name is its \
                 source's final path component; archive them via a parent directory \
                 or rename one",
                first.display(),
                source.display(),
                name.display()
            );
        }
    }
    Ok(())
}

fn entry_name(path: &Path) -> crate::Result<&Path> {
    path.file_name()
        .map(Path::new)
        .context(format!("source path {} has no file name", path.display()))
}

/// Files the walk leaves out, by (device, inode): this build's own
/// output — staged, spilled, or the previous archive at the destination
/// — which a source containing the destination's directory would
/// otherwise archive.
type Skip = Vec<(u64, u64)>;

fn own_output(staged: &mut StagedWriter, dest: &Path) -> crate::Result<Skip> {
    let mut skip = vec![identity(staged.as_file_mut())?];
    if let Ok(md) = std::fs::symlink_metadata(dest) {
        skip.push((md.dev(), md.ino()));
    }
    Ok(skip)
}

fn identity(file: &std::fs::File) -> crate::Result<(u64, u64)> {
    let md = file
        .metadata()
        .context("Couldn't stat the staged archive")?;
    Ok((md.dev(), md.ino()))
}

/// Visit every source and everything under it, parents first, children
/// in name order, each with the name it is stored under.
fn walk(
    sources: &[PathBuf],
    skip: &Skip,
    visit: &mut dyn FnMut(&Path, &Path, &Metadata) -> crate::Result<()>,
) -> crate::Result<()> {
    fn descend(
        path: &Path,
        name: &Path,
        skip: &Skip,
        visit: &mut dyn FnMut(&Path, &Path, &Metadata) -> crate::Result<()>,
    ) -> crate::Result<()> {
        let md =
            std::fs::symlink_metadata(path).context(format!("Couldn't stat {}", path.display()))?;
        if skip.contains(&(md.dev(), md.ino())) {
            return Ok(());
        }
        visit(path, name, &md)?;
        if md.is_dir() {
            let mut children = std::fs::read_dir(path)
                .context(format!("Couldn't read dir {}", path.display()))?
                .collect::<Result<Vec<_>, _>>()
                .context(format!("Couldn't read dir {}", path.display()))?;
            children.sort_by_key(|e| e.file_name());
            for child in children {
                descend(&child.path(), &name.join(child.file_name()), skip, visit)?;
            }
        }
        Ok(())
    }
    for source in sources {
        descend(source, entry_name(source)?, skip, visit)?;
    }
    Ok(())
}

fn build_tar(codec: Codec, staged: &mut StagedWriter, state: &State) -> crate::Result<()> {
    fn fill<W: std::io::Write>(writer: W, sources: &[PathBuf], skip: &Skip) -> crate::Result<W> {
        let mut builder = tar::Builder::new(writer);
        // Store symlinks as links, like `tar` without `-h`: following
        // them dereferences, fails on dangling links, loops on cycles.
        builder.follow_symlinks(false);
        walk(sources, skip, &mut |path, name, md| {
            if md.is_dir() {
                builder.append_dir(name, path)
            } else {
                builder.append_path_with_name(path, name)
            }
            .context(format!("Couldn't add {} to the archive", path.display()))
        })?;
        builder
            .into_inner()
            .context("Couldn't finalise the tar stream")
    }

    let mut skip = own_output(staged, &state.dest)?;
    match codec {
        Codec::Store => {
            fill(staged.as_file_mut(), &state.sources, &skip)?;
        }
        Codec::Gzip => {
            let gz =
                flate2::write::GzEncoder::new(staged.as_file_mut(), flate2::Compression::default());
            fill(gz, &state.sources, &skip)?
                .finish()
                .context("gzip finalisation failed")?;
        }
        // No streaming encoder: spill the tar, then compress the file.
        Codec::Xz | Codec::Zstd => {
            let mut spill = super::path::spill_in(super::path::parent_dir(&state.dest))?;
            skip.push(identity(spill.as_file())?);
            fill(spill.as_file_mut(), &state.sources, &skip)?;
            let mut tar =
                std::fs::File::open(spill.path()).context("Couldn't reopen the tar spill")?;
            super::compress::compress_into(codec, &mut tar, staged.as_file_mut())?;
        }
    }
    Ok(())
}

fn build_zip(staged: &mut StagedWriter, state: &State) -> crate::Result<()> {
    let skip = own_output(staged, &state.dest)?;
    let mut zip = zip::ZipWriter::new(staged.as_file_mut());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    walk(&state.sources, &skip, &mut |path, name, md| {
        let name_str = name.to_string_lossy();
        if md.is_symlink() {
            let target = std::fs::read_link(path)
                .context(format!("Couldn't read symlink {}", path.display()))?;
            zip.add_symlink_from_path(name, &target, options)?;
        } else if md.is_dir() {
            zip.add_directory(format!("{name_str}/"), options)?;
        } else {
            // Keep exec bits, as tar does.
            zip.start_file(name_str, options.unix_permissions(md.mode()))?;
            let mut file =
                std::fs::File::open(path).context(format!("Couldn't open {}", path.display()))?;
            std::io::copy(&mut file, &mut zip)?;
        }
        Ok(())
    })?;
    zip.finish().context("Couldn't finalise the zip archive")?;
    Ok(())
}

fn build_7z(staged: &mut StagedWriter, state: &State) -> crate::Result<()> {
    let skip = own_output(staged, &state.dest)?;
    let mut writer = sevenz_rust2::ArchiveWriter::new(staged.as_file_mut())
        .context("Couldn't create the 7z writer")?;
    walk(&state.sources, &skip, &mut |path, name, md| {
        if md.is_symlink() {
            crate::bail!(
                "{} is a symlink; the 7z writer can't represent symlinks — \
                 use a tar or zip archive for trees containing them",
                path.display(),
            );
        }
        let entry =
            sevenz_rust2::ArchiveEntry::from_path(path, name.to_string_lossy().into_owned());
        let content = if md.is_dir() {
            None
        } else {
            Some(std::fs::File::open(path).context(format!("Couldn't open {}", path.display()))?)
        };
        writer
            .push_archive_entry(entry, content)
            .context(format!("Couldn't add {} to 7z", path.display()))?;
        Ok(())
    })?;
    writer
        .finish()
        .context("Couldn't finalise the 7z archive")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srcs(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn colliding_entry_names_are_rejected_up_front() {
        let msg = check_unique_entry_names(&srcs(&["/a/conf", "/b/conf"]))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("/a/conf"), "{msg}");
        assert!(msg.contains("/b/conf"), "{msg}");
        assert!(msg.contains("`conf`"), "{msg}");

        assert!(check_unique_entry_names(&srcs(&["/a/conf", "/a/conf.d"])).is_ok());
        assert!(check_unique_entry_names(&srcs(&["/only/one"])).is_ok());
    }

    /// An archive written into the directory it archives must not
    /// contain itself, in any form.
    #[test]
    fn an_archive_inside_its_source_does_not_contain_itself() {
        for (ext, format) in [
            ("tar", Format::Tar(None)),
            ("tar.zst", Format::Tar(Some(Codec::Zstd))),
            ("zip", Format::Zip),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let src = tmp.path().join("tree");
            std::fs::create_dir(&src).unwrap();
            std::fs::write(src.join("a.txt"), b"a").unwrap();
            let dest = src.join(format!("self.{ext}"));
            // Twice: the second run finds the first's archive in the tree.
            for _ in 0..2 {
                archive::inner(State {
                    sources: vec![src.clone()],
                    dest: dest.clone(),
                    format: Some(format),
                    mode: Some(super::super::path::Mode(0o644)),
                })
                .unwrap();
            }

            let out = tmp.path().join("out");
            super::super::unarchive::unarchive::inner(super::super::unarchive::State {
                src: dest,
                dest: out.clone(),
                format: Some(format),
                max_bytes: None,
            })
            .unwrap();
            let names: Vec<_> = std::fs::read_dir(out.join("tree"))
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            assert_eq!(names, ["a.txt"], "{ext}: {names:?}");
        }
    }
}
