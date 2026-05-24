use crate as cindy;

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
/// / `decompress::decompress::inner` for the tar-based formats.
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
