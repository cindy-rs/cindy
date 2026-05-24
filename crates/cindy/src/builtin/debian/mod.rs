//! Debian/Ubuntu-specific modules.
//!
//! Modules here assume a Debian-family remote (the `apt`/`dpkg`
//! toolchain). Grouping them under `debian` keeps distro-specific
//! package management distinct from the cross-distro builtins.

pub mod apt;
