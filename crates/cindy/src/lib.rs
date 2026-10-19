//! Infrastructure as a Rust crate: a playbook is a binary whose
//! `#[cindy::main]` runs on your machine, while `#[cindy::remote]` fns
//! run on each target — over SSH, with nothing left behind.
//!
//! - [`main`], [`remote`], [`inventory`], [`wire`], [`action`] — the
//!   macros a playbook is written with.
//! - [`builtin`] — converged-state building blocks: files, packages,
//!   services, users, archives, commands. Each reports whether it
//!   changed anything.
//! - [`check`] — `cindy play --check`, report without applying.
//! - [`Secret`] and [`secret!`] — values sealed at rest, revealed only
//!   where they are used.
//! - [`error`] — `cindy::Result` is `anyhow::Result`; remote errors keep
//!   their chain.
//!
//! The `cindy` command line tool builds, deploys and runs playbooks;
//! see <https://cindy.rs>.

#[doc(hidden)]
pub mod common;
#[doc(hidden)]
pub mod entry;
#[doc(hidden)]
pub mod inventory;
#[doc(hidden)]
pub mod orchestrator;
#[doc(hidden)]
pub mod remote;
#[doc(hidden)]
pub mod secret;

#[doc(hidden)]
pub mod __reexports {
    pub use base64;
    pub use inventory;
    pub use postcard;
    pub use serde;
    pub use serde_json;
    pub use tokio;
}

pub mod builtin;
pub mod check;
pub mod diff;

pub use cindy_macros::{action, inventory, main, remote, wire};

pub use check::dry_run;
pub use diff::Diff;
pub use inventory::{Host, Inventory};
pub use secret::Secret;

pub mod error;
pub use error::{Context, Error, Result, anyhow, bail, ensure};

pub use tokio::join;

#[doc = include_str!("../../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
