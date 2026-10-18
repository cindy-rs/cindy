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

pub use anyhow_serde::Context;
/// `anyhow`-style error that serialises, so it can cross the RPC wire.
/// It doesn't implement `std::error::Error` (no more than
/// `anyhow::Error` does), so `?` won't turn it into an `anyhow::Error`
/// — use [`IntoAnyhow`].
pub use anyhow_serde::Error;
pub use anyhow_serde::Result;
pub use anyhow_serde::bail;

mod into_anyhow;
pub use into_anyhow::IntoAnyhow;

pub use tokio::join;

#[doc = include_str!("../../../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
