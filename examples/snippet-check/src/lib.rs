//! Compile guard for the code snippets rendered on https://cindy.rs.
//!
//! Each module below includes — by path — the *same file* the website
//! renders (`web/src/snippets/*.rs`), so a snippet can't drift from the
//! real `cindy` API: changing the API breaks this crate's build, and
//! changing a snippet breaks both this build and the site's own
//! compile-time highlighting. The snippets are documentation first —
//! nothing here is executed, hence the dead-code allowance.

#![allow(dead_code, unused_variables)]

#[path = "../../../web/src/snippets/action.rs"]
mod action;

#[path = "../../../web/src/snippets/async.rs"]
mod r#async;

#[path = "../../../web/src/snippets/quickstart.rs"]
mod quickstart;

#[path = "../../../web/src/snippets/remote.rs"]
mod remote;

#[path = "../../../web/src/snippets/reveal.rs"]
mod reveal;

// `secret!` on a plain value intentionally trips the "unsealed secret"
// deprecation — that's the seal workflow's UX, not an API problem.
#[allow(deprecated)]
#[path = "../../../web/src/snippets/secret.rs"]
mod secret;
