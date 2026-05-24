//! Pretty-printable structural diffs.
//!
//! The [`Diff`] trait renders a unified-style diff of two values of the same
//! type. The default implementation pretty-prints both sides with `{:#?}` and
//! runs [`similar`]'s line-based text diff over the result, so any type that
//! implements [`Debug`] gets a usable diff for free.
//!
//! Types holding payloads that don't survive `Debug` well (binary blobs,
//! large blobs, secrets, ...) should override [`Diff::diff`] and call
//! [`text_diff`] with a custom string representation.
//!
//! ```rust,ignore
//! use cindy::diff::Diff;
//! let mut out = std::io::stderr().lock();
//! old.diff(&new, &mut out)?;
//! ```

use std::fmt::Debug;
use std::io::{self, Write};

use similar::{ChangeTag, TextDiff, udiff::UnifiedDiff};

const CONTEXT_LINES: usize = 3;

pub trait Diff: Debug {
    /// Write a human-readable diff of `self` (old) against `new` to `out`.
    fn diff(&self, new: &Self, out: &mut dyn Write) -> io::Result<()> {
        text_diff(&format!("{self:#?}"), &format!("{new:#?}"), out)
    }
}

/// Line-based text diff helper, exposed so manual [`Diff`] impls can build a
/// custom string representation and still share the rendering.
///
/// Output is colorized with ANSI escapes (red for removals, green for
/// additions) unless the `NO_COLOR` environment variable is set
/// (<https://no-color.org/>). TTY detection is deliberately not used: this
/// crate's primary writer is a pipe from a remote process back to the
/// orchestrator, where a `is_terminal()` check would always be wrong.
pub fn text_diff(old: &str, new: &str, out: &mut dyn Write) -> io::Result<()> {
    let style = Style::detect();
    let textdiff = TextDiff::from_lines(old, new);
    let mut udiff = UnifiedDiff::from_text_diff(&textdiff);
    udiff.context_radius(CONTEXT_LINES);

    for hunk in udiff.iter_hunks() {
        write_styled_line(out, style.header, &hunk.header().to_string(), style.reset)?;

        for change in hunk.iter_changes() {
            let (sign, color) = match change.tag() {
                ChangeTag::Delete => ('-', style.delete),
                ChangeTag::Insert => ('+', style.insert),
                ChangeTag::Equal => (' ', ""),
            };

            // Split the trailing newline (if any) off so the ANSI reset
            // lands *before* it. Otherwise some terminals carry the color
            // attribute into the next line on resize/copy.
            let value = change.value();
            let (body, nl) = match value.strip_suffix('\n') {
                Some(body) => (body, "\n"),
                None => (value, ""),
            };

            if color.is_empty() {
                write!(out, "{sign}{body}{nl}")?;
            } else {
                write!(out, "{color}{sign}{body}{}{nl}", style.reset)?;
            }
        }
    }
    Ok(())
}

fn write_styled_line(out: &mut dyn Write, color: &str, body: &str, reset: &str) -> io::Result<()> {
    let body = body.strip_suffix('\n').unwrap_or(body);
    if color.is_empty() {
        writeln!(out, "{body}")
    } else {
        writeln!(out, "{color}{body}{reset}")
    }
}

struct Style {
    delete: &'static str,
    insert: &'static str,
    header: &'static str,
    reset: &'static str,
}

impl Style {
    fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
            Self {
                delete: "",
                insert: "",
                header: "",
                reset: "",
            }
        } else {
            Self {
                delete: "\x1b[31m",   // red
                insert: "\x1b[32m",   // green
                header: "\x1b[36;1m", // bold cyan
                reset: "\x1b[0m",
            }
        }
    }
}
