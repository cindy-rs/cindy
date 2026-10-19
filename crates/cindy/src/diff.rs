//! Line diffs of two values' `{:#?}` renderings. A type whose `Debug`
//! renders badly in a diff gives a field a better `Debug` (as
//! `builtin::path` does for file content), or overrides [`Diff::diff`]
//! and calls [`text_diff`].

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

/// Coloured unless `NO_COLOR` is set. No tty detection: the usual
/// writer is the worker's stderr pipe, which is never a terminal.
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

            // Reset before the newline, or some terminals carry the
            // colour onto the next line.
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

/// One line for work with no structural diff (a restart, an attribute
/// fix), styled like a hunk header.
pub fn note(out: &mut dyn Write, body: &str) -> io::Result<()> {
    let style = Style::detect();
    write_styled_line(out, style.header, body, style.reset)
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
