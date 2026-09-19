//! Run an arbitrary process (`command`) or a script through an
//! explicit interpreter (`shell`) on the remote machine.
//!
//! Unlike the other builtins, these execute opaque user-supplied
//! programs, so the framework cannot introspect what a change *is* —
//! there is no on-disk state to read back, and therefore no honest
//! "changed / unchanged" to report. These modules deliberately make no
//! idempotency claim: they always run, and they hand you back the raw
//! [`Output`] (exit code, stdout, stderr). Deciding whether the
//! intended effect happened is *your* job — inspect the code/output, or
//! check filesystem state with a read-only builtin (e.g. `stat`) before
//! and after.
//!
//! Consistent with that, a **non-zero exit is not an error** — it's
//! data, reported in [`Output::code`]. Only failing to run the program
//! at all errors. When "non-zero should fail the play" is what you
//! mean, say so with [`Output::exit_ok`]. One exception: under
//! `cindy play --check` the program is not executed at all — the
//! returned [`Output`] marks itself [`dry_run`](Output::dry_run) with
//! empty streams, and `exit_ok` passes so plays flow through check
//! mode (logic that reads `stdout` sees the absence).
//!
//! ```ignore
//! command(vec!["systemctl".into(), "reload".into(), "nginx".into()], <_>::default())
//!     .await?      // spawn/transport errors
//!     .exit_ok()?; // non-zero exit fails the play, with stdout/stderr attached
//! ```

use crate::Context;

/// Captured result of the executed process.
///
/// Returned for both [`command`] and [`shell`]. Outside check mode the
/// program always ran, so there is no "changed" flag — just the
/// observable result for you to act on. Under check mode nothing ran
/// and [`dry_run`](Output::dry_run) is set.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub struct Output {
    /// Process exit code, or `None` if the program was terminated by a
    /// signal (no code available).
    pub code: Option<i32>,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// True when check mode suppressed the execution: `code` is `None`
    /// and the streams carry a not-executed note. `exit_ok` passes so
    /// plays flow through `--check`, but logic reading `stdout` sees
    /// the absence.
    pub dry_run: bool,
}

impl Output {
    /// `true` if the program exited successfully (`code == 0`).
    pub fn success(&self) -> bool {
        self.dry_run || self.code == Some(0)
    }

    /// Turn a non-zero (or signal-terminated) exit into an error
    /// carrying the captured stdout/stderr, for callers where anything
    /// but success should fail the play.
    pub fn exit_ok(self) -> crate::Result<Self> {
        if self.success() {
            return Ok(self);
        }
        crate::bail!(
            "process exited with {:?}:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code,
            self.stdout,
            self.stderr,
        );
    }
}

/// Execution environment shared by [`command`] and [`shell`].
#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Working directory to run the program in. `None` ⇒ inherit the
    /// remote worker's current directory.
    pub chdir: Option<std::path::PathBuf>,
    /// Extra environment variables to set for the child process. These
    /// are layered on top of the worker's inherited environment.
    pub env: std::collections::BTreeMap<String, String>,
    /// Kill the program if it hasn't exited after this long, and fail
    /// the call. The timeout is *our* intervention, not the program's
    /// exit behavior, so it surfaces as an error rather than an
    /// [`Output`]. `None` (the default) waits forever, like a plain
    /// shell would.
    pub timeout: Option<std::time::Duration>,
}

/// Run an already-configured [`Command`] to completion and capture its
/// [`Output`]. Errors only when the program couldn't be run at all (or
/// hit [`State::timeout`]); the exit status — zero or not — is the
/// caller's data, not our verdict (see the module docs and
/// [`Output::exit_ok`]).
async fn run(
    mut cmd: tokio::process::Command,
    state: &State,
    label: &str,
) -> crate::Result<Output> {
    if let Some(dir) = state.chdir.as_ref() {
        cmd.current_dir(dir);
    }
    for (k, v) in &state.env {
        cmd.env(k, v);
    }
    // A timed-out call drops the in-flight `output()` future; without
    // this the orphaned child would keep running on the target.
    cmd.kill_on_drop(true);

    // Check mode never executes the program: running it *is* the
    // mutation, and there is no desired state to compare against.
    // Report the absence honestly and loudly.
    if crate::dry_run() {
        let note = format!("[dry-run] {label} not executed");
        eprintln!("{note}");
        return Ok(Output {
            code: None,
            stdout: String::new(),
            stderr: note,
            dry_run: true,
        });
    }

    let out = match state.timeout {
        None => cmd.output().await,
        Some(limit) => match tokio::time::timeout(limit, cmd.output()).await {
            Ok(res) => res,
            Err(_elapsed) => {
                crate::bail!("{label} timed out after {limit:?} and was killed")
            }
        },
    }
    .context(format!("Failed to spawn {label}"))?;

    Ok(Output {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        dry_run: false,
    })
}

/// Run a program directly, without a shell.
///
/// `argv[0]` is the program to execute and the remaining elements are
/// its arguments, passed verbatim — there is **no** shell, so globbing,
/// pipes, redirection, `&&`, environment-variable expansion, etc. are
/// *not* interpreted. If you need any of that, reach for [`shell`].
///
/// `argv` must be non-empty. This module makes no idempotency claim: it
/// runs every time and reports the raw [`Output`].
#[crate::remote]
pub async fn command(argv: Vec<String>, state: State) -> crate::Result<Output> {
    let Some((program, args)) = argv.split_first() else {
        crate::bail!("`command` requires a non-empty argv (argv[0] is the program)");
    };

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    run(cmd, &state, &format!("`command` {program:?}")).await
}

/// Run a script through an explicit interpreter.
///
/// `shell` deliberately refuses to assume an interpreter: `interpreter`
/// is the **full path** to the shell binary (`/bin/sh`, `/bin/bash`,
/// `/usr/bin/zsh`, …) and `script` is handed to it via `-c`. There is
/// no implicit `bash`/`sh`/`zsh` — the caller must spell out exactly
/// which interpreter runs, so plays don't silently depend on whatever
/// `/bin/sh` happens to point at on a given host.
///
/// `interpreter` must be an absolute path that exists on the remote;
/// the module fails fast otherwise rather than letting the OS produce a
/// confusing `ENOENT`.
#[crate::remote]
pub async fn shell(
    interpreter: std::path::PathBuf,
    script: String,
    state: State,
) -> crate::Result<Output> {
    if !interpreter.is_absolute() {
        crate::bail!(
            "`shell` interpreter must be an absolute path, got {}; \
             there is no implicit shell — spell out e.g. /bin/bash",
            interpreter.display()
        );
    }
    if !interpreter.exists() {
        crate::bail!(
            "`shell` interpreter {} does not exist on the remote",
            interpreter.display()
        );
    }

    let mut cmd = tokio::process::Command::new(&interpreter);
    cmd.arg("-c").arg(&script);
    run(
        cmd,
        &state,
        &format!("`shell` via {}", interpreter.display()),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_kills_the_child_and_errors() {
        let state = State {
            timeout: Some(std::time::Duration::from_millis(300)),
            ..State::default()
        };
        let err = command::inner(vec!["sleep".into(), "30".into()], state)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "{err:#}");
    }

    #[tokio::test]
    async fn no_timeout_still_waits_forever_semantics() {
        // No timeout configured: a plain quick command behaves exactly
        // as before the field existed.
        let out = command::inner(vec!["true".into()], State::default())
            .await
            .unwrap();
        assert_eq!(out.code, Some(0));
    }
}
