//! Run a process (`command`) or a script through an explicit interpreter
//! (`shell`) on the remote machine.
//!
//! These run opaque programs, so cindy can't read back what changed:
//! they make no idempotency claim, always run, and return the raw
//! [`Output`]. A non-zero exit is data ([`Output::status`]), not an
//! error; say "non-zero fails the play" with [`Output::exit_ok`].
//!
//! # Check mode
//!
//! Under `--check` a program isn't run — cindy assumes it mutates — and
//! its status is [`Status::Skipped`]. A play that *branches* on output
//! would then take the wrong branch, so anything you branch on should
//! be a [`probe`]: it asserts [`Effect::ReadOnly`] and runs under
//! `--check` too.
//!
//! ```ignore
//! command(vec!["systemctl".into(), "reload".into(), "nginx".into()], <_>::default())
//!     .await?      // spawn/transport errors
//!     .exit_ok()?; // non-zero exit fails the play, with stdout/stderr attached
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::Context;

/// The result of running (or, under `--check`, not running) a program.
#[derive(Clone, PartialEq, Eq)]
#[crate::wire]
pub struct Output {
    pub status: Status,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[crate::wire]
pub enum Status {
    Exited(i32),
    /// Terminated by a signal, so there is no exit code.
    Signalled,
    /// Check mode didn't run it: nothing in the [`Output`] is a result.
    Skipped,
}

const SKIPPED_SUCCESS_WARNING: &str = "! success() read on a command --check didn't run: the \
     answer is meaningless. If you branch on it, it's a query — use `probe`.";

impl Output {
    /// Exited with code 0.
    ///
    /// A skipped program has no answer — `true` or `false`, one of
    /// `if out.success()` / `if !out.success()` skips a branch a real
    /// run takes — so it answers `false` and warns that the branch
    /// wants a [`probe`].
    pub fn success(&self) -> bool {
        if self.status == Status::Skipped {
            let _ = crate::diff::note(&mut std::io::stderr().lock(), SKIPPED_SUCCESS_WARNING);
        }
        self.status == Status::Exited(0)
    }

    /// Fail on anything but a clean exit, attaching stdout/stderr. A
    /// skipped program passes: nothing ran, so nothing failed.
    pub fn exit_ok(self) -> crate::Result<Self> {
        if matches!(self.status, Status::Exited(0) | Status::Skipped) {
            return Ok(self);
        }
        crate::bail!(
            "process {:?}:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.status,
            self.stdout,
            self.stderr,
        );
    }
}

/// What running the program does to the target — the one thing check
/// mode can't work out, so it has to be told.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[crate::wire]
pub enum Effect {
    /// May change the target: `--check` skips it.
    #[default]
    Mutating,
    /// Only reports: `--check` runs it, so plays can branch on the
    /// answer.
    ///
    /// **cindy can't verify this.** It is the one place `--check`'s
    /// never-mutate guarantee is delegated to you: mislabel a mutating
    /// program and `--check` mutates the target. The test is "does it
    /// write anything", not "is it safe to re-run" (`mkdir -p` is
    /// idempotent and still `Mutating`).
    ///
    /// Read-only: `systemctl is-enabled`, `test -f`, `dpkg-query -W`,
    /// `id -u`, `uname -m`, `--version`. Plausible-looking mislabels:
    /// `apt-get update` (writes `/var/lib/apt`), any script with a
    /// redirect or pipe into a file/FIFO/device, `mktemp`, `touch`, an
    /// HTTP `GET` that changes the far side or saves a file, and RPCs
    /// that load state as a side effect (D-Bus `LoadUnit`, unlike
    /// `GetUnit`).
    ReadOnly,
}

/// Execution environment shared by [`command`] and [`shell`].
#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    pub effect: Effect,
    /// `None` ⇒ the worker's working directory.
    pub chdir: Option<PathBuf>,
    /// Layered over the worker's environment.
    pub env: BTreeMap<String, String>,
    /// Kill the program and fail the call after this long. `None` waits
    /// forever.
    pub timeout: Option<Duration>,
}

fn executes(effect: Effect, dry_run: bool) -> bool {
    !dry_run || effect == Effect::ReadOnly
}

async fn run(
    mut cmd: tokio::process::Command,
    state: &State,
    label: &str,
) -> crate::Result<Output> {
    if let Some(dir) = &state.chdir {
        cmd.current_dir(dir);
    }
    cmd.envs(&state.env);
    // A timeout drops the `output()` future; don't leave the child behind.
    cmd.kill_on_drop(true);

    if !executes(state.effect, crate::dry_run()) {
        let note = format!("[dry-run] {label} not executed");
        eprintln!("{note}");
        return Ok(Output {
            status: Status::Skipped,
            stdout: String::new(),
            stderr: note,
        });
    }
    if crate::dry_run() {
        // Every process check mode starts must be visible to the operator:
        // this is where the never-mutate guarantee was handed off.
        let _ = crate::diff::note(
            &mut std::io::stderr().lock(),
            &format!("? probe {label} (asserted read-only)"),
        );
    }

    let out = match state.timeout {
        None => cmd.output().await,
        Some(limit) => tokio::time::timeout(limit, cmd.output())
            .await
            .map_err(|_| crate::anyhow!("{label} timed out after {limit:?} and was killed"))?,
    }
    .context(format!("Failed to spawn {label}"))?;

    Ok(Output {
        status: out.status.code().map_or(Status::Signalled, Status::Exited),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Run `argv[0]` with `argv[1..]` verbatim — no shell, so no globbing,
/// pipes or expansion; use [`shell`] for those.
#[crate::remote]
pub async fn command(argv: Vec<String>, state: State) -> crate::Result<Output> {
    command_impl(argv, state).await
}

async fn command_impl(argv: Vec<String>, state: State) -> crate::Result<Output> {
    let Some((program, args)) = argv.split_first() else {
        crate::bail!("`command` requires a non-empty argv (argv[0] is the program)");
    };
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    run(cmd, &state, &format!("`command` {program:?}")).await
}

/// Run `script` via `interpreter -c`. The interpreter is an absolute
/// path on purpose: no play should depend on what `/bin/sh` happens to
/// be on a given host.
#[crate::remote]
pub async fn shell(interpreter: PathBuf, script: String, state: State) -> crate::Result<Output> {
    shell_impl(interpreter, script, state).await
}

async fn shell_impl(interpreter: PathBuf, script: String, state: State) -> crate::Result<Output> {
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
    let label = format!("`shell` via {}", interpreter.display());
    run(cmd, &state, &label).await
}

const PROBE: State = State {
    effect: Effect::ReadOnly,
    chdir: None,
    env: BTreeMap::new(),
    timeout: None,
};

/// [`command`] asserting [`Effect::ReadOnly`], so it also runs under
/// `--check`. Use it for anything the play branches on:
///
/// ```rust,ignore
/// let enabled = probe(vec!["systemctl".into(), "is-enabled".into(), "nginx".into()]).await?;
/// if enabled.stdout.trim() != "enabled" {
///     systemd::enable("nginx").await?;
/// }
/// ```
///
/// With [`command`], `--check` would see empty stdout and report an
/// enable the real run might not do (or, with the comparison inverted,
/// skip one it would).
#[crate::action]
pub async fn probe(argv: impl Into<Vec<String>>) -> crate::Result<Output> {
    command_impl(argv, PROBE).await
}

/// [`shell`] asserting [`Effect::ReadOnly`]; see [`probe`].
#[crate::action]
pub async fn probe_shell(
    interpreter: impl Into<PathBuf>,
    script: impl Into<String>,
) -> crate::Result<Output> {
    shell_impl(interpreter, script, PROBE).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Check-mode behaviour itself is covered end to end: `check::install`
    // is a set-once process global, so installing it here would decide
    // the answer for every later test in this binary.

    #[test]
    fn check_mode_runs_only_asserted_read_only_programs() {
        assert!(executes(Effect::Mutating, false));
        assert!(executes(Effect::ReadOnly, false));
        assert!(!executes(Effect::Mutating, true));
        assert!(executes(Effect::ReadOnly, true));
        assert_eq!(State::default().effect, Effect::Mutating);
    }

    fn output(status: Status) -> Output {
        Output {
            status,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn success_is_literal_and_only_exit_ok_passes_a_skipped_program() {
        assert!(!output(Status::Skipped).success());
        assert!(output(Status::Skipped).exit_ok().is_ok());

        assert!(output(Status::Exited(0)).success());
        assert!(output(Status::Exited(0)).exit_ok().is_ok());

        assert!(!output(Status::Exited(1)).success());
        let err = output(Status::Exited(1)).exit_ok().unwrap_err().to_string();
        assert!(err.contains("Exited(1)"), "{err}");

        assert!(!output(Status::Signalled).success());
        assert!(output(Status::Signalled).exit_ok().is_err());
    }

    #[test]
    fn the_skipped_success_warning_points_at_probe() {
        assert!(SKIPPED_SUCCESS_WARNING.contains("probe"));
        assert!(SKIPPED_SUCCESS_WARNING.contains("--check"));
    }

    #[tokio::test]
    async fn timeout_kills_the_child_and_errors() {
        let state = State {
            timeout: Some(Duration::from_millis(300)),
            ..State::default()
        };
        let err = command::inner(vec!["sleep".into(), "30".into()], state)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "{err:#}");
    }

    #[tokio::test]
    async fn exit_status_is_reported_not_raised() {
        let out = command::inner(vec!["false".into()], State::default())
            .await
            .unwrap();
        assert_eq!(out.status, Status::Exited(1));
    }
}
