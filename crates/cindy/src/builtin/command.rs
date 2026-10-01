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
//! mean, say so with [`Output::exit_ok`].
//!
//! # Check mode
//!
//! Under `cindy play --check` a program is not executed: cindy can't
//! introspect an opaque binary, so it assumes the worst. The returned
//! [`Output`] marks itself [`dry_run`](Output::dry_run) with empty
//! streams, and `exit_ok` passes so plays flow through.
//!
//! That default is safe but not sufficient. A play that *branches* on a
//! command's output takes the wrong branch when the output is empty, so
//! the change set check mode reports stops matching what a real run
//! would do — and when the branch it skips contains work, that's an
//! under-report, which check mode must never produce. [`probe`] (and
//! [`probe_shell`]) are the way out: they assert [`Effect::ReadOnly`],
//! so check mode runs them and the branch sees real information. The
//! assertion is yours to keep — see [`Effect::ReadOnly`].
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

/// What running this program does to the target — the one thing cindy
/// cannot work out for itself, and therefore the one thing check mode
/// has to be told.
///
/// Default is [`Mutating`](Effect::Mutating): an opaque program is
/// assumed to change the host, so `--check` doesn't run it.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[crate::wire]
pub enum Effect {
    /// Running this may change the target, so check mode skips it and
    /// reports the absence. The safe default.
    #[default]
    Mutating,
    /// Running this changes nothing — it only reports. Check mode
    /// executes it, because the *information* is what the rest of the
    /// play branches on.
    ///
    /// **This is an assertion cindy cannot verify, and the only place
    /// `--check`'s never-mutate guarantee is delegated to you.** Mark a
    /// mutating program `ReadOnly` and `--check` will mutate the
    /// target.
    ///
    /// The line is "does running this write anything", not "is it safe
    /// to re-run". Those differ: `mkdir -p` is perfectly idempotent and
    /// still `Mutating`.
    ///
    /// Genuinely read-only: `systemctl is-enabled`, `test -f`,
    /// `dpkg-query -W`, `--version`, `id -u`, `uname -m`.
    ///
    /// `Mutating` despite sounding like a query — the cases worth
    /// knowing, because each is a plausible mislabel:
    ///
    /// - `apt-get update` "just refreshes information", and writes
    ///   `/var/lib/apt`.
    /// - any `shell` script with a redirect: `… > /tmp/out`, `… | tee`,
    ///   or anything writing to a pipe, FIFO or device node.
    /// - `mktemp`, `touch` — they create.
    /// - `curl`/`fetch` of a remote endpoint: read-only *here*, but a
    ///   `GET` can still change the far side, and it leaves artefacts
    ///   if it writes a file.
    /// - a "read" that mutates server-side state: this project hit one
    ///   in `systemd` itself, where D-Bus `LoadUnit` loads a unit as a
    ///   side effect where `GetUnit` only looks.
    ///
    /// Why it has to exist: without it, a play that branches on a
    /// command's output takes the *wrong branch* under `--check`,
    /// because the output is empty. That can silently skip work a real
    /// run would do — an under-report, which is the one thing check
    /// mode must never do.
    ReadOnly,
}

/// Execution environment shared by [`command`] and [`shell`].
#[derive(Clone, Default, PartialEq, Eq)]
#[crate::wire]
pub struct State {
    /// Whether running this program changes the target, which decides
    /// what `--check` does with it. See [`Effect`]; defaults to
    /// [`Effect::Mutating`], and [`probe`] is the ergonomic way to ask
    /// for the other one.
    pub effect: Effect,
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

/// Does this call actually start a process?
///
/// A pure decision, extracted and tested because it is exactly the
/// shape that has gone wrong before: a check-mode condition inlined at
/// its one call site, with nothing holding it to the invariant. Both
/// branches of `run` read this one answer.
fn executes(effect: Effect, dry_run: bool) -> bool {
    !dry_run || matches!(effect, Effect::ReadOnly)
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

    if !executes(state.effect, crate::dry_run()) {
        let note = format!("[dry-run] {label} not executed");
        eprintln!("{note}");
        return Ok(Output {
            code: None,
            stdout: String::new(),
            stderr: note,
            dry_run: true,
        });
    }

    // A probe running under `--check` is the one place check mode runs
    // a program, so it says so. An operator reading a check run must be
    // able to account for every process it started — that is where the
    // never-mutate guarantee was handed to the playbook author, and an
    // invisible delegation is an unreviewable one.
    if crate::dry_run() {
        let _ = crate::diff::note(
            &mut std::io::stderr().lock(),
            &format!("? probe {label} (asserted read-only)"),
        );
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
    command_impl(argv, state).await
}

/// Shared body behind [`command`] and [`probe`]: not itself a remote fn
/// (those are), just what they both funnel into — the same split every
/// other builtin makes with its `apply`.
async fn command_impl(argv: Vec<String>, state: State) -> crate::Result<Output> {
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
    shell_impl(interpreter, script, state).await
}

/// Shared body behind [`shell`] and [`probe_shell`].
async fn shell_impl(
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

/// Run a read-only program — one that *reports* rather than changes —
/// so its output is available under `--check` too.
///
/// The same as [`command`] with [`Effect::ReadOnly`], which is the
/// assertion you are making by calling this: cindy executes it in check
/// mode on your word. Use it for queries whose answer the rest of the
/// play branches on:
///
/// ```rust,ignore
/// let enabled = probe(vec!["systemctl".into(), "is-enabled".into(), "nginx".into()]).await?;
/// if enabled.stdout.trim() != "enabled" {
///     systemd::enable("nginx").await?;
/// }
/// ```
///
/// Written with [`command`] instead, that `if` takes the wrong branch
/// under `--check` — empty stdout never equals `"enabled"` — and check
/// mode reports an enable the real run wouldn't do. Invert the
/// comparison and it under-reports instead, which is worse. A probe is
/// how the branch stays honest.
#[crate::action]
pub async fn probe(argv: impl Into<Vec<String>>) -> crate::Result<Output> {
    command_impl(
        argv,
        State {
            effect: Effect::ReadOnly,
            ..State::default()
        },
    )
    .await
}

/// [`shell`] for a read-only script — the [`probe`] counterpart, with
/// the same assertion and the same caveat.
#[crate::action]
pub async fn probe_shell(
    interpreter: impl Into<std::path::PathBuf>,
    script: impl Into<String>,
) -> crate::Result<Output> {
    shell_impl(
        interpreter,
        script,
        State {
            effect: Effect::ReadOnly,
            ..State::default()
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole check-mode contract, as a table. Extracted into
    /// `executes` precisely so it can be one — every `--check` defect
    /// so far came from this decision being inlined at its call site.
    #[test]
    fn executes_decides_check_mode_by_asserted_effect() {
        // Outside check mode everything runs, whatever it claims.
        assert!(executes(Effect::Mutating, false));
        assert!(executes(Effect::ReadOnly, false));
        // Under --check, only an asserted read-only program runs.
        assert!(!executes(Effect::Mutating, true));
        assert!(executes(Effect::ReadOnly, true));
    }

    /// `Mutating` must be what you get by forgetting to choose: a
    /// defaulted `State` that ran mutating programs under `--check`
    /// would break the invariant silently.
    #[test]
    fn the_default_effect_is_the_safe_one() {
        assert_eq!(State::default().effect, Effect::Mutating);
        assert!(!executes(State::default().effect, true));
    }

    // Check-mode *behaviour* is deliberately not tested here:
    // `check::install` is a set-once process global (it arrives in the
    // worker's handshake), so a unit test that installed it would
    // decide the answer for every later test in this binary — an
    // order-dependent suite. The contract lives in `executes` above,
    // exhaustively; the end-to-end behaviour lives in the e2e suites,
    // where a real worker gets a real handshake.

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
