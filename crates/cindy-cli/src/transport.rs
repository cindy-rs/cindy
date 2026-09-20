//! The host transport seam: what stands between the CLI's play loop
//! and a target's shell.
//!
//! Everything the play path does to a host — probe its platform, pick
//! a staging directory, upload the worker, run it — goes through
//! [`Transport`], which is either an SSH session to a real host or
//! [`Transport::Local`], spawning the same commands as local child
//! processes. The hidden `play --local` flag selects the local half:
//! the e2e-cli harness drives the *real* CLI binary through the whole
//! play path (inventory, `--limit`, preflight, deployment, summary)
//! with local hosts, and maintainers can do the same by hand. It is
//! not a supported deploy mode — a real playbook run this way
//! converges the operator's own machine.
//!
//! The abstraction is deliberately two methods: "run this to
//! completion" and "spawn this with piped stdio". Everything else
//! (sudo policy, stdio plumbing, exit reporting) is shared by the
//! callers, so the two transports cannot drift apart in behaviour —
//! only in transport.

use crate::conditional_sudo_command::ConditionalSudoCommand as _;

/// A connection to one target: an SSH session, or this machine.
#[derive(Debug)]
pub enum Transport {
    Ssh(openssh::Session),
    Local,
}

/// A spawned host-side child with all three streams piped, as returned
/// by [`Transport::spawn_piped`]. The deploy loop takes the pipes,
/// forwards stderr, and awaits the exit — uniform across transports.
#[derive(Debug)]
pub enum HostChild<'a> {
    Ssh(openssh::RemoteChild<'a>),
    Local(tokio::process::Child),
}

impl Transport {
    /// Run `program` with `args` to completion, capturing its output.
    /// SSH failures and local spawn failures surface as the same
    /// `eyre` error the callers already handle.
    pub async fn check_output(
        &self,
        program: &str,
        args: &[&str],
    ) -> eyre::Result<std::process::Output> {
        match self {
            Transport::Ssh(session) => {
                let mut command = session.command(program);
                command.args(args);
                Ok(command.output().await?)
            }
            Transport::Local => {
                let out = tokio::process::Command::new(program)
                    .args(args)
                    .stdin(std::process::Stdio::null())
                    .output()
                    .await?;
                // tokio's `Output` is its own struct over the same
                // parts; hand the callers the std shape the SSH path
                // produces so no call site branches on the transport.
                Ok(std::process::Output {
                    status: out.status,
                    stdout: out.stdout,
                    stderr: out.stderr,
                })
            }
        }
    }

    /// Spawn `program` with `args`, all three streams piped.
    ///
    /// `sudo` applies only to the SSH transport (the remote deploy
    /// runs the worker as root unless `--unprivileged`); a local play
    /// always runs as the invoking user, and discovery pins
    /// `use_sudo = false` for local hosts so the flag never disagrees
    /// with reality.
    pub async fn spawn_piped<'a>(
        &'a self,
        sudo: bool,
        program: &str,
        args: &[&str],
    ) -> eyre::Result<HostChild<'a>> {
        match self {
            Transport::Ssh(session) => {
                let mut command = session.conditional_sudo_command(sudo, program);
                command
                    .args(args)
                    .stdin(openssh::Stdio::piped())
                    .stdout(openssh::Stdio::piped())
                    .stderr(openssh::Stdio::piped());
                Ok(HostChild::Ssh(command.spawn().await?))
            }
            Transport::Local => {
                let mut command = tokio::process::Command::new(program);
                command
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    // The SSH child ends when its stdin EOFs or the
                    // play aborts; kill-on-drop gives the local child
                    // the same teardown-on-drop semantics.
                    .kill_on_drop(true);
                Ok(HostChild::Local(command.spawn()?))
            }
        }
    }
}

impl HostChild<'_> {
    /// Take the child's stdin, if it was piped.
    pub fn take_stdin(&mut self) -> Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>> {
        match self {
            HostChild::Ssh(child) => child.stdin().take().map(|s| Box::new(s) as _),
            HostChild::Local(child) => child.stdin.take().map(|s| Box::new(s) as _),
        }
    }

    /// Take the child's stdout, if it was piped.
    pub fn take_stdout(&mut self) -> Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> {
        match self {
            HostChild::Ssh(child) => child.stdout().take().map(|s| Box::new(s) as _),
            HostChild::Local(child) => child.stdout.take().map(|s| Box::new(s) as _),
        }
    }

    /// Take the child's stderr, if it was piped.
    pub fn take_stderr(&mut self) -> Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> {
        match self {
            HostChild::Ssh(child) => child.stderr().take().map(|s| Box::new(s) as _),
            HostChild::Local(child) => child.stderr.take().map(|s| Box::new(s) as _),
        }
    }

    /// Wait for the child to exit. Both transports close the child's
    /// stdin first (the SSH child's `wait` does it internally; the
    /// local one drops the pipe with the taken handles gone), so a
    /// worker serving RPC ends on EOF instead of hanging the wait.
    pub async fn wait(self) -> eyre::Result<std::process::ExitStatus> {
        match self {
            HostChild::Ssh(child) => Ok(child.wait().await?),
            HostChild::Local(mut child) => Ok(child.wait().await?),
        }
    }
}
