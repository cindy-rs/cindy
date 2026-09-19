use uuid::Uuid;

#[doc(hidden)]
#[crate::wire]
pub struct RemoteFnPayload {
    pub uuid: Uuid,
    pub fn_id: String,
    pub data: Vec<u8>,
}

/// A message the orchestrator sends *to* the worker over the RPC
/// channel.
///
/// The first frame is always a [`Handshake`](WorkerInbound::Handshake)
/// carrying the vault keys this worker needs; everything after is a
/// [`Call`](WorkerInbound::Call). Routing keys through the channel
/// (rather than an env var or argv) means the raw key material never
/// appears in the target's process table — it lives only in the
/// SSH-protected pipe and the worker's memory.
#[doc(hidden)]
#[crate::wire]
pub enum WorkerInbound {
    /// Sent once, first: the `{vault: raw-key-bytes}` map the worker
    /// installs into its keychain before serving any calls, plus the
    /// check-mode decision (`cindy play --check`) installed before any
    /// call is dispatched.
    Handshake {
        vault_keys: std::collections::HashMap<String, Vec<u8>>,
        dry_run: bool,
    },
    /// A remote-function invocation.
    Call(RemoteFnPayload),
}

#[doc(hidden)]
#[crate::wire]
pub enum RemoteFnResponse {
    Ok(Vec<u8>),
    Panic(String),
}

#[doc(hidden)]
#[crate::wire]
pub struct RemoteFnResponsePayload {
    pub uuid: Uuid,
    pub response: RemoteFnResponse,
}

#[doc(hidden)]
pub fn quarantine_stdio() -> (tokio::fs::File, tokio::fs::File) {
    let saved_in = nix::unistd::dup(std::io::stdin()).expect("Couldn't dup RPC stdin off FD 0");
    let saved_out = nix::unistd::dup(std::io::stdout()).expect("Couldn't dup RPC stdout off FD 1");

    // Mark the saved RPC fds close-on-exec. Without this, every process a
    // `#[remote]` fn spawns inherits the pipe ends: a daemonizing child
    // would hold the RPC stream open (so the orchestrator never sees EOF
    // when the worker exits) and could even write garbage into it.
    for fd in [&saved_in, &saved_out] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .expect("Couldn't set FD_CLOEXEC on the saved RPC fd");
    }

    nix::unistd::dup2_stdout(std::io::stderr()).expect("Couldn't redirect FD 1 to stderr");

    let dev_null =
        std::fs::File::open("/dev/null").expect("Couldn't open /dev/null for FD 0 redirect");
    nix::unistd::dup2_stdin(&dev_null).expect("Couldn't redirect FD 0 to /dev/null");
    // `dev_null` drops here; the kernel still holds the underlying file
    // via FD 0, which `dup2_stdin` just pointed at it.

    (
        tokio::fs::File::from_std(std::fs::File::from(saved_in)),
        tokio::fs::File::from_std(std::fs::File::from(saved_out)),
    )
}
