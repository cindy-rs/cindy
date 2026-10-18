//! cindy's errors are [`anyhow`](mod@anyhow)'s: `cindy::Result` *is*
//! `anyhow::Result`, so `?` moves errors between playbook code, cindy and
//! anyhow-based tooling without conversion.
//!
//! A remote fn returning `cindy::Result<T>` that fails on the worker
//! arrives on the orchestrator as an `anyhow::Error` with the same
//! chain: every link's message, in order, so `{:#}` and
//! [`chain`](anyhow::Error::chain) read as they did on the worker. The
//! original types can't be rebuilt — each link becomes a
//! [`RemoteError`] — except [`io::Error`], which comes back as an
//! `io::Error` of the same [`kind`](io::Error::kind), so
//! `err.downcast_ref::<io::Error>()` works as it would locally.
//!
//! A remote fn that needs its exact error type on the orchestrator can
//! return `Result<T, MyError>` with a serialisable `MyError` instead:
//! that crosses the wire like any other value.

use std::fmt;
use std::io;

pub use anyhow::{Context, Error, Result, anyhow, bail, ensure};

/// One link of an error chain that failed on the worker, rebuilt on
/// the orchestrator. Displays the original link's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteError(String);

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RemoteError {}

/// An error chain as it travels: outermost link first.
#[doc(hidden)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct WireError(Vec<WireLink>);

#[derive(serde::Serialize, serde::Deserialize)]
struct WireLink {
    message: String,
    /// `io::ErrorKind`'s variant name; a name this side doesn't know
    /// degrades the link to a plain [`RemoteError`].
    io_kind: Option<String>,
}

impl From<&Error> for WireError {
    fn from(error: &Error) -> Self {
        WireError(
            error
                .chain()
                .map(|link| WireLink {
                    message: link.to_string(),
                    io_kind: link
                        .downcast_ref::<io::Error>()
                        .map(|e| format!("{:?}", e.kind())),
                })
                .collect(),
        )
    }
}

impl From<WireError> for Error {
    fn from(wire: WireError) -> Self {
        // Innermost first, each outer link a context on top: anyhow's
        // own layering, so `chain()`, `{:#}` and `downcast_ref` behave
        // as they do on an error built locally with `.context(..)`.
        wire.0
            .into_iter()
            .rev()
            .fold(None, |inner: Option<Error>, link| {
                let remote = RemoteError(link.message);
                let kind = link.io_kind.as_deref().and_then(io_kind);
                Some(match (kind, inner) {
                    (Some(kind), None) => Error::new(io::Error::new(kind, remote)),
                    (Some(kind), Some(inner)) => inner.context(io::Error::new(kind, remote)),
                    (None, None) => Error::new(remote),
                    (None, Some(inner)) => inner.context(remote),
                })
            })
            .unwrap_or_else(|| anyhow!("the worker reported an error without a message"))
    }
}

fn io_kind(name: &str) -> Option<io::ErrorKind> {
    IO_KINDS.iter().copied().find(|k| format!("{k:?}") == name)
}

/// The stable `io::ErrorKind`s, by which a kind is matched up by name.
const IO_KINDS: &[io::ErrorKind] = {
    use io::ErrorKind::*;
    &[
        NotFound,
        PermissionDenied,
        ConnectionRefused,
        ConnectionReset,
        HostUnreachable,
        NetworkUnreachable,
        ConnectionAborted,
        NotConnected,
        AddrInUse,
        AddrNotAvailable,
        NetworkDown,
        BrokenPipe,
        AlreadyExists,
        WouldBlock,
        NotADirectory,
        IsADirectory,
        DirectoryNotEmpty,
        ReadOnlyFilesystem,
        StaleNetworkFileHandle,
        InvalidInput,
        InvalidData,
        TimedOut,
        WriteZero,
        StorageFull,
        NotSeekable,
        QuotaExceeded,
        FileTooLarge,
        ResourceBusy,
        ExecutableFileBusy,
        Deadlock,
        CrossesDevices,
        TooManyLinks,
        InvalidFilename,
        ArgumentListTooLong,
        Interrupted,
        Unsupported,
        UnexpectedEof,
        OutOfMemory,
        Other,
    ]
};

/// How a remote fn's return value crosses the wire, picked by type in
/// the generated code: `Result<T, anyhow::Error>` sends its error as a
/// [`WireError`], anything else is serialised as is. A blanket impl
/// can't express "Serialize, except anyhow results" (the two would
/// overlap as far as coherence knows), so the macros use autoref
/// specialisation: `(&Return::<R>::new()).encode(..)` finds
/// `ViaWireError` on `Return<R>` first and falls back to
/// `ViaSerde` on `&Return<R>`. That only resolves for a concrete
/// `R`, which every remote fn's return type is.
#[doc(hidden)]
pub mod wire {
    use std::marker::PhantomData;

    use serde::Serialize;
    use serde::de::DeserializeOwned;

    use super::WireError;

    pub struct Return<R>(PhantomData<R>);

    impl<R> Return<R> {
        #[allow(clippy::new_without_default)]
        pub const fn new() -> Self {
            Return(PhantomData)
        }
    }

    pub trait ViaWireError {
        type Value;
        fn encode(&self, value: Self::Value) -> postcard::Result<Vec<u8>>;
        fn decode(&self, bytes: &[u8]) -> postcard::Result<Self::Value>;
    }

    impl<T: Serialize + DeserializeOwned> ViaWireError for Return<super::Result<T>> {
        type Value = super::Result<T>;

        fn encode(&self, value: Self::Value) -> postcard::Result<Vec<u8>> {
            postcard::to_allocvec(&value.as_ref().map_err(WireError::from))
        }

        fn decode(&self, bytes: &[u8]) -> postcard::Result<Self::Value> {
            Ok(postcard::from_bytes::<Result<T, WireError>>(bytes)?.map_err(super::Error::from))
        }
    }

    pub trait ViaSerde {
        type Value;
        fn encode(&self, value: Self::Value) -> postcard::Result<Vec<u8>>;
        fn decode(&self, bytes: &[u8]) -> postcard::Result<Self::Value>;
    }

    impl<R: Serialize + DeserializeOwned> ViaSerde for &Return<R> {
        type Value = R;

        fn encode(&self, value: R) -> postcard::Result<Vec<u8>> {
            postcard::to_allocvec(&value)
        }

        fn decode(&self, bytes: &[u8]) -> postcard::Result<R> {
            postcard::from_bytes(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wire::{Return, ViaSerde as _, ViaWireError as _};
    use super::*;

    fn over_the_wire<R>(value: R) -> R
    where
        R: serde::Serialize + serde::de::DeserializeOwned,
    {
        let bytes = (&Return::<R>::new()).encode(value).unwrap();
        (&Return::<R>::new()).decode(&bytes).unwrap()
    }

    // The macros' exact call form, borrow included.
    #[allow(clippy::needless_borrow)]
    fn over_the_wire_result(value: Result<u8>) -> Result<u8> {
        let bytes = (&Return::<Result<u8>>::new()).encode(value).unwrap();
        (&Return::<Result<u8>>::new()).decode(&bytes).unwrap()
    }

    fn chain(e: &Error) -> Vec<String> {
        e.chain().map(ToString::to_string).collect()
    }

    #[test]
    fn the_whole_chain_crosses_not_just_the_outermost_message() {
        let local = std::fs::read("/nonexistent/cindy-error-test")
            .context("reading the config")
            .context("configuring nginx")
            .unwrap_err();
        let remote = over_the_wire_result(Err(local)).unwrap_err();

        let chain = chain(&remote);
        assert_eq!(chain.len(), 3, "{chain:?}");
        assert_eq!(chain[0], "configuring nginx");
        assert_eq!(chain[1], "reading the config");
        assert!(chain[2].contains("No such file or directory"), "{chain:?}");
        assert!(
            format!("{remote:#}").starts_with("configuring nginx: reading the config: "),
            "{remote:#}"
        );
    }

    #[test]
    fn io_errors_keep_their_kind_and_are_downcastable_like_local_ones() {
        let local = std::fs::read("/nonexistent/cindy-error-test")
            .context("reading the config")
            .unwrap_err();
        let remote = over_the_wire_result(Err(local)).unwrap_err();

        let io = remote
            .downcast_ref::<io::Error>()
            .expect("no io::Error in chain");
        assert_eq!(io.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            remote
                .downcast_ref::<RemoteError>()
                .map(ToString::to_string),
            Some("reading the config".to_owned())
        );
    }

    #[test]
    fn links_that_were_not_io_errors_are_not_io_errors_after() {
        let remote = over_the_wire_result(Err(anyhow!("plain failure"))).unwrap_err();
        assert!(remote.downcast_ref::<io::Error>().is_none());
        assert_eq!(chain(&remote), ["plain failure"]);
    }

    #[test]
    fn unknown_io_kind_degrades_to_a_plain_link() {
        let wire = WireError(vec![WireLink {
            message: "from a newer std".to_owned(),
            io_kind: Some("SomeFutureKind".to_owned()),
        }]);
        let e = Error::from(wire);
        assert!(e.downcast_ref::<io::Error>().is_none());
        assert_eq!(chain(&e), ["from a newer std"]);
    }

    #[test]
    fn every_listed_io_kind_round_trips_by_name() {
        for &kind in IO_KINDS {
            assert_eq!(io_kind(&format!("{kind:?}")), Some(kind));
        }
    }

    #[test]
    fn ok_values_and_non_result_returns_cross_unchanged() {
        assert_eq!(over_the_wire_result(Ok(7)).unwrap(), 7);
        assert_eq!(
            over_the_wire((1u8, "two".to_owned())),
            (1, "two".to_owned())
        );
    }

    #[test]
    fn typed_serde_errors_cross_as_themselves() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        enum Typed {
            Missing { what: String },
        }
        let back = over_the_wire::<std::result::Result<(), Typed>>(Err(Typed::Missing {
            what: "eth0".to_owned(),
        }));
        assert_eq!(
            back,
            Err(Typed::Missing {
                what: "eth0".to_owned()
            })
        );
    }
}
