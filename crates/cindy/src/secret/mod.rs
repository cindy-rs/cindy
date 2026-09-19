//! Vaulted secrets. A `Secret<T>` is a wrapper that:
//!
//!   * Round-trips through serde — JSON, postcard, anything — as a
//!     compact tagged blob (`{ vault, ciphertext }`).
//!   * Reveals the inner `T` only on an explicit `.reveal()` call,
//!     using a per-vault key looked up at runtime.
//!   * Refuses to leak the plaintext via `Debug`/`Display`. The
//!     plaintext buffers on the reveal path are wiped with `zeroize`
//!     after use (the decrypted `SealedPayload`, the raw key bytes
//!     handed to the keychain); transport frames and the sealed
//!     ciphertext form are *not* scrubbed — treat swapped/coredumped
//!     memory as out of scope for this design.
//!
//! There are two states the type lives in over its lifecycle. **Plain**
//! is only meant to exist transiently in source code that hasn't been
//! sealed yet (and at runtime in dev/tests); the `cindy secret seal`
//! workflow rewrites these into the **Sealed** form. The sealed form
//! is what the CLI actually serialises, deserialises, and ships to the
//! orchestrator process through the host-context hand-off (see
//! `cindy::entry`), and so on.

use std::fmt;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use zeroize::Zeroize as _;

pub mod crypto;
pub mod keychain;

use crate::Context as _;

/// Vaulted wrapper over `T`.
///
/// Two states:
///   * `Plain(T)` — pre-seal. The CLI's `cindy secret seal` step rewrites
///     this in source to `Sealed { .. }`. At runtime, `.reveal()` just
///     hands the inner value back.
///   * `Sealed { vault, ciphertext }` — committed form. `.reveal()`
///     looks up the named vault's key via the keychain and decrypts.
pub enum Secret<T> {
    Plain(T),
    Sealed { vault: String, ciphertext: Vec<u8> },
}

/// What actually gets encrypted by `cindy secret seal`. The wrapper
/// carries both the postcard-encoded `T` (so `Secret::<T>::reveal`
/// can hand a typed value back to user code) *and* the literal
/// source-tokens of the original `secret!` value expression (so
/// `cindy secret unseal` can splice the same syntax back into the file
/// and recover the editable shape).
///
/// Cost: roughly 2× the ciphertext size compared with a postcard-only
/// payload. Worth it for the round-trip UX — and `cargo fmt` cleans up
/// the whitespace `stringify!()` injects.
#[doc(hidden)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SealedPayload {
    /// `postcard::to_allocvec(&value)` — the bytes `Secret<T>::reveal`
    /// hands to `postcard::from_bytes::<T>(...)`.
    pub value: Vec<u8>,
    /// `stringify!($value)` captured at macro time. Used only by
    /// `cindy secret unseal` to put the original `secret!(...)` call
    /// back. Encrypted alongside `value` so leaking nothing about
    /// shape/field-names.
    pub source: String,
}

impl<T> Secret<T> {
    /// Construct a not-yet-sealed secret. Used in source code before
    /// `cindy secret seal` rewrites it. Never produced at runtime on the
    /// orchestrator.
    pub fn new(value: T) -> Self {
        Self::Plain(value)
    }

    /// Construct an already-sealed secret. Used by the seal step (and
    /// by serde deserialisation).
    pub fn sealed(vault: impl Into<String>, ciphertext: Vec<u8>) -> Self {
        Self::Sealed {
            vault: vault.into(),
            ciphertext,
        }
    }

    /// Construct a sealed secret from a base64-encoded ciphertext.
    /// This is the constructor the `cindy secret seal` source-rewriter
    /// emits in your code, because pasting raw bytes into a `.rs` file
    /// is awful and base64 is unambiguous + greppable.
    ///
    /// Panics at runtime if `ciphertext_b64` isn't valid base64; we'd
    /// rather fail loudly than silently produce a `Sealed` with bogus
    /// bytes that only blows up much later in `.reveal()`.
    pub fn sealed_b64(vault: impl Into<String>, ciphertext_b64: &str) -> Self {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_b64.as_bytes())
            .expect("`Secret::sealed_b64` got non-base64 ciphertext");
        Self::Sealed {
            vault: vault.into(),
            ciphertext: bytes,
        }
    }

    /// Name of the vault this secret is encrypted under. `Plain`
    /// secrets have no vault yet; this returns `None` for them.
    pub fn vault(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Sealed { vault, .. } => Some(vault.as_str()),
        }
    }
}

/// Inventory-crate slot for a `secret!(...)` macro invocation waiting
/// to be sealed. The `#[cindy::main]`-generated entry walks all
/// `PendingSecret`s when launched with `CINDY_SEAL_SECRETS=1`, invokes
/// each `serialize` thunk to get the plaintext bytes, encrypts them
/// under the named vault's key, and emits one JSON object per pending
/// secret on stdout so the CLI can patch the source files.
///
/// The same registry doubles as the *vault-preflight* source: iterating
/// it yields every vault literal compiled into the binary (see
/// [`registered_vaults`]).
#[doc(hidden)]
pub struct PendingSecret {
    /// Source-file path captured by `file!()` at the macro call site.
    pub file: &'static str,
    /// 1-based line number from `line!()`.
    pub line: u32,
    /// 1-based column number from `column!()`.
    pub column: u32,
    /// Vault name (the macro's first argument).
    pub vault: &'static str,
    /// Thunk that re-evaluates the macro's value expression and
    /// returns its `postcard`-serialised bytes. Required to be a
    /// `fn` pointer (no captures) so it's registerable at link time;
    /// this is what forces the "literals-only" constraint on
    /// `secret!`.
    pub serialize: fn() -> Vec<u8>,
}

inventory::collect!(PendingSecret);

/// Collect the distinct vaults referenced by `secret!` invocations
/// compiled into this binary.
///
/// This is the "secrets in code" half of the vault preflight. It's an
/// over-approximation of what a given run will actually touch — it
/// includes `secret!`s in code paths a host might not hit, and can't
/// tell whether a given secret reveals on the orchestrator or a worker
/// (that isn't recoverable cross-crate). Both are the conservative bias
/// a key preflight wants: every participating machine is simply
/// required to hold every vault any `secret!` references, so a run can
/// never fail mid-play on a missing in-code secret key.
///
/// The *precise*, per-host half — secrets living in inventory `vars` —
/// is handled separately by walking the host's data (see the CLI and
/// `inventory`), because there the exact vault set per host *is*
/// knowable.
#[doc(hidden)]
pub fn registered_vaults() -> Vec<String> {
    let mut vaults: Vec<String> = crate::__reexports::inventory::iter::<PendingSecret>()
        .map(|p| p.vault.to_owned())
        .collect();
    vaults.sort();
    vaults.dedup();
    vaults
}

/// Verify that every vault in `vaults` has a reachable key, returning
/// the sorted list of those that don't.
///
/// "Reachable" means the keychain can load it — from the in-memory
/// cache (on a worker, pre-installed from `CINDY_VAULT_KEYS`) or the
/// on-disk `keys/<vault>.key` (on the orchestrator). This is the actual
/// preflight probe: it touches no ciphertext, just confirms the key is
/// present, so it can run before any real work.
#[doc(hidden)]
pub fn missing_vaults<I, S>(vaults: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut missing: Vec<String> = vaults
        .into_iter()
        .filter(|v| keychain::get_vault_key(v.as_ref()).is_err())
        .map(|v| v.as_ref().to_owned())
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

/// Run the vault preflight for a participant (orchestrator or worker):
/// the union of every `secret!`-referenced vault compiled into this
/// binary plus any vaults found in `host_context_json` (a serialised
/// `Host<V>`, whose sealed `vars` secrets are walked precisely). If any
/// key is missing, print an actionable message naming all of them and
/// return `Err` so the caller can fail before doing any work.
///
/// `host_context_json` is optional: pass `None` for the zero-arg `main`
/// shape (no host context), in which case only the in-code `secret!`
/// vaults are checked.
#[doc(hidden)]
pub fn preflight(role: &str, host_context_json: Option<&str>) -> crate::Result<()> {
    let mut needed: std::collections::BTreeSet<String> = registered_vaults().into_iter().collect();

    if let Some(json) = host_context_json {
        let value: crate::__reexports::serde_json::Value =
            crate::__reexports::serde_json::from_str(json)
                .context("host context was not valid JSON during vault preflight")?;
        crate::inventory::collect_sealed_vaults(&value, &mut needed);
    }

    let missing = missing_vaults(&needed);
    if missing.is_empty() {
        return Ok(());
    }
    crate::bail!(
        "missing decryption keys before {role} could start: \
         no key available for vault(s) {missing:?}. \
         Provision the key file(s) (`cindy secret vault create <name>`, \
         or copy `keys/<name>.key` from a teammate) and re-run. \
         Failing now rather than partway through the play."
    )
}

#[allow(non_snake_case, unused)]
#[deprecated(
    since = "0.0.0",
    note = "\n\n⚠️ Unsealed secret. Run `cindy secret seal`.\n\n"
)]
#[doc(hidden)]
pub fn UNSEALED_SECRET() {}

/// Wrap a literal value in a [`Secret<T>`] and register it for the
/// `cindy secret seal` step to encrypt in-place.
///
/// At runtime this expands to a [`Secret<T>::Plain`]. Your code will
/// be analyzed and will compile, but you might not be able to run
/// it, depending on where the [`Secret`] is present, and if it needs
/// to be transferred over the wire
/// (in other words; if [`serde::Serialize`] needs to be used).
///
/// To seal the secret, use `cindy secret seal [--all]`.
/// The [`secret!`] calls will get rewritten in the source code to a [`Secret::sealed_b64`]
/// call containing the encrypted value + encrypted raw tokens for `cindy secret unseal [--all]`.
///
/// The values used as secrets must be either constants or literals
/// (or [`include_str!`] / [`include_bytes!`]; anything resolvable at compile time).
/// You cannot capture variables from local scope. Doing so will surface as E0435 or E0425.
///
/// ```rust,ignore
/// let pw = cindy::secret!("prod", Credentials {
///     user: "admin".into(),
///     pw:   "hunter2".into(),
/// });
/// // After `cindy secret seal`:
/// // let pw = ::cindy::Secret::sealed_b64("prod", "AAAA...");
/// ```
#[macro_export]
macro_rules! secret {
    ($vault:literal, $value:expr $(,)?) => {{
        #[allow(non_upper_case_globals)]
        const __CINDY_SECRET_VALUES_MUST_BE_SELF_CONTAINED: fn() -> ::std::vec::Vec<u8> = || {
            let value_bytes = $crate::__reexports::postcard::to_allocvec(&($value))
                .expect("`cindy::secret!`: postcard couldn't serialise the value");
            let payload = $crate::secret::SealedPayload {
                value: value_bytes,
                source: ::core::stringify!($value).to_owned(),
            };
            $crate::__reexports::postcard::to_allocvec(&payload)
                .expect("`cindy::secret!`: postcard couldn't serialise the SealedPayload")
        };
        $crate::__reexports::inventory::submit! {
            $crate::secret::PendingSecret {
                file:      ::core::file!(),
                line:      ::core::line!(),
                column:    ::core::column!(),
                vault:     $vault,
                serialize: __CINDY_SECRET_VALUES_MUST_BE_SELF_CONTAINED,
            }
        }

        $crate::secret::UNSEALED_SECRET();

        $crate::Secret::new($value)
    }};
}

impl<T: serde::de::DeserializeOwned> Secret<T> {
    /// Reveal the inner value. For `Plain`, returns it as-is. For
    /// `Sealed`, fetches the vault key from the keychain, decrypts
    /// the ciphertext into a [`SealedPayload`], and
    /// `postcard`-deserialises the inner `T` out of its `value`
    /// field. The `source` field of the payload is ignored here —
    /// it's there for `cindy secret unseal`.
    pub fn reveal(self) -> crate::Result<T> {
        match self {
            Self::Plain(v) => Ok(v),
            Self::Sealed { vault, ciphertext } => {
                let key = keychain::get_vault_key(&vault)?;
                let plaintext = crypto::unseal(&key, &ciphertext)?;
                let mut payload: SealedPayload =
                    postcard::from_bytes(&plaintext).context(format!(
                            "couldn't deserialise SealedPayload for vault `{vault}`. \
                             If this secret was sealed by an older cindy version, \
                             rewrite it as `cindy::secret!(\"{vault}\", ..)` and re-run `cindy secret seal`."
                        ))?;
                let value: T = postcard::from_bytes(&payload.value)
                    .context(format!("couldn't deserialise inner T for vault `{vault}`"))?;
                payload.value.zeroize();
                payload.source.zeroize();
                Ok(value)
            }
        }
    }
}

thread_local! {
    /// When set, the `Debug` and `Serialize` impls of `Secret<T>`
    /// decrypt and render the real inner value instead of redacting it.
    /// Scoped strictly to the closure passed to [`with_revealed_secrets`]
    /// so it can never leak into ordinary logging or persisted output.
    static REVEAL_SECRETS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether reveal mode is currently active on this thread.
pub(crate) fn revealing() -> bool {
    REVEAL_SECRETS.with(|c| c.get())
}

/// Run `f` with secret revelation enabled on the current thread, then
/// restore the previous setting. Inside the closure, `Debug` and
/// `Serialize` of any `Secret<T>` render the *decrypted value* rather
/// than `<secret vault=…>` / the sealed `{vault, ciphertext}` blob.
///
/// This is *only* wired up by `cindy inventory --reveal`, which runs in
/// the orchestrator process where the vault keys are reachable. It is
/// deliberately not exposed to normal operation — a misplaced reveal is
/// exactly the leak `Secret` exists to prevent.
pub fn with_revealed_secrets<R>(f: impl FnOnce() -> R) -> R {
    let _guard = REVEAL_SECRETS.with(|c| RevealGuard(c.replace(true)));
    f()
}

/// Restores `REVEAL_SECRETS` on drop.
///
/// Saving and restoring around the call is not equivalent: if `f`
/// panics, the restore never runs and reveal mode stays set on a thread
/// the tokio runtime will hand to the next task — whose `Debug` /
/// `Serialize` would then emit plaintext. Unwinding through `Drop` is
/// what makes the scope actually scoped.
struct RevealGuard(bool);

impl Drop for RevealGuard {
    fn drop(&mut self) {
        REVEAL_SECRETS.with(|c| c.set(self.0));
    }
}

impl<T: serde::de::DeserializeOwned> Secret<T> {
    /// Decrypt into the inner `T` by reference (for reveal rendering).
    /// Unlike [`Secret::reveal`], doesn't consume `self`. `Plain` is
    /// not decryptable by reference (we can't move the value out), so
    /// it errors — but `Plain` never reaches the reveal path in
    /// practice, since the orchestrator only renders sealed inventories.
    fn reveal_ref(&self) -> crate::Result<T> {
        match self {
            Self::Plain(_) => crate::bail!("cannot reveal a `Plain` secret by reference"),
            Self::Sealed { vault, ciphertext } => {
                let key = keychain::get_vault_key(vault)?;
                let plaintext = crypto::unseal(&key, ciphertext)?;
                let mut payload: SealedPayload = postcard::from_bytes(&plaintext).context(
                    format!("couldn't deserialise SealedPayload for vault `{vault}`"),
                )?;
                let value: T = postcard::from_bytes(&payload.value)
                    .context(format!("couldn't deserialise inner T for vault `{vault}`"))?;
                payload.value.zeroize();
                payload.source.zeroize();
                Ok(value)
            }
        }
    }
}

impl<T: fmt::Debug + serde::de::DeserializeOwned> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if revealing() {
            match self.reveal_ref() {
                Ok(value) => return value.fmt(f),
                Err(e) => return write!(f, "<secret reveal failed: {e}>"),
            }
        }
        match self {
            Self::Plain(_) => write!(f, "<secret plain>"),
            Self::Sealed { vault, .. } => write!(f, "<secret vault={vault}>"),
        }
    }
}

impl<T: Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Plain(v) => Self::Plain(v.clone()),
            Self::Sealed { vault, ciphertext } => Self::Sealed {
                vault: vault.clone(),
                ciphertext: ciphertext.clone(),
            },
        }
    }
}

// Note: deliberately no `Drop` impl. We'd want one for zeroizing the
// ciphertext buffer, but auto-`Drop` makes `reveal(self)` impossible
// (you can't move out of a type that implements `Drop`). Ciphertext is
// non-secret material once it's left our process anyway; the
// load-bearing zeroize is on the plaintext that lives inside the
// `Zeroizing<Vec<u8>>` returned by [`crypto::unseal`] during a
// `.reveal()` call. For `Plain(T)` containing sensitive data, callers
// should make sure `T` itself uses zeroize-aware types.

// ---- serde ---------------------------------------------------------
//
// The on-the-wire shape is **always** the sealed form. `Plain` values
// serialise by encrypting on the fly (so JSON dumps from a dev `main`
// don't leak plaintext to disk). The `vault` lookup pulls a vault key from
// the keychain at serialisation time — note this means *Plain* secrets
// can't be serialised by code that doesn't have the vault key loaded;
// that's a deliberate guardrail, not a bug.
//
// Deserialisation always produces `Sealed`; revealing requires an
// explicit `.reveal()` call.

#[derive(Serialize, Deserialize)]
struct WireForm<'a> {
    vault: std::borrow::Cow<'a, str>,
    /// Base64 of the AEAD blob (nonce || ciphertext || tag).
    ciphertext: std::borrow::Cow<'a, str>,
}

impl<T: Serialize + serde::de::DeserializeOwned> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        // Reveal mode (orchestrator, `inventory --reveal --json`):
        // decrypt and serialise the *plaintext value* in place of the
        // sealed blob. Strictly scoped to `with_revealed_secrets`.
        if revealing() {
            let value = self.reveal_ref().map_err(S::Error::custom)?;
            return value.serialize(serializer);
        }
        match self {
            Self::Sealed { vault, ciphertext } => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
                WireForm {
                    vault: std::borrow::Cow::Borrowed(vault),
                    ciphertext: std::borrow::Cow::Owned(b64),
                }
                .serialize(serializer)
            }
            Self::Plain(_) => Err(S::Error::custom(
                "refusing to serialise a `Secret::Plain(_)`. \
                 Run `cindy secret seal` to turn it into `Secret::Sealed { .. }` \
                 before persisting it (or any inventory containing it).",
            )),
        }
    }
}

impl<'de, T> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let wire = WireForm::deserialize(deserializer)?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(wire.ciphertext.as_bytes())
            .map_err(D::Error::custom)?;
        Ok(Self::Sealed {
            vault: wire.vault.into_owned(),
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Creds {
        user: String,
        pw: String,
    }

    #[test]
    fn debug_never_leaks_plain() {
        let s = Secret::new(Creds {
            user: "alice".into(),
            pw: "hunter2".into(),
        });
        let out = format!("{s:?}");
        assert!(!out.contains("alice"));
        assert!(!out.contains("hunter2"));
        assert_eq!(out, "<secret plain>");
    }

    #[test]
    fn debug_includes_vault_for_sealed() {
        let s: Secret<Creds> = Secret::sealed("prod", b"ignored".to_vec());
        let out = format!("{s:?}");
        assert!(out.contains("prod"));
    }

    #[test]
    fn refuses_to_serialise_plain() {
        let s = Secret::new(Creds {
            user: "alice".into(),
            pw: "hunter2".into(),
        });
        assert!(serde_json::to_string(&s).is_err());
    }

    #[test]
    fn sealed_round_trips_through_json() {
        let s: Secret<()> = Secret::sealed("prod", vec![1, 2, 3, 4]);
        let j = serde_json::to_string(&s).unwrap();
        let back: Secret<()> = serde_json::from_str(&j).unwrap();
        assert!(matches!(back, Secret::Sealed { ref vault, ref ciphertext }
                              if vault == "prod" && ciphertext == &[1, 2, 3, 4]));
    }

    #[test]
    fn reveal_plain_is_identity() {
        let s = Secret::new(Creds {
            user: "u".into(),
            pw: "p".into(),
        });
        let revealed = s.reveal().unwrap();
        assert_eq!(revealed.user, "u");
        assert_eq!(revealed.pw, "p");
    }

    #[test]
    fn reveal_sealed_roundtrip_with_installed_key() {
        let key = crypto::generate_vault_key();
        let creds = Creds {
            user: "alice".into(),
            pw: "hunter2".into(),
        };
        let payload = SealedPayload {
            value: postcard::to_allocvec(&creds).unwrap(),
            source: "Creds { user: \"alice\".into(), pw: \"hunter2\".into() }".to_owned(),
        };
        let payload_bytes = postcard::to_allocvec(&payload).unwrap();
        let ciphertext = crypto::seal(&key, &payload_bytes).unwrap();

        let mut chain = std::collections::HashMap::new();
        chain.insert("test-reveal".to_owned(), key);
        keychain::install_keys(chain);

        let s: Secret<Creds> = Secret::sealed("test-reveal", ciphertext);
        let revealed = s.reveal().unwrap();
        assert_eq!(revealed, creds);
    }

    fn seal_creds(vault: &str, creds: &Creds) -> Vec<u8> {
        let key = crypto::generate_vault_key();
        let payload = SealedPayload {
            value: postcard::to_allocvec(creds).unwrap(),
            source: "ignored".to_owned(),
        };
        let ciphertext = crypto::seal(&key, &postcard::to_allocvec(&payload).unwrap()).unwrap();
        let mut chain = std::collections::HashMap::new();
        chain.insert(vault.to_owned(), key);
        keychain::install_keys(chain);
        ciphertext
    }

    #[test]
    fn debug_reveal_prints_real_value_only_inside_scope() {
        let creds = Creds {
            user: "bob".into(),
            pw: "s3cr3t".into(),
        };
        let s: Secret<Creds> = Secret::sealed("dbg-reveal", seal_creds("dbg-reveal", &creds));

        // Default: redacted.
        assert_eq!(format!("{s:?}"), "<secret vault=dbg-reveal>");

        // Inside the scope: the *decrypted value's* own Debug, not the
        // source tokens.
        let revealed = with_revealed_secrets(|| format!("{s:?}"));
        assert_eq!(revealed, format!("{creds:?}"));
        assert!(revealed.contains("s3cr3t"));

        // Flag is restored afterwards.
        assert_eq!(format!("{s:?}"), "<secret vault=dbg-reveal>");
    }

    #[test]
    fn serialize_reveal_emits_plaintext_value_inside_scope() {
        let creds = Creds {
            user: "carol".into(),
            pw: "pw123".into(),
        };
        let s: Secret<Creds> = Secret::sealed("ser-reveal", seal_creds("ser-reveal", &creds));

        // Default: sealed blob with vault + ciphertext, no plaintext.
        let sealed_json = serde_json::to_value(&s).unwrap();
        assert!(sealed_json.get("ciphertext").is_some());
        assert!(!sealed_json.to_string().contains("pw123"));

        // Revealed: the plaintext value serialised in place.
        let revealed = with_revealed_secrets(|| serde_json::to_value(&s).unwrap());
        assert_eq!(revealed, serde_json::to_value(&creds).unwrap());
        assert_eq!(revealed["pw"], "pw123");
    }

    #[test]
    fn collect_sealed_vaults_finds_nested_secrets() {
        let value = crate::inventory::Host {
            name: "h1".into(),
            tags: crate::tags![],
            vars: serde_json::json!({
                "api_token": { "vault": "prod", "ciphertext": "AAAA" },
                "nested": {
                    "deep": { "vault": "staging", "ciphertext": "BBBB" }
                },
                "list": [
                    { "vault": "prod", "ciphertext": "CCCC" },
                    { "vault": "ci", "ciphertext": "DDDD" }
                ],
                "decoy_vault_only": { "vault": "not-a-secret" },
                "decoy_ct_only": { "ciphertext": "no-vault" }
            }),
        };

        let mut out = std::collections::BTreeSet::new();
        crate::inventory::collect_sealed_vaults(&serde_json::to_value(value).unwrap(), &mut out);
        let got: Vec<&str> = out.iter().map(String::as_str).collect();
        assert_eq!(got, vec!["ci", "prod", "staging"]);
    }

    #[test]
    fn missing_vaults_reports_unavailable_only() {
        // Install one vault; the other should be reported missing.
        let key = crypto::generate_vault_key();
        let mut chain = std::collections::HashMap::new();
        chain.insert("present-vault".to_owned(), key);
        keychain::install_keys(chain);

        let missing = missing_vaults(["present-vault", "absent-vault-xyz"]);
        assert_eq!(missing, vec!["absent-vault-xyz".to_owned()]);
    }

    #[test]
    fn a_panic_inside_a_reveal_scope_does_not_leave_reveal_mode_set() {
        // The scope has to survive unwinding: tokio hands the thread to
        // the next task, and a leaked flag would make *its* `Debug` emit
        // plaintext.
        let caught = std::panic::catch_unwind(|| {
            with_revealed_secrets(|| panic!("boom"));
        });
        assert!(caught.is_err(), "the panic must propagate");
        assert!(!revealing(), "reveal mode leaked past a panicking scope");

        let s: Secret<Creds> = Secret::sealed("leak-check", vec![1, 2, 3]);
        assert_eq!(format!("{s:?}"), "<secret vault=leak-check>");
    }

    #[test]
    fn debug_reveal_failure_does_not_leak_and_does_not_panic() {
        // No key installed for this vault → reveal fails gracefully.
        let s: Secret<Creds> = Secret::sealed("no-such-vault-for-debug", vec![9, 9, 9]);
        let out = with_revealed_secrets(|| format!("{s:?}"));
        assert!(out.starts_with("<secret reveal failed:"));
    }
}
