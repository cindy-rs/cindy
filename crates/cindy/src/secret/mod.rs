//! Vaulted secrets: a value that serialises only sealed, never
//! `Debug`-prints, and decrypts only on an explicit
//! [`reveal`](Secret::reveal).
//!
//! Plaintext buffers on the reveal path are zeroized. Transport frames
//! and ciphertext aren't, and swapped or core-dumped memory is out of
//! scope.

use std::fmt;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use zeroize::Zeroize as _;

pub mod crypto;
pub mod keychain;

use crate::Context as _;

// No zeroizing `Drop`: it would forbid moving out in `reveal(self)`,
// and ciphertext isn't secret. A `Plain(T)` that matters should hold
// zeroize-aware types.
#[derive(Clone)]
pub enum Secret<T> {
    /// What `secret!` produces in source, until `cindy secret seal`
    /// rewrites it. Refuses to serialise.
    Plain(T),
    /// The committed form; decrypts with the vault's key.
    Sealed { vault: String, ciphertext: Vec<u8> },
}

/// What `cindy secret seal` encrypts: the value, and the source tokens
/// of the `secret!` expression so `unseal` can put the editable form
/// back — about twice the size, for a lossless round trip.
#[doc(hidden)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SealedPayload {
    /// postcard of the value.
    pub value: Vec<u8>,
    /// `stringify!` of the expression.
    pub source: String,
}

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self::Plain(value)
    }

    pub fn sealed(vault: impl Into<String>, ciphertext: Vec<u8>) -> Self {
        Self::Sealed {
            vault: vault.into(),
            ciphertext,
        }
    }

    /// What `cindy secret seal` writes into source. Panics on invalid
    /// base64 — loudly now, rather than at a much later `reveal`.
    pub fn sealed_b64(vault: impl Into<String>, ciphertext_b64: &str) -> Self {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_b64.as_bytes())
            .expect("`Secret::sealed_b64` got non-base64 ciphertext");
        Self::Sealed {
            vault: vault.into(),
            ciphertext: bytes,
        }
    }

    /// `None` until sealed.
    pub fn vault(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Sealed { vault, .. } => Some(vault.as_str()),
        }
    }
}

/// A `secret!` waiting to be sealed, registered at link time. Also the
/// source of [`registered_vaults`].
#[doc(hidden)]
pub struct PendingSecret {
    pub file: &'static str,
    pub line: u32,
    pub column: u32,
    pub vault: &'static str,
    /// The `SealedPayload` bytes. A `fn` pointer so it registers at
    /// link time — hence `secret!` takes no captures.
    pub serialize: fn() -> Vec<u8>,
}

inventory::collect!(PendingSecret);

/// Every vault a `secret!` in this binary names. An over-approximation
/// — paths a host never takes, orchestrator- and worker-side alike —
/// which is the right bias for a preflight: it can't let a run fail
/// halfway on a missing key. Secrets in inventory `vars` are walked
/// per host instead, where the exact set is knowable.
#[doc(hidden)]
pub fn registered_vaults() -> Vec<String> {
    let mut vaults: Vec<String> = crate::__reexports::inventory::iter::<PendingSecret>()
        .map(|p| p.vault.to_owned())
        .collect();
    vaults.sort();
    vaults.dedup();
    vaults
}

/// The vaults the keychain can't load, sorted.
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

/// Fail before any work if a key for a vault in this binary or in the
/// host's context is missing.
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

/// A [`Secret::Plain`] in source, registered for `cindy secret seal`,
/// which rewrites the call into an encrypted [`Secret::sealed_b64`]
/// (`cindy secret unseal` puts it back). Until sealed it warns, and
/// refuses to cross the wire.
///
/// The value must be self-contained — literals, constants,
/// `include_str!` — not local variables (E0435/E0425).
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
    pub fn reveal(self) -> crate::Result<T> {
        match self {
            Self::Plain(v) => Ok(v),
            Self::Sealed { vault, ciphertext } => decrypt(&vault, &ciphertext),
        }
    }

    /// For reveal-mode rendering, which can't consume. A `Plain` can't
    /// be revealed by reference, and never reaches that path.
    fn reveal_ref(&self) -> crate::Result<T> {
        match self {
            Self::Plain(_) => crate::bail!("cannot reveal a `Plain` secret by reference"),
            Self::Sealed { vault, ciphertext } => decrypt(vault, ciphertext),
        }
    }
}

fn decrypt<T: serde::de::DeserializeOwned>(vault: &str, ciphertext: &[u8]) -> crate::Result<T> {
    let key = keychain::get_vault_key(vault)?;
    let plaintext = crypto::unseal(&key, ciphertext)?;
    let mut payload: SealedPayload = postcard::from_bytes(&plaintext).context(format!(
        "couldn't deserialise SealedPayload for vault `{vault}`. If this secret was sealed \
         by an older cindy version, rewrite it as `cindy::secret!(\"{vault}\", ..)` and \
         re-run `cindy secret seal`."
    ))?;
    let value = postcard::from_bytes(&payload.value)
        .context(format!("couldn't deserialise inner T for vault `{vault}`"));
    payload.value.zeroize();
    payload.source.zeroize();
    value
}

thread_local! {
    static REVEAL_SECRETS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn revealing() -> bool {
    REVEAL_SECRETS.with(|c| c.get())
}

/// Inside `f`, on this thread, `Debug` and `Serialize` of a `Secret`
/// render the decrypted value. Only `cindy inventory --reveal` uses it;
/// anywhere else it is the leak `Secret` exists to prevent.
pub fn with_revealed_secrets<R>(f: impl FnOnce() -> R) -> R {
    let _guard = REVEAL_SECRETS.with(|c| RevealGuard(c.replace(true)));
    f()
}

/// A guard, not save-and-restore: a panic in `f` would otherwise leave
/// reveal mode on, for whichever task tokio runs on this thread next.
struct RevealGuard(bool);

impl Drop for RevealGuard {
    fn drop(&mut self) {
        REVEAL_SECRETS.with(|c| c.set(self.0));
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

// The wire form is always sealed: a `Plain` refuses to serialise
// rather than leak or fake one, except in reveal mode. Deserialising
// always yields `Sealed`.
#[derive(Serialize, Deserialize)]
struct WireForm<'a> {
    vault: std::borrow::Cow<'a, str>,
    ciphertext: std::borrow::Cow<'a, str>,
}

impl<T: Serialize + serde::de::DeserializeOwned> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
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

        assert_eq!(format!("{s:?}"), "<secret vault=dbg-reveal>");

        let revealed = with_revealed_secrets(|| format!("{s:?}"));
        assert_eq!(revealed, format!("{creds:?}"));
        assert!(revealed.contains("s3cr3t"));

        assert_eq!(format!("{s:?}"), "<secret vault=dbg-reveal>");
    }

    #[test]
    fn serialize_reveal_emits_plaintext_value_inside_scope() {
        let creds = Creds {
            user: "carol".into(),
            pw: "pw123".into(),
        };
        let s: Secret<Creds> = Secret::sealed("ser-reveal", seal_creds("ser-reveal", &creds));

        let sealed_json = serde_json::to_value(&s).unwrap();
        assert!(sealed_json.get("ciphertext").is_some());
        assert!(!sealed_json.to_string().contains("pw123"));

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
        let key = crypto::generate_vault_key();
        let mut chain = std::collections::HashMap::new();
        chain.insert("present-vault".to_owned(), key);
        keychain::install_keys(chain);

        let missing = missing_vaults(["present-vault", "absent-vault-xyz"]);
        assert_eq!(missing, vec!["absent-vault-xyz".to_owned()]);
    }

    #[test]
    fn a_panic_inside_a_reveal_scope_does_not_leave_reveal_mode_set() {
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
        let s: Secret<Creds> = Secret::sealed("no-such-vault-for-debug", vec![9, 9, 9]);
        let out = with_revealed_secrets(|| format!("{s:?}"));
        assert!(out.starts_with("<secret reveal failed:"));
    }
}
