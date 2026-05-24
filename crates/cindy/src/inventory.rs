use crate as cindy;

/// The entire fleet as the user's [`cindy::inventory`] function declares
/// it.
#[crate::wire]
pub struct Inventory<V> {
    pub hosts: Vec<Host<V>>,
}

/// Dummy key in [`InventoryDump::debug`] for the whole-inventory
/// `Debug` rendering.
pub const WHOLE_INVENTORY_KEY: &str = "__cindy:all";

/// Walk an arbitrary JSON value and collect the names of every vault a
/// sealed `Secret<T>` in it references.
///
/// A sealed secret serialises (see `secret::WireForm`) as an object
/// `{ "vault": "<name>", "ciphertext": "<base64>" }`, so any object
/// carrying *both* a string `vault` and a string `ciphertext` is taken
/// to be a sealed secret. This is the precise, per-host half of the
/// vault preflight: given a host's (sealed) `vars` as JSON, it yields
/// exactly the vaults that host's data needs — no over-approximation.
///
/// The two-key shape is specific enough that a user struct accidentally
/// matching it would be a remarkable coincidence; even if one did, the
/// only consequence is requiring an extra key, which preflight reports
/// rather than silently mis-handling.
pub fn collect_sealed_vaults(
    value: &serde_json::Value,
    out: &mut std::collections::BTreeSet<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if let (Some(serde_json::Value::String(vault)), Some(serde_json::Value::String(_))) =
                (map.get("vault"), map.get("ciphertext"))
            {
                out.insert(vault.clone());
            }
            for v in map.values() {
                collect_sealed_vaults(v, out);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                collect_sealed_vaults(v, out);
            }
        }
        _ => {}
    }
}

/// What the orchestrator emits on the wire in `CINDY_DUMP_INVENTORY`
/// mode.
///
/// The `json` field is the type-erased `Inventory<serde_json::Value>`
/// the CLI consults for `--limit` targeting (it never names the user's
/// `V`). Secrets in it stay sealed; it never depends on vault keys, so
/// targeting and plain `cindy inventory --json` always work. The
/// `debug` field carries `Debug` renderings produced *inside* the
/// orchestrator, where the real `V` and its `Debug` impl are in scope —
/// keyed by host name, plus [`WHOLE_INVENTORY_KEY`] for the entire
/// `Inventory<V>`. This lets `cindy inventory` print the user's actual
/// struct rather than a JSON-`Value` `Debug`.
///
/// When `cindy inventory --reveal` runs, `debug` is rendered with
/// `Secret<T>` values decrypted, and `json_revealed` is populated with
/// a secrets-decrypted JSON (or an error string if a vault key was
/// missing). Outside reveal mode `json_revealed` is `None`.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(crate = "cindy::__reexports::serde")]
#[doc(hidden)]
pub struct InventoryDump {
    pub json: serde_json::Value,
    pub debug: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub json_revealed: Option<Result<serde_json::Value, String>>,
}

/// Conversion glue so `#[cindy::inventory]` can accept *either*
/// `Inventory<V>` or `Result<Inventory<V>, E>` and always emit the same
/// [`InventoryDump`] shape on the wire.
///
/// The infallible impl serialises through and renders `Debug`. The
/// fallible impl does the same on `Ok`, prints the debug rendering of
/// the error to stderr and exits 1 on `Err`. Either way the CLI reads
/// a clean `InventoryDump` from FD 1 — no `{"Ok": {...}}` wrapper for
/// it to peel.
#[doc(hidden)]
pub trait IntoInventoryDump {
    fn into_inventory_dump(self) -> InventoryDump;
}

/// Build the debug map for an inventory: one entry per host (keyed by
/// `host.name`) plus the whole-inventory rendering under
/// [`WHOLE_INVENTORY_KEY`].
fn build_debug_map<V: std::fmt::Debug>(
    inv: &Inventory<V>,
) -> std::collections::BTreeMap<String, String> {
    let mut debug = std::collections::BTreeMap::new();
    for host in &inv.hosts {
        debug.insert(host.name.clone(), format!("{host:#?}"));
    }
    debug.insert(WHOLE_INVENTORY_KEY.to_owned(), format!("{inv:#?}"));
    debug
}

impl<V: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug> IntoInventoryDump
    for Inventory<V>
{
    fn into_inventory_dump(self) -> InventoryDump {
        let json = serde_json::to_value(&self).expect("Failed to serialise `Inventory<V>` to JSON");

        if std::env::var_os("CINDY_REVEAL_SECRETS").is_some() {
            crate::secret::with_revealed_secrets(|| {
                let debug = build_debug_map(&self);
                let json_revealed = serde_json::to_value(&self).map_err(|e| e.to_string());
                InventoryDump {
                    json,
                    debug,
                    json_revealed: Some(json_revealed),
                }
            })
        } else {
            InventoryDump {
                json,
                debug: build_debug_map(&self),
                json_revealed: None,
            }
        }
    }
}

impl<V: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug, E: std::fmt::Debug>
    IntoInventoryDump for ::std::result::Result<Inventory<V>, E>
{
    fn into_inventory_dump(self) -> InventoryDump {
        match self {
            Ok(inv) => inv.into_inventory_dump(),
            Err(e) => {
                ::std::eprintln!("`#[cindy::inventory]` failed: {e:?}");
                ::std::process::exit(1);
            }
        }
    }
}

#[doc(hidden)]
pub struct RegisteredInventory {
    pub dump: fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = InventoryDump> + Send>>,
}
inventory::collect!(RegisteredInventory);

/// A single deployment target as the orchestrator sees it at run-time.
///
/// `Host<V>` is the runtime view that the `#[cindy::main]`-generated entry
/// hands to your `main`. The generic `V` is *your* per-host vars struct
/// — anything `Serialize + DeserializeOwned`. The CLI itself never
/// names `V`; it only deals with the structural fields (`name`,
/// `tags`) and treats `vars` as an opaque JSON blob that round-trips
/// through `serde_json::Value`. That keeps the CLI ignorant of your
/// project's types while still letting your code reach typed vars.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(crate = "cindy::__reexports::serde")]
pub struct Host<V = ()> {
    /// Operator-facing host name. Whatever the CLI calls this target —
    /// typically the SSH host alias.
    pub name: String,

    /// Free-form labels for filtering via `--limit`. Pure targeting
    /// metadata — no implicit vars resolution / no inheritance.
    /// Composition of per-host vars is done explicitly in the
    /// (eventual) `#[cindy::inventory]` function with normal Rust.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Whatever per-host typed data your inventory wants to surface.
    /// Round-trips through JSON between the CLI and the orchestrator
    /// process; the CLI never deserialises it past
    /// `serde_json::Value`.
    pub vars: V,
}

impl<V> Host<V> {
    /// Build a [`Host`] without spelling out `.into()` / `tags!`. The
    /// struct-literal form (`Host { name, tags, vars }`) still works; this
    /// is just the compact path:
    ///
    /// ```ignore
    /// Host::new("web-01", ["env:prod", "web"], MyVars { .. })
    /// Host::new("web-01", [] as [&str; 0], MyVars { .. }) // no tags
    /// ```
    pub fn new(
        name: impl Into<String>,
        tags: impl IntoIterator<Item = impl Into<String>>,
        vars: V,
    ) -> Self {
        Self {
            name: name.into(),
            tags: tags.into_iter().map(Into::into).collect(),
            vars,
        }
    }
}

impl<V> Inventory<V> {
    /// Build an [`Inventory`] from anything iterable of [`Host`]s, e.g. a
    /// `Vec`, an array, or a `map(..)` chain — no explicit `.collect()`.
    /// The struct-literal form (`Inventory { hosts }`) still works.
    pub fn new(hosts: impl IntoIterator<Item = Host<V>>) -> Self {
        Self {
            hosts: hosts.into_iter().collect(),
        }
    }
}

/// A simple wrapper around the `vec!` macro; all it does is wrap the passed elements inside a
/// `Into::<String>::into` so they're automatically coerced into a `String` without an explicit
/// `.into()` call
#[macro_export]
macro_rules! tags {
    ($($el:expr),* $(,)?) => {
        vec![$(Into::<String>::into($el)),*]
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_inventory_constructors_accept_into() {
        // `&str` name + `&str` array tags, no `.into()` / `tags!`.
        let a = Host::new("web-01", ["env:prod", "web"], 42u64);
        assert_eq!(a.name, "web-01");
        assert_eq!(a.tags, vec!["env:prod", "web"]);
        assert_eq!(a.vars, 42);

        // `String` name + `Vec<String>` tags also fit the `Into` bounds.
        let b = Host::new(String::from("web-02"), vec![String::from("db")], 7u64);
        assert_eq!(b.name, "web-02");

        // No tags: a typed empty iterator (no annotation needed on `Host`).
        let c = Host::new("web-03", std::iter::empty::<&str>(), 1u64);
        assert!(c.tags.is_empty());

        // The struct-literal form is untouched and interops with `::new`.
        let d = Host {
            name: "web-04".into(),
            tags: crate::tags!["t"],
            vars: 0u64,
        };

        let inv = Inventory::new([a, b, c, d]);
        assert_eq!(inv.hosts.len(), 4);
    }
}
