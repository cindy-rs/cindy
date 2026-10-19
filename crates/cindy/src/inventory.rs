/// The fleet, as the playbook's `#[cindy::inventory]` fn declares it.
#[crate::wire]
pub struct Inventory<V> {
    pub hosts: Vec<Host<V>>,
}

/// The [`InventoryDump::debug`] key of the whole inventory.
pub const WHOLE_INVENTORY_KEY: &str = "__cindy:all";

/// Every vault a sealed secret in `value` names — the exact per-host
/// half of the key preflight. A sealed secret serialises as
/// `{ "vault": "…", "ciphertext": "…" }`; a user struct of that shape
/// would at worst demand one extra key, reported by the preflight.
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

/// The inventory as the CLI gets it, which never names the playbook's
/// `V`.
///
/// `json` keeps secrets sealed, so targeting works without any key.
/// `debug` is rendered here, where `V`'s own `Debug` is in scope — per
/// host and under [`WHOLE_INVENTORY_KEY`]. Under `--reveal`, `debug` is
/// rendered decrypted and `json_revealed` holds the decrypted JSON (or
/// the error, if a key was missing).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::__reexports::serde")]
#[doc(hidden)]
pub struct InventoryDump {
    pub json: serde_json::Value,
    pub debug: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub json_revealed: Option<Result<serde_json::Value, String>>,
}

/// Lets `#[cindy::inventory]` return `Inventory<V>` or a `Result` of
/// one. An `Err`, or a `V` that fails to serialise, is reported on
/// stderr and exits 1.
#[doc(hidden)]
pub trait IntoInventoryDump {
    fn into_inventory_dump(self) -> InventoryDump;
}

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

/// Separate from the trait impl, which exits, so failure is testable.
fn try_into_inventory_dump<V: serde::Serialize + std::fmt::Debug>(
    inv: Inventory<V>,
) -> Result<InventoryDump, serde_json::Error> {
    let json = serde_json::to_value(&inv)?;
    let reveal = std::env::var_os("CINDY_REVEAL_SECRETS").is_some();
    let render = || {
        let revealed = reveal.then(|| serde_json::to_value(&inv).map_err(|e| e.to_string()));
        (build_debug_map(&inv), revealed)
    };
    let (debug, json_revealed) = if reveal {
        crate::secret::with_revealed_secrets(render)
    } else {
        render()
    };
    Ok(InventoryDump {
        json,
        debug,
        json_revealed,
    })
}

impl<V: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug> IntoInventoryDump
    for Inventory<V>
{
    fn into_inventory_dump(self) -> InventoryDump {
        match try_into_inventory_dump(self) {
            Ok(dump) => dump,
            Err(e) => {
                eprintln!("`#[cindy::inventory]` failed to serialise the inventory to JSON: {e:?}");
                std::process::exit(1);
            }
        }
    }
}

impl<V: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug, E: std::fmt::Debug>
    IntoInventoryDump for Result<Inventory<V>, E>
{
    fn into_inventory_dump(self) -> InventoryDump {
        match self {
            Ok(inv) => inv.into_inventory_dump(),
            Err(e) => {
                eprintln!("`#[cindy::inventory]` failed: {e:?}");
                std::process::exit(1);
            }
        }
    }
}

#[doc(hidden)]
pub struct RegisteredInventory {
    pub dump: fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = InventoryDump> + Send>>,
}
inventory::collect!(RegisteredInventory);

/// One target, as `main` receives it. `V` is the playbook's own vars
/// type; the CLI only sees `name` and `tags`, and carries `vars` as JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(crate = "crate::__reexports::serde")]
pub struct Host<V = ()> {
    /// Usually the SSH host alias.
    pub name: String,
    /// For `--limit`. Targeting only: no vars inheritance — compose vars
    /// in the inventory fn, in plain Rust.
    #[serde(default)]
    pub tags: Vec<String>,
    pub vars: V,
}

impl<V> Host<V> {
    /// The literal form works too; this skips the `.into()`s:
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
    pub fn new(hosts: impl IntoIterator<Item = Host<V>>) -> Self {
        Self {
            hosts: hosts.into_iter().collect(),
        }
    }
}

/// `vec!` of `String`s, converting each element with `Into`.
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
        let a = Host::new("web-01", ["env:prod", "web"], 42u64);
        assert_eq!(a.name, "web-01");
        assert_eq!(a.tags, vec!["env:prod", "web"]);
        assert_eq!(a.vars, 42);

        let b = Host::new(String::from("web-02"), vec![String::from("db")], 7u64);
        assert_eq!(b.name, "web-02");

        let c = Host::new("web-03", std::iter::empty::<&str>(), 1u64);
        assert!(c.tags.is_empty());

        let d = Host {
            name: "web-04".into(),
            tags: crate::tags!["t"],
            vars: 0u64,
        };

        let inv = Inventory::new([a, b, c, d]);
        assert_eq!(inv.hosts.len(), 4);
    }

    #[test]
    fn failing_serialize_is_an_error_not_a_panic() {
        #[derive(Debug, serde::Deserialize)]
        struct FailsSerialize;

        impl serde::Serialize for FailsSerialize {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }

        let inv = Inventory::new([Host::new("boom", [] as [&str; 0], FailsSerialize)]);
        assert!(try_into_inventory_dump(inv).is_err());
    }
}
