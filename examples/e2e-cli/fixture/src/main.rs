//! The e2e-cli fixture: three local hosts (`alpha` and `beta` tagged
//! `suite:one`, `gamma` `suite:two`), one builtin and one marker-writing
//! remote fn. `E2E_CLI_MARKERS_DIR` arrives at inventory time, so it
//! reaches the play in the host context like any var.

use std::path::PathBuf;

#[cindy::wire]
pub struct Vars {
    #[serde(default = "default_markers_dir")]
    markers_dir: PathBuf,
}

fn default_markers_dir() -> PathBuf {
    std::env::temp_dir().join("cindy-e2e-cli")
}

#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    let markers_dir =
        std::env::var_os("E2E_CLI_MARKERS_DIR").map_or_else(default_markers_dir, PathBuf::from);
    let host = |name: &str, tags: &[&str]| cindy::Host {
        name: name.into(),
        tags: tags.iter().map(|tag| tag.to_string()).collect(),
        vars: Vars {
            markers_dir: markers_dir.clone(),
        },
    };
    cindy::Inventory {
        hosts: vec![
            host("alpha", &["suite:one"]),
            host("beta", &["suite:one"]),
            host("gamma", &["suite:two"]),
        ],
    }
}

/// Proof that playbook code ran on the host's worker. User code runs
/// under `--check` too.
#[cindy::remote]
fn drop_marker(dest: PathBuf) -> cindy::Result<()> {
    std::fs::create_dir_all(dest.parent().expect("marker path has a parent"))?;
    std::fs::write(dest, b"ran")?;
    Ok(())
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use cindy::builtin;

    let markers = &host.vars.markers_dir;

    // Applied only in a real play — the check-mode test's signal. The
    // per-host content proves the host context arrived.
    let (user, group) = builtin::current_owner_names();
    builtin::path::directory(
        markers.clone(),
        user.clone(),
        group.clone(),
        cindy::mode!(0o755),
    )
    .await?;
    builtin::path::file(
        markers.join(format!("{}.config", host.name)),
        format!("managed by cindy for {}", host.name),
        user,
        group,
        cindy::mode!(0o644),
    )
    .await?;

    drop_marker(markers.join(format!("{}.marker", host.name))).await?;
    Ok(())
}
