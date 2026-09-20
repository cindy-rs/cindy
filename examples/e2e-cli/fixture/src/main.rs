//! Fixture playbook for the e2e-cli suite (`tests/e2e.rs`): three
//! local hosts, one converged-state builtin and one marker-writing
//! remote fn, so driving the real `cindy` binary proves the whole play
//! path — inventory pull, `--limit` selection, worker build/upload/run
//! over the local transport, and the run summary.
//!
//! `alpha`/`beta` share the `suite:one` tag and `gamma` wears
//! `suite:two`, giving the `--limit` tests a tag to select and an
//! expression to compose. The markers directory arrives via
//! `E2E_CLI_MARKERS_DIR`, read at inventory time so it lands in the
//! host context like any var; the default keeps a standalone
//! `cindy play --local` from this directory runnable.

use std::path::PathBuf;

#[cindy::wire]
pub struct Vars {
    /// Where the play drops its per-host markers. See the module docs.
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

/// Worker-side marker: proves playbook code ran on a host — the RPC
/// reached a genuinely spawned worker process. Runs even under
/// `--check` (cindy can't know what user code mutates), which the
/// check-mode test accounts for.
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

    // A converged-state builtin: its file appears only in a real play,
    // never under `--check` — the check-mode test's "nothing was
    // applied" signal. The per-host content proves the host context
    // (vars) reached the play.
    let (user, group) = builtin::current_owner_names();
    builtin::path::directory(
        markers.clone(),
        user.clone(),
        group.clone(),
        builtin::path::Mode::try_from(0o755)?,
    )
    .await?;
    builtin::path::file(
        markers.join(format!("{}.config", host.name)),
        format!("managed by cindy for {}", host.name),
        user,
        group,
        builtin::path::Mode::try_from(0o644)?,
    )
    .await?;

    drop_marker(markers.join(format!("{}.marker", host.name))).await?;
    Ok(())
}
