//! The container e2e playbook. Each scenario is selected by an env var
//! the harness sets on the **orchestrator** (see `tests/e2e.rs`); the
//! assertions run inside the container through [`probe`], because the
//! play's remote functions execute in the worker there.
//!
//! These are the scenarios `examples/e2e-localhost` can't cover: the
//! mutating builtins that need a real system — systemd, shadow-utils,
//! apt — which is exactly where the `--check` mutation bug shipped
//! (see AGENTS.md: audit for mutations, not for guards).

#[cfg(feature = "orchestrator")]
use std::path::PathBuf;

/// The scenarios don't need host vars: every path they touch is fixed
/// inside the throwaway container.
#[cindy::wire]
pub struct Vars {}

#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    // The harness overrides this via the host-context hand-off; the
    // inventory body just needs to exist and type-check.
    cindy::Inventory {
        hosts: vec![cindy::Host {
            name: "cindy-e2e-container".into(),
            tags: vec!["example:e2e".into()],
            vars: Vars {},
        }],
    }
}

/// Read-only probe for the scenarios' assertions: runs `cmd` in the
/// container and returns `(exited 0, combined output, trimmed)`.
///
/// Deliberately a custom `#[remote]` rather than the `command` builtin:
/// under `--check` the builtin (correctly) refuses to execute anything,
/// while assertions still need to *read* state to prove nothing
/// mutated — and reads are exactly what check mode permits. It only
/// ever reads; the scenarios pass it `systemctl is-*`, `getent`,
/// `dpkg-query`.
#[cindy::remote]
fn probe(cmd: Vec<String>) -> (bool, String) {
    let output = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .output()
        .expect("probe command spawned");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text.trim().to_owned())
}

/// Reached only from `main`'s body, which the worker side discards —
/// see [`assert_unit`].
#[cfg(feature = "orchestrator")]
const UNIT: &str = "cindy-e2e";

#[cfg(feature = "orchestrator")]
fn unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/cindy-e2e.service")
}

#[cfg(feature = "orchestrator")]
fn unit_body() -> Vec<u8> {
    b"[Unit]\nDescription=cindy container e2e probe\n\n[Service]\nType=simple\nExecStart=/bin/sleep infinity\n\n[Install]\nWantedBy=multi-user.target\n".to_vec()
}

/// Orchestrator-side only: it calls `probe`, which the `#[remote]`
/// macro turns into its registration *enum* on the worker side — there
/// the fn of that name doesn't exist (the worker entry never runs
/// `main`'s body, and this helper is only reachable from it).
/// A unit that ships disabled in `/usr/lib/systemd/system`, so
/// masking it leaves the original intact (an admin-authored file
/// under `/etc` is *removed* to complete the mask — loudly, by design
/// — which would leave nothing to unmask) and unmasking returns it to
/// plain `disabled`. The check-mode pin needs a unit that survives
/// its own mask.
#[cfg(feature = "orchestrator")]
const MASKABLE: &str = "debug-shell";

#[cfg(feature = "orchestrator")]
async fn assert_enabled(unit: &str, expected: &str) -> cindy::Result<()> {
    let (_, out) = probe(vec!["systemctl".into(), "is-enabled".into(), unit.into()]).await;
    if out != expected {
        cindy::bail!("enablement of {unit} was {out:?}, expected {expected:?}");
    }
    Ok(())
}

#[cfg(feature = "orchestrator")]
async fn assert_unit(active: &str, enabled: &str) -> cindy::Result<()> {
    let (ok, out) = probe(vec!["systemctl".into(), "is-active".into(), UNIT.into()]).await;
    if out != active || (active == "active" && !ok) {
        cindy::bail!("unit active state was {out:?} (ok={ok}), expected {active:?}");
    }
    let (_, out) = probe(vec!["systemctl".into(), "is-enabled".into(), UNIT.into()]).await;
    if out != enabled {
        cindy::bail!("unit enablement was {out:?}, expected {enabled:?}");
    }
    Ok(())
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use cindy::builtin;
    let _ = host;

    // systemd lifecycle (see tests/e2e.rs): install a unit the way
    // real plays do — the `path` builtin — then drive it through
    // enable/start, convergence, stop/disable and mask.
    if std::env::var_os("CINDY_E2E_SYSTEMD").is_some() {
        use builtin::{path, systemd};

        path::file(
            unit_path(),
            unit_body(),
            "root",
            "root",
            path::Mode::try_from(0o644)?,
        )
        .await?;
        systemd::daemon_reload().await?;

        if !systemd::enable_and_start(UNIT).await?.changed() {
            cindy::bail!("enable_and_start reported Unchanged for a fresh unit");
        }
        assert_unit("active", "enabled").await?;

        // Converged state must report Unchanged, not re-do work.
        if systemd::enable_and_start(UNIT).await?.changed() {
            cindy::bail!("enable_and_start reported Changed on a converged unit");
        }

        if !systemd::disable_and_stop(UNIT).await?.changed() {
            cindy::bail!("disable_and_stop reported Unchanged for a running enabled unit");
        }
        assert_unit("inactive", "disabled").await?;

        if !systemd::mask(UNIT).await?.changed() {
            cindy::bail!("mask reported Unchanged for an unmasked unit");
        }
        assert_unit("inactive", "masked").await?;
        return Ok(());
    }

    // Setup for the check-mode pair (see tests/e2e.rs): mask a
    // /usr/lib-backed unit so there is a mask to disable against.
    if std::env::var_os("CINDY_E2E_SYSTEMD_MASK").is_some() {
        use builtin::systemd;

        if !systemd::mask(MASKABLE).await?.changed() {
            cindy::bail!("mask of an unmasked unit reported Unchanged");
        }
        assert_enabled(MASKABLE, "masked").await?;
        return Ok(());
    }

    // The f576ecc regression, pinned (see tests/e2e.rs): run with
    // CINDY_DRY_RUN=1 against a masked unit. `disable` must report
    // the would-change *without unmasking* — the check-mode contract,
    // on the exact arm where it was originally missed.
    if std::env::var_os("CINDY_E2E_SYSTEMD_CHECK").is_some() {
        use builtin::systemd;

        assert_enabled(MASKABLE, "masked").await?;
        if !systemd::disable(MASKABLE).await?.changed() {
            cindy::bail!("check-mode disable of a masked unit under-reported");
        }
        assert_enabled(MASKABLE, "masked").await?;
        return Ok(());
    }

    // The same request for real (see tests/e2e.rs): the unmask is
    // applied — the unit ends unmasked (disabled or static, whichever
    // its [Install] situation yields, but not masked).
    if std::env::var_os("CINDY_E2E_SYSTEMD_UNMASK").is_some() {
        use builtin::systemd;

        if !systemd::disable(MASKABLE).await?.changed() {
            cindy::bail!("disable of a masked unit reported Unchanged");
        }
        let (_, out) = probe(vec![
            "systemctl".into(),
            "is-enabled".into(),
            MASKABLE.into(),
        ])
        .await;
        if out == "masked" {
            cindy::bail!("disable left the unit masked");
        }
        return Ok(());
    }

    // user + group against real shadow-utils (see tests/e2e.rs):
    // create, converge, reconcile attributes, supplementary groups,
    // the shadow-utils create race, and absence.
    if std::env::var_os("CINDY_E2E_USERS").is_some() {
        use builtin::{group, user};
        use user::Presence;

        if !user::present("cindye2e").await?.changed() {
            cindy::bail!("present() reported Unchanged for a missing account");
        }
        let (_, passwd) = probe(vec!["getent".into(), "passwd".into(), "cindye2e".into()]).await;
        if passwd.is_empty() {
            cindy::bail!("getent found no passwd entry for the created account");
        }
        if user::present("cindye2e").await?.changed() {
            cindy::bail!("present() reported Changed on a converged account");
        }

        // Attribute reconcile: pin uid, shell and comment on the
        // existing account, then converge.
        let pinned = Presence::Present {
            uid: Some(4242),
            group: None,
            groups: None,
            shell: Some("/bin/sh".into()),
            home: None,
            comment: Some("cindy container e2e".into()),
            system: None,
        };
        if !user::user(user::State {
            name: "cindye2e".into(),
            presence: pinned.clone(),
        })
        .await?
        .changed()
        {
            cindy::bail!("pinning uid/shell/comment reported Unchanged");
        }
        let (_, passwd) = probe(vec!["getent".into(), "passwd".into(), "cindye2e".into()]).await;
        for expected in ["4242", "/bin/sh", "cindy container e2e"] {
            if !passwd.contains(expected) {
                cindy::bail!("passwd line {passwd:?} lacks {expected:?}");
            }
        }
        if user::user(user::State {
            name: "cindye2e".into(),
            presence: pinned,
        })
        .await?
        .changed()
        {
            cindy::bail!("reconcile of pinned attributes reported Changed on convergence");
        }

        // Supplementary groups via the group builtin.
        if !group::present("cindye2eops").await?.changed() {
            cindy::bail!("group present() reported Unchanged for a missing group");
        }
        if !user::user(user::State {
            name: "cindye2e".into(),
            presence: Presence::Present {
                uid: None,
                group: None,
                groups: Some(user::Groups::Exact(vec!["cindye2eops".into()])),
                shell: None,
                home: None,
                comment: None,
                system: None,
            },
        })
        .await?
        .changed()
        {
            cindy::bail!("adding supplementary group reported Unchanged");
        }
        let (_, id) = probe(vec!["id".into(), "cindye2e".into()]).await;
        if !id.contains("cindye2eops") {
            cindy::bail!("memberships after Exact reconcile: {id:?}");
        }

        // The shadow-utils create race (the PLAN.md pairing): eight
        // concurrent identical creates must all converge — a loser of
        // the race re-observes and reconciles instead of failing, and
        // exactly one passwd entry exists at the end.
        let racers = futures_util::future::join_all((0..8).map(|_| {
            user::user(user::State {
                name: "cindy-race".into(),
                presence: Presence::default(),
            })
        }))
        .await;
        for (i, r) in racers.into_iter().enumerate() {
            if let Err(e) = r {
                cindy::bail!("concurrent create #{i} failed: {e:?}");
            }
        }
        let (_, count) = probe(vec![
            "sh".into(),
            "-c".into(),
            "getent passwd cindy-race | wc -l".into(),
        ])
        .await;
        if count.trim() != "1" {
            cindy::bail!("race left {} passwd entries, expected 1", count.trim());
        }

        // A pinned-gid group, and absence.
        if !group::present_with_gid("cindye2egid", 4242)
            .await?
            .changed()
        {
            cindy::bail!("present_with_gid reported Unchanged for a missing group");
        }
        let (_, grp) = probe(vec!["getent".into(), "group".into(), "cindye2egid".into()]).await;
        if !grp.contains("4242") {
            cindy::bail!("group line {grp:?} lacks the pinned gid");
        }
        if !user::absent("cindy-race").await?.changed() {
            cindy::bail!("absent() reported Unchanged for an existing account");
        }
        let (ok, _) = probe(vec!["getent".into(), "passwd".into(), "cindy-race".into()]).await;
        if ok {
            cindy::bail!("getent still finds the removed account");
        }
        return Ok(());
    }

    // apt against the image's file:// repo (see tests/e2e.rs): `sl` is
    // installable but absent, `dash` ships in the image — so install,
    // convergence, no-op-on-installed and removal all run with no
    // test-time network.
    if std::env::var_os("CINDY_E2E_APT").is_some() {
        use builtin::debian::apt;

        if !apt::install("sl").await?.changed() {
            cindy::bail!("install reported Unchanged for a missing package");
        }
        let (ok, _) = probe(vec!["dpkg-query".into(), "-W".into(), "sl".into()]).await;
        if !ok {
            cindy::bail!("dpkg-query can't find the installed package");
        }
        if apt::install("sl").await?.changed() {
            cindy::bail!("install reported Changed on a converged package");
        }
        // An already-installed package must report Unchanged —
        // `Presence::Present` promises no upgrade chase.
        if apt::install("dash").await?.changed() {
            cindy::bail!("install of an already-installed package reported Changed");
        }
        if !apt::remove("sl").await?.changed() {
            cindy::bail!("remove reported Unchanged for an installed package");
        }
        let (ok, _) = probe(vec!["dpkg-query".into(), "-W".into(), "sl".into()]).await;
        if ok {
            cindy::bail!("dpkg-query still finds the removed package");
        }
        return Ok(());
    }

    cindy::bail!("no CINDY_E2E_* scenario selected — the harness picks one");
}
