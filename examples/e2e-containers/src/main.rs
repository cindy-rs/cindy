//! The container e2e playbook: the mutating builtins against a real
//! systemd, shadow-utils and apt. Each test in `tests/e2e.rs` picks a
//! scenario by setting its `CINDY_E2E_*` variable on the orchestrator;
//! assertions read the container's state through `probe`.

/// Every path the scenarios touch is fixed inside the container.
#[cindy::wire]
pub struct Vars {}

/// The tests supply the host context; this only has to exist.
#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    cindy::Inventory::new([cindy::Host::new(
        "cindy-e2e-container",
        ["example:e2e"],
        Vars {},
    )])
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use scenarios::*;

    let _ = host;
    let on = |var| std::env::var_os(var).is_some();
    if on("CINDY_E2E_SYSTEMD") {
        unit_lifecycle().await
    } else if on("CINDY_E2E_SYSTEMD_MASK") {
        mask_the_maskable().await
    } else if on("CINDY_E2E_SYSTEMD_CHECK") {
        check_mode_disable_keeps_the_mask().await
    } else if on("CINDY_E2E_SYSTEMD_UNMASK") {
        disable_unmasks().await
    } else if on("CINDY_E2E_USERS") {
        users_and_groups().await
    } else if on("CINDY_E2E_APT") {
        apt_packages().await
    } else {
        cindy::bail!("no CINDY_E2E_* scenario selected — the harness picks one")
    }
}

#[cfg(feature = "orchestrator")]
mod scenarios {
    use std::future::Future;

    use cindy::builtin::debian::apt;
    use cindy::builtin::{Return, command, group, path, systemd, user};

    const UNIT: &str = "cindy-e2e";

    /// Ships disabled in /usr/lib, so its file survives a mask (an /etc
    /// unit is removed to make room for one) and unmasking leaves it
    /// plain `disabled`.
    const MASKABLE: &str = "debug-shell";

    async fn changes(
        what: &str,
        call: impl Future<Output = cindy::Result<Return>>,
    ) -> cindy::Result<()> {
        if !call.await?.changed() {
            cindy::bail!("{what} reported Unchanged");
        }
        Ok(())
    }

    async fn converged(
        what: &str,
        call: impl Future<Output = cindy::Result<Return>>,
    ) -> cindy::Result<()> {
        if call.await?.changed() {
            cindy::bail!("{what} reported Changed");
        }
        Ok(())
    }

    /// `(exited 0, stdout+stderr trimmed)`. A probe, so it runs under
    /// `--check` too.
    async fn probe(argv: &[&str]) -> (bool, String) {
        let out = command::probe(argv.iter().map(|a| a.to_string()).collect::<Vec<_>>())
            .await
            .expect("probe command spawned");
        let text = format!("{}{}", out.stdout, out.stderr);
        (
            out.status == command::Status::Exited(0),
            text.trim().to_owned(),
        )
    }

    async fn assert_enabled(unit: &str, expected: &str) -> cindy::Result<()> {
        let (_, out) = probe(&["systemctl", "is-enabled", unit]).await;
        if out != expected {
            cindy::bail!("enablement of {unit} was {out:?}, expected {expected:?}");
        }
        Ok(())
    }

    async fn assert_unit(active: &str, enabled: &str) -> cindy::Result<()> {
        let (ok, out) = probe(&["systemctl", "is-active", UNIT]).await;
        if out != active || (active == "active" && !ok) {
            cindy::bail!("unit active state was {out:?} (ok={ok}), expected {active:?}");
        }
        assert_enabled(UNIT, enabled).await
    }

    /// Installed the way plays do it — `path`, then `daemon_reload`.
    pub async fn unit_lifecycle() -> cindy::Result<()> {
        path::file(
            "/etc/systemd/system/cindy-e2e.service",
            "[Unit]\nDescription=cindy container e2e probe\n\n\
             [Service]\nType=simple\nExecStart=/bin/sleep infinity\n\n\
             [Install]\nWantedBy=multi-user.target\n",
            "root",
            "root",
            path::Mode::try_from(0o644)?,
        )
        .await?;
        systemd::daemon_reload().await?;

        changes(
            "enable_and_start of a fresh unit",
            systemd::enable_and_start(UNIT),
        )
        .await?;
        assert_unit("active", "enabled").await?;
        converged(
            "enable_and_start of a converged unit",
            systemd::enable_and_start(UNIT),
        )
        .await?;
        changes(
            "disable_and_stop of a running unit",
            systemd::disable_and_stop(UNIT),
        )
        .await?;
        assert_unit("inactive", "disabled").await?;

        // A runtime-only enable is gone after a reboot: not enabled.
        let enable_runtime = || {
            command::command(
                vec![
                    "systemctl".into(),
                    "enable".into(),
                    "--runtime".into(),
                    UNIT.into(),
                ],
                command::State::default(),
            )
        };
        enable_runtime().await?.exit_ok()?;
        assert_enabled(UNIT, "enabled-runtime").await?;
        changes(
            "enable of a runtime-only enabled unit",
            systemd::enable(UNIT),
        )
        .await?;
        assert_enabled(UNIT, "enabled").await?;
        // Persistent and runtime links at once: one disable removes both.
        enable_runtime().await?.exit_ok()?;
        changes("disable of an enabled unit", systemd::disable(UNIT)).await?;
        assert_enabled(UNIT, "disabled").await?;
        converged("a second disable", systemd::disable(UNIT)).await?;

        changes("mask of an unmasked unit", systemd::mask(UNIT)).await?;
        assert_unit("inactive", "masked").await
    }

    pub async fn mask_the_maskable() -> cindy::Result<()> {
        changes("mask of an unmasked unit", systemd::mask(MASKABLE)).await?;
        assert_enabled(MASKABLE, "masked").await
    }

    /// Run under CINDY_DRY_RUN=1: report the change, keep the mask.
    pub async fn check_mode_disable_keeps_the_mask() -> cindy::Result<()> {
        assert_enabled(MASKABLE, "masked").await?;
        changes(
            "check-mode disable of a masked unit",
            systemd::disable(MASKABLE),
        )
        .await?;
        assert_enabled(MASKABLE, "masked").await
    }

    pub async fn disable_unmasks() -> cindy::Result<()> {
        changes("disable of a masked unit", systemd::disable(MASKABLE)).await?;
        let (_, out) = probe(&["systemctl", "is-enabled", MASKABLE]).await;
        if out == "masked" {
            cindy::bail!("disable left the unit masked");
        }
        Ok(())
    }

    pub async fn users_and_groups() -> cindy::Result<()> {
        let account = |presence| {
            user::user(user::State {
                name: "cindye2e".into(),
                presence,
            })
        };

        changes("present() of a missing account", user::present("cindye2e")).await?;
        let (_, passwd) = probe(&["getent", "passwd", "cindye2e"]).await;
        if passwd.is_empty() {
            cindy::bail!("getent found no passwd entry for the created account");
        }
        converged(
            "present() of a converged account",
            user::present("cindye2e"),
        )
        .await?;

        let pinned = user::Presence::Present(user::Account {
            uid: Some(4242),
            shell: Some("/bin/sh".into()),
            comment: Some("cindy container e2e".into()),
            ..Default::default()
        });
        changes("pinning uid/shell/comment", account(pinned.clone())).await?;
        let (_, passwd) = probe(&["getent", "passwd", "cindye2e"]).await;
        for expected in ["4242", "/bin/sh", "cindy container e2e"] {
            if !passwd.contains(expected) {
                cindy::bail!("passwd line {passwd:?} lacks {expected:?}");
            }
        }
        converged("re-pinning the same attributes", account(pinned)).await?;

        changes(
            "group present() of a missing group",
            group::present("cindye2eops"),
        )
        .await?;
        let grouped = user::Presence::Present(user::Account {
            groups: Some(user::Groups::Exact(vec!["cindye2eops".into()])),
            ..Default::default()
        });
        changes("adding a supplementary group", account(grouped)).await?;
        let (_, id) = probe(&["id", "cindye2e"]).await;
        if !id.contains("cindye2eops") {
            cindy::bail!("memberships after Exact reconcile: {id:?}");
        }

        // Eight identical creates at once: the losers of the race
        // reconcile instead of failing, and one account results.
        let racers = futures_util::future::join_all((0..8).map(|_| {
            user::user(user::State {
                name: "cindy-race".into(),
                presence: user::Presence::default(),
            })
        }))
        .await;
        for (i, r) in racers.into_iter().enumerate() {
            if let Err(e) = r {
                cindy::bail!("concurrent create #{i} failed: {e:?}");
            }
        }
        let (_, count) = probe(&["sh", "-c", "getent passwd cindy-race | wc -l"]).await;
        if count != "1" {
            cindy::bail!("race left {count} passwd entries, expected 1");
        }

        changes(
            "present_with_gid of a missing group",
            group::present_with_gid("cindye2egid", 4242),
        )
        .await?;
        let (_, grp) = probe(&["getent", "group", "cindye2egid"]).await;
        if !grp.contains("4242") {
            cindy::bail!("group line {grp:?} lacks the pinned gid");
        }
        changes(
            "absent() of an existing account",
            user::absent("cindy-race"),
        )
        .await?;
        if probe(&["getent", "passwd", "cindy-race"]).await.0 {
            cindy::bail!("getent still finds the removed account");
        }
        Ok(())
    }

    /// Against the image's `file://` repo: `sl` is installable but
    /// absent, `dash` ships in the image.
    pub async fn apt_packages() -> cindy::Result<()> {
        changes("install of a missing package", apt::install("sl")).await?;
        if !probe(&["dpkg-query", "-W", "sl"]).await.0 {
            cindy::bail!("dpkg-query can't find the installed package");
        }
        converged("install of a converged package", apt::install("sl")).await?;
        // `Present` never chases an upgrade.
        converged(
            "install of an already-installed package",
            apt::install("dash"),
        )
        .await?;
        changes("remove of an installed package", apt::remove("sl")).await?;
        if probe(&["dpkg-query", "-W", "sl"]).await.0 {
            cindy::bail!("dpkg-query still finds the removed package");
        }
        Ok(())
    }
}
