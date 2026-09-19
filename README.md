<p align="center">
  <img src="https://raw.githubusercontent.com/cindy-rs/cindy/main/assets/logo.png" alt="Cindy" width="520">
</p>

# [Cindy](https://cindy.rs)

[![Home Page](https://img.shields.io/badge/home-cindy.rs-e6731b?logo=firefox)](https://cindy.rs)
[![Discord](https://img.shields.io/badge/chat-Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/M7x6hyq57h)
[![License](https://img.shields.io/crates/l/cindy.svg?color=e6731b)](https://github.com/cindy-rs/cindy)
[![crates.io](https://img.shields.io/crates/v/cindy.svg?logo=rust&color=e6731b)](https://crates.io/crates/cindy)
[![docs.rs](https://img.shields.io/docsrs/cindy?logo=docs.rs&color=e6731b)](https://docs.rs/cindy)

> A remarkably simple infrastructure management solution.

The purpose of this project is to provide a faster, safer, simpler, and overall better alternative
to current provisioning tools like Ansible and Salt.

It aims to solve all of the pain points of Ansible, while still being "agent-less" and easy to use.

You write Rust. That's it.

## Install

```sh
cargo install cindy-cli
```

Like Ansible, cindy is agent-less: it needs only SSH access to your targets and
passwordless `sudo` there. Remote workers are cross-compiled with
[`cross`](https://github.com/cross-rs/cross) + podman, driven automatically by
`cindy play`. The controller builds your playbook with the local Rust toolchain
(nightly; `rustup toolchain install nightly`).

## Quickstart

A playbook is a Rust crate:

```rust,ignore
#[cindy::wire]
struct Vars {
    greeting: String,
}

#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    cindy::Inventory::new([cindy::Host::new(
        "host.example.net",
        ["proxy", "prague"],
        Vars { greeting: "Hello".into() },
    )])
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use cindy::builtin::{debian::apt, systemd};

    apt::install("nginx").await?;
    if apt::install("curl").await?.changed() {
        systemd::restart("nginx").await?;
    }
    Ok(())
}
```

Then run it against any slice of your fleet:

```sh
cindy play --limit prague
```

Preview what a run would change without applying anything:

```sh
cindy play --check
```

Every builtin renders its diff and reports `Changed` for what it *would*
have applied; `command`/`shell` don't execute. Your own `#[remote]`
functions still run — cindy can't know what user code mutates, so treat
a green `--check` as "the builtins wouldn't touch anything".

Full documentation lives at [cindy.rs](https://cindy.rs).

## Security model

Secrets are sealed at rest (`cindy secret seal` rewrites them in your source)
and decrypted only where they are used. Vault keys (`keys/<vault>.key`) stay on
the operator machine and travel to workers over the encrypted RPC channel —
they never appear in a target's argv or environment.

## Repository layout

- `crates/` — `cindy` (the framework library), `cindy-macros`,
  `cindy-cli` (the `cindy` binary).
- `examples/` — `e2e-localhost` (hermetic integration suite),
  `snippet-check` (compile guard for the website's code snippets), and
  example playbooks.
- `web/` — the [cindy.rs](https://cindy.rs) site.

## License

GPL-3.0-only.
