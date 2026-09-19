# cindy-cli — the `cindy` binary

```sh
cargo install cindy-cli
```

Compiles your playbook, cross-builds one remote worker per target triple
(`cross` + podman), deploys over SSH, streams progress, and manages secret
vaults (`cindy secret seal` / `unseal`).

[![crates.io](https://img.shields.io/crates/v/cindy-cli.svg?logo=rust&color=e6731b)](https://crates.io/crates/cindy-cli)

Documentation at [cindy.rs](https://cindy.rs); source in the
[cindy monorepo](https://github.com/cindy-rs/cindy).
