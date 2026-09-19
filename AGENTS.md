# AGENTS.md

Guidelines for AI agents working in this repository. Multiple agents (Claude Opus,
GLM, GPT, ...) collaborate here alongside the human owner.

## Session protocol

- **Read this file first**, every session — other agents may have updated it.
- **Check `git log` before starting work** (`git log --oneline -20`, `git diff`) and
  review anything that isn't yours. Do not assume the code still matches your memory
  of it.
- Commit each unit of work separately. Commit messages are prefixed with your model
  tag, e.g. `glm: `, `opus: `, `gpt: `. Put detailed explanations (rationale,
  root-cause analysis, rejected alternatives) in the commit message — code comments
  stay minimal.
- **Never amend, rebase, or otherwise touch existing commits.** If you believe you
  need to, ask the human first.
- Verify before committing: `cargo check --workspace`, `cargo clippy --workspace`,
  plus tests for whatever you touched. Full commands below.
- Never run `cindy play` (or anything else that deploys to real hosts). The human
  runs plays; compiling/building steps are fine. The human's real playbook lives at
  `/home/martin/files/projects/home-infra` — don't modify it unasked.

## Commands

```sh
cargo check --workspace        # fast type check
cargo clippy --workspace       # lints
cargo test --workspace         # unit tests
cargo test -p e2e-localhost    # e2e suite; slow (builds two binaries), hermetic
```

## Repo layout

- `crates/cindy` — the framework library user playbooks depend on.
  - `src/entry.rs`, `src/orchestrator.rs`, `src/remote.rs` — `#[cindy::main]`
    runtime: orchestrator and remote-worker entry paths + RPC loop.
  - `src/builtin/` — converged-state builtins (path, user, group, apt, systemd,
    fetch, archive/unarchive, command, compress/decompress).
  - `src/secret/` — vault crypto (ChaCha20-Poly1305), keychain, sealed secrets.
  - `src/inventory.rs` — typed inventory dump format.
- `crates/cindy-macros` — proc macros: `#[cindy::main]`, `#[cindy::inventory]`,
  `#[remote]`, `#[action]`, `secret!`.
- `crates/cindy-cli` — the `cindy` binary: compiles the user's orchestrator,
  cross-builds remote workers via `cross` + podman, deploys over SSH, streams
  progress (ratatui), manages vaults (`cindy secret seal/unseal`).
- `examples/e2e-localhost` — hermetic end-to-end harness; the only integration
  coverage.
- `examples/snippet-check` — compile guard: `#[path]`-includes
  `web/src/snippets/*.rs` so the site's code examples can't drift from the real
  `cindy` API. Nothing executes; edit the snippets in `web/`, not here.
- `web/` — the cindy.rs marketing/docs site (Dioxus). Its own nested workspace,
  excluded from the root one — the coupling to the framework is editorial (docs
  prose + snippets), not crates. `dx` builds it; `assets/tailwind.css` is
  generated from `tailwind.css` (gitignored).

## Architecture invariants

- A playbook is a Rust crate with `orchestrator`/`remote` features. `cindy play`
  builds the orchestrator locally and one worker per target triple via `cross`.
- Orchestrator↔worker RPC: postcard + COBS framing over SSH-piped stdio; the first
  frame is the vault-key handshake. Vault keys must never reach hosts via argv/env.
- Secrets are sealed at rest (`keys/<vault>.key` on the operator machine) and
  revealed only inside remote fns. `Debug`/`Serialize` impls on secret types must
  stay redacting.
- Builtins must stay idempotent: compute the full desired state, diff against live
  state, apply, and report `Changed`/`Unchanged` honestly. Never claim convergence
  that didn't happen.
- No shell string construction for process launches — argv vectors with `--`
  separators only.

## Conventions

- Edition 2024, MSRV 1.98. Nightly toolchain is the default (tier-3 builds use
  `-Zbuild-std`).
- `cross` + podman (no docker) build remote workers; host `$CARGO_HOME` is mounted
  into the build container — keep that leak in mind for anything config-dependent.
- Dependencies for `crates/cindy` should move toward `[workspace.dependencies]`.
