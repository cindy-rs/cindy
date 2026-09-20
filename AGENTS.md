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
- Verify before committing, with the same commands CI runs (below) — including
  `cargo fmt --check` and clippy's `--all-targets -- -D warnings`. A plain
  `cargo clippy --workspace` passes where CI fails.
- Outstanding work is not parked in a plan file: PLAN.md was consumed once
  every item had either shipped (each deleted in the commit that implemented
  it) or been moved to the settled decisions below. Keep that shape —
  rationale lives in commit messages and settled decisions, and new work goes
  through the owner before it lands anywhere.
- Never run `cindy play` (or anything else that deploys to real hosts). The human
  runs plays; compiling/building steps are fine. The human's real playbook lives at
  `/home/martin/files/projects/home-infra` — don't modify it unasked.

## Commands

These are what `.github/workflows/ci.yml` runs; match them exactly or CI will
disagree with your local pass.

```sh
cargo check --workspace                              # fast type check
cargo fmt --check                                    # CI fails on any drift
cargo clippy --workspace --all-targets -- -D warnings # lints
cargo test --workspace                               # unit + e2e
cargo test -p e2e-localhost    # e2e alone; slow (builds two binaries), hermetic
cargo test -p e2e-containers   # mutating-builtins e2e; needs a container engine
cargo test -p e2e-cli          # real-binary play-path e2e; slow (builds CLI + fixture), hermetic
cargo audit                    # vulnerabilities; must stay empty

# The site is a nested workspace — the root commands don't reach it.
cargo fmt --check --manifest-path web/Cargo.toml
cargo audit --file web/Cargo.lock
cargo check --manifest-path web/Cargo.toml --target wasm32-unknown-unknown
```

`check.web` copies `web/tailwind.css` to `web/assets/tailwind.css` first —
raw `cargo check` only needs the file to exist.

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
  cross-builds remote workers via `cross` + podman, deploys over SSH (or, with
  `play --local`, runs every host as a local process — no SSH, no cross: the
  smoke-test and e2e path), streams progress (ratatui), manages vaults
  (`cindy secret seal/unseal`).
- `examples/e2e-localhost` — hermetic end-to-end harness (local pipes,
  no SSH, no containers).
- `examples/e2e-containers` — container end-to-end harness: the
  mutating builtins (`systemd`, `apt`, `user`, `group`) against a real
  Debian-systemd container (`Containerfile.systemd` in that crate
  builds the image). Speaks the Docker API directly (testcontainers +
  bollard), so podman and docker both work and no CLI is involved.
  **Required, not optional** — no engine fails the suite, naming what's
  missing; `CINDY_E2E_CONTAINERS=skip` is the deliberate opt-out for
  machines with no engine.
- `examples/e2e-cli` — drives the *real* `cindy` binary through its whole
  play path (`play --local`) against the checked-in fixture playbook in
  `fixture/` — a nested workspace excluded from the root one, because
  `cindy play` must resolve the fixture playbook, not the framework
  monorepo the suite lives in. Covers `--limit` selection end to end
  (tag, expression, unknown-term refusal), the run summary, and
  `--check` applying nothing.
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
- Nothing cindy writes outlives a play on the target beyond the managed resources
  themselves: no state directory, no cache, no sidecars. The worker unlinks its
  own binary on startup. "Agent-less" is load-bearing, not marketing.
- `cindy play --check` must never mutate a target. Every mutating operation needs
  a `crate::dry_run()` guard, and check mode may over-report a change but must
  never under-report one. See the practices below for the shape that holds.

## Settled decisions — don't re-litigate

Each was proposed, considered, and settled. The reasoning lives in the named
commit (this repo keeps rationale in commit messages); don't re-open one without
new information.

- **Diffs show secrets.** A config file holding a revealed secret appears in the
  operator's terminal and the run view, as in Ansible. Redaction was built and
  reverted (`09ec86e`, `61857f3`): the old side of a diff can't be redacted
  without withholding it always or keeping state on the target, a partial guard
  reads as a guarantee and isn't, and the operator already holds every vault key
  the play touches. This *qualifies* the redaction invariant above —
  `Debug`/`Serialize` stay redacting; diffs deliberately don't.
- **No value-based secret masking** (scanning output for known secret values):
  misses anything transformed, and mangles diffs when a value is short or common.
- **Diffs are not opt-in.** An operator should be able to introspect a deploy
  without a flag. A `--no-diff` for CI logs is still open.
- **No AAD on sealed ciphertexts.** The threat model it defends — rearranging
  ciphertexts without code execution — doesn't exist when ciphertexts live in
  playbook source. The version byte was the half worth keeping (`9c6234a`).
- **`apt::install_all` was rejected** in favour of `impl Into<PackageList>`
  (`fe3dc4e`).
- **Buster (apt < 2.1.10) is not a target.** The fleet is VyOS 1.3+ (apt ≥ 2.2.4)
  and OpenWrt (no apt), so `apt-get` relies on `-o DPkg::Lock::Timeout` and
  doesn't need the retry wrapper `apt-mark` gets.
- **No `--forks`/`--serial`** for this fleet (`441e5b2`). Worth knowing if it
  comes back: rolling deploys are *not* expressible in playbook code — each host
  gets its own orchestrator process with no cross-host coordination point — so
  `--serial N` would have to be built as one orchestrator driving hosts in
  batches, not a per-playbook workaround.
- **The `nix 0.31.3` future-incompat warning stays.** Every build prints it;
  it is blocked upstream — the lint is a trailing semicolon in a macro used in
  expression position, in nix's own `build.rs` (`cfg_aliases!`), no fixed
  release exists to bump to, and future-incompat lints are exempt from
  `--cap-lints=allow`, so it can't even be silenced for a transitive
  dependency. An informed wait with a tripwire, not a workaround: bump `nix`
  when a release ships the fix and the warning dies. Pinning the toolchain
  was rejected — this repo floats nightly by design (tier-3 builds need
  `-Zbuild-std`), so a pin trades the warning for a bigger problem.

## Practices learned the hard way

Each of these cost a shipped bug. They're cheap to apply and expensive to
rediscover.

- **Conditional behaviour goes in a pure decision function.** Every `--check`
  defect came from a condition replicated across call sites with nothing
  enforcing it. The shape that survives review is `plan_holds`,
  `system_conflict`, `disable_would_change`, `file_attrs_satisfied`: extract the
  would-this-change decision, unit-test it, and have both the real path and the
  dry-run path read the same answer.
- **When the message is the feature, assert on the message.**
  `assert!(x.is_err())` let two separate regressions ship green — an
  unknown-version error that didn't name the version, then a wrong-key error
  that claimed to be a version problem. Error-path tests assert the text in both
  directions: it says X, and it does *not* say Y.
- **Audit for mutations, not for guards.** Grepping existing `dry_run()` call
  sites found nothing wrong with `daemon_reload` — it had no guard at all, so it
  never appeared in the results. Enumerate the mutating operations and confirm
  each one is covered.

## Conventions

- Edition 2024, MSRV 1.98. Nightly toolchain is the default (tier-3 builds use
  `-Zbuild-std`).
- `cross` + podman (no docker) build remote workers; host `$CARGO_HOME` is mounted
  into the build container — keep that leak in mind for anything config-dependent.
- A dependency used by more than one crate belongs in
  `[workspace.dependencies]`, so versions can't drift apart. Single-consumer
  deps (`zbus_systemd`, `ureq`, `nix`, …) are fine inline — hoisting those buys
  nothing.
