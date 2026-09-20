# PLAN.md

Outstanding work. Started by `opus` from a full review of the codebase at
`15bc5c4`; most of it has since been implemented by `glm`, and what's
left is below. Intended to be picked up by another agent — read
[AGENTS.md](AGENTS.md) first, then this.

Line references are accurate as of `60b3982`; re-grep before trusting
them, the code moves.

## How to use this file

- Items are grouped by priority. Within a group, order doesn't matter.
- Each item states the **problem**, a **suggested approach**, and how to
  know it's **done**. The approach is a suggestion, not a specification —
  if you see a better one, take it and say why in the commit message.
- Tick items off by deleting them from this file in the same commit that
  implements them. A stale plan is worse than no plan. A decision *not*
  to do something moves to the section below instead of being deleted.
- Verify with `cargo check --workspace`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --check`, `cargo test
  --workspace`. Current baseline: **120 tests** (82 lib, 32 CLI, 6 e2e),
  clippy and fmt clean, `cargo audit` free of vulnerabilities. Don't
  regress that.

## Decisions already made — do not re-litigate

Recorded because each of these was proposed, considered, and settled for
a reason that isn't visible in the code.

- **Diffs show secrets, and that's accepted.** `path` prints a content
  diff to stderr, so a config file holding a revealed secret appears in
  the operator's terminal and the run view. This is deliberate, and
  matches Ansible. A full redaction implementation landed in `09ec86e`
  and was reverted in `61857f3` — read that commit message before
  proposing anything in this area. The short version: the old side of a
  diff can't be redacted without either withholding it always (which
  guts every diff) or keeping state on the target; a partial guard reads
  as a guarantee and isn't; and the operator already holds every vault
  key the play touches, so a diff discloses nothing they couldn't get
  from `cindy inventory --reveal`.
- **No state on the target.** cindy is agent-less and stays that way.
  This is what rules out the otherwise-clean solutions to diff
  redaction and to out-of-band drift detection. The human may revisit
  it later; until then it's a hard constraint.
- **No value-based secret masking.** Scanning output for known secret
  values (the CI-systems approach) was rejected: it misses anything
  transformed, and mangles diffs when a secret is short or common.
- **Diffs are not opt-in.** A `--diff` flag was rejected — an operator
  should be able to introspect a deploy by default. (A `--no-diff` for
  non-interactive/CI use is still fair game; that's about logs, not
  about defaults.)
- **No AAD on sealed ciphertexts.** Binding the vault name into the AEAD
  was proposed and correctly rejected: the threat model it defends
  ("attacker can rearrange ciphertexts but not execute code") doesn't
  exist here, because ciphertexts live in the playbook source and anyone
  who can move a blob can rewrite the code that consumes it. The
  *version byte* half of that proposal was the part worth keeping, and
  shipped in `9c6234a`.
- **`apt::install_all` was rejected** in favour of `impl
  Into<PackageList>`, which is what `fe3dc4e` implemented.
- **Buster (apt < 2.1.10) is not a target.** The fleet is VyOS 1.3+
  (apt ≥ 2.2.4) and OpenWrt (no apt), so `apt-get` relies on
  `-o DPkg::Lock::Timeout` and doesn't need the
  `run_check_retry_locks` wrapper `apt-mark` gets.
- **`--forks`/`--serial` were rejected** for the current fleet: the
  fan-out cost is SSH sessions against realistic fleet sizes, and the
  RPC byte budget already throttles the heavy traffic — the knobs
  advertise a slowness problem cindy doesn't have. Correction of the
  original rationale (which said rolling deploys are expressible in
  playbook code — they aren't): each host gets its own orchestrator
  process with no cross-host coordination point, so "deploy 10%,
  verify, then the rest" cannot be written today. The rejection
  stands for a router/AP fleet; if rolling deploys ever matter,
  `--serial N` is the shape, and it must be designed as a cross-host
  coordination primitive (one orchestrator driving hosts in batches),
  not a per-playbook workaround.

## Practices this codebase learned the hard way

Not tasks — the review findings that recurred, and the shapes that
stopped them. Worth applying to new code rather than rediscovering.

- **Conditional behaviour belongs in a pure decision function.** Every
  `--check` defect (the `Enablement::Disabled` unmask that mutated
  under `--check`, `fetch` under-reporting attr drift, and the guard in
  the reverted `09ec86e`) came from a condition replicated across call
  sites with nothing enforcing it. The shape that survives review is
  `plan_holds`, `system_conflict`, `disable_would_change`,
  `file_attrs_satisfied`: extract the would-this-change decision,
  unit-test it, and let both the real path and the dry-run path read
  the same answer.
- **When the message is the feature, assert on the message.**
  `assert!(result.is_err())` let two separate regressions ship green —
  an unknown-version error that didn't name the version, then a
  wrong-key error that claimed to be a version problem. Error-path
  tests assert the text in both directions: it says X, and it does
  *not* say Y.
- **Audit for mutations, not for guards.** Grepping existing
  `dry_run()` call sites found nothing wrong with `daemon_reload` —
  because it had no guard at all and so never appeared in the results.
  Enumerate the mutating operations and check each one is covered.

## Priority 2 — robustness and consistency

### `nix 0.31.3` future-incompat

Every build prints a future-incompatibility warning for `nix`. Blocked
upstream: bump when a fixed release exists. Until then it's noise that
trains people to ignore warnings.

## Priority 3 — architecture

Bigger pieces. Each is worth its own discussion before implementation;
don't start one without checking it's still wanted.

### Integration coverage for the mutating builtins

The highest-leverage item left. `examples/e2e-localhost` covers the
happy path, worker death, both backpressure budgets, check mode and
streaming fetch — but **nothing exercises `systemd`, `apt`, `user` or
`group`**, because they need a real system rather than a pipe. That is
exactly where the `--check` mutation bug shipped, and unit tests over
pure decision functions mitigate that without closing it.

A container-based harness would cover them (podman is already a
dependency, for `cross`). Also still untested at the integration level:
the vault-key handshake reaching a worker-side `reveal()`, preflight
failure on a missing key, `--limit` end to end, and concurrent
invocation of one builtin — which is the shadow-utils create race, so
it pairs with whichever of these lands first.

### Vault key rotation

There is no `cindy secret vault rotate`. Recovering from a leaked key
today means `unseal --all`, delete the key file by hand, `vault create`,
`seal --all` — with plaintext transiently on disk and no atomicity. A
first-class rotate belongs in the secrets story.

### `fetch` has no headers, auth, or proxy

`a9f7208` made it stream and bounded it, but there's still no way to pass
an `Authorization` header — so a private GitHub release can't be
fetched. `State` is the natural home.

### `archive`/`unarchive` still buffer whole trees

`crates/cindy/src/builtin/unarchive.rs:284` reads the whole archive into
memory before handing it to `decompress::bounded`, and
`archive.rs:62`/`:79` build tar and zip output in a `Vec<u8>`. The
decompression *ceiling* (`2d2574b`) closed the OOM-on-hostile-input
half; this is the remaining O(archive size) resident cost on ordinary
input. Same treatment `fetch` got in `a9f7208` — tar, zip and 7z all
support streaming readers.
