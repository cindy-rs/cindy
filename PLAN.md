# PLAN.md

Outstanding work, written up by `opus` after a full review of the
codebase at `15bc5c4` plus the five commits that followed. Intended to be
picked up by another agent — read [AGENTS.md](AGENTS.md) first, then this.

Line references are accurate as of `61857f3`; re-grep before trusting
them, the code moves.

## How to use this file

- Items are grouped by priority. Within a group, order doesn't matter.
- Each item states the **problem**, a **suggested approach**, and how to
  know it's **done**. The approach is a suggestion, not a specification —
  if you see a better one, take it and say why in the commit message.
- Some items are blocked on a decision only the human can make. They're
  in [Needs a decision](#needs-a-decision). Don't guess; ask.
- Tick items off by deleting them from this file in the same commit that
  implements them. A stale plan is worse than no plan.
- Verify with `cargo check --workspace`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --check`, `cargo test
  --workspace`. Current baseline: **96 tests** (68 lib, 24 CLI, 4 e2e),
  clippy and fmt clean, `cargo audit` free of vulnerabilities. Don't
  regress that.

## Decisions already made — do not re-litigate

Recorded because each of these was proposed, considered, and rejected
for a reason that isn't visible in the code.

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
  *version byte* half of that proposal was implemented separately
  (see git history).
- **`apt::install_all` was rejected** in favour of `impl
  Into<PackageList>`, which is what `fe3dc4e` implemented.
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

## Priority 1 — correctness bugs

## Priority 2 — robustness and consistency

### `apt-get` on pre-2.1.10 apt

Decided: **buster is not a target** — the fleet is VyOS 1.3+ (apt ≥
2.2.4) and OpenWrt (no apt). `apt-get` keeps plain `run_check_retry_locks`
coverage only via the `-o DPkg::Lock::Timeout` option old apt silently
ignores, which is acceptable.

### `nix 0.31.3` future-incompat

Every build prints a future-incompatibility warning for `nix`. Bump when
a fixed release exists; until then it's noise that trains people to
ignore warnings.

## Priority 3 — architecture

Bigger pieces. Each is worth its own discussion before implementation;
don't start one without checking it's still wanted.

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

`crates/cindy/src/builtin/unarchive.rs:275` reads the whole archive into
memory and then decompresses into a second buffer;
`archive.rs` builds trees in a `Vec<u8>`. The same treatment `fetch` got
in `a9f7208` — tar, zip and 7z all support streaming readers. Do the
decompression ceiling above first; it's the safety-relevant half.

### e2e coverage gaps

`examples/e2e-localhost` covers the happy path, worker death,
backpressure and streaming fetch. Untested: the vault-key handshake
reaching a worker-side `reveal()`, preflight failure on a missing key,
`--limit` end to end, and concurrent builtin invocation — which is where
the shadow-utils race above lives, so that item and this one pair well.