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
  *version byte* half of that proposal does still stand — see below.
- **`apt::install_all` was rejected** in favour of `impl
  Into<PackageList>`, which is what `fe3dc4e` implemented.

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

### `--check` / dry-run

The largest missing feature versus Ansible, and the one that gets more
expensive to add the longer it waits. The machinery is mostly there:
every builtin already computes desired-vs-live and renders a diff before
acting. Thread a `dry_run` flag through `WorkerInbound::Handshake` into a
worker-global, and have each `apply` return after the diff. Doing this
before more builtins land is much cheaper than after.

### `--forks` and `--serial`

`crates/cindy-cli/src/main.rs:459` fans out discovery with
`try_join_all` and `:776` fans out deployment with `join_all`, both
unbounded. Two hundred selected hosts means two hundred concurrent SSH
sessions and two hundred local orchestrator processes. `--forks N` is a
semaphore (the `build_gate` at `:494` is the pattern); `--serial N` is
batching, and is the reason people tolerate Ansible's slowness — it's
what makes rolling deploys possible.

### Worker upload is O(hosts × binary) per run

`crates/cindy-cli/src/main.rs:617` pipes the whole (~8 MB static musl)
binary to every host on every play, uncompressed, with no cache. Hash it,
probe the target for an existing copy, upload only on miss. Related:
`/tmp` is `noexec` on hardened hosts, which fails the play with a
confusing exec error — make the staging directory configurable (`:579`)
and say so explicitly when exec fails.

### Orchestrator-side RPC backpressure

`0e2c8fc` gave the worker a byte-weighted budget. The orchestrator's
`writer_tx` (`crates/cindy/src/orchestrator.rs:76`) is still unbounded,
so when the worker stalls the pipe, serialized frames pile up in
orchestrator memory — a second full copy of everything the play holds.
Mirror the worker's semaphore on the dispatch side.

### systemd: connection per call, fixed job timeout

`crates/cindy/src/builtin/systemd.rs:484` opens a fresh system-bus
connection for every action; a play touching 20 units opens 20. A
worker-global `OnceCell<Connection>` is a small safe win. `JOB_TIMEOUT`
(`:234`) is hardcoded at 90s, which is short for a database start —
make it a `State` field. Separately, `read_active_state` uses `LoadUnit`
for what is a read-only probe, which *loads* the unit as a side effect;
`GetUnit` with a fallback is the non-mutating form.

### Vault key rotation

There is no `cindy secret vault rotate`. Recovering from a leaked key
today means `unseal --all`, delete the key file by hand, `vault create`,
`seal --all` — with plaintext transiently on disk and no atomicity. A
first-class rotate belongs in the secrets story.

### A version byte on sealed ciphertexts

The surviving half of the rejected AAD proposal, and *not* a security
argument. Sealed ciphertexts get committed to source and live for years.
Today the only way to tell a v1 blob from a future v2 is that postcard
fails to parse it — which is literally how `crates/cindy/src/secret/mod.rs`
guesses ("probably sealed by an older cindy version"). One leading byte
turns every future crypto change into a clean, detectable migration.
Cheapest now, before there's a corpus of blobs in the wild.

### `KnownHosts::Add` is blind TOFU

`crates/cindy-cli/src/main.rs:426` silently trusts the first host key it
sees. At minimum log the accepted fingerprint; ideally offer a strict
mode.

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

## Needs a decision

Ask the human; don't pick for them.

1. **Is `--check` wanted for 0.4?** It's the item whose cost grows
   fastest with delay.
