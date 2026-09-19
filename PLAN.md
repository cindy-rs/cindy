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

### `group.rs`: the system-ness guard is unreachable when a GID is pinned

`crates/cindy/src/builtin/group.rs:212` — the GID-change arm has guard
`if want != have` and sits *above* the arm at `:241` that carries the
system-ness `bail!`. Rust matches top-down, and the GID arm never reads
`system`. So:

| Desired | Live group | Result |
|---|---|---|
| `{gid: None, system: Some(true)}` | gid 1500, non-system | **errors** |
| `{gid: Some(2000), system: Some(true)}` | gid 1500, non-system | **silently runs `groupmod --gid 2000`**, group stays non-system |

The second row is the stronger request and the one where crossing the
boundary matters, and it's the one that skips the check. Worse, the GID
arm's own diff view computes `system: Some(*want <= sys_gid_max())` —
so it renders a diff that contradicts the request it was handed, and
proceeds anyway. `user.rs:507` does this correctly: its check runs
*before* reconciliation, so it catches every combination.

**Blocked on a decision** — see [Needs a decision](#needs-a-decision).

### Shadow-utils: the observe→mutate race is still open

`fe3dc4e` added `run_check_retry_locks`, which handles lock contention.
It does not handle this: two concurrent runs both `observe()` "user
absent" through nix, both spawn `useradd`, and the loser fails with
`user 'bob' already exists`. That is correctly *not* treated as lock
contention, so it doesn't retry — and the play fails.

**Approach:** treat `already exists` (and `GID already in use`) as
convergence rather than failure — re-observe and reconcile. Another
agent having created the user is the desired end state, not an error.
The alternative, a cindy-private `flock` wrapping observe+mutate, also
works but costs a lock file; prefer the first.

**Done when:** a test drives two concurrent `user::present` calls for the
same name and both report success, one `Changed` and one `Unchanged`.

### Decompression has no output ceiling

`crates/cindy/src/builtin/decompress.rs:27` decompresses into an
unbounded `Vec<u8>`. `unarchive` feeds it whole archives, so a crafted
`.tar.gz` OOMs the worker. This matters more now than it looks:
`a9f7208` bounded `fetch`, and `fetch` → `unarchive` is the natural
pipeline, so the bound I added stops at exactly the wrong place.

**Approach:** a `max_bytes` on the decompress path mirroring
`fetch::State::max_bytes` (same default, same "reject and name the
knob" error). A `Read` adapter that errors past N bytes is enough for
all three codecs.

**Done when:** a test decompresses a small highly-compressible input
under a low ceiling and gets a named error, not an allocation.

### The seal/unseal rewriter hardcodes `::cindy::`

`crates/cindy-cli/src/secret.rs:287` emits `::cindy::Secret::sealed_b64`
and `:471` emits `::cindy::secret!`. That undoes `0fa1373`, which
specifically taught the macros to resolve the crate name so renamed
dependencies work. A playbook with `[dependencies] infra = { package =
"cindy" }` gets source that doesn't compile.

**Approach:** resolve the name the way the macros do (`proc-macro-crate`
against the playbook's manifest), or read it out of the `cargo metadata`
the CLI already has. Note the CLI runs from the playbook's directory, so
the manifest is reachable.

**Done when:** the round-trip test in that module runs against a
renamed-dependency fixture.

### One unparseable `.rs` breaks `unseal` for the whole workspace

`crates/cindy-cli/src/secret.rs:404` propagates tokenization errors, and
`unseal_all` walks *every* `.rs` file under the workspace root. A single
syntax-error test fixture anywhere makes `cindy secret unseal`
impossible.

**Approach:** skip files that don't tokenize, with a `tracing::warn!`
naming the path. A file cindy can't parse also can't contain a sealed
call it needs to find.

## Priority 2 — robustness and consistency

### Unbounded TUI log buffer

`crates/cindy-cli/src/progress.rs:64` — `log_buffer()` is a
`Mutex<Vec<String>>` that never evicts. `5ea6f0c` capped per-host output
at `MAX_LINES` (`:47`) but missed this one, so a long play grows it
without bound. Also `lock().unwrap()` inside a `Write` impl: one poisoned
lock and every subsequent log write panics.

**Approach:** same cap and eviction as the host panes; swallow poisoning
rather than panicking in a logging path.

### Key material left unzeroized, and inconsistent poison handling

`crates/cindy/src/secret/keychain.rs:132` — `read_key_file` reads a key
into a plain `Vec<u8>` and drops it unzeroized, while `install_raw_keys`
carefully zeroizes the equivalent buffer. And `cache_get` (`:37`)
swallows mutex poisoning by silently falling back to a disk read, where
`cache_put` (`:41`) panics on it. Pick one and apply it to both.

### `apt-get` on pre-2.1.10 apt

`fe3dc4e` passes `-o DPkg::Lock::Timeout`, which buster's apt 1.8 accepts
and ignores. `apt-get` itself is still called through plain `run_check`
(`crates/cindy/src/builtin/debian/apt.rs:672`). Wrapping it in
`run_check_retry_locks` covers old apt too and is safe — a lock
acquisition failure means apt did nothing at all. Only worth doing if
buster is a target; ask.

### Doc drift

Three comments that describe code that doesn't exist:

- `crates/cindy/src/secret/crypto.rs:10` says the wire layout is what
  `encrypt_in_place_detached` produces. The code calls `encrypt`.
- `crates/cindy/src/secret/mod.rs:427` says `Plain` values "serialise by
  encrypting on the fly". They don't — the impl returns an error. This
  one matters: it's a claim about behaviour in the security-critical
  module.
- `crates/cindy/src/builtin/systemd.rs:356` says `mask` removes a real
  unit file "or drop-in" that is in the way. Only a path named exactly
  `<unit>` is checked; `<unit>.service.d/` is untouched. Either handle
  drop-ins or fix the sentence. Note separately that `mask` deletes an
  admin-authored unit file with no warning and no diff — deliberate per
  the comment, but worth a loud line on stderr when it happens.

### Blocking I/O on async paths in the CLI

`crates/cindy-cli/src/main.rs`: `std::process::Command` for rustup at
`:476` and `:485`, `std::fs::read` of the entire worker binary **per
host** at `:617`, and the context-file write at `:661`. All inside async
tasks. Use `tokio::process` / `tokio::fs`, and read the worker binary
once per platform into an `Arc<[u8]>` rather than once per host.

### `cargo metadata` spawned three-plus times per run

`crates/cindy-cli/src/main.rs:170`, `:491`, `:918` — and `:918` is inside
`extract_executable`, so it runs once per artifact extraction. The
`Arc<Metadata>` at `:491` already exists; thread it through.

### `nix 0.31.3` future-incompat

Every build prints a future-incompatibility warning for `nix`. Bump when
a fixed release exists; until then it's noise that trains people to
ignore warnings.

### Workspace dependency hygiene

AGENTS.md says cindy's dependencies "should move toward
`[workspace.dependencies]`". `base64` and `tempfile` are still pinned
independently in `crates/cindy` and `crates/cindy-cli`.

### `archive` collides on basenames

`crates/cindy/src/builtin/archive.rs:35` — `entry_name` uses the final
path component, so `create(["/a/conf", "/b/conf"], …)` silently writes
two entries with the same name. Error on a duplicate.

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

1. **`group.rs` system-ness semantics.** Either (a) mirror `user.rs` and
   hoist the check above the GID arm, so `system` uniformly means
   "assert this" and moving a GID across the boundary requires dropping
   the field; or (b) treat an explicit `gid` as *the* mechanism for
   changing system-ness, in which case the error message at `:241` must
   say so instead of claiming `groupmod` can't do it. (a) is
   recommended — (b) makes `system` mean two different things depending
   on whether a sibling field is set.
2. **Is buster (apt < 2.1.10) a target?** Decides whether `apt-get` gets
   the retry wrapper.
3. **Is `--check` wanted for 0.4?** It's the item whose cost grows
   fastest with delay.
