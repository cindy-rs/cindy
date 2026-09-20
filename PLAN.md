# PLAN.md

Outstanding work, in rough priority order. Read [AGENTS.md](AGENTS.md)
first — settled decisions, review practices and the verification
commands live there, not here.

Delete an item below in the same commit that implements it. If you
decide *against* one, move it to AGENTS.md's settled decisions rather
than dropping it. Line references are accurate as of `60b3982`; re-grep
before trusting them.

Each item states the **problem** and a **suggested approach**. The
approach is a suggestion, not a specification — if you see a better one,
take it and say why in the commit message. The P3 items are large enough
to be worth confirming they're still wanted before starting.

## P2 — robustness

### `nix 0.31.3` future-incompat

Every build prints a future-incompatibility warning for `nix`. Blocked
upstream: bump when a fixed release exists. Until then it's noise that
trains people to ignore warnings.

## P3 — architecture

### Integration coverage for the mutating builtins

The highest-leverage item left. `examples/e2e-localhost` covers the
happy path, worker death, both backpressure budgets, check mode and
streaming fetch — but **nothing exercises `systemd`, `apt`, `user` or
`group`**, because they need a real system rather than a pipe. That is
exactly where the `--check` mutation bug shipped; unit tests over pure
decision functions mitigate that without closing it.

A container-based harness would cover them (podman is already a
dependency, for `cross`). Also untested at the integration level: the
vault-key handshake reaching a worker-side `reveal()`, preflight failure
on a missing key, `--limit` end to end, and concurrent invocation of one
builtin — which is the shadow-utils create race, so it pairs with
whichever of these lands first.

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
