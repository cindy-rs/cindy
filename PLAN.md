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

### Integration coverage for the secrets and CLI paths

The mutating-builtins half of the old coverage item is closed:
`examples/e2e-containers` runs `systemd`, `apt`, `user` and `group`
against a real Debian-systemd container under podman — including the
`--check` mask regression pinned end to end, and the shadow-utils
create race (eight concurrent identical creates must converge to one
account). It self-skips where podman or its image is unavailable, so
the hermetic CI jobs stay green.

Still untested at the integration level, none of it needing
containers:

- the vault-key handshake reaching a worker-side `reveal()` — the
  localhost harness passes no keys, so a sealed secret has never
  crossed the wire in a test;
- preflight failure on a missing key (the worker must refuse before
  any playbook code runs);
- `--limit` end to end (CLI-side host filtering; only unit-tested).
  The localhost harness can carry the first two with a real vault;
  `--limit` needs the CLI's play path.

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
