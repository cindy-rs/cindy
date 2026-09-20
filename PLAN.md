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

### `--limit` end to end (CLI-side host filtering; only unit-tested)

The rest of the old integration-coverage item is closed. The mutating
builtins run against a real Debian-systemd container in
`examples/e2e-containers` (`6f26f59`, required, not optional), and the
secrets paths are pinned in `examples/e2e-localhost`: a real vault key
crosses the RPC handshake and reveals worker-side
(`secret_reveals_on_the_worker_through_the_handshake`), the
orchestrator refuses a missing key before any playbook code runs
(`missing_key_refuses_before_any_playbook_code_runs`), and the worker
refuses a keyless handshake at the preflight, before dispatching a
call (`worker_refuses_a_keyless_handshake_before_any_code_runs`,
driven by a `worker-vault-demand` cargo feature so ordinary scenario
workers stay demand-free).

What's left is driving the real CLI through `play --limit`, and the
blocker is architectural: discovery and deployment hold
`openssh::Session` values directly (`main.rs`), so no harness can
inject a host transport. The seam would be a session enum —
`Ssh(openssh::Session)` or a local stdio transport — threaded through
discovery, worker upload and deploy. That would make the whole play
path e2e-able (`--check`, the CLI vault preflight, the run summary),
not just `--limit`; it's this item's real payload and its real cost.
P3-sized: confirm before starting.
