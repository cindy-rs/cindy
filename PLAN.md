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
