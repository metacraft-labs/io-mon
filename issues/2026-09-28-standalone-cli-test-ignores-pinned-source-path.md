# Standalone CLI fixture ignores the configured hooks source

- Status: open
- Observed in: `8d83702`

The complete Linux suite fails `dirExists(hooksSrc)` in
`test_io_mon_snoop_cli_smoke.nim` when the pinned Nix dependency is supplied
through `STACKABLE_HOOKS_SRC`. The fixture hardcodes a sibling checkout while
`config.nims` and `scripts/build_shim.sh` support the environment override.
The subsequent CLI compile succeeds, demonstrating that the compiler can
resolve the supplied source and the preflight checked a different path.

The [standalone CLI contract](../../reprobuild-specs/io-mon-hardening-protocol.md)
requires io-mon and nim-stackable-hooks, not
a particular checkout layout. Match the configured-source selection already
used by `test_io_mon_shim_builds_standalone.nim`; retain the real standalone
compile and depfile round-trip. Validate with a real dependency directory
outside the sibling layout and with a missing override as a negative control.

Evidence: [complete Linux run at 8d83702](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36435521649/job/108972317309).
Synced `origin/dev` and `origin/agents`, and searched current issues and issue
history for configured source paths and hardcoded sibling layouts before filing.

Validation at `5ec3816` plus the fixture fix: a temporary checkout with no
sibling dependency builds the CLI and round-trips its depfile using the configured
source directory. Pointing the same test at a missing source directory fails the
prerequisite assertion. The full Linux suite is being rerun before promotion.
