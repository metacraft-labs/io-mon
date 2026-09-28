# Standalone CLI fixture ignores the configured hooks source

- Status: open
- Observed in: `8d83702`

The complete Linux suite fails `dirExists(hooksSrc)` in
`test_io_mon_snoop_cli_smoke.nim` when the pinned Nix dependency is supplied
through `STACKABLE_HOOKS_SRC`. The fixture hardcodes a sibling checkout while
`config.nims` and `scripts/build_shim.sh` support the environment override.
The subsequent CLI compile succeeds, demonstrating that the compiler can
resolve the supplied source and the preflight checked a different path.

The M8 standalone CLI contract requires io-mon and nim-stackable-hooks, not
a particular checkout layout. Match the configured-source selection already
used by `test_io_mon_shim_builds_standalone.nim`; retain the real standalone
compile and depfile round-trip. Validate with a real dependency directory
outside the sibling layout and with a missing override as a negative control.

Evidence: [complete Linux run at 8d83702](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36435521649/job/108972317309).
Synced `origin/dev` and `origin/agents`, and searched current issues and issue
history for configured source paths and hardcoded sibling layouts before filing.
