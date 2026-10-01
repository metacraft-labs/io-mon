# Full local pre-commit gate fails on tracked files

Status: open. Observed at io-mon `51b5fea3c541c21af1a0d24a32aaca8fa6ac5edc`.

## Observed

In the repository's pinned macOS ARM64 Nix development shell,
`prek run --all-files` fails its end-of-file, Prettier and ShellCheck hooks.
Formatting hooks modify documentation and archived research fixtures.
ShellCheck 0.11.0 reports unquoted arguments, unused variables and a Zsh
shebang in an otherwise portable research script. The declared CI
`just lint` target checks only Nix formatting and cannot detect these failures.

## Expected

[How To Promote agents to dev, Step 3](https://github.com/metacraft-labs/metacraft-dev-guidelines/blob/0a223c939347bc29525d23c88e9917fe3029bc2d/policies/how-to-promote-agents-to-dev.md#3-stabilise-locally)
requires the complete local pre-commit gate before opening a promotion PR.
Tracked scripts and documents should satisfy the enabled checks.

## Evidence and scope

The complete output is `/tmp/io-mon-agents-local-lint.log` on the reporting
workstation. Representative findings are SC2086 in
`research/adversarial-2026-06-round3/r3_merge/run_kill.sh`, SC1071 in
`research/adversarial-2026-06-round2/r2_implicit/sig.sh`, and SC2034 in
`scripts/bench_beam_overhead.sh`. These files are unchanged between dev
`2d07041` and agents `51b5fea`; the failures predate the current promotion.

Fetched both branches and searched open issues and their complete Git history
for ShellCheck, the full pre-commit sweep and SC1071 before recording this.
Repair quoting and unused values, use the supported shell for portable code,
and accept the configured formatting. Keep every enabled gate and test.
