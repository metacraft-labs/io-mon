# macOS Nimble test command crashes before executing the suite

|             |                                             |
| ----------- | ------------------------------------------- |
| Status      | open                                        |
| Recorded    | 2026-09-28                                  |
| Observed in | io-mon @ `0d636e2`                          |
| Area        | `just test`, pinned macOS development shell |

## Observed

The native macOS ARM64 Nix CI job enters the pinned development shell and
runs `nimble test`. It immediately prints `SIGSEGV: Illegal storage access.
(Attempt to read from nil?)` and exits 139, before compiling a test.
Direct portable-test compilation was previously successful at `d49abaf`.
This is a test-driver failure, not evidence that the full host suite passed.

## Expected

`AGENTS.md` documents `just test` as the supported portable and host-OS test
entrypoint. `tests/README.md` defines the selected test classes. The command
must execute them or report an actionable setup failure.

## Evidence

[Native macOS Nix test job at 0d636e2](https://github.com/metacraft-labs/io-mon/actions/runs/36378715964/job/108789783089).
The same immediate Nimble crash was seen locally during release preparation.
The release changes did not introduce the manifest's version expression;
`origin/dev` has the same expression. The precise crash cause remains unknown.

Refreshed `origin/dev` (`279a17b`) and searched open issues and issue history
for Nimble crashes before recording. Preserve the full suite when repairing
its entrypoint; the separate release capture checks do not replace it.
