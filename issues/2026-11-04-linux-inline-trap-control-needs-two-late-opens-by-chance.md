# Linux: the inline-trap control needs two late opens in 20 attempts, which a fast runner may not produce

|             |                                                                                                                               |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Status | in-progress (gpu-server-001:fix-linux-inline-trap-control-needs-two-late) |
| Observed in | io-mon `95ca754` (`dev`), CI (reprobuild) job 126587113787 `linux-x64 — repro build/test`                                     |
| Recorded    | 2026-11-04                                                                                                                    |
| Area        | `tests/linux/test_io_mon_shim_inline_trap_loss_inside_hook.nim`, `t_inline_events_trapped_after_the_final_drain_are_reported` |

## Observed

On the push run of `dev` at `95ca754`, the test failed at
`check lateOpens >= 2` with `lateOpens` = 1. The test runs a host whose second
thread keeps opening files while the main thread exits, up to 20 times, and
counts the attempts in which some opens landed after the shim's final drain.
For each such attempt it asserts that the loss is reported and the capture is
not complete. In this run the one late-open attempt it saw **was** reported
as a loss and graded incomplete; only the "the race happened at least twice"
precondition failed.

The same tree passed the same job in PR #58's run (`9cd683f`, identical
tree), in every local run on nixos-ci-bare-002 at load 140–900, and the dev
CI of `48e6d67` failed the same check once before (noted in the 2026-11-04
promotion report). So the outcome depends on scheduling.

## Expected

Not specified. The capture behaviour the test grades is correct in every
observed run. Proposed: make the precondition deterministic (hold the opening
thread until the drain has begun, the way
`test_io_mon_uninjectable_image_entry.nim`'s held chdir control does), so the
graded path is exercised on every run instead of by chance, without weakening
the per-attempt assertions.
