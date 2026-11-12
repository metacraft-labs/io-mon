# Linux: the inline-trap control needs two late opens in 20 attempts, which a fast runner may not produce

|             |                                                                                                                               |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Status      | resolved — the host holds its image open after the final drain (see Resolution)                                               |
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

## Resolution

Recorded 2026-11-11 against io-mon `7a9b2f3` (`agents`). The flake was
reproduced by pinning the test to one CPU (`taskset -c 3`): the unchanged test
failed `lateOpens >= 2` in 3 of 9 runs, with 0 late-open attempts in 20 in a
failing run.

The host fixture now holds the image open after the shim's final drain until
its opening thread has completed two more opens. Its destructor, which
glibc's `_dl_fini` runs before the shim's, registers an `on_exit` handler;
glibc runs a handler registered during `_dl_fini` after `_dl_fini` returns,
so after the drain. Every attempt therefore has an open trapped after the
drain, and the test now requires a late open in each of five attempts (was:
two of up to twenty), with the per-attempt loss and completeness assertions
unchanged. Measured at `7a9b2f3` plus the change: 20 of 20 runs passed, 10
pinned to one CPU and 10 unpinned; with the `on_exit` registration removed,
3 of 3 pinned runs failed (0, 2 and 1 late-open attempts of 5).

`dev` fixed the same failure independently in `5477f9f` (PR #60): it preloads
a library whose destructor sleeps 20 ms after the shim's drain and keeps the
two-of-twenty precondition. Merging `dev` into the promotion branch kept the
`on_exit` hold above instead, because it waits for two opens that started
after the drain rather than for a fixed time, so a late open does not depend
on the opening thread being scheduled within 20 ms, and it requires a late
open in every attempt rather than in two of up to twenty.
