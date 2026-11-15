# macOS: the tree-guard `vanish` seam reports a later sweep's verdict, so "an unrelated process vanishing mid-sweep" fails on a busy host

|             |                                                                                                                      |
| ----------- | -------------------------------------------------------------------------------------------------------------------- |
| Status      | fix written, not yet measured on macOS (see Resolution)                                                              |
| Recorded    | 2026-11-15                                                                                                           |
| Observed in | io-mon `51eb62a` (`agents-to-dev-2026-11-11`, PR #61), CI run 43308100179, macOS arm64 (GitHub-hosted `macos-26`)    |
| Area        | `tests/macos/test_io_mon_macos_tree_lifetime_guard_faults.nim`, the `vanish` seam in `src/io_mon/macos_tree_guard.c` |

## Observed

In the step "Verify isolated POSIX tests execute again" of the macOS repro
job, one check failed:

```
test_io_mon_macos_tree_lifetime_guard_faults.nim(451, 33): Check failed: faultVanishVerdict() == "nonmember"
faultVanishVerdict() was dead
[FAILED] an unrelated process vanishing mid-sweep is classified through its parent
```

The other assertions of the case (exit code, `mcComplete`, no loss) passed,
and so did every other case of the file.

## Why

The guard behaved as specified. The seam's bookkeeping did not report what it
documents.

- The case starts a helper from the test process, arms the seam with its pid,
  and runs a capture. The seam releases the helper (SIGUSR1) right after the
  first sweep's snapshot. The helper forks and exits, the census meets it
  gone, and the parent rule classifies it a non-member through its parent,
  the monitor's own process. That is the verdict the case asserts.
- The helper is the test process's child, and the test reaps it only in its
  `finally`, after the capture. Until then it is a zombie.
- `classify` stored the verdict on every classification of the pid, in every
  sweep of the capture. When the first sweep is inconclusive for another
  reason (an unrelated young process on a busy runner), the next sweep's
  snapshot lists the zombie helper, `classify` grades it `TG_DEAD` (correct:
  a zombie is not a live descendant, and it is not a hit), and that overwrote
  the first sweep's `nonmember`.

So the case passed only when the first sweep was conclusive. The sibling case
("a member that vanishes mid-sweep leaving a child is not trusted") was not
exposed: its member is reparented to launchd and reaped, so later snapshots
do not list it.

## Resolution

Test seam only (compiled only under `-d:ioMonMacosTreeGuardFaultTest`); no
census decision and no assertion changed.

- The seam keeps the first classification after the release, which is the
  classification in the sweep that released the pid, as its comment and
  `faultVanishVerdict` already said. Later sweeps of the capture no longer
  change it.
- The case says why a later sweep would see the helper as dead.

`nim check --os:macosx --cpu:arm64` of the test passes against the change.
The test has not been run on macOS.
