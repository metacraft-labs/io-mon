# macOS: the tree-guard "starved host" churn cases pass only when the churner is scheduled on time, and the launchd case needs `launchctl` on PATH

|             |                                                                                                                                              |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Status      | fix written, not yet measured on macOS (see Resolution)                                                                                      |
| Recorded    | 2026-11-12                                                                                                                                   |
| Observed in | io-mon `83eb364` (`agents-to-dev-2026-11-11`, PR #61), CI run 43122211901 job 130865269168 and run 43122211701 job 130865255802, macOS arm64 |
| Area        | `tests/macos/test_io_mon_macos_tree_lifetime_guard_faults.nim`, suite "macOS tree-lifetime guard: a starved host"                            |

## Observed

Three checks failed, each in only one of the two macOS jobs that ran the same
tree:

1. "unclassifiable young processes that keep changing stretch the window, and
   the quiesced capture completes" (`repro build/test` job): the capture was
   `mcComplete` with no loss, as required, but `spentMs` was 5059 against
   `spentMs < MacosDescendantGraceCeilingMsDefault` (5000).
2. "churn that never stops ends at the ceiling, and the loss names it"
   (`nix` job): the capture was `mcComplete` with no loss at all, where the
   case requires `mcIncomplete` and one `could not classify young processes`
   loss naming `ceiling-reached`.
3. "a launchd job is not classified by its creator id, and fails closed"
   (`repro build/test` job): `require submit.exitCode == 0` failed with 127.

## Why

The guard behaved as `docs/usage.md`, "The macOS tree-lifetime guard
(normative)", specifies in all three: it completes only after a conclusive,
empty sweep, and stretches the window only while unclassified young processes
remain and keep changing. The fixture did not hold the conditions the cases
assert against.

- The churner (`--guard-churn`) counted its duration in intervals
  (`waited += interval`), not wall-clock time. Each iteration is a fork, a
  `waitpid` and a `sleep(interval)`, so on a slow runner a "2000 ms" churn ran
  for about 5 s; the guard waited for it, correctly, and case 1 measured the
  host's speed.
- Each orphan lived a fixed 150 ms and a new one came every 40 ms. A churner
  descheduled for longer than about 110 ms left an instant with no orphan
  alive. A sweep at that instant is conclusive and empty, so the guard
  correctly graded the capture complete, and case 2, whose churn is meant to
  outlast the ceiling, saw no loss. The same gap can end case 1's churn early
  and fail its `spentMs >= 1000`.
- `launchctl` was invoked by bare name through `/bin/sh`. Under `repro test`
  the action's PATH holds only the tools `repro.nim` declares, so the shell
  did not find it (127). The `ps` probe of the "orphan-first" case had the
  same dependency and, failing, only timed out silently after 5 s, leaving
  its precondition unchecked.

## Resolution

Test fixture only; no product code and no assertion changed.

- The churn's duration is a monotonic deadline taken when it writes its
  ready file, so the cases measure the guard and not the churner's speed.
- Each orphan lives at least `life` ms and until the next orphan exists: it
  waits for EOF on a pipe whose only write end the churner closes once the
  next orphan has been forked (a SIGKILLed churner closes it too, so no
  orphan leaks). An orphan is therefore alive at every instant until the
  churn stops. A failed `pipe` or `fork` ends the churner with an error
  rather than leaving a gap.
- `launchctl` and `ps` are named `/bin/launchctl` and `/bin/ps`, as
  `test_io_mon_macos_tree_lifetime_guard.nim` already names `/bin/ps`, and
  the "orphan-first" case now `require`s that its `ps` probe saw U's exec.

Measured on Linux x86_64 against `83eb364` plus the change, with the churner
copied into a standalone program (the test itself is macOS-only): with the
churner SIGSTOPped for 400 ms mid-churn, the old churner had no orphan alive
in 5 of 17 and 4 of 18 samples, the new one in 0 of 20 in both runs; a
SIGKILLed new churner left no orphan 400 ms later. `nim check --os:macosx` of
the test passes, and fails when a call in the churner is broken on purpose,
so the macOS branch was type-checked. The test has not been run on macOS.

Remaining dependency: the stretch needs the unclassified set to change at
least once per grace window (500 ms), so a churner descheduled for longer
than that still ends case 1 incomplete and case 2 short of the ceiling.
