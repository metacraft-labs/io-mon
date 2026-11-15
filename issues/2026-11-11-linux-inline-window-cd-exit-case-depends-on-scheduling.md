# Linux: the "cd-exit" inline-window case passes only when its 5 ms sleeps land inside a 20 ms window

|             |                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------- |
| Status      | resolved — the kill is ordered by a join and the window held open for 10 s (see Resolution)                     |
| Recorded    | 2026-11-11                                                                                                      |
| Observed in | io-mon `7a9b2f3` (`agents`) plus the 2026-11-11 stabilisation diff, Linux x86_64, `repro test` at load about 60 |
| Area        | `tests/linux/test_io_mon_shim_inline_loss_windows.nim`, `t_armed_inline_loss_holds_in_widened_windows`, cd-exit |

## Observed

During the 2026-11-11 stabilisation of `agents`, one run of
`t_armed_inline_loss_holds_in_widened_windows` failed its "cd-exit" case at
`check "child killed by signal 9" in cap.output`: the host reported
`child exited 0`. Other runs of the same tree pass, under `repro test` and
directly. The capture assertions of that attempt did not fail; only the
precondition that the process was killed inside the window did.

## Why

The case needs a SIGKILL to land while thread A's exit drain is inside the
widened claim window (`-d:ioMonInlineWindowTest` sleeps 20 ms between
claiming the queued event and recording it, `linux_preload.nim`
`drainInlineRawSyscallEvents`) and after thread B's failing exec has run a
second drain. The host arranges that with two fixed 5 ms sleeps on the main
thread (`child` in `hostSource`). On a loaded host the main thread can be
descheduled for longer than the 20 ms window, so A finishes its drain and
the process exits 0 before the kill is sent. Nothing orders the kill after B's
drain or before A's record; only the sleep lengths do.

## Expected

Not specified. The test's header says the windows are widened so the kill
lands inside them; it does not state a tolerance for scheduling. Lengthening
the sleeps alone would only make the failure rarer, and asserting less
(dropping the `killed by signal 9` check) would stop the test proving the
window was hit.

## Resolution

Recorded 2026-11-11 against io-mon `7a9b2f3` (`agents`) plus the
stabilisation diff. The same failure reproduced once in one
`repro build .#test-monitor-isolation` run at load about 50.

- The test-only shim build reads `IO_MON_INLINE_WINDOW_TEST_CLAIM_US` for
  the claim-to-record hold (20 ms when unset, so the other cases are
  unchanged), and the "cd-exit" case sets it to 10 s.
- The host waits until thread A's exit has reached the executable's
  destructor (which glibc runs before the shim's exit drain), starts B 5 ms
  later, joins B, and only then sends the SIGKILL. The kill is ordered after
  B's drain by the join, and lands inside A's window unless the host is
  starved for 10 s.

The assertions are unchanged. Measured at `7a9b2f3` plus the change: 24 of
24 runs of the whole test passed, eight at a time, at load about 60; a debug
print showed every "cd-exit" capture with the open unrecorded, the
unclassified-inline loss reported, `mcIncomplete`, and the child killed by
signal 9, so the window was hit in every attempt. Removing both
`ct_inline_in_flight` checks from `ct_linux_retract_inline_loss_if_drained`
(the concurrent-drain withdrawal the case guards against) failed all eight
"cd-exit" attempts with a complete capture missing the open.
