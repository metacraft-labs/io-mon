# Linux grandchild capture is graded incomplete

|             |                                     |
| ----------- | ----------------------------------- |
| Status      | open — loss reason not yet recorded |
| Observed in | io-mon `cba489f`                    |
| Recorded    | 2026-09-28                          |
| Area        | Linux descendant propagation        |

## Observed

The full Linux suite fails `grandchild_of_launched_shell_is_monitored` in
`test_io_mon_propagation.nim`: `dep.completeness` is `mcIncomplete`, with an
`mrEventLoss` record. The real grandchild's file read, distinct process IDs,
and successful child exit checks pass. Both exec-chain propagation arms pass.
The test currently omits the loss record's details, so the cause is unknown.

## Expected

[IoMon-Pipeline-Capture IM-2](../../reprobuild-specs/IoMon-Pipeline-Capture.milestones.org)
requires monitoring throughout the descendant tree. This test explicitly
requires complete capture for a shell/child-shell/reader tree. Inspect the
loss before changing either the monitor or the fixture; retain completeness,
file-read and process-depth assertions.

## Evidence

[Linux job 108980569032](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36437923927/job/108980569032)
at `cba489f`. The earlier standalone CLI fixture repair passes in this run;
the suite reaches Linux-specific coverage before this failure.

Synced `origin/dev` and `origin/agents`; searched current issues and issue
history for propagation, grandchild loss and the failing case before filing.
