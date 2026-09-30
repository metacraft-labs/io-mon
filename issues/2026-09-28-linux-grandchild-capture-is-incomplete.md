# Linux grandchild capture is graded incomplete

|             |                                                |
| ----------- | ---------------------------------------------- |
| Status      | in progress — vfork identity and guard repairs |
| Observed in | io-mon `cba489f`                               |
| Recorded    | 2026-09-28                                     |
| Area        | Linux descendant propagation                   |

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

## Diagnosis and repair plan

Focused run `36441926922` at `cba489f` plus diagnostic logging records root
PID 5068, child shell 5069 and reader 5070. The child's `/bin/sh` exec is
attributed to 5068, and the reader exec to 5069. The resulting root exec/start
counts (1/1) falsely signal a missing post-exec start.

The Linux shim caches PID/PPID/TID and clears them in `pthread_atfork`, but
`vfork` shares the parent's TLS and does not run those handlers. Sample live
kernel identities for successful and failed exec records without overwriting
the suspended parent's caches. Keep the cached file-event path and the
completeness rules unchanged. Add an explicit real `vfork`/failed-exec/exec
regression that verifies the child's exec identities and the resumed parent's
file-write identity, then rerun propagation and the full Linux suite.

At `3d65deb`, native run `36443250340` passes both original propagation
tests and the new child's exec identity checks. The resumed parent's write
is absent. The C preload wrapper raises a thread-local recursion guard
around exec, but successful exec cannot lower it. With `vfork`, that guard
is shared with the suspended parent, so it remains raised when the parent
resumes. Tag exec guards with their owning PID and pre-dispatch depth;
restore the saved depth on the parent's next hook. Retain suppression
during libc PATH lookup and restore the previous guard context when exec
fails. The existing parent-write assertion must pass without weakening it.

## Validation

At `d6465ca`, native propagation run `36445335981` passes every assertion,
including the resumed parent's write. Restoring cached exec identities makes
the original grandchild and explicit `vfork` cases fail. The preceding guard
at `3d65deb` independently fails the parent-write assertion.

The complete Linux suite passes 428 cases at `d6465ca` in `36445342794`;
macOS passes 473 cases and Windows injection checks pass in `36444835899`.
Keep this issue until the verified repair is promoted to `dev`.
