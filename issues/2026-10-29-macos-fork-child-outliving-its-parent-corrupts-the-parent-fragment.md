# macOS: a fork child that outlives its parent can corrupt the parent's fragment

|             |                                                                                         |
| ----------- | --------------------------------------------------------------------------------------- |
| Status      | fixed in the working tree (pending review), see "Root cause"                            |
| Observed in | io-mon `6fccd92` plus the uncommitted macOS tree-lifetime guard                         |
| Recorded    | 2026-10-29                                                                              |
| Area        | macOS shim fragment writer across `fork` (`writer.nim`, `discardFragmentSlotAfterFork`) |

## Observed

A monitored root `fork`s 40 children and exits at once. Each child sleeps
120 ms, reads one file and exits. About one capture in 15 to 30 is graded
`mcIncomplete` with `corrupt or partial iomon fragment in <dir>`. The corrupt
file is always the ROOT's fragment, not a child's.

- With the same children created by `posix_spawn` (re-exec, no inherited
  writer state), 0 of 60 captures were corrupt.
- When the root waits for its forked children before exiting, 0 of 40
  captures were corrupt.
- When the children exec after the delay instead of reading, the rate does
  not change (1 of 45).
- Afterwards the root fragment on disk ended on a frame boundary: its last
  frame is a `fork` `mrProcessSpawn` with a complete length prefix. So the
  merge most likely read the file while bytes were still being added to it,
  and the obvious suspect is the stdio state a fork child inherits for the
  parent's fragment.

This was invisible before the macOS tree-lifetime guard. Every macOS capture
carried the blanket tree-lifetime marker and graded `mcIncomplete` anyway,
and the merge ran before the children wrote anything. Now the guard waits for
the children, the merge runs after them, and the corruption shows up as a
loss of its own.

## Expected

A fork child must never write to its parent's fragment.
`discardFragmentSlotAfterFork` is meant to make sure of that: it drops the
batch and closes the inherited handle. Find out whether it runs on every
macOS fork path (the trampoline `fork`, interpose-only `fork`, a fork from a
non-main thread), and whether an inherited `FILE*` buffer can still be
flushed into the shared file description by the child's `exit()`.

## Impact

The loss is fail-safe: a false `mcIncomplete`, never a false `mcComplete`.
But the step is then not cached. Trees whose forked processes outlive their
parents (daemonising tools, some shell pipelines) are affected.

## Evidence

The scratch reproduction harness is in
`/private/tmp/claude-508/-Users-zahary/a9984338-0dc6-4203-af4b-1b4c3a0d92f4/scratchpad/iomon/exp`
(`tree.c` in `burst` mode; the instrumented host keeps fragment directories
and prints the corrupt path and size). The guard's own census logged every
child as a member until it was gone, so the guard did not end early.
`tests/macos/test_io_mon_macos_tree_lifetime_guard.nim` case 4 uses
posix_spawned children for this reason.

## Root cause (2026-10-30)

The macOS shim never called `discardFragmentSlotAfterFork`; only the Linux
shim's `atfork` child handler does. A macOS fork child therefore kept the
parent's open fragment slot, and its FIRST record (in practice an
`mrEnvRead` that libsystem's own fork child handlers trigger, before the
shim's fork hook returns in the child) saw a new `(osPid, threadId)` key and
took the key-change path in `appendFragmentRecord`: flush the in-flight
batch, then close. That batch is the parent's, and the descriptor shares the
parent's open file description, so every fork child appended a copy of the
parent's pending frames to the parent's fragment at the shared offset. The
waiting variant duplicates frames deterministically (a root that forks and
waits for 5 children carried its own `mrProcessStart` 6 times and 15 spawn
records for 5 forks; for 500 forks the root fragment was 3.35 MB instead of
52 KB). When the parent's own flush races a child's, the frames interleave
and the fragment is corrupt: 1 in 20 runs of 500 waited-for forks with
the shim at `6fccd92`, and 17 in 20 once the tree ledger made each fork child
do a little more work before its first record.

The fix is in the writer, where the flush happens, not in a fork hook that
runs too late: a slot records the pid that opened it (`ownerPid`), and
`flushFragmentBatch` and the key-change path drop an open slot whose owner is
not the current process (`slotInheritedAcrossFork`) instead of flushing it.
After the fix: 0 of 20 corrupt, no duplicate frames, and
`tests/macos/test_io_mon_macos_tree_lifetime_guard.nim` case 4b counts the
root's spawn records for 40 forked children that outlive it (exactly 40, on
both launch paths).
