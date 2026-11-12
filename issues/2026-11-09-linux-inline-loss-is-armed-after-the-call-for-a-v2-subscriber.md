# On Linux, a V2 raw-syscall subscriber arms the inline loss only after the call ran

|             |                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------- |
| Status      | open — needs raw-syscall owner ABI V3                                                             |
| Recorded    | 2026-11-09                                                                                        |
| Observed in | io-mon @ `343c419` with the change that arms the inline loss; x86_64 Linux, by reading            |
| Area        | `src/io_mon/hooks/linux_preload_runtime.nim` (`ct_linux_preload_raw_enqueue_v1`, "AN ARMED LOSS") |

## Observed

A process that traps its own inline `syscall` instructions arms an
event-loss before each trapped call runs: an empty
`*-armed-inline-loss.iomon-frag` file, created with `mknodat` on its absolute
path, so no descriptor is needed. A drain withdraws it once everything
trapped is classified. A death that skips the drain leaves the file behind,
and the merge reads its existence as
`inline raw syscall events unclassified at image end`. The arm covers the
cases that used to leave a false complete:

- a death the shim's signal handlers never see;
- concurrent drains;
- a failed inline exec (an exec-armed file named by pid and start time, which
  the new image withdraws);
- a process with no descriptor left;
- a forked child.

Each is tested.

One path is not covered by THIS image's arm. When two io-mon shim images are
loaded in one process, only one owns the trap. The other subscribes through
raw-syscall owner ABI V2, which calls
`ct_linux_preload_raw_enqueue_v1` with the call's result. ABI V2 has no
callback before the call, so the subscriber can arm only after the call has
run and before it queues the event. A death in between loses the
subscriber's copy of the event.

When the owner is a build that arms, nothing is lost. The owner arms before
its replay and counts the call in flight until its subscriber callbacks
return, so its own armed file covers the same event. The gap is real only
when the owner is an older image that does not arm.

## Expected

A pre-call subscriber callback in a raw-syscall owner ABI V3, so a subscriber
arms before the owner replays the call. Until then, this path depends on the
owner arming.

## Impact

It needs two distinct io-mon shim builds loaded in one process (nested
monitoring with mixed versions), with an owner that predates arming, and a
death within a few instructions of a trapped call. In that case a capture can
read complete while lacking that call.

## Not covered here, by design

- **The fragment directory made unwritable.** A tracee that makes the fragment
  directory unwritable stops the arm from creating its file. The loss then
  goes out through the dependency set's no-grow insert (or its growth-failure
  counter), or through the thread's open fragment. With neither (the
  fragment-file transport, and no fragment open yet), the next trap retries.
  The tracee's own fragments cannot be written in that directory either, a
  class that predates the arm.
- **Spurious losses, which are safe.** A `vfork` or `CLONE_VM` child shares
  the armed state with its parent. When it overwrites the state with its own
  pid, the parent's file is orphaned (kept, never wrongly removed). Such
  children come from an inline `clone`, which is already reported as
  `inline raw syscall unsupported nr=56`, so this adds no new incomplete
  grade.
