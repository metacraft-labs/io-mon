# On Linux, the inline syscalls of a process killed by a signal are dropped without a loss

|             |                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------ |
| Status      | open                                                                                                   |
| Recorded    | 2026-11-09                                                                                             |
| Observed in | io-mon @ `f98f17e`, and the same with the change that follows it; x86_64 Linux, kernel 7.2             |
| Area        | `src/io_mon/shim/linux_preload.nim` (terminating-signal handler), `linux_preload_runtime.nim` (inline) |

## Observed

The x86_64 inline backend traps a program's own `syscall` instructions and
queues each trapped call. The queue is classified into records only at the
process-exit destructor, before a libc exec, and before an inline
`exit_group`/`execve`. Whatever is still queued at that point and cannot be
classified is reported as `inline raw syscall unsupported nr=<n>`.

A process that dies of a catchable terminating signal (SIGSEGV, SIGABRT,
SIGBUS, …) reaches none of those points. The shim's terminating-signal
handler (`repro_linux_terminating_signal_handler`) flushes the buffered
batch and writes the fragment's committed marker, but it neither classifies
nor reports the queued inline calls. So they disappear, and nothing marks
the capture incomplete.

Measured with a short C program. The root forks a child, which opens and
reads an input file through its own inline `openat` and `read`. The child
then either exits 0 or dereferences a null pointer. The root waits and exits
0 either way:

| Child               | Root exit | Capture      | Input read recorded | Event-loss |
| ------------------- | --------- | ------------ | ------------------- | ---------- |
| exits 0             | 0         | `mcComplete` | yes                 | none       |
| killed by signal 11 | 0         | `mcComplete` | **no**              | **none**   |

The second capture claims to be complete, but it is missing a read the
child made. A process that makes an inline clone with `CLONE_VM` and no
child stack (both processes then run on one stack) dies the same way, and
its capture also reads `mcComplete`, with no loss, although the trapped
`clone` was never reported.

## Expected

A trapped inline call that was never classified is never dropped silently.
Before writing the committed marker, the terminating-signal handler should
report the process's unclassified inline calls as event-loss. The report it
needs, `ct_report_unclassified_inline_events`, already uses raw system calls
and pre-encoded frames only, so it is safe to call from a signal handler.
The alternative is to withhold the committed marker while calls are queued,
which the inline `exit_group` path already does. SIGKILL is out of scope:
it cannot be caught, and its unretired pending sentinel already makes the
capture incomplete.

## Impact

A build step whose helper process reads inputs through inline system calls
(a statically linked or libc-free tool, or a language runtime that issues
its own syscalls) and then crashes, while its parent tolerates the crash
(for example, a configure-style probe that expects some programs to fail),
produces a capture graded complete that is missing the helper's reads. A
consumer that caches on `mcComplete` would then not rerun the step when that
input changes. On x86_64 Linux this is a false complete, not just a
behaviour difference.
