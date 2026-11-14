# On Linux, a program's own inline `clone` with a child stack crashes the child under the shim

|             |                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------ |
| Status | open |
| Recorded    | 2026-11-08                                                                                             |
| Observed in | io-mon @ `75a4ccb`, and the same with the change that follows it; x86_64 Linux, kernel 7.2             |
| Area        | `src/io_mon/hooks/linux_preload_runtime.nim` (inline-syscall trap handler), nim-stackable-hooks replay |

## Observed

A program that issues `clone` through its OWN `syscall` instruction, with a
child stack, loses the child when it runs under the shim. The x86_64 inline
backend patches that instruction to trap, and the trap handler replays the
call with `stackable_linux_replay_syscall_regs`, which is a plain raw system
call made from inside the handler. The kernel starts the child at the
instruction after that system call, inside the handler, on the stack the
program passed. The handler's frames are not on that stack, so the child
crashes as soon as it returns.

Measured with a 30-line C program (`clone(SIGCHLD [| CLONE_VM], stack)` in
inline assembly; the child calls a function that exits 7, the parent waits).
Every run below passes a child stack; only the flags differ:

| Run          | Flags (all with a child stack) | Child               |
| ------------ | ------------------------------ | ------------------- |
| unmonitored  | `SIGCHLD`                      | exited 7            |
| unmonitored  | `SIGCHLD \| CLONE_VM`          | exited 7            |
| `io-mon run` | `SIGCHLD`                      | killed by signal 11 |
| `io-mon run` | `SIGCHLD \| CLONE_VM`          | killed by signal 11 |

Both monitored captures are `mcIncomplete` with
`inline raw syscall unsupported nr=56`, because no trapped clone is
classified. So the capture fails closed, but the monitored program behaves
differently from the unmonitored one.

A clone WITHOUT a child stack (`newsp == 0`, the form `fork` uses) is not
affected. Measured at `f98f17e` (with the change that follows it) with the
same program and `SIGCHLD`: under `io-mon run` the child exits 7, as it does
unmonitored, because it continues on a copy of the handler's stack. That capture is still `mcIncomplete` with
`inline raw syscall unsupported nr=56`, as in the runs with a stack.
(`CLONE_VM` without a child stack is not a usable form, monitored or not:
both processes would run on one stack.)

## Expected

A monitored program runs as it does unmonitored. The trap handler should
replay a clone that names a child stack so that the child resumes at the
trapped instruction's successor with the program's registers and stack,
not inside the handler: for example through a trampoline that the child
enters on the new stack and that restores the trapped register state (the
`stackable_linux_clone_continuation_trampoline` declared in
nim-stackable-hooks is shaped for this, but the replay does not use it).

When that works, the trap path should also write the tree-ledger entry and
the CLONE_VM-process loss for a CLONE_VM child, as the `syscall(2)` route
does (`ct_linux_preload_after_raw_fork_syscall`). It does not today; the
child cannot survive the replay, so there is nothing for an entry to name,
and the capture is already incomplete through the unsupported-syscall loss.

## Impact

Programs that create processes or threads with their own inline `clone`
and a separate stack (code that implements its own threads or process
creation without libc) crash their children under the shim on x86_64 Linux.
Their captures are graded incomplete, so no wrong evidence is published, but
the action does not run as it would unmonitored.
