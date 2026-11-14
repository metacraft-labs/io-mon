# On x86_64 Linux, an inline `clone3` with `CLONE_CLEAR_SIGHAND` and a child stack loses its child to SIGTRAP

|             |                                                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------------------------------ |
| Status      | open                                                                                                                     |
| Recorded    | 2026-11-14                                                                                                               |
| Observed in | io-mon @ `3f0c0e6ff` plus the fix for `2026-11-08-linux-inline-clone-with-a-child-stack-crashes-the-child`; x86_64 Linux |
| Area        | `src/io_mon/hooks/linux_preload_runtime.nim` (inline-syscall trap handler, clone resume stubs)                           |

## Observed

The fix for `2026-11-08-linux-inline-clone-with-a-child-stack-crashes-the-child`
sends a trapped `clone` / `clone3` that names a child stack through a per-site
resume stub, `syscall; int3`, in the shim's text. Both the parent and the
child stop at the stub's `int3`, and the shim's SIGTRAP handler finishes the
call in each (see `docs/contributors/architecture.md`, "A trapped call runs as
it would unmonitored").

`CLONE_CLEAR_SIGHAND` (clone3 only, Linux 5.5+) resets every signal handler of
the child to the default before the child runs. The child's `int3` then
raises SIGTRAP with the default disposition, and the child is killed by
SIGTRAP (signal 5) instead of continuing after the program's `syscall`.

Measured with the fixture of
`tests/linux/test_io_mon_shim_inline_clone_child_stack.nim`, its clone3
`flags` widened by `CLONE_CLEAR_SIGHAND` (`0x100000000`), against the shim
built from that working tree:

| Run          | clone3 flags (child stack named)             | Child                                    |
| ------------ | -------------------------------------------- | ---------------------------------------- |
| unmonitored  | `CLONE_CLEAR_SIGHAND`, exit signal `SIGCHLD` | exited 7                                 |
| `io-mon run` | the same                                     | killed by signal 5                       |
| unmonitored  | `CLONE_CLEAR_SIGHAND \| CLONE_VM`, `SIGCHLD` | reported 7                               |
| `io-mon run` | the same                                     | died, wait status `0x85` (SIGTRAP, core) |

This is not a regression: before that fix the same children were started
inside the handler and died by SIGSEGV.

The flag combination matters in practice. glibc 2.42's `posix_spawn` issues
`clone3` with `CLONE_CLEAR_SIGHAND | CLONE_VFORK | CLONE_VM` and a child stack
(`movabs $0x100004100` in `__spawni`). glibc's own `clone3` is in `libc.so.6`,
which the inline scanner skips, and a statically linked program does not load
the shim at all, so ordinary programs do not reach this path. A program that
carries its own copy of that code in a dynamically linked executable or
custom shared object does.

## Expected

A monitored program runs as it does unmonitored (the expectation stated in the
issue this one follows). A child that shares the parent's memory needs no
bookkeeping of its own, so its route from the stub back to the program need
not trap at all. One possible shape, without clobbering the flags the kernel
restored from `r11`: `syscall; xchg %rax,%rcx; jrcxz child; xchg %rax,%rcx;
int3`, where `child` loads the site's resume address into `rcx` (which then
matches what an unmonitored `syscall` leaves there), sets `rax` to 0 with
`mov`, and jumps. A fork-like child with `CLONE_CLEAR_SIGHAND` still needs the
inherited-lock reclaim that the trap gives it today, and needs a design of
its own.
