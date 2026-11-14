# On 32-bit ARM Linux, a program's own inline `clone` with a child stack still runs inside the trap handler

|             |                                                                                               |
| ----------- | --------------------------------------------------------------------------------------------- |
| Status      | open                                                                                          |
| Recorded    | 2026-11-14                                                                                    |
| Observed in | io-mon @ `3f0c0e6ff` plus the x86_64 fix for this defect's sibling (below); by reading, armhf |
| Area        | `src/io_mon/hooks/linux_preload_runtime.nim` (inline-syscall trap handler), `__arm__` arm     |

## Observed

This is the 32-bit ARM half of
`2026-11-08-linux-inline-clone-with-a-child-stack-crashes-the-child`, which
was fixed for x86_64 only. The x86_64 handler now sends a trapped `clone` /
`clone3` that names a child stack through a per-site resume stub
(`syscall; int3`) in the shim's text, so the call runs in the program's
restored context and the child starts there, on its new stack (see
`docs/contributors/architecture.md`, "A trapped call runs as it would
unmonitored").

The armhf trap path shares the same handler (`#if defined(__x86_64__) ||
defined(__arm__)`) but not the stub table, which is x86_64 assembly. On ARM a
trapped ARM-state `svc #0` issuing `clone` / `clone3` with a child stack is
still replayed by `stackable_linux_replay_syscall_regs` inside the SIGILL
handler, so the kernel starts the child inside the handler, on the stack the
program passed, with none of the handler's frames on it. By the same
reasoning as the x86_64 measurement, the child crashes as soon as the handler
returns.

Not measured: this host (x86_64) has no armhf toolchain, no binfmt
registration and no ARM machine it may use, and `qemu-arm` user mode refuses
a CLONE_VM clone that is not a thread, so the CLONE_VM cases could not be
exercised there anyway. The existing ARM suites
(`tests/linux/test_io_mon_linux_arm_thumb_unscanned.nim`) run on an ARM host.

## Expected

Not specified for ARM beyond the general contract the x86_64 fix wrote down
(`docs/contributors/architecture.md`, Raw Syscall Hooking: a trapped call runs
as it would unmonitored). Proposed: the same design on ARM. A per-site table
of ARM-state stubs (`svc #0; udf #<n>`), one per site, call (`clone`,
`clone3`) and class of child (fork-like, CLONE_VM process, other CLONE_VM),
the second trap recognised by the SIGILL pc falling inside the table,
resuming at the site's `pc + 4`. Only ARM-state sites qualify, because
Thumb-capable images are not scanned. Then run
`tests/linux/test_io_mon_shim_inline_clone_child_stack.nim` (x86_64 today)
with an ARM fixture on an ARM host.

## Impact

Same as the x86_64 issue, on armhf: programs that create processes or
threads with their own inline `clone` and a separate stack crash their
children under the shim. Their captures are graded incomplete
(`inline raw syscall unsupported nr=120` / `nr=435`), so no wrong evidence is
published.
