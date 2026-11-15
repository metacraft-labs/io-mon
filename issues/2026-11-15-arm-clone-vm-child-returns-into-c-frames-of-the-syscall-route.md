# ARM and AArch64: a CLONE_VM child created through syscall(2) returns into the shim's C frames with the parent's frame pointer

|             |                                                                                            |
| ----------- | ------------------------------------------------------------------------------------------ |
| Status      | open; the raw-syscall leaf is fixed, the route above it needs a design                     |
| Recorded    | 2026-11-15                                                                                 |
| Observed in | io-mon `51eb62a` plus the leaf fix, cross-compiled at -O0 with GCC 15.3 (no ARM host run)  |
| Area        | `ct_linux_preload_syscall_replacement`, `ct_raw_syscall6`, the shim's `syscall` interposer |

## Background

A clone with `CLONE_VM` and a new stack (`syscall(SYS_clone, CLONE_VM, sp)`,
or `SYS_clone3` with `stack`) starts the child at the instruction after the
syscall instruction, with the child's stack pointer and every other register,
the frame pointer included, the parent's. Whatever code runs in the child
before it reaches its own frames therefore runs against the parent's frame.

On x86-64 that code is only the raw-syscall leaf: its `ret` pops the child's
new stack, so the child skips every C frame of the shim (glibc's `syscall(2)`
behaves the same way, and `tests/linux/test_io_mon_linux_tree_ledger.nim`
case 15 relies on it). The leaf was a C function that, built at -O0, stored
its result into the parent's frame, so the parent later returned to address 0.
nim-stackable-hooks now provides the leaf as a hand-written function, and on
AArch64 io-mon's own leaf (`ct_linux_aarch64_raw_syscall6`) is one too.

## The defect

On 32-bit ARM and AArch64 the return address is in a register (`lr` / `x30`),
not on the stack. The child's leaf returns through it into the C function
that called the leaf, still with the new stack pointer and the parent's frame
pointer:

- 32-bit ARM, the syscall(2) replacement: `ct_raw_syscall6` (C) and then
  `ct_linux_preload_syscall_replacement` (C) run in the child. Measured on the
  -O0 cross build of the runtime: `ct_raw_syscall6` ends in `sub sp, fp, #4;
pop {fp, pc}`, which moves the child back onto the PARENT's stack and pops
  the parent's saved registers, after which the child runs the replacement's
  post-syscall bookkeeping on the parent's stack.
- AArch64, where the replacement is not installed: the shim's `syscall`
  interposer forwards to libc's `syscall(2)`, whose child returns into the
  interposer (C), which runs `ct_linux_preload_after_raw_fork_syscall` in the
  child before its epilogue loads its return address from the new stack.

The leaf fix removes the part of this that happened inside the leaf (on ARM
the old C leaf restored `sp` from the frame pointer at every optimisation
level). It cannot fix the frames above it.

## What a fix needs

The x86-64 inline-trap path already has the shape: nim-stackable-hooks'
`stackable_linux_clone_continuation_trampoline` issues the syscall and sends
the child (result 0) straight to the resume address, while only the parent
returns to C. The syscall(2) route on ARM and AArch64 needs the same for
clone, clone3 and vfork-like calls: run the pre-call bookkeeping in C, then
issue the call from an assembly stub that hands the child to the caller's
return address with the caller's registers, and returns only the parent to C
for the post-call bookkeeping. That is a change to the shim's syscall-route
design and to nim-stackable-hooks' ARM/AArch64 substrate, so it is recorded
here rather than made in passing. No ARM host has run case 15.
