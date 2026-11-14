# On Linux, `system(3)` and `popen(3)` go unseen when `/bin/sh` is an image the shim cannot enter

|             |                                                                                                                                   |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Status | in-progress (nixos-ci-bare-002:fix-linux-system-popen-uninjectable) |
| Recorded    | 2026-11-08                                                                                                                        |
| Observed in | io-mon @ `ac06360` plus the Linux tree-ledger change; by reading glibc 2.40 `stdlib/system.c` and `libio/iopopen.c`, not measured |
| Area        | `src/io_mon/shim/linux_preload.nim` (posix_spawn hooks), `src/io_mon/tree_ledger.nim`                                             |

## Observed

glibc's `system(3)` and `popen(3)` start `/bin/sh` through the internal
`__posix_spawn`, which never reaches the shim's interposed `posix_spawn` /
`posix_spawnp`. When `/bin/sh` loads the shim (a dynamically linked shell, as
on every distribution io-mon is tested on), the shell records itself at shim
init, including its tree-ledger entry, so nothing is missed.

When `/bin/sh` is an image the shim cannot enter (a static shell, such as a
static busybox, or one of another ELF class), the shell and everything it
starts run unmonitored. The calling process records no spawn and no
uninjectable-image loss, because it never sees the spawn. The capture can
then be graded complete without the shell's reads, writes or survivors.

## Expected

Every entry into an image the shim cannot enter is recorded as a loss where
the shim can see it (the "AN EXEC INTO AN IMAGE THE SHIM CANNOT ENTER IS
EVENT-LOSS" rule in `src/io_mon/hooks/linux_preload_runtime.nim`).
Interposing `system` and `popen` would let the shim classify `/bin/sh`
before the call, as the posix_spawn hooks do for their target, and report
the loss when the shell cannot be entered.

## Impact

Only hosts whose `/bin/sh` the shim cannot enter are affected. On those, the
work of every `system(3)` and `popen(3)` call is missing from the capture.
