# The declared Intel macOS release cannot run an injected child

Observed at `1b17d71` on 2026-09-28, in release job
<https://github.com/metacraft-labs/io-mon/actions/runs/36362490802/job/108742379730>.
The same failure reproduces under Rosetta locally.

The approved [release specification](https://github.com/metacraft-labs/metacraft-specs/blob/1056f9f/infrastructure/gosti-io-mon-runquota-releases.md)
retains io-mon's existing Intel macOS target and requires an extracted-payload
file capture. The x86_64 probe exits 7 normally; injecting the x86_64 monitor
changes this to exit 1 and `out of memory` before it reads the file.

`repro_macos_real_mmap_syscall` returns `MAP_FAILED`/`ENOSYS` for every non-ARM
Darwin call. Its interpose entry is active during process startup, so the
allocator cannot obtain memory. The general raw-syscall forwarder has the same
unsupported branch. The fork fallback also uses the generic libc `syscall`,
which discards Darwin's separate child-return indicator.

Implement and test the x86_64 forwarding ABI, including full-width mmap
returns, errno and child fork behavior. Keep libc fork bookkeeping intact.
Open and deleted issue history had no earlier record of this defect.
