# Linux preload stat forwarding fails on older glibc

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Status      | in-progress, `release/unified-0.1.0`                        |
| Recorded    | 2026-09-28                                                  |
| Observed in | io-mon @ `408ce12`                                          |
| Area        | `ct_linux_preload_real_stat`, `ct_linux_preload_real_lstat` |

## Observed

The extracted Linux x86_64 release fails its real file-capture check in
Debian 11 (glibc 2.31). `LD_DEBUG=libs` shows that the shim loads, then its
lookup fails: `undefined symbol: stat`. The child exits with its expected 7,
but capture contains no child file events. Imported-symbol version checks
pass because the missing symbol is resolved dynamically.

## Expected

[Release scope and payload verification](https://github.com/metacraft-labs/metacraft-specs/blob/5f364d0/infrastructure/gosti-io-mon-runquota-releases.md)
requires functioning Linux capture in clean distro images. The release
runbook includes Debian 11, and the build selects glibc 2.28 as its floor.

## Evidence

[Native release job at 408ce12](https://github.com/metacraft-labs/io-mon/actions/runs/36366001229/job/108753662068).
The forwarders only resolve `stat` and `lstat`, which older glibc implements
through header wrappers over `__xstat` and `__lxstat`. glibc 2.31's
[x86 ABI](https://github.com/bminor/glibc/blob/release/2.31/master/sysdeps/unix/sysv/linux/x86/bits/stat.h)
uses version 1 on x86_64; its
[generic ABI](https://github.com/bminor/glibc/blob/release/2.31/master/sysdeps/unix/sysv/linux/generic/bits/stat.h)
uses version 0 on ARM64.

Refreshed `origin/dev` (`279a17b`) and searched open issues and issue history
for stat/glibc forwarding before recording this finding. Verification must
include real regular files, symlinks, missing-path errno and actual capture
on old and current glibc; compilation alone cannot close this issue.
