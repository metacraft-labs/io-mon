# ARM64 preload dlsym uses the x86 glibc symbol version

|             |                                                        |
| ----------- | ------------------------------------------------------ |
| Status      | in-progress, `release/unified-0.1.0`                   |
| Recorded    | 2026-09-28                                             |
| Observed in | io-mon @ `bacb6cc`                                     |
| Area        | `ct_linux_preload_real_dlsym`, exported dlsym versions |

## Observed

The Linux ARM64 release probe exits 7 without monitoring, but 127 under the
shim on Debian 11. Loader diagnostics repeatedly report `undefined symbol:
dlsym, version GLIBC_2.2.5`. The shim uses this x86 version for its real-symbol
lookup and exports it alongside GLIBC_2.34. Its fallback can re-enter dlsym
through the interposed resolver.

## Expected

[Release payload verification](https://github.com/metacraft-labs/metacraft-specs/blob/latest/infrastructure/gosti-io-mon-runquota-releases.md)
requires native Linux ARM64 capture. glibc's
[ARM64 ABI list](https://github.com/bminor/glibc/blob/release/2.31/master/sysdeps/unix/sysv/linux/aarch64/libdl.abilist)
defines dlsym at GLIBC_2.17. Lookup and the public wrapper must use the target's
ABI and must not recurse when resolution fails.

## Evidence

[Native ARM64 diagnostic job at bacb6cc](https://github.com/metacraft-labs/io-mon/actions/runs/36378193163/job/108788453205).
Refreshed `origin/dev` (`279a17b`) and `origin/agents` (`bacb6cc`); searched
open issues and issue history for dlsym/glibc before recording this finding.
The native release probe covers the lookup while checking real stat/lstat,
file reads/writes and child exit propagation on old and current glibc.
