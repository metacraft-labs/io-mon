# Linux dlopen selects an incompatible ELF class before a working library

Status: open. Measured against io-mon `91a0e66909ef6d7d8ecd5a515038f559450604e1`.

## Expected

[dlopen transparency](../docs/cases/dlopen-runpath-transparency.md) requires the
monitored program to resolve the same library as the native loader. Search must
skip incompatible ELF classes, preserve search order, and keep genuine malformed
library failures. It must not load candidates merely to inspect them.

## Observed

`ct_dlopen_try_dir` in `src/io_mon/hooks/linux_preload_runtime.nim` checks only
`access(F_OK)`. It turns the first existing soname into an absolute path, so glibc
cannot continue searching when that candidate is 32-bit and the process is 64-bit.

Reprobuild CI [37129418148](https://github.com/metacraft-labs/reprobuild/actions/runs/37129418148)
at `60af697ddd80b54df99ca47164a4b67fd4b9c514` exposes this in the required
CodeTracer prerequisite. Artifact `11276054395`, trace `ct-loader.965332`, names
the bootstrapped Reprobuild engine under its Linux monitor. Native startup skips
OpenSSL 3.6.2's incompatible candidate and loads the 64-bit OpenSSL 3.6.1 copy.
The monitored dynamic call fails on the absolute 3.6.2 path with `ELFCLASS32`.
This is not evidence that a newly compiled interface helper failed at startup.

[glibc open_verify](https://codebrowser.dev/glibc/glibc/elf/dl-load.c.html#1699)
distinguishes a skippable class mismatch from fatal malformed files.

## Fix and qualification

Check candidate ELF identity without loading it, skip the incompatible class,
and leave malformed candidates to the real loader. Retain every existing
transparency assertion. Extend the real-loader regression with an incompatible
candidate before a native library, both RPATH variants, environment search order,
and a malformed candidate that must still fail. A restored existence-only
resolver must fail the new regression on Linux. macOS can prepare the change
but cannot qualify glibc behavior.

Before filing, fetched `agents`/`dev` and searched current issues plus deleted
issue history for dlopen, RUNPATH and ELF; no existing owner issue covers this.
Consumer evidence: [Reprobuild loader issue](../../reprobuild-specs/issues/2026-10-03-source-interface-extraction-cannot-load-openssl-in-codetracer-ci.md).

## Verified repair

Implementation `10249629cc97f01aa5bafe9dff8fa3c00cc82749` passes all six real
Linux loader cases in [run 37132084729](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/37132084729),
using diagnostic workflow `6d41c0c9aa67e2fdbca0bbeed9269c99f69e113e` on
`ubuntu-24.04`. Restoring the existence-only search reproduces `ELFCLASS32` for
RPATH, RUNPATH and LD_LIBRARY_PATH, failing the new assertion. The malformed
candidate case remains fatal in both runs. Local Linux-targeted C generation
passes for the shim and regression on macOS. Full promotion CI remains required.
