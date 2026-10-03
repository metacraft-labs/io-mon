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

## Bootstrap pin in full-suite CI

At io-mon `f84d25aa091224ac98433cdf35086dae90d8027e`, full Reprobuild
[run 37150204740](https://github.com/metacraft-labs/io-mon/actions/runs/37150204740)
reports 132 successful actions and one failure on Linux x64. The new real ELF
class case fails its `bare.code == 0` prerequisite with `ELFCLASS32`; all four
older loader cases pass. Artifact `11283962983` retains the failure report.
This execution is inside Repro's enclosing monitor. Both CI workflows still
pin that Linux bootstrap monitor to `3df08c24`, whose `ct_dlopen_try_dir`
uses the old existence-only search. The fixture's own monitor includes the
repaired implementation, but that does not repair an enclosing older shim.

Refresh both Linux bootstrap pins to qualified `10249629`. Keep all real-loader
assertions, the outer automatic-monitor policy, cacheability and current test
ordering. Full CI must establish the enclosing repair; do not remove preload
state or isolate the fixture to bypass the old implementation. This extends
the existing consumer qualification of the same ELF transparency requirement.
Refreshed `agents` and searched the issue archive before recording this result.

## Enclosing-monitor result

At `db2f11cd767fa489ccf5bf1265ded7373b5c2501`, supplemental run
[37152432111](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/37152432111)
passes on `ubuntu-24.04` using shared diagnostic `1749c38783215f27cecf6396ffb6836ff7950244`.
All four selected actions actually launch and succeed; the real ELF regression
passes all six unchanged cases. The only recipe addition is a collection alias
for the existing action. The production bootstrap engine, RunQuota and repaired
outer-monitor pins are used, without changing monitoring or cache policy.
Full product CI still must repeat the result. The promotion PR remains at
`f84d25aa` while its Windows ARM cleanup run finishes, preserving that separate
qualification before advancing the Linux-only pin repair.
