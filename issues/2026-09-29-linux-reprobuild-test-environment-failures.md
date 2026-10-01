# Linux Reprobuild tests lose tools and interfere with nested monitors

Status: open. Observed at `4b2bb39`; ordinary x64 job `109170184482`
and full graph diagnostic `109167771814`.

The ordinary job forces PATH provisioning and fails because `strace` is absent.
The diagnostic reaches the full graph but selects a Rustup dispatcher as rustc
and observes nine failing assertions across nested-monitor programs. Host-session
children exit 139; the older-shim fixture captures no lookups; the loader closure
contains the enclosing shim; the descriptor-reuse probe writes unexpected data.
The golden exec record names `true`, while its committed Nix fixture names
`coreutils`. The direct native suite passed all 430 cases at `7d0d135`.

[Dependency provisioning](../../reprobuild-specs/Dependency-Provisioning-In-Build-Graph.md)
requires declared tools to be realized. Use explicit POSIX Nix provisioning and
the bootstrap that retains RUNQUOTAD_BIN. The Windows development cross-check
also needs `just` declared in the package's tool set (job `109170184513`).

For nested-monitor failures, compare identical binaries with and without the
outer shim before changing policy. If a test must own its monitor, use the
[monitor failure disposition](../../reprobuild-specs/Monitor-Hook-Shim.md)
already used on macOS and Windows: keep compilation monitored, execute the full
assertions without an enclosing shim, declare prerequisite artifacts, and make
every such execution non-cacheable. Demonstrate a second real execution.
Do not relax capture completeness, golden comparisons, or file assertions.

Refreshed dev `9c1d52b`, merged it into the candidate, and searched current and
deleted issues for strace, provisioning, fixture outputs and outer shims.

Diagnostic `36539293111` at `179f925` builds the product with Nix provisioning,
then refuses the test graph because `strace` has no `nixPackage` declaration.
The selected Reprobuild stdlib has no strace recipe. Declare its pinned Nix
realization in `repro_support/strace.nim`, following the existing cctools
declaration. This is a missing consumer tool definition; the diagnostic did not
compile or execute the tests and supplies no new nested-monitor evidence.

Diagnostic `36542453553` at `d6c5ab5` gets past strace provisioning, compiles
the test programs, then fails the prerequisite shim link: `version node not
found for symbol dlsym@@GLIBC_2.34`. Its link command lacks the version-script
flag selected by `getconf GNU_LIBC_VERSION`. That probe is another undeclared
runtime tool in `scripts/build_shim.sh`; its failure is treated as a non-glibc
host. Supply pinned glibc's getconf to both the shim action and tests that
build their own shims. The graph reports 60 successful actions, one failed
and 59 blocked; these are not new results for the nested-monitor tests.

The direct controls from `36542453553` are not yet a clean comparison of outer
monitoring. The host compile evidence reads shared-memory source
`c646982` (`/nix/store/x67xglpx2nnyz6dff8iqd1jp9whp349h-source`, layout 3),
while the direct control shell prefers sibling `cf0adf2` (layout 1) for the
private shims it builds. Diagnostic `36549278937` checks matched sources and
deliberately mismatched sources before attributing empty host captures to a
monitoring defect. No production capture assertion is relaxed.

Source-pair diagnostic `36549278937` at `31b7f72` passes both programs with
matching layout-3 sources. Running those identical binaries with layout-1
private shims reproduces the empty captures. The previous direct comparison
therefore cannot establish an outer-monitor cause for those two programs.

Full graph `36546393370` at `31b7f72` plus diagnostic-only record printing
passes 115 of 120 actions. The remaining five execution failures are host
session scope, older-shim evidence scope, shim-gate evidence scope, loader
closure and fragment descriptor reuse. The graph's enclosing shared-memory
session defeats the explicit file-transport fixtures; the loader truth set
contains the enclosing shim; host-session children exit 139. Apply the existing
non-cacheable execution disposition to these five programs, then validate the
complete graph, a second execution and a monitored negative control using
identical test binaries and dependency sources. This verification remains
pending; the source-pair result alone does not prove the disposition.

Full graph diagnostic `36551504711` at `eb4451a` passes 123 of 124 actions.
The loader-closure program reaches its startup-object reopening case, where
the `ldd | grep | head` pipeline fails with `grep: command not found`.
Declare the pinned grep package and attach it to Linux execution actions.
The diagnostic stops before its repeat and negative-control stages, so these
remain pending. No capture assertion or fixture binary is changed.

## Observation-fold fixtures after the upstream merge

At `80a7c4a`, both Linux Reprobuild jobs (`109641951343` with bootstrap
`90dc4321` and `109642508667` with `c14b1e6`) fail the two new merge-time
observation cases. Native Nix execution passes at that same commit.
`test_io_mon_observation_identity_fold` supplies records stamped `run=r1`
but omits `currentRunId`; the documented ambient-session fallback correctly
drops all of them. Running its unchanged binary locally with
`REPRO_MONITOR_SESSION=unrelated-outer-session` reproduces all four missing
record assertions. Pass the fixture's own run ID, preserving the session guard.

`test_io_mon_dep_identity_scope` now also exercises Linux file transport.
Under an enclosing monitor its child sees shared-memory transport even when
disabled, and the file capture contains zero processes. This program already
uses the non-cacheable isolated execution disposition on macOS; extend that
disposition to its new Linux transport experiment and verify a second actual
execution. Compilation and every transport/census assertion remain required.

Refreshed dev `07cc4af` and searched open and deleted session/isolation issues
before extending this record. The expected session behavior is documented on
`mergeFragments`; the execution disposition follows the failure semantics
cited above. Logs: `/tmp/io-mon-80a7-linux-repro-native-failure.log`,
`/tmp/io-mon-80a7-linux-new-repro-failure.log`, and
`/tmp/io-mon-fold-old-outer-session.log`.

## IPC fixture selects the bootstrap shim instead of its own build

At `378d272`, the complete native Linux suite passes. The Reprobuild-flavor
[job 110447411884](https://github.com/metacraft-labs/io-mon/actions/runs/36885410804/job/110447411884)
fails only the new AF_UNIX endpoint/peer-UID case in
`test_io_mon_linux_stdio_ipc`: the captured connect has an empty path and the
older detail format `connect af_unix peer=... run=...`, with no `peeruid`.

The fixture runs `build_shim.sh` but then calls `findShimLibrary`, which honors
the enclosing build's `REPRO_MONITOR_SHIM_LIB`. Thus building the current shim
does not ensure the test selects it. Use the existing real private-shim builder
and its exact returned path for this suite, preserving the endpoint, UID and
incomplete-capture assertions. Verify the fixture with a deliberately different
ambient shim selection and retain any further nested-monitor finding separately.

The expected real connect identity is specified in
`reprobuild-specs/Dev-Env-Warm-Entry.md`, section 3, as cited by the test.
Fetched `agents` and `dev` and searched the existing and archived fixture-shim
records before extending this issue. The Linux CI log is retained locally as
`/tmp/io-mon-378-linux-repro-flavor-promotion.log`.

## Private IPC shim exposes the enclosing monitor

At `13d12f3`, the private-shim repair selects the current fixture artifact.
The native Linux IPC cases pass, apart from the independent valid-entropy-byte
rejection recorded and repaired by `f4c99a9` / `bee8758`. Both Reprobuild lanes
now fail at the first stdio, AF_UNIX and relative-cwd cases with child exit 139;
the first capture is incomplete and the new connect capture contains no event.
[Ordinary Reprobuild-flavor job 110470015758](https://github.com/metacraft-labs/io-mon/actions/runs/36892095599/job/110470015758)
and full Reprobuild job `110470523403` expose the same program failure.

The fixture supplies its private shim path but retains the enclosing
`LD_PRELOAD`; `injectionValue` prepends the private shim to that value. The
resulting child loads two distinct monitor libraries. This is a concrete
candidate mechanism, not yet an identical-binary control. Compare monitored
and isolated executions using the same fixture binary and dependency sources.
If confirmed, extend the existing non-cacheable execution disposition to this
suite, keeping compilation monitored, every capture assertion, and a second
real execution. Retain a monitored negative control.

Fetched `agents` / `dev` at `bee8758` / `2d07041` before extending this record.
The existing issue already owns nested Linux monitor interference; the
`Monitor-Hook-Shim.md` failure semantics above govern the proposed disposition.
Log: `/tmp/io-mon-13d-linux-repro-flavor-promotion.log`; full-graph artifacts:
`/tmp/io-mon-13d-linux-full-repro-artifacts`.
