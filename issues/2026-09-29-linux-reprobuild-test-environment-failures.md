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
