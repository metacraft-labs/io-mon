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
