# Complete Windows Reprobuild tests expose fixture and monitor isolation failures

|             |                                                            |
| ----------- | ---------------------------------------------------------- |
| Status      | open                                                       |
| Recorded    | 2026-09-28                                                 |
| Observed in | io-mon `73e4792`, Reprobuild `0d69de55`, Windows x64       |
| Area        | portable tests, Windows injection tests, nested monitoring |

## Evidence

[Native job 109024094897](https://github.com/metacraft-labs/io-mon/actions/runs/36450606215/job/109024094897)
passes the Reprobuild bootstrap and compiles the complete platform catalog.
Seven test programs fail during execution:

- Element-key source audits compare Windows backslashes with POSIX literals.
- Evidence-scope mutation probes cannot find LF anchors in CRLF checkouts.
- Synthetic breakaway fragments carry their own session IDs, but the merge
  falls back to the outer Reprobuild monitor's session and drops those records.
- The escape-shim fixture omits the production-required `-d:useMalloc`.
- Native read capture and the plain spawn probe fail calling the injected
  shim's runtime initializer on its parked main thread.
- The inert-shim root-guard fixture unexpectedly sees a process-start record
  and complete evidence.
- The abandoned-injection probe reports timeout while its child remains alive.

The last three symptoms are not yet attributed. The existing separate Windows
job runs only three selected programs; its success does not validate this
complete catalog. Compare the complete suite directly with the same suite
under Reprobuild before changing the injection or test execution contract.

## Expected

`repro.nim` defines the complete portable plus Windows catalog. The source
mutation tests require both successful mutations and intentional compile
failures. Normalize representation differences while keeping unique-anchor and
exact-source-site assertions. Give synthetic fragment merges their declared
session IDs. Build the escape fixture with the production allocation flags.

[Monitor-Hook-Shim](../../reprobuild-specs/Monitor-Hook-Shim.md) requires honest
root/descendant completeness. Retain native capture, child termination and
root-loss assertions; do not turn a missing record into complete evidence or
skip the failing programs. Any runtime repair needs real Windows execution.

Refreshed `origin/dev` at `279a17b` (already an ancestor of `73e4792`) and
searched open and deleted issues for Windows fixtures, nested monitoring and
CRLF before recording.

## Direct Windows comparison

At `1cabd874115573fce23e7533b1a4b33d515afc1e`, [job 109054198659](https://github.com/metacraft-labs/io-mon/actions/runs/36459498969/job/109054198659) passes 41 of 42 programs directly, including all native injection, root-guard, child-termination and host-session tests. The remaining eight assertions are in the evidence-scope compiler diagnostic reader: `Stream.readAll` stops on the first short Windows pipe read, retaining only `stack trace: (most recent call last)`.

Drain the pipe to EOF and keep every exact rejection assertion and both successful-compilation controls. This direct result does not yet clear the nested Reprobuild execution failures.

At `303e1ef`, direct job `109065572161` passes all 368 assertions in the
complete 42-program Windows catalog. Reprobuild job `109066010867` at the same
product SHA fails host-session scope, read capture, root guard, abandoned
injection and resume invariant. The outer shim supplies hooks even when the
inner root-guard fixture chooses inert `kernel32.dll`.

The recipe repair isolates these five execution edges using the existing
generated-depfile policy, suppresses the outer shim seed, and marks them
non-cacheable. Their compiles and all other tests retain normal monitoring.
CI repeats the five after the complete suite and checks the real execution
report to prove they launched and passed again.

At `de755e5`, job `109087128933` passes the complete Reprobuild test graph.
The repeat executes all five again, but the plain spawn-resume probe fails
with `LoadLibraryW in child returned NULL (err=0)`. The other four programs and
the remaining three spawn-resume cases pass. The failed edge is explicitly
`cdNotCacheable`. Keep the repeat gate; diagnose the child loader result
before changing runtime behavior or attributing this intermittent failure.

The concurrent diagnostic at `de755e5`, shared-actions `7992b87`, job
`109100142914`, reproduces a shared-artifact race: host-session scope rebuilds
`build/lib/librepro_monitor_shim.dll` while another fixture has it loaded.
The linker fails with permission denied. Its build must use private output
and compiler-cache directories. Keep the earlier loader NULL issue open until
the repaired concurrent run and full Reprobuild repeat establish the result.

At `a24739d`, the private fixture shim passes 20 concurrent rounds of all
five programs (100 successful executions) in job `109108531426`, using the
same child-loader diagnostic. No NULL load or shared-DLL linker failure was
observed. The complete Windows Reprobuild repeat still gates promotion.

The same commit passes the complete local macOS graph (179 actions), all 41
isolated programs on a second actual execution, and the five repaired session
fixtures with an explicitly unrelated ambient session. Repro executable
`4adfd0e7`, provider source `90dc4321`, bootstrap shim `de755e5`; evidence is in
`/tmp/io-mon-isolated-macos-full-fixed.json`,
`/tmp/io-mon-macos-isolation-repeat.json` and
`/tmp/io-mon-explicit-session-control.log`.

## Windows ARM64 host with the x64 test toolchain

At `0a0b592`, Windows ARM64 job `109452792104` compiles and executes the
complete x64-emulation graph. Five programs fail. Library-load observation,
process-start and root-guard tests report
`CreateRemoteThread(LoadLibraryW) failed (err=5)`. The abandoned-injection
fixture resumes its child, which exits 42 rather than timing out and being
terminated. Those four programs select the host's `ComSpec` or System32
`cmd.exe`, although the tests and shim are x64. Verify the actual PE machine
types on the runner before attributing the cross-architecture injection.
Use real child executables built with the test toolchain for architecture
independent fixture assertions; retain the expected image records, process
start, incomplete root evidence and terminated-child status. Compare the
original host-shell fixtures and repaired children on the same ARM64 host.
This is an x64-emulation fixture correction; the native Windows ARM64 backend
remains deferred.

The fifth failure is separate: both host-session scope assertions pass, then
removing its private shim directory fails with `Access is denied` on the DLL.
Retain module/cleanup evidence before choosing a repair; do not discard the
cleanup error. The complete macOS Reprobuild job at the same `0a0b592` passes.

Refreshed dev `9c1d52b` and searched current and deleted ARM64, ComSpec and
fixture-isolation issues before extending this record. Full log:
`/tmp/io-mon-0a0-windows-arm-repro-failure.log`.
