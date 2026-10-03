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

At `e8df820`, ordinary ARM-host Reprobuild job `109567862804` in
[36615640369](https://github.com/metacraft-labs/io-mon/actions/runs/36615640369)
fails only the abandoned-injection program in its 99-action test graph.
The real same-architecture child exits 42; the hook reports successful spawn,
leaves its handles intact and reports error zero. The test never establishes
that the slow DLL reached its borrowed-call deadline. Earlier focused control
`36594769445` passed this repaired fixture three times at `af1af0f`.

Retain the existing deadline and child-termination assertions. Compare the DLL
and child PE machines, the process-architecture query and the injector outcome
on both Windows hosts. The newer native-ARM refusal guard, an entry-point park
timeout, and failure to load the fixture are distinct possible paths; the
current log does not identify which ran. The complete native workflow and
Linux x64/Windows x64 Reprobuild jobs pass at `e8df820`. Its macOS Reprobuild
job is still running. Full log: `/tmp/io-mon-e8-arm-failure.log`.

Refreshed `origin/dev` at `9c1d52b` and searched open and deleted injection
issues before extending this existing record.

Control [36626916265](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36626916265)
at shared `db2f08a` proves the guard introduced at `a2a7733` misclassifies
an emulated x64 child: `IsWow64Process2` returns `0000/AA64`, whereas
`GetProcessInformation(ProcessMachineTypeInfo)` returns `8664`, matching
both the child and slow DLL PE machine. At `e8df820`, with GCC and each of
Nim 2.2.8/2.2.10, all three ARM-host repetitions fail with the original guard
and pass with the explicit machine query. All x64-host repetitions pass
both ways. Injection with the corrected query reaches `ioChildTerminated`
at about 1546 ms; the unchanged 1500 ms deadline and exit assertions hold.
The production repair must also retain the real native-system-child refusal
test and complete ordinary CI. Evidence: `/tmp/io-mon-spawn-db2-evidence`.

At `3df08c2`, ordinary ARM-host job `109666585235` in `36645229405` passes
all native-exit and session-scope assertions, then fails deleting the private
`io-mon.exe` and shim DLL with `Access is denied`. This matches the separate
RunQuota finished-image investigation, whose real Restart Manager control at
shared `6cd12df` identifies `XtaCache.exe` retaining images after child exit.
Give these two fixture trees bounded removal retries; persistent failure must
still raise. Confirm with unchanged assertions on real ARM and x64 Windows
hosts. Refreshed dev `9c03325`; searched the existing and deleted cleanup
records before adding this evidence.

At `122cb167f36f51c642fecb4f2a18f399c5248511`, Windows ARM-host
[job 110510173629](https://github.com/metacraft-labs/io-mon/actions/runs/36903822440/job/110510173629)
passes the complete Reprobuild graph and its eight required isolated repeats.
The truthful native runner then exposes another immediate-removal site:
`test_io_mon_snoop_cli_smoke` passes both standalone-build and depfile-inspection
assertions, but `removeDir(work)` raises `Access is denied` on the finished
`io-mon.exe`. Apply the existing 30-second `removeFixtureTree` helper at this
site, retaining both assertions and fatal persistent cleanup errors. This is
consistent with the earlier finished-image symptom; the retaining process was
not measured in this run. The complete Windows x64 and macOS native cross-checks
pass at the same revision. ARM native qualification remains incomplete.

Refreshed `agents` at `122cb16` and `dev` at `2d07041`; searched current and
archived cleanup/XtaCache records before extending this issue. Log:
`/tmp/io-mon-122-windows-arm-repro-complete.log`. The final workflow cancellation
stopped the optional S3 mirror after it spent 51 minutes retrying connection
timeouts; every build/test step had already finished.

## Persistent finished-image cleanup failure at f03032af

At `f03032af422c2fcc2f59568135167b203b9abdd6`, Windows ARM64 emulation
[job 111202263312](https://github.com/metacraft-labs/io-mon/actions/runs/37122834544/job/111202263312)
completes 98 of 100 graph actions successfully. Two execution actions fail only
at fixture cleanup, after their native exit-status and session-scope checks pass:

- `test_io_mon_cli_exit_status`: the private `io-mon.exe` cannot be removed.
- `test_io_mon_windows_host_session_scope`: its private
  `librepro_monitor_shim.dll` cannot be removed.

Both failures survive the existing 30-second monotonic removal bound and report
`Access is denied`. The failure artifact is `11276046801`, containing the actual
build failure report. The same commit passes all Linux, macOS and Windows x64 CI.
The ARM repeat and native cross-check steps do not execute after this failure.

The previous XtaCache observation is a hypothesis for this run, not an owner
measurement. Preserve the current cleanup bound and every functional assertion.
Use the existing real Restart Manager diagnostic, including its live-image
positive control, to record the remaining file users and attributes before
choosing another cleanup repair. A focused native Windows diagnostic can run the
two unchanged fixtures and retain its precise source patch and output. It must
not kill cache services, delete unrelated files, bypass access checks or treat
persistent cleanup failure as success.

Focused diagnostic [37129790109](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/37129790109)
at shared-actions `6f7fb73` runs io-mon `f03032af` with the pinned release
compiler and added cleanup diagnostics. Both unchanged programs pass three
times each on Windows x64 and Windows ARM64 x64 emulation. On ARM, CLI
rounds take 10.0–10.6 seconds and session-scope rounds 29.9–30.6 seconds
including their private builds. There is no persistent cleanup failure in
that narrower compiler/environment context, so it establishes no owner for
the full Reprobuild failure.

Retain the Restart Manager query in the shared Windows fixture cleanup helper,
only after the existing 30-second limit has already failed. It records file
attributes and actual process owners and validates the query against its own
live image. Diagnostic failure must not replace the original fatal cleanup
error. No waits, assertions, fixture placement, or cache policy change. The
full native Windows ARM64 Reprobuild graph must produce the missing evidence.
