# Windows monitoring changes the exit status of successful threaded programs

Status: open. Observed through Reprobuild `c14b1e61`, shared setup `93de03f`,
and RunQuota `8add804`. The bootstrap fetched io-mon and stackable-hooks from
`dev`; that run did not record their resolved source SHAs.

## Observed

Control [36599148160](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36599148160)
at shared diagnostic `ac8ecbb` executes unchanged real atomicity and host-load
test binaries on Windows x64. Both return zero directly and through timeout,
sh, and sh plus timeout. Through `repro internal io monitor`, both still
print every passing assertion but return 255 for direct execution and 127
through each shell/timeout combination. These codes were captured by Bash,
so the full Windows exit status is not yet established. The finalized
monitor streams contain no event-loss records.

This reproduces outside the build graph and without an MSYS wrapper around
the monitored native program. It does not yet identify the failing shim,
injector or process-teardown operation. Atomicity binary SHA256:
`a46193da266dea5e63f2cf8adbd584ca4a78b0ff7f43e7c95722a4a8c19e188e`.
Host-load binary SHA256:
`89c6044b1bc9c2cd313df6175e6175b1ca831254b88b037b3efd4203f450f449`.

## Expected and investigation

[Architecture / Scope](../docs/contributors/architecture.md) defines io-mon
as an observation layer. `FsSnoopResult.exitCode` in `src/io_mon/fs_snoop.nim`
is the monitored command's exit status. Preserve that command's execution;
do not reinterpret its failed monitored run as success because its assertions
passed. The [monitor failure contract](../../reprobuild-specs/Monitor-Hook-Shim.md#failure-semantics)
also requires a shim crash to reject cache publication.

Capture full Windows process exit codes without Bash truncation, real crash
events and minidumps, and the resolved bootstrap source identities. Compare
the same binaries and a small real thread-lifecycle probe. Attribute the
failure before changing runtime behavior or test scheduling. Keep ordinary
CI, native checks and release smoke assertions enabled.

Fetched io-mon dev `9c1d52b` and searched open/deleted exit-status, shutdown
and termination-flush issues before filing. RunQuota's
`2026-09-29-windows-ci-bypasses-declared-tool-store.md` records the consumer
symptom; this record owns the isolated monitor failure.

## Full command status and smaller control

At shared `18d1fde`, control
[36607212920](https://github.com/metacraft-labs/metacraft-github-actions/actions/runs/36607212920)
records bootstrap io-mon `9c1d52b`, hooks `a42306d`, Reprobuild `c14b1e61`
and RunQuota `8add804`. Python launches each command directly with regular-file
output and a 180-second bound. Both real programs return zero natively,
`0x7fffffff` from the direct monitor command and 127 through monitored
sh/timeout; none times out. All assertions still pass. This is the monitor
command's full status; the child API result needs a direct-library control.

A real eight-thread file-I/O probe returns zero in all three modes. No dump
or crash-event artifact was produced. Both failing programs use PDH performance
counters, unlike the small probe. A standalone real PDH load/query/shutdown
control will distinguish that path; the distinction alone does not establish
causation. Hooks `72f5782` (candidate dependency) and `a42306d` have identical
runtime code; their only difference is deletion of a CI workflow.
