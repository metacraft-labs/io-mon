# Windows exit callbacks can repeat the termination flush

|             |                                                                  |
| ----------- | ---------------------------------------------------------------- |
| Status      | open; source mismatch established, timeout attribution pending   |
| Recorded    | 2026-10-01                                                       |
| Observed in | io-mon `5e71adf` and current dev `2d07041`                       |
| Area        | `src/io_mon/shim/windows_interpose.nim`, `src/io_mon/writer.nim` |

## Observed

`snoopNtTerminateProcess` guards `flushAllRegisteredSlots` with the atomic
`terminateFlushDone` flag. Its contract says that a later sweep could acquire
a lock owned by a terminated thread and must not run. The `addExitProc`
callback in `repro_monitor_shim_init` nevertheless calls the same sweep
unconditionally before uninstalling hooks. `flushAllRegisteredSlots` acquires
`registryLock` and touches the registered threads' TLS/file buffers.

These call sites are identical at `5e71adf`, used by RunQuota's release CI,
and dev `2d07041`. This records a source/contract mismatch. It does not yet
prove that an observed RunQuota timeout is this deadlock or that the callback
runs in the unsafe order on the affected toolchain.

## Expected

The [shim build policy](../docs/contributors/shim-build-policy.md) requires
hostile-context hooks to avoid unsafe runtime operations. The transport's
[LF-1 invariant](../docs/contributors/event-transport-and-loss-freedom.md)
requires captured events to reach the consumer or be reported as loss.
Any shutdown repair must preserve that accounting.

Windows [ExitProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)
terminates other threads before DLL process-detach callbacks, and explicitly
documents deadlock when such a callback takes a lock held by a terminated
thread. Not specified separately in the io-mon documents. Proposed: define
one coordinated shutdown protocol for termination and CRT callbacks, preserving
the early durable sweep and refusing late unsafe access to other threads.

## Evidence and next observation

RunQuota diagnostic `36735013860` at tooling `b60cba4` prints all eight export
test successes in its serial arm, but the wrapper eventually returns 124.
That suggests inspecting exit as well as startup; it does not locate the wait.
The currently running read-only phase diagnostic `36774529116` at tooling
`8817d55` has initialization/hook checkpoints, but no separate shutdown phase.

Extend that disposable observer with a separate exported shutdown checkpoint:
termination sweep entry/return, CRT callback entry, late sweep entry/return,
and hook-uninstall entry/return. Record the real image name and parent PID
for each observed process. Checkpoints must be volatile stores only; keep
all existing operations, waits, assertions and capture semantics. Preserve
the original observer's real known-phase and wrong-phase controls. No target
thread may be suspended by observation. Attribute a timeout only if its
retained process/phase evidence supports the connection.

Before filing, fetched dev `2d07041` and agents `e750199`, merged current dev
into the agents checkout at `61859f0`, and searched current issues and full
issue history for `atexit`, `terminateFlushDone` and `flushAllRegisteredSlots`.
The existing successful-threaded-exit issue covers exit-code corruption,
not this repeated sweep.
