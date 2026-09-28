# Host evidence merge uses an inherited monitor session on macOS and Windows

|             |                                                                 |
| ----------- | --------------------------------------------------------------- |
| Status      | in-progress on `agents`                                         |
| Recorded    | 2026-09-28                                                      |
| Observed in | io-mon `8fc04ce`, macOS ARM64                                   |
| Area        | `startMonitorInner`, `collectMonitorEvidence`, `mergeFragments` |

## Observed

A real self-executing reader monitored through `runMonitored` exits zero in
both arms. With no ambient `REPRO_MONITOR_SESSION`, capture contains one
process-start and three file observations, graded `mcComplete`. With the
launcher's variable set to `enclosing-monitor-session`, capture contains zero
starts and zero file observations, graded `mcIncomplete`.

The macOS and Windows launch paths give the child a fresh run ID but do not
save it on the monitor handle or pass it to the evidence merge. The merge then
filters against the launcher's inherited session. Linux already supplies the
handle's run ID. Windows has the same source defect; its native execution is
pending. This observation does not attribute the separate Windows injection
timeouts.

## Expected

[`IoMon-Decomposed-Host-API`, DH-1](../../reprobuild-specs/IoMon-Decomposed-Host-API.milestones.org)
requires each monitor to retain its own evidence and leave the parent
environment unchanged. The milestone's historical claim that a fresh fragment
directory makes an omitted merge session harmless overlooks an inherited
session. Keep the existing stale-record filter and supply this handle's actual
run ID on every platform.

## Evidence

The reproduction creates a real input, executes the current test binary as its
reader, and compares capture with and without the ambient variable. It uses
the real macOS shim at `8fc04ce`, with no synthetic records or fake injector.
The regression will live in the host-platform suites with the same control.

Refreshed `origin/dev` at `279a17b`, already an ancestor of `8fc04ce`, and
searched current issues plus `git log --all -G
'ambient.*session|inherited.*session|currentRunId' -- issues/`; no prior issue
covered this runtime defect. The Windows complete-suite issue records a
related synthetic-fixture failure, fixed separately at `59dc99c`.

## Repair validation

The candidate based on `5eeb2cd` retains the generated session on the handle
and passes it to the macOS and Windows merge, matching Linux. The shared
real-child regression passes both arms on macOS; against the original host
implementation its control passes and its inherited-session arm loses every
child record. Windows x64 typechecking passes. Native Windows execution and
the complete macOS suite remain pending.
