# macOS root-evidence fixture assumes SIP is enabled

|             |                                                            |
| ----------- | ---------------------------------------------------------- |
| Status      | in-progress; native protected and hosted controls required |
| Recorded    | 2026-09-29                                                 |
| Observed in | io-mon `2582d90`, shared-actions run `36559025544`         |
| Area        | tests/macos/test_io_mon_macos_r5_path_canon.nim            |

## Observed

The hosted macOS ARM64 native suite reaches the root guard after its normal
compiler completeness assertion passes. `/bin/cat` emits a real root
process-start and the merged capture is `mcComplete`; the fixture expects no
root event, incomplete evidence and event loss. The run has not independently
reported SIP status, so disabled SIP is a candidate explanation pending that
measurement. The local machine reports SIP enabled.

## Expected

[io-mon hardening protocol](../../reprobuild-specs/io-mon-hardening-protocol.md)
requires both failing closed for unobserved processes and avoiding false
downgrades for complete evidence. Make the unobserved-root control explicit
by launching a real child without injection, retaining every existing absence,
spawn and event-loss assertion. Separately measure SIP with `/usr/bin/csrutil
status` and test the real system binary against that state. An unrecognized
state must fail the fixture; never infer the expected result from the capture
being tested. No system security setting is changed.

Refreshed origin/dev `9c1d52b` and searched current and deleted issues for SIP
root/disabled-SIP records before filing; none matched.

Local verification at `e76aa8c` plus the fixture repair passes all six cases on
macOS with SIP enabled. Replacing the expected-root PID with the legacy zero
value makes the new uninjected-child control fail, demonstrating that it
exercises the missing-evidence guard. Hosted disabled-SIP execution is pending.

## Spawn and system-child fixtures

Hosted job `109383371674` at `a33714c` independently reports SIP disabled and
passes the repaired root-evidence cases. The next failure is the plain-spawn
`/bin/cat` case in `test_io_mon_macos_setexec`: capture is complete but the
fixture assumes an uninjectable child. Its SETEXEC case still reports incomplete,
so a global SIP flag alone cannot establish the expected result for every launch
mode. `test_io_mon_macos_sip_system_child` makes the same unconditional assumption.

Use a separate benign constructor dylib, with no io-mon code or hooks, to
measure injection for each real launch mode. Require its parent marker and
successful child exit, then derive the system-child expectation from the
independently observed target marker. Retain every drop-in capture assertion and
the unconditional uninjected-root negative control. A mismatch between this
probe and monitored capture is a failure requiring investigation, not a skip.
Run the three fixtures on protected local macOS and disabled-SIP hosted macOS.
