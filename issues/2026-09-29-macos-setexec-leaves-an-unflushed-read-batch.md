# macOS SETEXEC leaves an unflushed read batch

|             |                                              |
| ----------- | -------------------------------------------- |
| Status      | in-progress; fix/release-validation-failures |
| Recorded    | 2026-09-29                                   |
| Observed in | io-mon `b6f196a`, diagnostic `36570121741`   |
| Area        | macOS spawn forwarding and fragment flush    |

## Observed

A native hosted macOS machine with SIP disabled permits injection into
`/bin/cat`, as measured by an independent constructor dylib. The SETEXEC
fixture records the exec and the child's real marker read, but merges an
unmatched read-tail marker into `kill-before-flush` loss and `mcIncomplete`.
Ordinary spawning of the same system binary and SETEXEC to the fixture's
reader both pass. Job `109411742855` retains the evidence.

## Expected

The [hardening protocol](../../reprobuild-specs/io-mon-hardening-protocol.md)
requires preserving observations across image replacement and earning complete
capture. Keep the existing fail-closed loss guard. Attribute the unmatched
batch to its image and actual records, then flush at the correct non-returning
launch boundary. The current hook flushes its exec record before environment
and SIP-path rewriting; whether that rewrite adds new records is being checked.
Retain the independent injection control, marker read and completeness checks,
and validate both protected local and disabled-SIP hosted macOS.

Refreshed `origin/dev` at `9c1d52b`; searched open and deleted SETEXEC/flush
issues. The SIP-state fixture issue covers incorrect test assumptions; this
record covers the actual loss detected after that repair.

## Local attribution and regression control

At `c296287` plus the regression test, real SETEXEC and execve both lose
the absent sandbox-path probe and leave an unmatched pending marker. Ordinary
spawn preserves that exact probe. The rewrite invokes `fileExists` after
the initial hook flush. Flush again after rewriting at each non-returning
forwarder, with a C runtime-ready guard. The test requires the actual absent
probe, no unflushed batch, and the independent injection outcome. Pass the
known launched root PID to `mergeFragments` so the existing subtree guard
checks the real image transition. Previously, the incidental batch loss had
masked the fixture's missing root anchor.

Local verification of `c296287` plus this repair passes the spawn/exec,
recorded-once, system-child, body-patch spawn and vfork-exit suites (26 cases
across the complete control set). The original forwarders fail both the
SETEXEC and execve probe/flush regression assertions. Interpose-only controls
also pass their existing coverage boundary; the required sandbox probe is
observed with the production combined backend. Hosted SIP-disabled verification
and the complete ordinary CI suite remain required.
