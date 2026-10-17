# macOS (and Windows) monitors grade an action whose detached descendant is still running `mcComplete`: the §4.1 guard is Linux-only

| | |
|---|---|
| Status | open |
| Recorded | 2026-10-17 |
| Observed in | io-mon @ f33311e, consumed from the sibling checkout by reprobuild `agents` @ 8a61fb6963, aarch64-darwin (m1) |
| Area | `src/io_mon/fs_snoop.nim` `settleMonitorDescendants`, `waitForLinuxInjectedDescendants`, `liveInjectedDescendants` |

## Observed

A monitored root that forks a child, detaches the child's stdio, and exits
while the child sleeps for 4 s is graded `mcComplete` on macOS, by the batch
`runMonitored` (the `repro internal io monitor` wrapper) and by a decomposed
host (`startMonitor` → `finishMonitor`) alike:

```
the HOSTED arm graded an action with a descendant alive across the whole grace window mcComplete; the §4.1 guard did not downgrade it ...
the WRAPPED reference graded the descendant fixture mcComplete, so this fixture does not exercise the §4.1 guard at all ...
```

`settleMonitorDescendants` runs the guard only `when defined(linux)`; its
`else` arm is a `discard` under the comment "macOS and Windows have no §4.1
equivalent yet — the detached-descendant scan is a `/proc` walk."
`IO_MON_LINUX_DESCENDANT_GRACE_MS` therefore has no effect off Linux, and the
monitor's finish holds no grace window open.

## Expected

`docs/usage.md` §"The §4.1 descendant guard is not yours to remember" (DH-3):
a detached descendant "keeps reading and writing files outside the evidence",
and "Reporting `mcComplete` where the batch entry point reports `mcIncomplete`
would be a false cache hit for the whole action". That section names only the
Linux mechanism (`/proc/*/environ`, `IO_MON_LINUX_DESCENDANT_GRACE_MS`) and
does not say the guard is absent elsewhere. Not specified for macOS/Windows.
Proposed: either an equivalent guard (macOS: enumerate processes carrying the
run's injection environment via `sysctl(KERN_PROCARGS2)` / `proc_listpids`;
Windows: the job object or a toolhelp snapshot), or, until one exists, fail
closed — publish an event-loss marker whenever the root's process tree cannot
be shown to be empty at finish — and state the platform limitation in
`docs/usage.md`.

## Evidence

reprobuild `libs/repro_build_engine/tests/test_monitor_finish_is_pooled.nim`,
case "evidence is unchanged versus the serial form", descendant fixture
(`--detached-descendant-fixture`), built and run under `scripts/run_tests.sh`'s
environment at reprobuild 8a61fb6963 on aarch64-darwin, at host load
averages ~3, ~6 and ~21 with the same result. The same test's one-worker
timing control measured a worst finish delay of 20–21 ms for four monitors
"each holding a 300 ms grace window", i.e. no window was held at all.

That test now asserts the `mcIncomplete` downgrade on Linux only and, off
Linux, pins `mcComplete` with a message telling whoever lands a guard here to
enable the Linux assertion for this platform. io-mon's own pins of the guard
(`tests/linux/test_io_mon_external_host_descendant_guard.nim`,
`tests/linux/test_io_mon_evidence_identical_across_launch_paths.nim`) are
Linux-only, so nothing in io-mon covers the other platforms.

## Related

- reprobuild-pm `issues/2026-10-16-test-monitor-finish-is-pooled-fails-on-a-loaded-macos-host.md`
  (where this was found; that test failure was the fixture's and this gap's,
  not load), closed by reprobuild b41768a32c, whose test header now carries
  the explanation.
- reprobuild-pm `milestones/MacOS-Monitoring-Adversarial-Hardening.milestones.org`
  R5-L2 / R6-L2 (daemonized injected descendant outlives root merge) and
  R7-L2, which closed that break on Linux only (io-mon `88b2c12`).
- reprobuild-pm `milestones/IoMon-Decomposed-Host-API.milestones.org` DH-3/DH-4.
