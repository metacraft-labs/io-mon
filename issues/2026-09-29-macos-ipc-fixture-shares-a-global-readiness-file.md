# macOS IPC fixture shares readiness across independent test runs

Status: in-progress. Observed at io-mon `31b7f72`.

[MacOS Reprobuild job 109333051526](https://github.com/metacraft-labs/io-mon/actions/runs/36546120504/job/109333051526)
passes the graph and repeated isolated tests, then fails the Just cross-check:
`waitForFile(ready)` reports `daemon did not become ready` in the IPC breakaway
regression. Later cases in the same program pass.

The C daemon always writes `/tmp/adv_proctree/daemon.ready`; every test process
removes and polls that same file. Its parent directory also survives between
jobs and users. The log does not distinguish a concurrent removal, a write
failure or a slow startup because the fixture ignores fopen failure and does
not show daemon output. A marker owned by another test can also falsely
satisfy readiness.

The contract is `reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org`,
T3a: real out-of-tree socket reads must force incomplete capture, while real
in-tree and authenticated daemon reads remain complete. Give this fixture a
private readiness path, verify the child PID, and report startup output on
failure. Keep all capture assertions and the existing readiness deadline.

Refreshed dev `9c1d52b` and agents `31b7f72`; searched open and deleted issues
for the fixture, readiness and marker names before recording.

The complete IPC-breakaway test program passes locally at `31b7f72` plus the
private-readiness patch, including all four real daemon/socket assertions.
Native CI reruns remain required.
Two concurrent executions of the repaired complete program also pass at the
same base plus patch. Readiness polling waits for the expected PID, avoiding
the interval between the C fixture opening and filling its marker file.
