## test_io_mon_t0_completeness — unit coverage for the T0 earned-completeness
## logic (`unmonitoredSubtreeLossCount`) on SYNTHETIC record sets, independent of
## any platform/shim. Locks in the exact downgrade algorithm
## (MacOS-Monitoring-Adversarial-Hardening.milestones.org §"T0 — Earn
## mcComplete"): an un-injected spawn child, or an exec/SETEXEC into an
## un-injectable image, each yields one event-loss so `mergeFragments` downgrades
## completeness to `mcIncomplete` — while a fully-monitored tree stays clean.

import std/unittest
import io_mon

proc start(pid: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart, osPid: pid)

proc spawn(parent, child: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessSpawn, observationKind: moExecute,
    osPid: parent, childOsPid: child)

proc execRec(pid: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessExec, observationKind: moExecute, osPid: pid)

suite "io-mon T0 earned-completeness (unmonitoredSubtreeLossCount)":
  test "a fully monitored fork+exec tree yields NO loss":
    # parent 100 forks child 200 (which emits its own start), then 200 execs into
    # an injectable image (a fresh post-exec start), runs and exits.
    let records = @[
      start(100), spawn(100, 200), start(200), execRec(200), start(200)]
    check unmonitoredSubtreeLossCount(records) == 0

  test "a spawn child with no process-start yields one loss":
    # posix_spawn 100 → 300 where 300 (a hardened binary) never loaded the shim.
    let records = @[start(100), spawn(100, 300)]
    check unmonitoredSubtreeLossCount(records) == 1

  test "an exec into an un-injectable image yields one loss":
    # 100 starts then execs (SETEXEC or execve) into a hardened image — no
    # post-exec start, so execCount(100)=1 >= startCount(100)=1.
    let records = @[start(100), execRec(100)]
    check unmonitoredSubtreeLossCount(records) == 1

  test "a SETEXEC into an injectable image (post-exec start) yields NO loss":
    let records = @[start(100), execRec(100), start(100)]
    check unmonitoredSubtreeLossCount(records) == 0

  test "a process that starts and exits (no spawn/exec) yields NO loss":
    check unmonitoredSubtreeLossCount(@[start(100)]) == 0

  test "multiple distinct un-injected children each count once":
    let records = @[start(100), spawn(100, 200), spawn(100, 300),
      spawn(100, 200)] # 200 repeated → counted once
    check unmonitoredSubtreeLossCount(records) == 2

  test "fork child (childOsPid == its own start) is never spuriously flagged":
    # The fork parent records the spawn; the child emits its own start.
    let records = @[start(1), spawn(1, 2), start(2)]
    check unmonitoredSubtreeLossCount(records) == 0
