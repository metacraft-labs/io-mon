## test_io_mon_t0_completeness — unit coverage for the T0 earned-completeness
## logic (`unmonitoredSubtreeLossCount`) on SYNTHETIC record sets, independent of
## any platform/shim. Locks in the exact downgrade algorithm
## (MacOS-Monitoring-Adversarial-Hardening.milestones.org §"T0 — Earn
## mcComplete"): an un-injected spawn child, or an exec/SETEXEC into an
## un-injectable image, each yields one event-loss so `mergeFragments` downgrades
## completeness to `mcIncomplete` — while a fully-monitored tree stays clean.

import std/[os, sets, unittest]
import io_mon

proc start(pid: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart, osPid: pid)

proc spawn(parent, child: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessSpawn, observationKind: moExecute,
    osPid: parent, childOsPid: child)

proc execRec(pid: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessExec, observationKind: moExecute, osPid: pid)

proc ipc(pid, peer: uint64; dest = "/tmp/d.sock"): MonitorRecord =
  ## An mrIpcConnect from `pid` to a peer whose pid is `peer` (0 ⇒ unknown peer,
  ## e.g. an INET socket where LOCAL_PEERPID is unobtainable).
  MonitorRecord(kind: mrIpcConnect, observationKind: moIpcConnect,
    osPid: pid, childOsPid: peer, path: dest)

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

suite "io-mon T3a IPC-breakaway downgrade (unmonitoredSubtreeLossCount)":
  test "connect to an OUT-OF-TREE daemon (peer pid not in set) yields one loss":
    # The adv_proctree escape: client 100 connects to daemon pid 999 which never
    # loaded the shim (no process-start) → out-of-tree breakaway → downgrade.
    let records = @[start(100), ipc(100, 999)]
    check unmonitoredSubtreeLossCount(records) == 1

  test "connect to an UNKNOWN peer (INET, pid 0) yields one loss":
    # An AF_INET socket whose LOCAL_PEERPID is unobtainable is treated
    # conservatively as out-of-tree.
    let records = @[start(100), ipc(100, 0, "1.2.3.4:80")]
    check unmonitoredSubtreeLossCount(records) == 1

  test "CARDINAL SIN: intra-tree IPC (peer is a monitored process) yields NO loss":
    # Two monitored processes (both emitted process-start) talking over a socket
    # must NOT downgrade — else every socket-using build re-runs forever.
    let records = @[start(100), start(200), ipc(200, 100)]
    check unmonitoredSubtreeLossCount(records) == 0

  test "repeated connects to the SAME out-of-tree peer count once":
    let records = @[start(100), ipc(100, 999), ipc(100, 999), ipc(100, 999)]
    check unmonitoredSubtreeLossCount(records) == 1

  test "distinct out-of-tree peers each count once":
    let records = @[start(100), ipc(100, 999), ipc(100, 888)]
    check unmonitoredSubtreeLossCount(records) == 2

  test "a TRUSTED daemon (reported its reads) is exempt from downgrade":
    # The peer pid 999 is out-of-tree, but a breakaway report accounted for its
    # reads, so it is trusted and does NOT downgrade (BuildXL Trusted-Tools).
    var trusted = initHashSet[uint64]()
    trusted.incl 999'u64
    let records = @[start(100), ipc(100, 999)]
    check unmonitoredSubtreeLossCount(records, trusted) == 0
    # …while an UNTRUSTED peer still downgrades even with a trusted set present.
    let records2 = @[start(100), ipc(100, 999), ipc(100, 777)]
    check unmonitoredSubtreeLossCount(records2, trusted) == 1

  test "IPC and spawn/exec losses accumulate independently":
    let records = @[start(100), spawn(100, 300), ipc(100, 999), execRec(100)]
    # spawn 300 (no start) + exec into un-injectable + connect to 999 = 3 losses.
    check unmonitoredSubtreeLossCount(records) == 3

suite "io-mon T3a breakaway-report folding (mergeFragments)":
  test "a trusted-daemon report keeps the build mcComplete and adds the read":
    # End-to-end through mergeFragments, platform-independent: synthesize a
    # client's fragment (process-start + ipc-connect to an OUT-OF-TREE daemon),
    # then prove the merge downgrades WITHOUT a report and stays complete WITH one
    # — and that the daemon-served file becomes a real dependency.
    let work = getTempDir() / ("io-mon-breakaway-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let frag = work / "frags"
    createDir(frag)
    let reportDir = work / "reports"
    createDir(reportDir)
    let clientPid = 4242'u64
    let daemonPid = 9999'u64
    appendFragmentRecord(frag, MonitorRecord(kind: mrProcessStart,
      observationKind: moProcessStart, osPid: clientPid, threadId: 1))
    appendFragmentRecord(frag, MonitorRecord(kind: mrIpcConnect,
      observationKind: moIpcConnect, osPid: clientPid, threadId: 1,
      childOsPid: daemonPid, path: "/tmp/sccache.sock",
      detail: "connect af_unix peer=9999"))
    let served = "/some/served/header.h"
    writeFile(reportDir / "report-4242-9999-0.io-mon-report",
      "io-mon-breakaway-report v1\nclient " & $clientPid & "\ndaemon " &
        $daemonPid & "\nread " & served & "\n")

    # WITHOUT the report: the out-of-tree peer downgrades to mcIncomplete.
    let depNo = mergeFragments(frag, work / "no.rdep")
    check depNo.completeness == mcIncomplete

    # WITH the report: the daemon accounted for its read → mcComplete, and the
    # served file appears in the depfile as a dependency.
    let depYes = mergeFragments(frag, work / "yes.rdep", reportDir)
    check depYes.completeness == mcComplete
    var sawServed = false
    for r in depYes.records:
      if r.path == served and r.observationKind == moFileRead:
        sawServed = true
    check sawServed
    removeDir(work)

  test "a report for ANOTHER build's client pid is ignored (per-build isolation)":
    # A persistent daemon serves many builds; a report whose client pid is NOT one
    # of THIS merge's monitored processes must not trust the daemon (the connect
    # still downgrades) nor inject a foreign read.
    let work = getTempDir() / ("io-mon-breakaway2-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let frag = work / "frags"
    createDir(frag)
    let reportDir = work / "reports"
    createDir(reportDir)
    let clientPid = 5151'u64
    let daemonPid = 9999'u64
    appendFragmentRecord(frag, MonitorRecord(kind: mrProcessStart,
      observationKind: moProcessStart, osPid: clientPid, threadId: 1))
    appendFragmentRecord(frag, MonitorRecord(kind: mrIpcConnect,
      observationKind: moIpcConnect, osPid: clientPid, threadId: 1,
      childOsPid: daemonPid, path: "/tmp/sccache.sock"))
    # The report names a DIFFERENT client pid (another build).
    writeFile(reportDir / "report-1111-9999-0.io-mon-report",
      "io-mon-breakaway-report v1\nclient 1111\ndaemon " & $daemonPid &
        "\nread /other/build/file.h\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    for r in dep.records:
      check r.path != "/other/build/file.h"
    removeDir(work)
