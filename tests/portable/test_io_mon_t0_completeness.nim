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

# ROUND-2 R7 helpers — records carrying the (pid, start-time) identity tokens the
# shim stamps. Used to prove a recycled (wrapped) pid no longer false-matches.
proc startAt(pid: uint64; startUsec: string; run = ""): MonitorRecord =
  result = MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
    osPid: pid, detail: "shim-loaded start=" & startUsec)
  if run.len > 0: result.detail.add " run=" & run

proc spawnChildAt(parent, child: uint64; childStartUsec: string): MonitorRecord =
  MonitorRecord(kind: mrProcessSpawn, observationKind: moExecute,
    osPid: parent, childOsPid: child,
    detail: "posix_spawn childstart=" & childStartUsec)

proc ipcPeerAt(pid, peer: uint64; peerStartUsec: string;
    dest = "/tmp/d.sock"; run = ""; nonce = ""): MonitorRecord =
  result = MonitorRecord(kind: mrIpcConnect, observationKind: moIpcConnect,
    osPid: pid, childOsPid: peer, path: dest,
    detail: "connect af_unix peer=" & $peer & " peerstart=" & peerStartUsec)
  if run.len > 0: result.detail.add " run=" & run
  if nonce.len > 0: result.detail.add " nonce=" & nonce

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

suite "io-mon R1 ROOT-process completeness guard (mergeFragments)":
  # ROUND-2 R1 — a SIP/hardened/notarized ROOT (e.g. /bin/cat) strips DYLD inject,
  # loads no shim, emits NO process-start, leaving an EMPTY fragment set that the
  # old merge published as mcComplete (a zero-effort false cache hit). The launcher
  # passes the root pid; the merge proves the root was monitored or downgrades.
  test "an un-monitored root (no process-start) downgrades to mcIncomplete":
    let work = getTempDir() / ("io-mon-r1-sip-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)            # empty fragment set — the SIP-root reality
    let dep = mergeFragments(frag, work / "out.rdep", expectedRootPid = 4321'u64)
    check dep.completeness == mcIncomplete
    removeDir(work)

  test "a monitored root (its process-start present) stays mcComplete":
    # The no-false-downgrade guard: a normal user-binary root DOES load the shim
    # and emits its own process-start, so the synthetic root-spawn is matched.
    let work = getTempDir() / ("io-mon-r1-ok-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(4321'u64, "9000"))
    let dep = mergeFragments(frag, work / "out.rdep", expectedRootPid = 4321'u64)
    check dep.completeness == mcComplete
    removeDir(work)

  test "expectedRootPid=0 preserves legacy behaviour (no synthetic spawn)":
    let work = getTempDir() / ("io-mon-r1-legacy-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, start(4321'u64))
    check mergeFragments(frag, work / "out.rdep").completeness == mcComplete
    removeDir(work)

suite "io-mon R7 (pid, start-time) identity (defeat pid-reuse)":
  # macOS pids WRAP (~40k allocs); a recycled pid otherwise false-matches a stale
  # monitored process-start, so the subtree/IPC checks pass and the unmonitored
  # child/peer is hidden (the round-2 R7 defeat). The merge now keys matching on
  # (pid, kernel-start-time). The full pid-wrap exploit is impractical to script,
  # so these unit tests construct records with the SAME pid but DIFFERENT start
  # times and assert NO false match — while a genuine in-tree match still holds.
  test "spawn child with RECYCLED pid (different start time) is NOT matched":
    # A stale monitored process-start for pid 200 @ t=1000 exists; later an
    # un-injectable child REUSES pid 200 with start time t=2000. The spawn names
    # (200, 2000) which is NOT the stale (200, 1000) ⇒ one loss (was 0 under the
    # old bare-pid match — the defeat).
    let records = @[startAt(200, "1000"), spawnChildAt(100, 200, "2000")]
    check unmonitoredSubtreeLossCount(records) == 1

  test "genuine in-tree child (matching pid AND start time) is still matched":
    # The cardinal-sin guard: a real fork/spawn child whose start time matches its
    # own process-start must NOT downgrade.
    let records = @[startAt(200, "2000"), spawnChildAt(100, 200, "2000")]
    check unmonitoredSubtreeLossCount(records) == 0

  test "IPC peer with RECYCLED pid (different start time) is out-of-tree":
    let records = @[startAt(999, "1000"), startAt(100, "5000"),
      ipcPeerAt(100, 999, "2000")]
    check unmonitoredSubtreeLossCount(records) == 1

  test "IPC peer that is a genuine in-tree process (pid+start match) → NO loss":
    let records = @[startAt(999, "2000"), startAt(100, "5000"),
      ipcPeerAt(100, 999, "2000")]
    check unmonitoredSubtreeLossCount(records) == 0

  test "missing start-time token falls back to bare-pid (no false downgrade)":
    # A record predating the identity stamp (or where proc_pidinfo failed) carries
    # no start token; matching degrades to bare pid, preserving old behaviour.
    let records = @[start(200), spawn(100, 200)]   # no start tokens anywhere
    check unmonitoredSubtreeLossCount(records) == 0

suite "io-mon R8 authenticated breakaway-report folding (mergeFragments)":
  # ROUND-2 R8 — the un-authenticated fold was DEFEATED by a forged no-reads
  # report (3b) and a stale cross-run report (3c). A report is now trusted only if
  # it is run-scoped, bound to an OBSERVED connection, explicitly complete, and
  # accounts for ≥1 read. These platform-independent tests lock the auth in.
  const runId = "session-abc-123"

  proc clientFrag(work: string; clientPid, daemonPid: uint64): string =
    ## A client fragment: process-start (run-stamped) + an ipc-connect to an
    ## OUT-OF-TREE daemon (so without a valid report the merge downgrades).
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(clientPid, "7000", runId))
    appendFragmentRecord(frag, ipcPeerAt(clientPid, daemonPid, "8000",
      "/tmp/sccache.sock", runId, "noncedeadbeef"))
    frag

  test "an AUTHENTICATED report keeps mcComplete and adds the read":
    let work = getTempDir() / ("io-mon-r8-ok-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 4242'u64, 9999'u64)
    let served = "/some/served/header.h"
    writeFile(reportDir / "report-4242-9999-0.io-mon-report",
      "io-mon-breakaway-report v1\nrun " & runId & "\nclient 4242\ndaemon 9999\n" &
        "read " & served & "\ncomplete\n")
    # WITHOUT the report the out-of-tree peer downgrades…
    check mergeFragments(frag, work / "no.rdep").completeness == mcIncomplete
    # …WITH the authenticated report it stays complete and the read is folded in.
    let dep = mergeFragments(frag, work / "yes.rdep", reportDir)
    check dep.completeness == mcComplete
    var sawServed = false
    for r in dep.records:
      if r.path == served and r.observationKind == moFileRead: sawServed = true
    check sawServed
    removeDir(work)

  test "3b FORGED: a report with NO reads does NOT suppress the downgrade":
    # The malicious_client.c forgery: it names itself client + the daemon, but
    # lists no reads and makes no completeness claim ⇒ untrusted ⇒ mcIncomplete.
    let work = getTempDir() / ("io-mon-r8-forge-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 4242'u64, 9999'u64)
    writeFile(reportDir / "forged.io-mon-report",
      "io-mon-breakaway-report v1\nrun " & runId & "\nclient 4242\ndaemon 9999\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    removeDir(work)

  test "3b PARTIAL: reads present but NOT declared complete ⇒ untrusted":
    let work = getTempDir() / ("io-mon-r8-partial-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 4242'u64, 9999'u64)
    writeFile(reportDir / "partial.io-mon-report",
      "io-mon-breakaway-report v1\nrun " & runId &
        "\nclient 4242\ndaemon 9999\nread /x/y.h\n")  # no `complete`
    check mergeFragments(frag, work / "out.rdep", reportDir).completeness ==
      mcIncomplete
    removeDir(work)

  test "MALFORMED: otherwise-valid report without magic header is ignored":
    let work = getTempDir() / ("io-mon-r8-nohdr-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 4242'u64, 9999'u64)
    let decoy = "/tmp/io-mon-breakaway-decoy.h"
    writeFile(reportDir / "no-header.io-mon-report",
      "run " & runId & "\nclient 4242\ndaemon 9999\n" &
        "read " & decoy & "\ncomplete\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    for r in dep.records:
      check r.path != decoy
    removeDir(work)

  test "MALFORMED: whitespace-padded magic header is ignored":
    let work = getTempDir() / ("io-mon-r8-paddedhdr-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 4242'u64, 9999'u64)
    let decoy = "/tmp/io-mon-breakaway-padded-decoy.h"
    writeFile(reportDir / "padded-header.io-mon-report",
      " " & BreakawayReportMagic & "\nrun " & runId &
        "\nclient 4242\ndaemon 9999\nread " & decoy & "\ncomplete\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    for r in dep.records:
      check r.path != decoy
    removeDir(work)

  test "3c STALE: a report from ANOTHER run is not folded (run mismatch)":
    let work = getTempDir() / ("io-mon-r8-stale-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 4242'u64, 9999'u64)
    # Same client pid (a collision) and a full report — but a DIFFERENT run id.
    writeFile(reportDir / "stale.io-mon-report",
      "io-mon-breakaway-report v1\nrun OLD-SESSION-999\nclient 4242\ndaemon 9999\n" &
        "read /stale/build/file.h\ncomplete\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    for r in dep.records:
      check r.path != "/stale/build/file.h"
    removeDir(work)

  test "a complete report for an UN-OBSERVED daemon (no connect) is rejected":
    # Connection binding: the report names a daemon the client never connected to.
    let work = getTempDir() / ("io-mon-r8-noconn-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 4242'u64, 9999'u64)  # client connected to 9999
    writeFile(reportDir / "wrong.io-mon-report",
      "io-mon-breakaway-report v1\nrun " & runId &
        "\nclient 4242\ndaemon 7777\nread /x.h\ncomplete\n")  # daemon 7777!
    check mergeFragments(frag, work / "out.rdep", reportDir).completeness ==
      mcIncomplete
    removeDir(work)

  test "a report for ANOTHER build's client pid is ignored (per-build isolation)":
    let work = getTempDir() / ("io-mon-r8-iso-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = clientFrag(work, 5151'u64, 9999'u64)
    writeFile(reportDir / "foreign.io-mon-report",
      "io-mon-breakaway-report v1\nrun " & runId &
        "\nclient 1111\ndaemon 9999\nread /other/build/file.h\ncomplete\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    for r in dep.records:
      check r.path != "/other/build/file.h"
    removeDir(work)

suite "io-mon R5 kill-before-flush durability (reading-sentinel)":
  # ROUND-2 R5 — a monitored process whose MAIN thread buffered read records is
  # SIGKILLed before its tail batch flushes (no dyld exit destructor) leaves the
  # early-flushed process-start on disk but loses the un-flushed reads. The old
  # merge published mcComplete MINUS those reads (the r2_machinery/kill_probe.c
  # defeat). The writer now drops a `.io-mon-reading` sentinel the instant a batch
  # turns dirty and removes it on flush; a leftover sentinel after the run proves a
  # kill-before-flush, so mergeFragments injects an event-loss and downgrades. The
  # sentinel lifecycle and the merge-side detection are BOTH platform-independent,
  # so these tests reproduce the defeat deterministically without an actual signal.

  proc readRec(pid: uint64; path: string): MonitorRecord =
    MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
      osPid: pid, path: path)

  test "a dirty batch MARKS the sentinel; a flush CLEARS it (lifecycle)":
    let work = getTempDir() / ("io-mon-r5-life-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    let sentinel = readingSentinelPath(frag, 700'u64, 0'u64)
    # A buffered (un-flushed) record turns the batch dirty → sentinel appears.
    appendFragmentRecord(frag, startAt(700'u64, "1000"))
    check fileExists(sentinel)
    # An explicit flush makes the tail durable → the sentinel is retired.
    flushFragmentBatch()
    check not fileExists(sentinel)
    removeDir(work)

  test "a leftover sentinel (killed pre-flush) downgrades to mcIncomplete":
    # Model the kill: a durable process-start is already on disk (early flush),
    # but an orphaned `.io-mon-reading` sentinel remains — the un-flushed read tail
    # the dead process never persisted. The merge MUST downgrade, NOT publish a
    # false mcComplete minus the lost read.
    let work = getTempDir() / ("io-mon-r5-kill-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    # Durable process-start (the early-flushed evidence that survives the kill).
    appendFragmentRecord(frag, startAt(700'u64, "1000"))
    flushFragmentBatch()
    # Orphaned tail sentinel left behind by the uncatchable SIGKILL.
    writeFile(readingSentinelPath(frag, 700'u64, 0'u64), "")
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcIncomplete
    # The merge CONSUMES the sentinel so a warm-restart merge does not double-count.
    check not fileExists(readingSentinelPath(frag, 700'u64, 0'u64))
    removeDir(work)

  test "a clean flushed run (no leftover sentinel) stays mcComplete":
    # The no-false-downgrade guard: a process that started, read a file and flushed
    # cleanly leaves NO sentinel, so its build is still complete.
    let work = getTempDir() / ("io-mon-r5-clean-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(700'u64, "1000"))
    appendFragmentRecord(frag, readRec(700'u64, "/dep/header.h"))
    flushFragmentBatch()
    check not fileExists(readingSentinelPath(frag, 700'u64, 0'u64))
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcComplete
    removeDir(work)

suite "io-mon S3a self-authored breakaway-report forgery (write provenance)":
  # ROUND-3 S3a — the res4_forge break: an in-tree client reads REPRO_MONITOR_SESSION
  # from its env, REALLY connects to an out-of-tree daemon (so the connection is
  # observed), then forges a `complete` report listing a DECOY read and OMITTING the
  # file the daemon truly served — defeating every R8 auth criterion (a client-side
  # nonce is recorded in the client's OWN fragment, so it is no secret from an
  # in-tree forger). The structural closure: a genuine cooperating daemon is OUT OF
  # TREE, so the shim never records it writing its report; an in-tree forger IS
  # monitored, so the shim DID record the write of its report file. A report whose
  # own file is an in-tree output write is therefore rejected as a forgery. These
  # platform-independent tests drive the exact write-provenance discriminator.
  const runId = "session-s3a-xyz"

  proc clientFragWithWrite(work, reportPath: string;
      clientPid, daemonPid: uint64): string =
    ## A client fragment: process-start + an ipc-connect to an OUT-OF-TREE daemon
    ## (so without a valid report the merge downgrades) + a WRITE of `reportPath`
    ## (the forger authoring its own report file — the in-tree provenance signal).
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(clientPid, "7000", runId))
    appendFragmentRecord(frag, ipcPeerAt(clientPid, daemonPid, "8000",
      "/tmp/sccache.sock", runId, "noncedeadbeef"))
    # The forger's own report-file WRITE, recorded by the shim (moFileWrite). Carries
    # a (dev, ino) so the alias-proof backstop is exercised too.
    appendFragmentRecord(frag, MonitorRecord(kind: mrFileWrite,
      observationKind: moFileWrite, osPid: clientPid, path: reportPath,
      detail: "dev=99 ino=12345"))
    frag

  test "FORGED: an in-tree-AUTHORED complete report is rejected (mcIncomplete)":
    let work = getTempDir() / ("io-mon-s3a-forge-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let reportPath = reportDir / "forged.io-mon-report"
    let frag = clientFragWithWrite(work, reportPath, 4242'u64, 9999'u64)
    # A report passing ALL R8 criteria (run, observed peer, complete, a read) — but
    # its own file was written in-tree, so it is a forgery.
    writeFile(reportPath,
      "io-mon-breakaway-report v1\nrun " & runId & "\nclient 4242\ndaemon 9999\n" &
        "read /tmp/DECOY.txt\ncomplete\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    # The decoy must NOT have been folded as a dependency.
    for r in dep.records:
      check r.path != "/tmp/DECOY.txt"
    removeDir(work)

  test "FORGED by (dev,ino) alias: a /private vs /tmp spelling is still rejected":
    # The report path the shim recorded differs in spelling from the walked path, so
    # only the (dev, ino) backstop can catch it. We point the recorded WRITE path at
    # a non-matching string but stamp the SAME (dev, ino) the report file will have.
    let work = getTempDir() / ("io-mon-s3a-ino-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let reportPath = reportDir / "aliased.io-mon-report"
    writeFile(reportPath,
      "io-mon-breakaway-report v1\nrun " & runId & "\nclient 4242\ndaemon 9999\n" &
        "read /tmp/DECOY.txt\ncomplete\n")
    let info = getFileInfo(reportPath)
    let dev = $cast[uint64](info.id.device)
    let ino = $cast[uint64](info.id.file)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(4242'u64, "7000", runId))
    appendFragmentRecord(frag, ipcPeerAt(4242'u64, 9999'u64, "8000",
      "/tmp/sccache.sock", runId, "noncedeadbeef"))
    # A DIFFERENT path spelling, but the SAME (dev, ino) as the report file.
    appendFragmentRecord(frag, MonitorRecord(kind: mrFileWrite,
      observationKind: moFileWrite, osPid: 4242'u64,
      path: "/some/other/spelling.io-mon-report",
      detail: "dev=" & dev & " ino=" & ino))
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcIncomplete
    removeDir(work)

  test "CARDINAL SIN: an out-of-tree daemon's report (no in-tree write) is honored":
    # The legitimate trusted-daemon path: the daemon is out of tree, so NO write
    # record for its report file exists; the report stays authenticated, the build
    # stays mcComplete, and the served read is folded.
    let work = getTempDir() / ("io-mon-s3a-legit-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let reportDir = work / "reports"
    createDir(reportDir)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(4242'u64, "7000", runId))
    appendFragmentRecord(frag, ipcPeerAt(4242'u64, 9999'u64, "8000",
      "/tmp/sccache.sock", runId, "noncedeadbeef"))
    let served = "/some/served/header.h"
    writeFile(reportDir / "report-4242-9999-0.io-mon-report",
      "io-mon-breakaway-report v1\nrun " & runId & "\nclient 4242\ndaemon 9999\n" &
        "read " & served & "\ncomplete\n")
    let dep = mergeFragments(frag, work / "out.rdep", reportDir)
    check dep.completeness == mcComplete
    var sawServed = false
    for r in dep.records:
      if r.path == served and r.observationKind == moFileRead: sawServed = true
    check sawServed
    removeDir(work)

suite "io-mon S3c warm-restart stale-fragment guard (mergeFragments run-id)":
  # ROUND-3 S3c — mergeFragments consumes the kill-sentinels but does NOT delete the
  # `.rmdf-frag` files, so a library caller that RE-MERGES a reused fragment dir
  # (a warm restart) would fold a PRIOR run's records (merge_attack.nim): a stale
  # run-1 process-start makes a run-2 out-of-tree breakaway peer look in-tree ⇒ a
  # FALSE mcComplete, plus the stale reads pollute the depfile. The guard namespaces
  # by the invocation run id and drops records owned by a different run.
  proc readRec(pid: uint64; path: string): MonitorRecord =
    MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
      osPid: pid, path: path)

  test "a stale prior-run fragment is NOT folded; the breakaway downgrades":
    let work = getTempDir() / ("io-mon-s3c-warm-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    # RUN 1: pid 500 is a monitored in-tree process of run "r1" that reads /fileA.
    appendFragmentRecord(frag, startAt(500'u64, "111", "r1"))
    appendFragmentRecord(frag, readRec(500'u64, "/fileA"))
    closeFragmentSlot()
    check mergeFragments(frag, work / "r1.rdep", currentRunId = "r1").completeness ==
      mcComplete
    # RUN 2 reuses the SAME dir (warm restart). A DIFFERENT client pid 600 connects
    # to an OUT-OF-TREE daemon whose pid is 500 (recycled) — the stale run-1
    # process-start for pid 500 would otherwise mask the out-of-tree peer.
    appendFragmentRecord(frag, startAt(600'u64, "222", "r2"))
    appendFragmentRecord(frag, ipcPeerAt(600'u64, 500'u64, "", "/tmp/d.sock", "r2"))
    closeFragmentSlot()
    let dep = mergeFragments(frag, work / "r2.rdep", currentRunId = "r2")
    # The stale run-1 start for pid 500 is dropped, so peer 500 is out-of-tree…
    check dep.completeness == mcIncomplete
    # …and the stale run-1 read /fileA is NOT folded into run-2's depfile.
    for r in dep.records:
      check r.path != "/fileA"
    removeDir(work)

  test "a clean current-run dir is unaffected (no false downgrade)":
    # The fresh-dir guarantee the CLI relies on: every fragment belongs to the
    # current run, so nothing is dropped and a fully-monitored read stays complete.
    let work = getTempDir() / ("io-mon-s3c-fresh-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(700'u64, "1000", "r2"))
    appendFragmentRecord(frag, readRec(700'u64, "/dep/header.h"))
    closeFragmentSlot()
    let dep = mergeFragments(frag, work / "out.rdep", currentRunId = "r2")
    check dep.completeness == mcComplete
    var sawDep = false
    for r in dep.records:
      if r.path == "/dep/header.h": sawDep = true
    check sawDep
    removeDir(work)

  test "without a run id (legacy fresh-dir callers) nothing is filtered":
    # Empty currentRunId + no env ⇒ legacy behaviour: the merge folds every fragment
    # exactly as before, so a single-run dir is unaffected.
    let work = getTempDir() / ("io-mon-s3c-legacy-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, startAt(800'u64, "1000", "r9"))
    appendFragmentRecord(frag, readRec(800'u64, "/dep/x.h"))
    closeFragmentSlot()
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcComplete
    removeDir(work)
