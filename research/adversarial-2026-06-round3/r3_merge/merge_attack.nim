## Direct mergeFragments attacks (warm-restart / stale-fragment / pid+start-time).
import std/[os, sets]
import io_mon

proc readRec(pid: uint64; path: string; seqNo: uint64): MonitorRecord =
  MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
    osPid: pid, path: path, seq: seqNo)

proc startRec(pid: uint64; startUsec: string; run = "r1"): MonitorRecord =
  result = MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
    osPid: pid, detail: "shim-loaded start=" & startUsec & " run=" & run)

proc ipcRec(pid, peer: uint64; peerStart: string; dest: string; run="r1"): MonitorRecord =
  result = MonitorRecord(kind: mrIpcConnect, observationKind: moIpcConnect,
    osPid: pid, childOsPid: peer, path: dest,
    detail: "peerstart=" & peerStart & " run=" & run)

proc writeFrag(dir: string; pid, tid: uint64; recs: seq[MonitorRecord]) =
  let p = fragmentPath(dir, pid, tid)
  for r in recs:
    var rr = r
    rr.threadId = tid
    appendFragmentRecord(dir, rr)
  closeFragmentSlot()
  doAssert fileExists(p)

proc completeness(dir, outp: string; rootPid: uint64 = 0): MonitorCompleteness =
  mergeFragments(dir, outp, expectedRootPid = rootPid).completeness

# ---- Attack 2a: WARM RESTART — stale process-start masks a breakaway peer ----
block:
  let dir = "/tmp/r3_merge/warm_dir"
  removeDir(dir); createDir(dir)
  let outp = "/tmp/r3_merge/warm.rdep"
  # RUN 1: pid 500 is a monitored in-tree process that reads fileA.
  writeFrag(dir, 500, 1, @[startRec(500, "111", "r1"), readRec(500, "/fileA", 2)])
  let c1 = completeness(dir, outp)
  echo "warm run1: ", c1, " (expect mcComplete)"
  # mergeFragments does NOT delete .rmdf-frag files. Simulate a SECOND invocation
  # reusing the SAME dir (warm restart). RUN 2: a DIFFERENT monitored client pid 600
  # connects to an OUT-OF-TREE daemon whose pid is 500 (recycled). The daemon served
  # a hidden file. peerstart EMPTY (client couldn't query peer start -> bare-pid path).
  writeFrag(dir, 600, 1, @[startRec(600, "222", "r2"),
    ipcRec(600, 500, "", "/tmp/daemon.sock", "r2")])
  let c2 = completeness(dir, outp)
  let stalePresent = readFile(fragmentPath(dir,500,1)).len > 0
  echo "warm run2: ", c2, " stale-frag-500-present=", stalePresent,
    "  (BREAK if mcComplete: stale start-500 masks out-of-tree daemon peer)"

# ---- Attack 2b: same but FRESH dir (the io-mon-run guarantee) ----
block:
  let dir = "/tmp/r3_merge/fresh_dir"
  removeDir(dir); createDir(dir)
  let outp = "/tmp/r3_merge/fresh.rdep"
  writeFrag(dir, 600, 1, @[startRec(600, "222", "r2"),
    ipcRec(600, 500, "", "/tmp/daemon.sock", "r2")])
  echo "fresh: ", completeness(dir, outp), " (expect mcIncomplete: peer 500 out-of-tree)"
