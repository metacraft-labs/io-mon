## test_io_mon_s1_external_content — pure-logic coverage for the ROUND-3 S1
## content-channel downgrade (`externalContentLossCount`) on SYNTHETIC
## `mrExternalContent` record sets, independent of any platform/shim.
##
## Locks in the CARDINAL-SIN GUARD that is the whole point of routing the
## shm/FIFO downgrade through the merge rather than the shim: the in-tree
## create/write side and the attach/read side are paired CROSS-PROCESS, so an
## entirely self-produced shm object / FIFO pipeline does NOT downgrade, while a
## channel fed by an out-of-tree producer yields exactly one event-loss (a
## conservative re-run). Mirrors the shim's `recordExternalContent` detail
## tokens (`chan=… role=…`) so a drift in either side is caught here on every OS.

import std/[os, sets, unittest]
import io_mon

proc ext(chan, role, path: string; pid: uint64 = 100; fd: uint32 = 7):
    MonitorRecord =
  ## A synthetic mrExternalContent exactly as the shim emits it.
  MonitorRecord(kind: mrExternalContent, observationKind: moExternalContent,
    osPid: pid, flags: fd, path: path, detail: "chan=" & chan & " role=" & role)

proc start(pid: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart, osPid: pid)

suite "io-mon ROUND-3 S1 external-content downgrade (externalContentLossCount)":
  test "out-of-tree shm attach (no in-tree create) downgrades":
    # probeC: an out-of-tree producer created /r3shm; the monitored consumer only
    # attaches (O_RDONLY) → unpaired → one loss.
    check externalContentLossCount(@[ext("shm", "attach", "shm:/r3shm")]) == 1

  test "self-produced shm (in-tree create AND attach) does NOT downgrade":
    # The cardinal-sin guard: a tree that creates and consumes its own shm is fully
    # accounted for. create may come from one process, attach from another (fork).
    let recs = @[
      ext("shm", "create", "shm:/own", pid = 100),
      ext("shm", "attach", "shm:/own", pid = 101)]
    check externalContentLossCount(recs) == 0

  test "shm create alone (producer only) does NOT downgrade":
    check externalContentLossCount(@[ext("shm", "create", "shm:/own")]) == 0

  test "out-of-tree FIFO read (no in-tree writer) downgrades":
    # probeD: the monitored reader opens the FIFO O_RDONLY; the feeder is
    # out-of-tree (no in-tree write open for that path) → one loss.
    check externalContentLossCount(@[ext("fifo", "read", "/tmp/fifoD")]) == 1

  test "in-tree FIFO pipeline (writer AND reader in-tree) does NOT downgrade":
    let recs = @[
      ext("fifo", "write", "/tmp/own.fifo", pid = 100),
      ext("fifo", "read", "/tmp/own.fifo", pid = 101)]
    check externalContentLossCount(recs) == 0

  test "inherited socket/pipe (opaque) is record-not-downgrade (IPC owns it)":
    # The cardinal-sin guard for intra-tree socket IPC / anonymous pipelines:
    # socket provenance is owned by the IPC-connect machinery, so an opaque marker
    # must NOT add a content-channel downgrade.
    check externalContentLossCount(@[ext("opaque", "read", "")]) == 0

  test "repeated touches of one channel collapse to a single loss (dedup)":
    let recs = @[
      ext("shm", "attach", "shm:/r3shm"),
      ext("shm", "attach", "shm:/r3shm"),
      ext("fifo", "read", "/tmp/fifoD"),
      ext("fifo", "read", "/tmp/fifoD")]
    check externalContentLossCount(recs) == 2

  test "mixed: out-of-tree shm + paired FIFO + opaque = 1 loss (only the shm)":
    let recs = @[
      ext("shm", "attach", "shm:/r3shm"),                 # out-of-tree → loss
      ext("fifo", "write", "/tmp/p.fifo", pid = 100),     # paired ↓
      ext("fifo", "read", "/tmp/p.fifo", pid = 101),      # in-tree → no loss
      ext("opaque", "read", "", pid = 101, fd = 3)]       # opaque → no loss
    check externalContentLossCount(recs) == 1

  test "mergeFragments folds an out-of-tree shm attach to mcIncomplete":
    # End-to-end through the real merge: a monitored process that only attaches an
    # out-of-tree shm publishes mcIncomplete (a conservative re-run).
    let work = getTempDir() / ("io-mon-s1-merge-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, start(100))
    appendFragmentRecord(frag, ext("shm", "attach", "shm:/r3shm", pid = 100))
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcIncomplete
    removeDir(work)

  test "mergeFragments keeps a self-produced shm tree mcComplete (cardinal sin)":
    let work = getTempDir() / ("io-mon-s1-merge2-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, start(100))
    appendFragmentRecord(frag, ext("shm", "create", "shm:/own", pid = 100))
    appendFragmentRecord(frag, ext("shm", "attach", "shm:/own", pid = 100))
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcComplete
    removeDir(work)
