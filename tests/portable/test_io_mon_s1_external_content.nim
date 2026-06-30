## test_io_mon_s1_external_content — pure-logic coverage for the ROUND-3 S1
## content-channel downgrade (`externalContentLossCount`) on SYNTHETIC
## `mrExternalContent` record sets, independent of any platform/shim.
##
## Locks in the CARDINAL-SIN GUARD that is the whole point of routing the
## shm/FIFO/opaque downgrade through the merge rather than the shim: the in-tree
## create/write side and the attach/read side are paired CROSS-PROCESS, so an
## entirely self-produced shm object / FIFO pipeline / in-tree pipe-socket pipeline
## does NOT downgrade, while a channel fed by an out-of-tree producer yields exactly
## one event-loss (a conservative re-run). Mirrors the shim's
## `recordExternalContent` detail tokens (`chan=… role=…`) so a drift in either side
## is caught here on every OS. ROUND-4 IP1 added the `opaque`/`localfd` pairing (an
## inherited pipe/socket with no in-tree create downgrades; an in-tree one pairs).

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

  test "ROUND-4 IP1: opaque read with NO inode key is record-not-downgrade":
    # An opaque read whose fd (dev,ino) was UNOBTAINABLE (fstat failed) carries an
    # EMPTY key and is NOT downgraded — the fail-safe toward mcComplete (a possible
    # missed dep, never a false re-run of a normal build).
    check externalContentLossCount(@[ext("opaque", "read", "")]) == 0

  test "ROUND-4 IP1: inherited pipe/socket (no in-tree create) DOWNGRADES":
    # The IP1 re-break closed: an opaque read keyed on the fd's (dev,ino) with NO
    # matching in-tree pipe/socketpair/socket/accept CREATE is an fd inherited from
    # an OUT-OF-TREE parent → one loss (a conservative re-run).
    check externalContentLossCount(@[ext("opaque", "read", "localfd:0:9001")]) == 1

  test "ROUND-4 IP1: in-tree pipe/socket pipeline does NOT downgrade (cardinal sin)":
    # The IP1 cardinal-sin guard: a monitored process created the pipe/socket
    # in-tree (recordLocalFdCreate), so an inherited read of the SAME object — even
    # in a forked child — PAIRS by (dev,ino) and does NOT downgrade. This keeps the
    # clang driver↔cc1 pipes and intra-tree socket IPC mcComplete.
    let recs = @[
      ext("localfd", "create", "localfd:0:9001", pid = 100),
      ext("opaque", "read", "localfd:0:9001", pid = 101)]
    check externalContentLossCount(recs) == 0

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
      ext("opaque", "read", "", pid = 101, fd = 3)]       # opaque (no key) → no loss
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
