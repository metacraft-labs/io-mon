## test_io_mon_macos_endpoint_security — unit coverage for the EndpointSecurity
## backend SKELETON's PURE logic (T3c), independent of the entitlement-restricted
## ES SDK. Exercises the three pure pieces the production backend is built on and
## that the design doc (MacOS-EndpointSecurity-Backend.md) specifies:
##   - the process-subtree filter (EsProcessTree) — ES is system-global, so only
##     the build's own root pid + descendants (grown via FORK/EXEC) are kept;
##   - the event-loss detector (EsSeqTracker.observeSeq) — a `global_seq_num` gap
##     maps to dropped events → an `mrEventLoss` record → `mcIncomplete`;
##   - the ES-event → RMDF-record mapping (classifyOpenFlags + es*Record), which
##     reuses the EXISTING record/observation kinds (no new wire-format enum).
## Also asserts the default build's `start()` is an HONEST design stub (refuses to
## start with a clear reason), so nothing mistakes the skeleton for a live backend.
## Platform-independent and SDK-free: the entitlement-gated ES client lives behind
## the off-by-default `-d:ioMonEndpointSecurity` define and is NOT exercised here.

import std/[strutils, unittest]
import io_mon/types
import io_mon/backends/endpoint_security

suite "io-mon EndpointSecurity skeleton — process-subtree filter":
  test "the root pid is in the subtree; an unrelated pid is not":
    let tree = initEsProcessTree(1000)
    check tree.inSubtree(1000)
    check not tree.inSubtree(2000)

  test "a fork child is admitted only when its parent is monitored":
    var tree = initEsProcessTree(1000)
    tree.onFork(1000, 1100)        # parent monitored → child admitted
    tree.onFork(9999, 1200)        # parent NOT monitored → child ignored
    check tree.inSubtree(1100)
    check not tree.inSubtree(1200)

  test "exec keeps the pid in the subtree (survives a hardened-image exec)":
    var tree = initEsProcessTree(1000)
    tree.onFork(1000, 1100)
    tree.onExec(1100)              # exec replaces image, keeps pid
    check tree.inSubtree(1100)

  test "exit drops the pid (guards against later pid reuse out-of-tree)":
    var tree = initEsProcessTree(1000)
    tree.onFork(1000, 1100)
    tree.onExit(1100)
    check not tree.inSubtree(1100)

  test "a grandchild is admitted transitively":
    var tree = initEsProcessTree(1000)
    tree.onFork(1000, 1100)
    tree.onFork(1100, 1200)        # parent (1100) is monitored → grandchild in
    check tree.inSubtree(1200)

suite "io-mon EndpointSecurity skeleton — event-loss detection":
  test "a contiguous global_seq_num stream reports NO loss":
    var t = EsSeqTracker()
    check t.observeSeq(1) == 0
    check t.observeSeq(2) == 0
    check t.observeSeq(3) == 0
    check t.droppedEvents == 0

  test "a forward gap reports the exact dropped count":
    var t = EsSeqTracker()
    check t.observeSeq(1) == 0
    check t.observeSeq(5) == 3     # 2,3,4 dropped
    check t.droppedEvents == 3
    check t.observeSeq(6) == 0     # back in step after the gap

  test "a duplicate / reorder reports no loss (only forward jumps count)":
    var t = EsSeqTracker()
    discard t.observeSeq(10)
    check t.observeSeq(10) == 0
    check t.observeSeq(9) == 0
    check t.droppedEvents == 0

  test "a detected drop maps to an mrEventLoss record (→ mcIncomplete path)":
    let rec = eventLossRecord(3)
    check rec.kind == mrEventLoss
    check rec.observationKind == moEventLoss
    check "3" in rec.detail

suite "io-mon EndpointSecurity skeleton — event → record mapping":
  test "read-only open classifies as a content read (moFileOpen)":
    check classifyOpenFlags(0'u32) == moFileOpen        # O_RDONLY

  test "writable / creating / truncating opens classify as writes":
    check classifyOpenFlags(0x0001'u32) == moFileWrite  # O_WRONLY
    check classifyOpenFlags(0x0002'u32) == moFileWrite  # O_RDWR
    check classifyOpenFlags(0x0200'u32) == moFileWrite  # O_CREAT
    check classifyOpenFlags(0x0400'u32) == moFileWrite  # O_TRUNC
    check classifyOpenFlags(0x0008'u32) == moFileWrite  # O_APPEND

  test "open record carries the path, pid, and classified observation":
    let r = esOpenRecord(1100, 1000, "/etc/services", 0'u32)
    check r.kind == mrFileOpen
    check r.observationKind == moFileOpen
    check r.osPid == 1100
    check r.parentOsPid == 1000
    check r.path == "/etc/services"

  test "clone and link record the SOURCE as a read dependency (break #3)":
    let c = esCloneRecord(1100, 1000, "/src/a")
    check c.kind == mrFileRead and c.observationKind == moFileRead
    check c.path == "/src/a"
    let l = esLinkRecord(1100, 1000, "/src/b")
    check l.kind == mrFileRead and l.observationKind == moFileRead

  test "rename records the DESTINATION as an output write":
    let r = esRenameRecord(1100, 1000, "/out/final")
    check r.kind == mrFileWrite and r.observationKind == moFileWrite
    check r.path == "/out/final"

  test "lookup records an existence probe with the right ProbeResult (break #5)":
    check esLookupRecord(1100, 1000, "/maybe", true).probeResult == prExistingFile
    check esLookupRecord(1100, 1000, "/gone", false).probeResult == prAbsent

  test "exec maps to process-exec; fork carries the child pid":
    check esExecRecord(1100, 1000, "/usr/bin/clang").kind == mrProcessExec
    let f = esForkRecord(1000, 900, 1100)
    check f.kind == mrProcessSpawn
    check f.childOsPid == 1100

suite "io-mon EndpointSecurity skeleton — honest default stub":
  test "the default build refuses to start with a clear gated reason":
    proc sink(r: MonitorRecord) {.gcsafe.} = discard
    var b = newEsBackend(1000, sink)
    let res = b.start()
    check not res.ok
    check not b.started
    check res.reason.len > 0
