## test_io_mon_parity_with_fs_snoop — io-mon reproduces the EXISTING fs-snoop
## captured read/write file sets, at the record/encode/decode level.
##
## ## What this test exercises (and what it does NOT)
##
## io-mon is a faithful relocation of reprobuild's `repro_monitor_depfile`
## fs-snoop stack. The behaviour it must preserve is: a monitored run produces
## a set of `MonitorRecord`s (file reads / writes / opens / probes), which are
## encoded into the binary RMDF depfile and decoded back into the SAME read and
## written file sets.
##
## Driving the REAL interpose monitor (`fs_snoop.runFsSnoop`) end-to-end
## requires the platform interpose shim shared library
## (`librepro_monitor_shim.{so,dylib,dll}`) to be present and the host to allow
## `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` style injection. That artifact is NOT
## built in io-mon's standalone tree (it belongs to the consumer / the M7
## reprobuild integration), so this test asserts parity at the
## **record / encode / decode / fragment-merge** level — the exact layers
## reprobuild's own fs-snoop unit + integration tests exercise
## (`tests/integration/t_monitor_depfile_reader.nim`,
## `tests/unit/t_m9r15f_1_fs_snoop_batched_writes.nim`,
## `tests/unit/t_m9r15c_1_fs_snoop_fragment_log_perf.nim`). It does NOT fake a
## passing live interpose run.
##
## The capture format is the parity boundary: if io-mon encodes/decodes the
## same records to the same read/write sets and byte-identical canonical bytes,
## then any front-end (reprobuild's fs-snoop OR the codetracer runner) that
## feeds the SAME observations gets the SAME captured file sets.

import std/[algorithm, os, sets, strutils, tempfiles, unittest]

import io_mon

proc readRecord(seqNo: uint64; path: string): MonitorRecord =
  ## A file-READ observation, as the interpose monitor would emit it.
  MonitorRecord(
    kind: mrFileRead,
    observationKind: moFileRead,
    seq: seqNo,
    osPid: 100,
    parentOsPid: 1,
    threadId: 7,
    result: 0,
    probeResult: prExistingFile,
    path: path)

proc writeRecord(seqNo: uint64; path: string): MonitorRecord =
  ## A file-WRITE observation.
  MonitorRecord(
    kind: mrFileWrite,
    observationKind: moFileWrite,
    seq: seqNo,
    osPid: 100,
    parentOsPid: 1,
    threadId: 7,
    result: 0,
    probeResult: prExistingFile,
    path: path)

proc openRecord(seqNo: uint64; osPid, threadId: uint64; path: string): MonitorRecord =
  MonitorRecord(
    kind: mrFileOpen,
    observationKind: moFileOpen,
    seq: seqNo,
    osPid: osPid,
    parentOsPid: 1,
    threadId: threadId,
    result: 3,
    probeResult: prUnknown,
    path: path)

proc readPaths(dep: MonitorDepFile): HashSet[string] =
  ## The set of files the monitored run READ.
  for r in dep.records:
    if r.kind == mrFileRead:
      result.incl r.path

proc writtenPaths(dep: MonitorDepFile): HashSet[string] =
  ## The set of files the monitored run WROTE.
  for r in dep.records:
    if r.kind == mrFileWrite:
      result.incl r.path

suite "io-mon parity with fs-snoop (record/encode/decode level)":

  test "captured read/write file sets survive a writeCanonical -> read round-trip":
    # This is the core parity property: the read set and the written set that
    # the monitor observed must come back BYTE-FOR-BYTE identical after the
    # depfile round-trip. This mirrors the behaviour reprobuild's fs-snoop
    # relies on: a depfile is the on-disk record of which files an action
    # read and wrote.
    let root = createTempDir("io-mon-parity", "")
    defer: removeDir(root)

    let expectedReads = [
      root / "src" / "a.nim",
      root / "src" / "b.nim",
      root / "include" / "header.h"
    ]
    let expectedWrites = [
      root / "out" / "a.o",
      root / "out" / "artifact.bin"
    ]

    var records: seq[MonitorRecord]
    var seqNo = 1'u64
    for p in expectedReads:
      records.add readRecord(seqNo, p); inc seqNo
    for p in expectedWrites:
      records.add writeRecord(seqNo, p); inc seqNo

    let depfile = root / "capture.rdep"
    writeCanonical(depfile, records)

    # The depfile is the canonical binary RMDF format, not JSON.
    let raw = readFile(depfile)
    check raw.len > 8
    check raw[0 .. 3] == RmdfMagic
    check raw[0] != '{'

    let dep = readMonitorDepFile(depfile)
    check dep.version == RmdfVersion
    check readPaths(dep) == toHashSet(expectedReads)
    check writtenPaths(dep) == toHashSet(expectedWrites)
    # Every observation survived; none were dropped or duplicated.
    check dep.records.len == expectedReads.len + expectedWrites.len

  test "fragment-log capture path merges to the same read/write sets":
    # The REAL fs-snoop capture path: the interpose monitor appends each
    # observation to a per-thread fragment log (open-once, batched), then
    # mergeFragments folds the fragments into the canonical depfile. Parity
    # means the merged read/write sets equal what was appended. This is the
    # path that runs inside a live interpose session, exercised here without
    # the shim by driving appendFragmentRecord directly.
    let root = createTempDir("io-mon-frag", "")
    defer: removeDir(root)
    let fragDir = root / "fragments"
    createDir(fragDir)

    resetFragmentLogOpenCount()

    let reads = [root / "in1.txt", root / "in2.txt"]
    let writes = [root / "out1.bin"]

    var seqNo = 1'u64
    for p in reads:
      var rec = readRecord(seqNo, p)
      appendFragmentRecord(fragDir, rec)
      inc seqNo
    for p in writes:
      var rec = writeRecord(seqNo, p)
      appendFragmentRecord(fragDir, rec)
      inc seqNo
    closeFragmentSlot()

    let merged = mergeFragments(fragDir, root / "merged.rdep")
    check readPaths(merged) == toHashSet(reads)
    check writtenPaths(merged) == toHashSet(writes)

    # Re-reading the merged file from disk yields the same sets.
    let reMerged = readMonitorDepFile(root / "merged.rdep")
    check readPaths(reMerged) == toHashSet(reads)
    check writtenPaths(reMerged) == toHashSet(writes)

  test "canonical encoding is deterministic (byte-identical for same input)":
    # The fs-snoop format is deterministic: the same observation sequence must
    # encode to byte-identical depfiles. reprobuild's determinism tests rely on
    # this so cache keys over depfiles are stable.
    let records = @[
      openRecord(1, 100, 7, "/work/a"),
      readRecord(2, "/work/a"),
      writeRecord(3, "/work/out")
    ]
    let a = encodeCanonical(records)
    let b = encodeCanonical(records)
    check a == b
    check a.len > 0

  test "tolerant reader recovers complete frames after a truncated tail (crash recovery)":
    # A producer SIGKILL'd mid-write leaves a partial trailing frame. The
    # tolerant decoder must return exactly the complete frames written before
    # the crash — so the read/write sets captured up to the crash are intact.
    let root = createTempDir("io-mon-crash", "")
    defer: removeDir(root)
    let fragDir = root / "frag"
    createDir(fragDir)

    let reads = [root / "x", root / "y", root / "z"]
    var seqNo = 1'u64
    for p in reads:
      var rec = readRecord(seqNo, p)
      appendFragmentRecord(fragDir, rec)
      inc seqNo
    closeFragmentSlot()

    # Find the fragment file and append a truncated partial frame.
    var fragFile = ""
    for kind, p in walkDir(fragDir):
      if kind == pcFile:
        fragFile = p
        break
    check fragFile.len > 0

    var bytes = readFile(fragFile)
    # Append a bogus, too-short frame tail (length prefix promising more
    # bytes than follow) to simulate a crash mid-frame.
    bytes.add("\xff\xff\xff\xff\x00\x00")
    writeFile(fragFile, bytes)

    var cleanEof = true
    let recovered = readFragmentRecordsTolerant(fragFile, cleanEof)
    var recoveredReads: HashSet[string]
    for r in recovered:
      if r.kind == mrFileRead:
        recoveredReads.incl r.path
    check recoveredReads == toHashSet(reads)
    # The complete leading frames are recovered, but the truncated tail means
    # the fragment did NOT decode cleanly to EOF — the fail-closed signal that
    # blocks cache publication (Monitor-Hook-Shim.md §"Failure Semantics":
    # "partial RMDF writes MUST fail reader validation").
    check not cleanEof

  test "merge fails closed on a corrupt fragment (incomplete evidence)":
    # Fail-closed contract (Monitor-Hook-Shim.md §"Failure Semantics":
    # "partial RMDF writes MUST fail reader validation"; "shim crash MUST
    # reject cache publication"; "successful child exit MUST NOT hide monitor
    # failure"). A fragment that does not decode cleanly — e.g. a shim that
    # crashed before writing any complete frame, leaving garbage — MUST make
    # the merged depfile ``mcIncomplete`` so the build engine refuses to
    # publish the action to the cache and re-executes it on the next run.
    let root = createTempDir("io-mon-corrupt-frag", "")
    defer: removeDir(root)
    let fragDir = root / "frag"
    createDir(fragDir)

    # Write a single complete, valid fragment so the merge has real evidence,
    # then drop a wholly-corrupt fragment alongside it.
    var rec = readRecord(1'u64, root / "good-input")
    appendFragmentRecord(fragDir, rec)
    closeFragmentSlot()
    writeFile(fragDir / "corrupt.rmdf-frag", "not an RMDF fragment")

    let dep = mergeFragments(fragDir, root / "merged.rdep")
    check dep.completeness == mcIncomplete
    check dep.summary.eventLossCount >= 1'u64
    # The valid fragment's record is still recovered for diagnostics.
    var goodReads: HashSet[string]
    for r in dep.records:
      if r.kind == mrFileRead:
        goodReads.incl r.path
    check (root / "good-input") in goodReads

    # And the on-disk depfile re-reads as incomplete via the canonical reader
    # the build engine uses, confirming the signal survives canonicalization.
    let reread = readMonitorDepFile(root / "merged.rdep")
    check reread.completeness == mcIncomplete

  test "reader rejects a corrupted depfile (checksum mismatch)":
    # Parity on the validation surface: a flipped byte must be caught, exactly
    # as reprobuild's reader-validation test asserts.
    let root = createTempDir("io-mon-corrupt", "")
    defer: removeDir(root)
    let depfile = root / "ok.rdep"
    writeCanonical(depfile, @[readRecord(1, root / "input.txt")])

    var raw = readFile(depfile)
    raw[^1] = char(ord(raw[^1]) xor 0x01)
    let bad = root / "bad.rdep"
    writeFile(bad, raw)

    var caught = false
    try:
      discard readMonitorDepFile(bad)
    except MonitorDepFileReaderError as err:
      caught = true
      check err.kind == mrChecksumMismatch
    check caught

  test "ordering of observations is preserved (sequence is canonical)":
    # The captured sets are order-insensitive, but the underlying record
    # stream must keep its canonical 1..N sequence so consumers that care
    # about ordering (e.g. read-before-write) see the same stream.
    let recs = @[
      readRecord(1, "/a"),
      writeRecord(2, "/b"),
      readRecord(3, "/c")
    ]
    let root = createTempDir("io-mon-order", "")
    defer: removeDir(root)
    let depfile = root / "seq.rdep"
    writeCanonical(depfile, recs)
    let dep = readMonitorDepFile(depfile)
    var seqs: seq[uint64]
    for r in dep.records:
      seqs.add r.seq
    var sorted = seqs
    sort(sorted)
    check seqs == sorted          # already in order
    check seqs == @[1'u64, 2'u64, 3'u64]
