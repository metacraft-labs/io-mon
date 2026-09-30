## test_io_mon_dep_codec_roundtrip — io-mon-Lossless-Event-Capture M3 (part 2b).
##
## Ring-free field-by-field round-trip coverage for the RETAINED dep-record codec
## (`encodeDepRecord` / `encodeDepRecordIdentity` -> `decodeDepRecord`). This is the
## sole assertion that the codec preserves EVERY output-affecting `MonitorRecord`
## field; it recovers the `block codec:` coverage from the removed
## `test_io_mon_dep_ring_mpsc_roundtrip.nim` (part 2b deleted the ring transport but
## kept the codec, which now travels the nim-shm-gset SET channel). The golden
## depfile tests zero several of these fields, so without this test a codec
## regression that drops e.g. `childOsPid` or `flags` would silently corrupt
## depfiles and still pass.
##
## Pure `io_mon/types` + `io_mon/shm/dep_queue` — no ring, no shm, no live shim —
## so it runs on EVERY OS (portable tier).
##
## Coverage:
##   * encodeDepRecord (real-seq variant): every field, INCLUDING `seq`, survives
##     the round-trip for several representative records (typical; empty
##     path/detail; max-ish values; non-ASCII detail).
##   * encodeDepRecordIdentity: process/completeness fields survive with `seq`
##     forced to 0; path-scoped and fact-scoped observations normalize
##     process-local coordinates; trailing per-exec image bytes are ignored by
##     the decoder.
##   * DA-1b `depIdentityScope` / `depIdentityKeepsIncarnation`: EVERY
##     `MonitorRecordKind` is classified, the three classes partition the enum,
##     a fact-scoped kind folds two observers into one element, and a
##     process-scoped kind still separates them. The decision table is restated
##     here as literal sets, INDEPENDENTLY of the implementation, so moving a
##     completeness-bearing kind across the line in `dep_queue.nim` alone turns
##     this file red instead of silently agreeing with itself.
##
## Falsifiable: dropping any field from `decodeDepRecord` (verified in review by
## breaking `childOsPid`/`flags` in a scratch copy) fails the matching `check`.

import std/[strutils, unittest]

import io_mon/types
import io_mon/shm/dep_queue

const CodecBufCap = 8192
  ## Comfortably larger than DepFixedHeaderLen + the longest path/detail below
  ## plus any appended identity-image suffix.

const
  # DA-1b — the decision table, restated as literal sets. This is deliberately a
  # SECOND statement of the classification rather than a call into
  # `depIdentityScope`: a test that asks the implementation what it decided
  # cannot notice a kind being moved. Adding a `MonitorRecordKind` without
  # placing it in exactly one of these three sets fails
  # `t_every_record_kind_has_a_stated_identity_scope`.
  PathScopedKinds = {mrFileOpen, mrFileRead, mrPathProbe, mrDirectoryEnumerate}
  FactScopedKinds = {mrLibraryLoad, mrEnvRead, mrSysctlRead, mrTimeRead}
  ProcessScopedKinds = {mrProcessStart, mrProcessExec, mrProcessSpawn,
    mrFileWrite, mrEventLoss, mrBackendProfile, mrCapabilityGap, mrIpcConnect,
    mrNonDeterministic, mrExternalContent, mrPathMutation}

proc representativeRecords(): seq[MonitorRecord] =
  result = @[
    # 1. Typical full record — every field non-trivial.
    MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
      seq: 42, osPid: 1234, parentOsPid: 12, threadId: 7, childOsPid: 99,
      result: -5, flags: 0xABCD'u32, probeResult: prExistingFile,
      path: "/some/deep/path/to/a/dependency.h",
      detail: "run=xyz ctx=[phase=emit]"),
    # 2. Empty path AND detail (varint length 0 on both).
    MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
      seq: 0, osPid: 1, parentOsPid: 0, threadId: 0, childOsPid: 0,
      result: 0, flags: 0'u32, probeResult: prUnknown,
      path: "", detail: ""),
    # 3. Max-ish values — high enums, big unsigned fields, negative result,
    #    full u32 flags (guards against sign/width truncation).
    MonitorRecord(kind: mrPathMutation, observationKind: moPathMutation,
      seq: high(uint64), osPid: high(uint64) - 1, parentOsPid: 0xDEADBEEF01234567'u64,
      threadId: 0x0123456789ABCDEF'u64, childOsPid: high(uint64) div 3,
      result: low(int64), flags: high(uint32), probeResult: prExistingOther,
      path: "/x".repeat(400), detail: "d".repeat(300)),
    # 4. Non-ASCII detail (bytes >= 0x80 must survive the char<->byte copy).
    MonitorRecord(kind: mrLibraryLoad, observationKind: moFileRead,
      seq: 7, osPid: 555, parentOsPid: 1, threadId: 3, childOsPid: 0,
      result: 0, flags: 0x8000_0001'u32, probeResult: prExistingDirectory,
      path: "/usr/lib/libfavorité.dylib",
      detail: "détail: café — naïve ☃ \xFF\x80\x00 tail"),
  ]

proc expectedIdentity(record: MonitorRecord): MonitorRecord =
  result = record
  result.seq = 0
  if record.kind in PathScopedKinds + FactScopedKinds:
    result.osPid = 0
    result.parentOsPid = 0
    result.threadId = 0
    result.childOsPid = 0
    case record.kind
    of mrFileRead:
      result.result = 0
      result.flags = 0
    of mrFileOpen, mrPathProbe:
      result.result = if record.result < 0: -1 else: 0
    else:
      discard

proc identityBytes(record: MonitorRecord): seq[byte] =
  var buf: array[CodecBufCap, byte]
  let n = encodeDepRecordIdentity(record, buf)
  if n > 0:
    result = newSeq[byte](n)
    for i in 0 ..< n:
      result[i] = buf[i]

template checkAllFields(d, r: MonitorRecord; expectSeq: uint64) =
  ## Assert every codec-carried field of `d` matches `r`, with `seq` compared
  ## against `expectSeq` (real `seq` for encodeDepRecord, 0 for the identity codec).
  ## A TEMPLATE (not a proc) so the `check`s expand into the test body and a
  ## failure flips the enclosing test to `[FAILED]` (unittest tracks status
  ## lexically, per test body).
  check d.kind == r.kind
  check d.observationKind == r.observationKind
  check d.seq == expectSeq
  check d.osPid == r.osPid
  check d.parentOsPid == r.parentOsPid
  check d.threadId == r.threadId
  check d.childOsPid == r.childOsPid
  check d.result == r.result
  check d.flags == r.flags
  check d.probeResult == r.probeResult
  check d.path == r.path
  check d.detail == r.detail

suite "io-mon dep record codec round-trip":

  test "t_codec_real_seq_roundtrip":
    # encodeDepRecord carries the record's real `seq`: EVERY field must survive.
    for r in representativeRecords():
      var buf: array[CodecBufCap, byte]
      let n = encodeDepRecord(r, buf)
      check n > 0
      var ok = false
      let d = decodeDepRecord(buf.toOpenArray(0, n - 1), ok)
      check ok
      checkAllFields(d, r, r.seq)

  test "t_codec_identity_normalizes_path_observations_and_ignores_suffix":
    # The identity codec preserves process/completeness fields. Path observations
    # decode to their dependency identity rather than process-local event values.
    let imageSuffix = "/proc/self/exe#incarnation-image-bytes\x00\x01\x02"
    for r in representativeRecords():
      let expected = expectedIdentity(r)
      var buf: array[CodecBufCap, byte]
      let n = encodeDepRecordIdentity(r, buf)
      check n > 0

      # Bare identity element decodes with seq=0, all other fields intact.
      var okBare = false
      let bare = decodeDepRecord(buf.toOpenArray(0, n - 1), okBare)
      check okBare
      checkAllFields(bare, expected, 0'u64)

      # Append the image suffix and decode again: the trailing bytes are dropped,
      # so the decoded record is byte-for-byte the bare (file) record.
      var withSuffix = buf
      var total = n
      for ch in imageSuffix:
        withSuffix[total] = byte(ch); inc total
      var okSuffix = false
      let dec = decodeDepRecord(withSuffix.toOpenArray(0, total - 1), okSuffix)
      check okSuffix
      checkAllFields(dec, expected, 0'u64)
      check dec == bare

  test "t_path_identity_folds_process_local_coordinates":
    let openA = MonitorRecord(kind: mrFileOpen, observationKind: moFileOpen,
      seq: 1, osPid: 100, parentOsPid: 10, threadId: 7, childOsPid: 9,
      result: 3, flags: 0x80000'u32, probeResult: prUnknown,
      path: "/usr/include/example.h", detail: "run=codec-test")
    var openB = openA
    openB.seq = 99
    openB.osPid = 200
    openB.parentOsPid = 20
    openB.threadId = 8
    openB.childOsPid = 19
    openB.result = 42
    check identityBytes(openA) == identityBytes(openB)

    var failedOpen = openB
    failedOpen.result = -1
    check identityBytes(openA) != identityBytes(failedOpen)
    var differentFlags = openB
    differentFlags.flags = 0
    check identityBytes(openA) != identityBytes(differentFlags)

    let readA = MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
      seq: 1, osPid: 100, threadId: 7, result: 1, flags: 3,
      path: "/usr/include/example.h", detail: "run=codec-test")
    var readB = readA
    readB.seq = 200
    readB.osPid = 300
    readB.threadId = 9
    readB.result = 65536
    readB.flags = 57
    check identityBytes(readA) == identityBytes(readB)

    let probeMissing = MonitorRecord(kind: mrPathProbe,
      observationKind: moPathProbe, osPid: 10, result: -1,
      probeResult: prAbsent, path: "/usr/include/missing.h",
      detail: "run=codec-test")
    var probeExisting = probeMissing
    probeExisting.osPid = 20
    probeExisting.result = 0
    probeExisting.probeResult = prExistingFile
    check identityBytes(probeMissing) != identityBytes(probeExisting)

    let startA = MonitorRecord(kind: mrProcessStart,
      observationKind: moProcessStart, osPid: 100, parentOsPid: 10,
      detail: "run=codec-test")
    var startB = startA
    startB.osPid = 200
    check identityBytes(startA) != identityBytes(startB)

    # DA-1b joined `mrDirectoryEnumerate` to this class: a directory's entries
    # are a property of the directory, not of whoever listed them.
    let dirA = MonitorRecord(kind: mrDirectoryEnumerate,
      observationKind: moDirectoryEnumerate, osPid: 100, parentOsPid: 10,
      threadId: 7, result: 1, path: "/usr/include", detail: "readdir run=codec-test")
    var dirB = dirA
    dirB.osPid = 200
    dirB.parentOsPid = 20
    dirB.threadId = 9
    check identityBytes(dirA) == identityBytes(dirB)
    var dirOther = dirB
    dirOther.path = "/usr/include/sys"
    check identityBytes(dirA) != identityBytes(dirOther)

  test "t_fact_scoped_identity_folds_the_observer":
    # DA-1b's headline at the codec: one fact observed by many processes is one
    # element. The measured shape is `library-load` — 33,128 records over 26
    # DSOs on a real `nim c`, `libpthread.so.0` alone 4,040 times, every field
    # byte-identical but for `osPid`.
    for kind in FactScopedKinds:
      let obs =
        case kind
        of mrLibraryLoad: moFileRead
        of mrEnvRead: moEnvRead
        of mrSysctlRead: moSysctlRead
        else: moTimeRead
      let a = MonitorRecord(kind: kind, observationKind: obs,
        seq: 1, osPid: 100, parentOsPid: 10, threadId: 7, childOsPid: 0,
        path: "/nix/store/aaaa/lib/libpthread.so.0",
        detail: "library-load startup-closure run=codec-test")
      var b = a
      b.seq = 4040
      b.osPid = 200
      b.parentOsPid = 20
      b.threadId = 9
      check identityBytes(a) == identityBytes(b)
      # …and the incarnation suffix, the other process-local coordinate, is not
      # appended for these kinds at all.
      check not depIdentityKeepsIncarnation(kind)

      # Everything the fact IS still separates two elements.
      var otherPath = b
      otherPath.path = a.path & ".1"
      check identityBytes(a) != identityBytes(otherPath)
      var otherDetail = b
      otherDetail.detail = a.detail & " extra"
      check identityBytes(a) != identityBytes(otherDetail)
      var otherObs = b
      otherObs.observationKind = moFileWrite
      check identityBytes(a) != identityBytes(otherObs)
      var otherResult = b
      otherResult.result = 17
      check identityBytes(a) != identityBytes(otherResult)
      var otherFlags = b
      otherFlags.flags = 0x40'u32
      check identityBytes(a) != identityBytes(otherFlags)

  test "t_process_scoped_identity_still_separates_observers":
    # The assertion that keeps DA-1b from erasing evidence. For every kind the
    # completeness machinery reads a pid from, two observers must remain two
    # elements — and a different PEER/CHILD must too, since `mrProcessSpawn`,
    # `mrIpcConnect` and `mrExternalContent` are matched on `childOsPid`.
    for kind in ProcessScopedKinds:
      let a = MonitorRecord(kind: kind, observationKind: moProcessStart,
        osPid: 100, parentOsPid: 10, threadId: 7, childOsPid: 33,
        path: "", detail: "run=codec-test")
      check depIdentityKeepsIncarnation(kind)
      var differentPid = a
      differentPid.osPid = 200
      check identityBytes(a) != identityBytes(differentPid)
      var differentParent = a
      differentParent.parentOsPid = 20
      check identityBytes(a) != identityBytes(differentParent)
      var differentThread = a
      differentThread.threadId = 8
      check identityBytes(a) != identityBytes(differentThread)
      var differentChild = a
      differentChild.childOsPid = 44
      check identityBytes(a) != identityBytes(differentChild)

  test "t_every_record_kind_has_a_stated_identity_scope":
    # A kind added to `MonitorRecordKind` without a decision is a kind whose
    # element key nobody chose, so make that a compile-and-run failure rather
    # than a default.
    var classified = 0
    for kind in MonitorRecordKind:
      let inPath = kind in PathScopedKinds
      let inFact = kind in FactScopedKinds
      let inProcess = kind in ProcessScopedKinds
      checkpoint("kind " & $kind & " -> " & $depIdentityScope(kind))
      # The three classes PARTITION the enum: exactly one, never zero, never two.
      check ord(inPath) + ord(inFact) + ord(inProcess) == 1
      let expected =
        if inPath: disPathScoped
        elif inFact: disFactScoped
        else: disProcessScoped
      check depIdentityScope(kind) == expected
      # The incarnation suffix follows the same decision and only that one.
      check depIdentityKeepsIncarnation(kind) == (expected != disFactScoped)
      inc classified
    check classified ==
      ord(high(MonitorRecordKind)) - ord(low(MonitorRecordKind)) + 1
