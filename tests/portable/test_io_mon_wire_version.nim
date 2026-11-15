## test_io_mon_wire_version — the `.iomon` envelope version says which reader
## can decode the file.
##
## WHY. `decodeRecordPayload` rejects a record kind past `high(MonitorRecordKind)`,
## so a reader built before a kind was appended fails a file that carries it as
## `mrSemanticValidationFailed` ("unknown iomon record kind"): it reports a
## newer capture as a corrupt one. Kinds 12..19 were appended at version 1,
## and so, at first, was `mrConnectAttempt` (20): exactly that skew.
## The rule on `IomonVersion` (types.nim) is now: bump whenever a writer can
## emit bytes an older reader rejects, and `iomonVersionIntroducing` names the
## version that first wrote each kind.
##
## What is graded:
##   * a capture carrying the newest kind is written, through BOTH writers
##     (`encodeCanonical` and `writeCanonicalInPlace`), with a header version
##     at least the one that introduced that kind. A reader built for version 1
##     therefore refuses it as unsupported instead of misreading it as corrupt;
##   * both readers (`readMonitorDepFile` and `streamMonitorDepFileRecords`)
##     still decode a version-1 file (backward compatibility: every bump so far
##     only appended kinds);
##   * the reader refuses version 0 and a version newer than its own as
##     `mrUnsupportedVersion`.
##
## Pure `io_mon/{types,encode,reader}` — portable tier, every OS. No mocks.

import std/[os, unittest]

import io_mon/types
import io_mon/codec
import io_mon/encode
import io_mon/reader

proc attemptRecords(): seq[MonitorRecord] =
  @[MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
      osPid: 4242, threadId: 1, detail: "test"),
    MonitorRecord(kind: mrConnectAttempt, observationKind: moConnectAttempt,
      osPid: 4242, threadId: 1, result: -1, path: "127.0.0.1:9",
      detail: "connect-attempt af_inet errno=61")]

proc fileOnlyRecords(): seq[MonitorRecord] =
  ## Kinds every version so far can carry.
  @[MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
      osPid: 4242, threadId: 1, detail: "test"),
    MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
      osPid: 4242, threadId: 1, path: "/etc/hosts")]

proc toBytesSeq(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  if s.len > 0: copyMem(addr result[0], unsafeAddr s[0], s.len)

proc writeBytes(path: string; bytes: openArray[byte]) =
  var s = newString(bytes.len)
  if bytes.len > 0: copyMem(addr s[0], unsafeAddr bytes[0], bytes.len)
  writeFile(path, s)

proc headerVersion(bytes: openArray[byte]): uint16 =
  loadU16Le(bytes, 4)

proc withVersion(bytes: seq[byte]; version: uint16): seq[byte] =
  ## The version field is not covered by the trailer checksum (it covers the
  ## body only), so patching it leaves an otherwise valid envelope.
  result = bytes
  storeU16Le(result, 4, version)

proc newestIntroduced(records: openArray[MonitorRecord]): uint16 =
  for r in records:
    result = max(result, iomonVersionIntroducing(r.kind))
    result = max(result, iomonVersionIntroducing(r.observationKind))

suite "io-mon: the iomon envelope version":
  let work = getTempDir() / ("io-mon-wire-version-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)

  test "a capture carrying mrConnectAttempt claims a version that introduced it":
    let records = attemptRecords()
    let needed = newestIntroduced(records)
    check needed >= 2'u16
    let buffered = encodeCanonical(records)
    # Stated independently of the table: every reader that says version 1
    # predates kind 20, so a file carrying it must not claim version 1.
    check headerVersion(buffered) > 1'u16
    check headerVersion(buffered) >= needed
    check headerVersion(buffered) == IomonVersion
    var owned = records
    let path = work / "attempt.iomon"
    writeCanonicalInPlace(path, owned)
    let streamed = toBytesSeq(readFile(path))
    check headerVersion(streamed) >= needed
    check headerVersion(streamed) == headerVersion(buffered)
    # And this build reads it back.
    let dep = readMonitorDepFile(path)
    check dep.version == IomonVersion
    check dep.records.len == records.len

  test "every kind is introduced by a version no newer than the one written":
    for kind in MonitorRecordKind:
      check iomonVersionIntroducing(kind) <= IomonVersion
    for kind in MonitorObservationKind:
      check iomonVersionIntroducing(kind) <= IomonVersion
    check iomonVersionReadable(IomonVersion)
    check iomonVersionReadable(IomonMinReadableVersion)

  test "a version-1 file still reads":
    let path = work / "v1.iomon"
    let bytes = withVersion(encodeCanonical(fileOnlyRecords()), 1'u16)
    writeBytes(path, bytes)
    let dep = readMonitorDepFile(path)
    check dep.version == 1'u16
    check dep.records.len == 2
    # The streaming reader has its own version gate; it must accept the same
    # versions as the batch reader.
    var streamed = 0
    for r in streamMonitorDepFileRecords(path):
      inc streamed
    check streamed == 2

  test "version 0 and a version newer than this reader are unsupported":
    for bad in [0'u16, IomonVersion + 1]:
      let path = work / ("bad-" & $bad & ".iomon")
      let bytes = withVersion(encodeCanonical(fileOnlyRecords()), bad)
      writeBytes(path, bytes)
      var kind = mrMissingFile
      var raised = false
      try:
        discard readMonitorDepFile(path)
      except MonitorDepFileReaderError as err:
        raised = true
        kind = err.kind
      check raised
      check kind == mrUnsupportedVersion
      # The streaming reader applies the same gate.
      raised = false
      try:
        for r in streamMonitorDepFileRecords(path):
          discard r
      except MonitorDepFileReaderError as err:
        raised = true
        kind = err.kind
      check raised
      check kind == mrUnsupportedVersion

  removeDir(work)
