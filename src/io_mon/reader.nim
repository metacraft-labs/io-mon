import std/[os, options, strutils]
from io_mon/paths import extendedPath

import io_mon/codec
import io_mon/types
import io_mon/writer

proc classifyEnvelopeError(err: ref EnvelopeError): MonitorDepFileReaderErrorKind =
  case err.kind
  of eeUnknownMagic:
    mrBadMagic
  of eeUnsupportedVersion:
    mrUnsupportedVersion
  of eeUnknownType:
    mrSemanticValidationFailed
  of eeMalformed:
    if err.msg.contains("truncated"):
      mrTruncated
    elif err.msg.contains("checksum"):
      mrChecksumMismatch
    else:
      mrSemanticValidationFailed

proc validateSequenceOrder(records: openArray[MonitorRecord]) =
  var expected = 1'u64
  for record in records:
    if record.seq != expected:
      raiseMonitorDepFileReaderError(mrRecordOrderInvalid,
        "RMDF record sequence is not canonical")
    inc expected

proc decodeMonitorDepFile(bytes: openArray[byte];
                          options: MonitorDepFileReaderOptions): MonitorDepFile =
  if bytes.len < 44:
    raiseMonitorDepFileReaderError(mrTruncated, "RMDF file is too short")
  if fromBytes(bytes.toOpenArray(0, 3)) != RmdfMagic:
    raiseMonitorDepFileReaderError(mrBadMagic, "unknown RMDF magic")

  var pos = 4
  let version = readU16Le(bytes, pos)
  if version != RmdfVersion:
    raiseMonitorDepFileReaderError(mrUnsupportedVersion, "unsupported RMDF version")
  discard readU16Le(bytes, pos)
  let headerCount = readU64Le(bytes, pos)
  let bodyLen = int(readU64Le(bytes, pos))
  if headerCount > options.maxObservationCount:
    raiseMonitorDepFileReaderError(mrRecordLimitExceeded,
      "RMDF record count exceeds configured limit")
  if pos + bodyLen + 20 != bytes.len:
    raiseMonitorDepFileReaderError(mrTruncated,
      "RMDF body length/trailer mismatch")

  let bodyStart = pos
  let bodyEnd = bodyStart + bodyLen
  pos = bodyEnd
  if fromBytes(bytes.toOpenArray(pos, pos + 3)) != RmdfTrailerMagic:
    raiseMonitorDepFileReaderError(mrTruncated, "missing RMDF trailer")
  pos += 4
  let trailerCount = readU64Le(bytes, pos)
  let trailerChecksum = readU64Le(bytes, pos)
  if trailerCount != headerCount:
    raiseMonitorDepFileReaderError(mrSemanticValidationFailed,
      "RMDF record count mismatch")
  if options.requireTrailerChecksum:
    let bodyChecksum =
      if bodyLen == 0: checksum(newSeq[byte]())
      else: checksum(bytes.toOpenArray(bodyStart, bodyEnd - 1))
    if trailerChecksum != bodyChecksum:
      raiseMonitorDepFileReaderError(mrChecksumMismatch, "RMDF checksum mismatch")

  var records: seq[MonitorRecord]
  try:
    if bodyLen == 0:
      records = @[]
    else:
      records = decodeFrames(bytes.toOpenArray(bodyStart, bodyEnd - 1))
  except EnvelopeError as err:
    raiseMonitorDepFileReaderError(classifyEnvelopeError(err), err.msg)
  if uint64(records.len) != headerCount:
    raiseMonitorDepFileReaderError(mrSemanticValidationFailed,
      "RMDF frame count mismatch")
  validateSequenceOrder(records)

  result = depFileFromOwnedRecords(move(records))
  result.version = version

proc readMonitorDepFile*(path: string;
                         options: MonitorDepFileReaderOptions): MonitorDepFile =
  if not fileExists(extendedPath(path)):
    raiseMonitorDepFileReaderError(mrMissingFile,
      "RMDF file does not exist: " & path)
  decodeMonitorDepFile(readFile(extendedPath(path)).toBytes(), options)

proc readMonitorDepFile*(path: string): MonitorDepFile =
  readMonitorDepFile(path, defaultMonitorDepFileReaderOptions())

proc tryReadMonitorDepFile*(path: string;
                            options: MonitorDepFileReaderOptions):
                            MonitorDepFileReaderResult =
  try:
    result.depFile = some(readMonitorDepFile(path, options))
  except MonitorDepFileReaderError as err:
    result.depFile = none(MonitorDepFile)
    result.diagnostics.add MonitorDiagnostic(level: mdlError, message: err.msg)

iterator streamMonitorDepFile*(path: string;
                               options: MonitorDepFileReaderOptions):
                               FsSnoopStreamItem =
  let dep = readMonitorDepFile(path, options)
  for record in dep.records:
    case record.kind
    of mrProcessStart:
      yield FsSnoopStreamItem(kind: fsiProcessStarted, record: record)
    of mrProcessExec, mrProcessSpawn:
      yield FsSnoopStreamItem(kind: fsiObservation, record: record)
    of mrEventLoss:
      yield FsSnoopStreamItem(kind: fsiEventLoss, record: record)
    else:
      if record.observationKind == moEventLoss:
        yield FsSnoopStreamItem(kind: fsiEventLoss, record: record)
      else:
        yield FsSnoopStreamItem(kind: fsiObservation, record: record)
  yield FsSnoopStreamItem(kind: fsiSummary, summary: dep.summary)

iterator streamMonitorDepFile*(path: string): FsSnoopStreamItem =
  for item in streamMonitorDepFile(path, defaultMonitorDepFileReaderOptions()):
    yield item

iterator streamMonitorDepFileRecords*(path: string;
                                      options: MonitorDepFileReaderOptions):
                                      MonitorRecord =
  ## Decode a depfile ONE record per frame, yielding each without ever building
  ## the full `seq[MonitorRecord]`.
  ##
  ## This is the memory-frugal read for a consumer that folds each record into a
  ## reduction (path sets + completeness) and keeps nothing else. A large
  ## provider depfile touches many source/toolchain files, and
  ## `readMonitorDepFile` (and `streamMonitorDepFile`, which is built on it)
  ## retains every decoded record — each with its own `path`/`detail` strings —
  ## at once. This walks the frames and hands the caller one record at a time, so
  ## only the raw file bytes plus a single record are live.
  ##
  ## Validation is identical to `readMonitorDepFile` — magic, version,
  ## count/length, trailer magic, record-count agreement, body checksum, and
  ## canonical (1..N) sequence order — and is performed up front (checksum,
  ## counts) and per frame (sequence order, frame bounds). The ONLY difference
  ## from the materializing readers is that the records are not accumulated. A
  ## consumer that breaks early skips the terminal `decoded == headerCount`
  ## agreement check, exactly as with any partial iteration.
  if not fileExists(extendedPath(path)):
    raiseMonitorDepFileReaderError(mrMissingFile, "RMDF file does not exist: " & path)
  let bytes = readFile(extendedPath(path)).toBytes()
  if bytes.len < 44:
    raiseMonitorDepFileReaderError(mrTruncated, "RMDF file is too short")
  if fromBytes(bytes.toOpenArray(0, 3)) != RmdfMagic:
    raiseMonitorDepFileReaderError(mrBadMagic, "unknown RMDF magic")
  var pos = 4
  let version = readU16Le(bytes, pos)
  if version != RmdfVersion:
    raiseMonitorDepFileReaderError(mrUnsupportedVersion, "unsupported RMDF version")
  discard readU16Le(bytes, pos)
  let headerCount = readU64Le(bytes, pos)
  let bodyLen = int(readU64Le(bytes, pos))
  if headerCount > options.maxObservationCount:
    raiseMonitorDepFileReaderError(mrRecordLimitExceeded,
      "RMDF record count exceeds configured limit")
  if pos + bodyLen + 20 != bytes.len:
    raiseMonitorDepFileReaderError(mrTruncated,
      "RMDF body length/trailer mismatch")
  let bodyStart = pos
  let bodyEnd = bodyStart + bodyLen
  var tpos = bodyEnd
  if fromBytes(bytes.toOpenArray(tpos, tpos + 3)) != RmdfTrailerMagic:
    raiseMonitorDepFileReaderError(mrTruncated, "missing RMDF trailer")
  tpos += 4
  let trailerCount = readU64Le(bytes, tpos)
  let trailerChecksum = readU64Le(bytes, tpos)
  if trailerCount != headerCount:
    raiseMonitorDepFileReaderError(mrSemanticValidationFailed,
      "RMDF record count mismatch")
  if options.requireTrailerChecksum:
    let bodyChecksum =
      if bodyLen == 0: checksum(newSeq[byte]())
      else: checksum(bytes.toOpenArray(bodyStart, bodyEnd - 1))
    if trailerChecksum != bodyChecksum:
      raiseMonitorDepFileReaderError(mrChecksumMismatch, "RMDF checksum mismatch")
  var framePos = bodyStart
  var expectedSeq = 1'u64
  var decoded = 0'u64
  while framePos < bodyEnd:
    var payloadPos = framePos
    let length = int(readU32Le(bytes, payloadPos))
    if length <= 0 or payloadPos + length > bodyEnd:
      raiseMonitorDepFileReaderError(mrTruncated, "truncated RMDF record frame")
    let record = decodeRecordPayload(
      bytes.toOpenArray(payloadPos, payloadPos + length - 1))
    if record.seq != expectedSeq:
      raiseMonitorDepFileReaderError(mrRecordOrderInvalid,
        "RMDF record sequence is not canonical")
    inc expectedSeq
    inc decoded
    yield record
    framePos = payloadPos + length
  if decoded != headerCount:
    raiseMonitorDepFileReaderError(mrSemanticValidationFailed,
      "RMDF frame count mismatch")

iterator streamMonitorDepFileRecords*(path: string): MonitorRecord =
  for record in streamMonitorDepFileRecords(path,
      defaultMonitorDepFileReaderOptions()):
    yield record
