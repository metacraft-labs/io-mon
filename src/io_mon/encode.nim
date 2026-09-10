## The pure `.iomon` file codec: record/frame encoding + decoding, canonical
## ordering, summarisation, and the depfile envelope writer.
##
## This module is TRANSPORT-FREE: it touches only `MonitorRecord` /
## `MonitorDepFile` / `MonitorSummary` and the low-level LE codec. It does NOT
## import the shim capture runtime (`writer`), the process driver (`fs_snoop`),
## or the shared-memory dependency transport (`shm_gset` / `dep_queue`), so the
## format cluster (types/codec/encode/reader/render) can be consumed without
## dragging in any shared-memory machinery.

import std/[algorithm, sets, strutils]
from io_mon/paths import extendedPath

import io_mon/codec
import io_mon/types
import io_mon/capabilities

const
  CanonicalFileKind = 1'u16
  FnvOffset = 14695981039346656037'u64
  FnvPrime = 1099511628211'u64

proc checksumUpdate(seed: uint64; bytes: openArray[byte]): uint64 =
  result = seed
  for b in bytes:
    result = result xor uint64(b)
    result = result * FnvPrime

proc checksum*(bytes: openArray[byte]): uint64 =
  checksumUpdate(FnvOffset, bytes)

proc writeBytes(outp: var File; bytes: seq[byte]) =
  if bytes.len == 0:
    return
  let written = outp.writeBuffer(unsafeAddr bytes[0], bytes.len)
  if written != bytes.len:
    raiseEnvelopeError(eeMalformed, "short write to iomon depfile")

proc writeI64Le(outp: var seq[byte]; value: int64) =
  outp.writeU64Le(cast[uint64](value))

proc readI64Le(bytes: openArray[byte]; pos: var int): int64 =
  cast[int64](readU64Le(bytes, pos))

proc encodeRecordPayload*(record: MonitorRecord): seq[byte] =
  result = @[]
  result.writeU16Le(uint16(ord(record.kind)))
  result.writeU16Le(uint16(ord(record.observationKind)))
  result.writeU64Le(record.seq)
  result.writeU64Le(record.osPid)
  result.writeU64Le(record.parentOsPid)
  result.writeU64Le(record.threadId)
  result.writeU64Le(record.childOsPid)
  result.writeI64Le(record.result)
  result.writeU32Le(record.flags)
  result.writeU32Le(uint32(ord(record.probeResult)))
  result.writeString(record.path)
  result.writeString(record.detail)

proc decodeRecordPayload*(payload: openArray[byte]): MonitorRecord =
  var pos = 0
  let kindOrd = readU16Le(payload, pos)
  let obsOrd = readU16Le(payload, pos)
  if kindOrd < uint16(ord(low(MonitorRecordKind))) or
      kindOrd > uint16(ord(high(MonitorRecordKind))):
    raiseEnvelopeError(eeUnknownType, "unknown iomon record kind")
  if obsOrd < uint16(ord(low(MonitorObservationKind))) or
      obsOrd > uint16(ord(high(MonitorObservationKind))):
    raiseEnvelopeError(eeUnknownType, "unknown iomon observation kind")

  result.kind = MonitorRecordKind(kindOrd.int)
  result.observationKind = MonitorObservationKind(obsOrd.int)
  result.seq = readU64Le(payload, pos)
  result.osPid = readU64Le(payload, pos)
  result.parentOsPid = readU64Le(payload, pos)
  result.threadId = readU64Le(payload, pos)
  result.childOsPid = readU64Le(payload, pos)
  result.result = readI64Le(payload, pos)
  result.flags = readU32Le(payload, pos)
  let probeOrd = readU32Le(payload, pos)
  if probeOrd > uint32(ord(high(ProbeResult))):
    raiseEnvelopeError(eeUnknownType, "unknown iomon probe result")
  result.probeResult = ProbeResult(probeOrd.int)
  result.path = readString(payload, pos)
  result.detail = readString(payload, pos)
  if pos != payload.len:
    raiseEnvelopeError(eeMalformed, "iomon record has trailing bytes")

proc encodeFrame*(record: MonitorRecord): seq[byte] =
  let payload = encodeRecordPayload(record)
  result = @[]
  result.writeU32Le(uint32(payload.len))
  result.add(payload)

proc decodeFrames*(bytes: openArray[byte]): seq[MonitorRecord] =
  var pos = 0
  while pos < bytes.len:
    let length = int(readU32Le(bytes, pos))
    if length <= 0 or pos + length > bytes.len:
      raiseEnvelopeError(eeMalformed, "truncated iomon record frame")
    result.add decodeRecordPayload(bytes.toOpenArray(pos, pos + length - 1))
    pos += length

proc decodeFramesTolerant*(bytes: openArray[byte]; cleanEof: var bool):
    seq[MonitorRecord] =
  ## DSL-port M9.R.15c.1 — like ``decodeFrames`` but stops at the first
  ## truncated trailing frame instead of raising. This is the crash-
  ## recovery path: a SIGKILL between ``writeBuffer`` and ``flushFile``
  ## may leave the fragment with a partial length-prefix or partial
  ## payload at the tail. Every complete frame ahead of it remains
  ## byte-identical to what the producer wrote.
  ##
  ## ``cleanEof`` reports whether decoding consumed the WHOLE buffer with
  ## no leftover bytes. ``false`` means the fragment ended with bytes that
  ## could not be decoded as a complete frame — a partial iomon write (e.g.
  ## a SIGKILL'd shim) or outright corruption. Per Monitor-Hook-Shim.md
  ## §"Failure Semantics" ("partial iomon writes MUST fail reader
  ## validation"; "shim crash MUST reject cache publication"), the caller
  ## MUST treat ``cleanEof == false`` as monitor-evidence incompleteness so
  ## the action fails closed and is not published to the cache. We still
  ## recover every complete leading frame so diagnostics/streaming can show
  ## what was captured before the truncation point.
  cleanEof = true
  var pos = 0
  while pos < bytes.len:
    if pos + 4 > bytes.len:
      # A trailing run of < 4 bytes can never form a frame's length
      # prefix: the producer was cut mid-write. Surface as not-clean.
      cleanEof = false
      break
    var lengthCursor = pos
    let length = int(readU32Le(bytes, lengthCursor))
    if length <= 0 or lengthCursor + length > bytes.len:
      # Either a non-positive/garbage length (corruption) or a length
      # prefix promising more payload bytes than remain (truncated tail).
      # Both leave the fragment not cleanly consumed.
      cleanEof = false
      break
    try:
      result.add decodeRecordPayload(
        bytes.toOpenArray(lengthCursor, lengthCursor + length - 1))
    except EnvelopeError:
      # A length that points at a payload the codec rejects is corruption,
      # not a clean tail truncation. Stop and flag incompleteness.
      cleanEof = false
      break
    pos = lengthCursor + length

proc decodeFramesTolerant*(bytes: openArray[byte]): seq[MonitorRecord] =
  ## Backwards-compatible overload that discards the clean-EOF signal.
  ## Prefer the ``cleanEof``-aware overload on any path that decides cache
  ## publication; this one is for callers that only want the recovered
  ## records (e.g. record-level parity assertions).
  var cleanEof: bool
  decodeFramesTolerant(bytes, cleanEof)

proc canonicalOrder(a, b: MonitorRecord): int =
  result = cmp(a.osPid, b.osPid)
  if result != 0: return
  result = cmp(a.threadId, b.threadId)
  if result != 0: return
  result = cmp(a.seq, b.seq)
  if result != 0: return
  result = cmp(ord(a.kind), ord(b.kind))
  if result != 0: return
  result = cmp(a.path, b.path)

proc summarizeRecords*(records: openArray[MonitorRecord]): MonitorSummary =
  result.recordCount = uint64(records.len)
  # M9.R.68.4 — drive-by fix: use a HashSet instead of `seq.find`. The
  # previous O(N^2) scan (`processPids.find(...) < 0`) is O(N * P) where
  # N is total records and P is unique-pid count. For a monitored
  # reproos-image build (7.7 GB depfile ≈ ~10⁸ records over ~10⁴
  # unique pids) this is ~10¹² comparisons and effectively hangs the
  # merge (measured 22 GB RSS + 30+ min CPU-bound with zero I/O
  # progress on the m9r68 phase D rebuild). HashSet incl+contains is
  # O(1) amortised so the whole summarise pass drops to O(N).
  var processPids = initHashSet[uint64]()
  for record in records:
    if record.osPid != 0:
      processPids.incl record.osPid
    if record.kind == mrEventLoss or record.observationKind == moEventLoss:
      inc result.eventLossCount
    else:
      inc result.observationCount
  result.processCount = uint64(processPids.len)

proc observedInterestFromRecords(records: openArray[MonitorRecord]):
    tuple[stated: bool, tokens: string, categories: set[EventCategory]] =
  ## DA-1j — read the capture-scope stamp off the backend-profile record.
  ##
  ## The depfile envelope carries ONLY records: `depFileFromOwnedRecords`
  ## reconstructs `profile`, `capabilityGaps`, `requiredFeatures`,
  ## `completeness` and `summary` from them. So the scope rides on a record too,
  ## as an `interest=` token in the `;`-separated profile detail. That is why
  ## this needed no envelope version bump and breaks no wire compatibility:
  ## `profileFromRecords` already ignores unknown keys (`else: discard`), and
  ## `parseInterestTokens` already ignores unknown tokens, so an older reader
  ## skips the stamp and a newer reader tolerates a category it does not know.
  ##
  ## RETURNS `stated` SEPARATELY FROM THE PARSED SET, and that separation is the
  ## whole point. "No stamp at all" and "a stamp naming only categories this
  ## build has never heard of" both parse to `{}`, and they mean opposite things:
  ## the first is an old file that must read as full scope, the second is a
  ## NARROWED capture from a newer io-mon that must not. Collapsing them let
  ## `interest=gpu` be accepted by a full-scope consumer — the same false
  ## complete this stamp exists to end, pointing forward in time instead of
  ## backward. `tokens` carries the raw value so the unnamable scope can be
  ## REPORTED rather than merely detected.
  ##
  ## An `interest=` key with an EMPTY value counts as stated. `parseInterestTokens`
  ## widens an empty string to `FullInterest` for the env channel (an absent
  ## `REPRO_MONITOR_INTEREST` means "capture everything"), but here the key's
  ## presence already proves the producer meant to say something, so the empty
  ## value is an unevaluable statement rather than a claim of full scope.
  for record in records:
    if record.kind == mrBackendProfile:
      for part in record.detail.split(';'):
        let pair = part.split("=", 1)
        if pair.len == 2 and pair[0] == "interest":
          if pair[1].strip().len == 0:
            return (true, pair[1], {})
          return (true, pair[1], parseInterestTokens(pair[1]))
  (false, "", {})

proc depFileFromOwnedRecords*(records: sink seq[MonitorRecord]): MonitorDepFile =
  let summary = summarizeRecords(records)
  let scope = observedInterestFromRecords(records)
  # The required-set is NOT empty, and that is the whole point. Deriving the
  # profile with `{}` meant no declared capability gap could ever mark itself
  # `required`, so none of them could ever clear `evidenceComplete` — the
  # architecture doc's "every uncertainty downgrades to mcIncomplete" was
  # stated but not wired. `InputEvidenceCapabilities` is the set whose absence
  # means an input channel is unobserved, so a backend missing one of them
  # cannot report `mcComplete` regardless of what the consumer asked for. A
  # consumer wanting a WIDER bar still calls `evaluateMonitorEvidence` with its
  # own set; this is the floor, not a ceiling.
  var profile = profileFromRecords(records, InputEvidenceCapabilities)
  if summary.eventLossCount != 0:
    profile.evidenceComplete = false
  result = MonitorDepFile(
    version: IomonVersion,
    producerVersion: IoMonDepfileProducer,
    backendFamily: profile.backendFamily,
    requiredFeatures: profile.requiredCapabilities,
    completeness: if profile.evidenceComplete and summary.eventLossCount == 0:
        mcComplete
      else:
        mcIncomplete,
    profile: profile,
    capabilityGaps: profile.gaps,
    summary: summary,
    observedInterest: scope.categories,
    observedInterestStated: scope.stated,
    observedInterestTokens: scope.tokens)
  result.records = move(records)

proc depFileFromRecords*(records: openArray[MonitorRecord]): MonitorDepFile =
  var owned = @records
  depFileFromOwnedRecords(move(owned))

proc encodeCanonical*(records: openArray[MonitorRecord]): seq[byte] =
  var ordered = @records
  ordered.sort(canonicalOrder)
  for i in 0 ..< ordered.len:
    ordered[i].seq = uint64(i + 1)

  var body: seq[byte] = @[]
  for record in ordered:
    body.add encodeFrame(record)

  result = @[]
  result.add IomonMagic.toBytes()
  result.writeU16Le(IomonVersion)
  result.writeU16Le(CanonicalFileKind)
  result.writeU64Le(uint64(ordered.len))
  result.writeU64Le(uint64(body.len))
  result.add body
  result.add IomonTrailerMagic.toBytes()
  result.writeU64Le(uint64(ordered.len))
  result.writeU64Le(checksum(body))

proc writeCanonicalInPlace*(outputPath: string; records: var seq[MonitorRecord]) =
  ## Write the canonical iomon envelope without materializing the full body/file.
  ##
  ## Large monitored builds can produce enough frames that `encodeCanonical`'s
  ## ordered copy + body buffer + final file buffer dominate the monitor process'
  ## RSS. The merge path already owns its record seq, so sort it in place, compute
  ## body length/checksum in one frame-at-a-time pass, then stream the envelope to
  ## disk in a second pass.
  records.sort(canonicalOrder)
  for i in 0 ..< records.len:
    records[i].seq = uint64(i + 1)

  var bodyLen = 0'u64
  var bodyChecksum = FnvOffset
  for record in records:
    let frame = encodeFrame(record)
    bodyLen += uint64(frame.len)
    bodyChecksum = checksumUpdate(bodyChecksum, frame)

  var outp: File
  if not open(outp, extendedPath(outputPath), fmWrite):
    raiseEnvelopeError(eeMalformed, "cannot open iomon depfile for write: " &
      outputPath)
  try:
    var header: seq[byte] = @[]
    header.add IomonMagic.toBytes()
    header.writeU16Le(IomonVersion)
    header.writeU16Le(CanonicalFileKind)
    header.writeU64Le(uint64(records.len))
    header.writeU64Le(bodyLen)
    outp.writeBytes(header)

    for record in records:
      outp.writeBytes(encodeFrame(record))

    var trailer: seq[byte] = @[]
    trailer.add IomonTrailerMagic.toBytes()
    trailer.writeU64Le(uint64(records.len))
    trailer.writeU64Le(bodyChecksum)
    outp.writeBytes(trailer)
  finally:
    close(outp)

proc writeCanonical*(outputPath: string; records: openArray[MonitorRecord]) =
  var owned = @records
  writeCanonicalInPlace(outputPath, owned)
