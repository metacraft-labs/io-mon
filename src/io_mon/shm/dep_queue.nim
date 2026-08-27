## Shared-memory dependency-record codec (`MonitorRecord` ↔ opaque element bytes).
##
## io-mon-Lossless-Event-Capture M3 part 2b — the superseded DEP-SHM MPSC ring
## transport (`DepQueue`, `createDepQueueAtPath`/`attachDepQueueAtPath`,
## `tryPushRecord`/`tryDrainOne`, the drop-on-full segment) has been REMOVED: the
## M1-winning `nim-shm-gset` SET transport is the sole Linux dependency channel and
## nothing on the retained set path used the ring any longer. What remains here —
## and is RETAINED — is ONLY the dep-specific `MonitorRecord` **codec** the SET
## transport depends on: it turns a `MonitorRecord` into the opaque element bytes
## the `nim-shm-gset` producer publishes (`encodeDepRecordIdentity`) and back
## (`decodeDepRecord`), plus the real-`seq` variant (`encodeDepRecord`).
##
## The codec is domain-only (no ring, no segment, no atomics): a fixed header +
## varint-length path/detail encoding of the SAME `MonitorRecord` the iomon frames
## carry. The real-sequence codec preserves every field. The SET identity codec
## preserves every field for process/completeness records, while path-scoped file
## observations discard process-local coordinates that do not change the observed
## dependency. No serialization dependency (pure `io_mon/types`), so the
## LD_PRELOAD shim that imports this module stays serialization-free.

import io_mon/types

# ---------------------------------------------------------------------------
# Record codec.
# ---------------------------------------------------------------------------

const
  DepFixedHeaderLen* = 2 + 2 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4
    ## kind(u16) obsKind(u16) seq(u64) osPid(u64) parentOsPid(u64)
    ## threadId(u64) childOsPid(u64) result(i64) flags(u32) probeResult(u32)

proc putVarint(buf: var openArray[byte]; pos: var int; value: uint64): bool =
  ## LEB128 unsigned varint. Returns false if it would overrun `buf`.
  var v = value
  while true:
    if pos >= buf.len:
      return false
    var b = byte(v and 0x7F)
    v = v shr 7
    if v != 0:
      b = b or 0x80'u8
    buf[pos] = b
    inc pos
    if v == 0:
      break
  true

proc getVarint(buf: openArray[byte]; pos: var int; value: var uint64): bool =
  var shift = 0
  var result0: uint64 = 0
  while true:
    if pos >= buf.len or shift >= 64:
      return false
    let b = buf[pos]
    inc pos
    result0 = result0 or (uint64(b and 0x7F) shl shift)
    if (b and 0x80) == 0:
      break
    shift += 7
  value = result0
  true

proc putU16(buf: var openArray[byte]; pos: var int; v: uint16) =
  buf[pos] = byte(v and 0xFF); buf[pos + 1] = byte((v shr 8) and 0xFF)
  pos += 2

proc putU32(buf: var openArray[byte]; pos: var int; v: uint32) =
  buf[pos] = byte(v and 0xFF); buf[pos + 1] = byte((v shr 8) and 0xFF)
  buf[pos + 2] = byte((v shr 16) and 0xFF); buf[pos + 3] = byte((v shr 24) and 0xFF)
  pos += 4

proc putU64(buf: var openArray[byte]; pos: var int; v: uint64) =
  for i in 0 ..< 8:
    buf[pos + i] = byte((v shr (8 * i)) and 0xFF)
  pos += 8

proc getU16(buf: openArray[byte]; pos: var int): uint16 =
  result = uint16(buf[pos]) or (uint16(buf[pos + 1]) shl 8)
  pos += 2

proc getU32(buf: openArray[byte]; pos: var int): uint32 =
  result = uint32(buf[pos]) or (uint32(buf[pos + 1]) shl 8) or
    (uint32(buf[pos + 2]) shl 16) or (uint32(buf[pos + 3]) shl 24)
  pos += 4

proc getU64(buf: openArray[byte]; pos: var int): uint64 =
  result = 0
  for i in 0 ..< 8:
    result = result or (uint64(buf[pos + i]) shl (8 * i))
  pos += 8

proc encodeDepRecordWithSeq(record: MonitorRecord; buf: var openArray[byte];
                            seqValue: uint64;
                            pathScopedIdentity = false): int =
  ## Shared codec body used by `encodeDepRecord` (carries the record's real
  ## `seq`) and `encodeDepRecordIdentity` (forces `seq = 0`). NO heap allocation:
  ## the caller supplies a stack buffer, keeping this fork/orc-safe on the shim
  ## hot path.
  var pos = 0
  let need = DepFixedHeaderLen
  if buf.len < need:
    return -1
  let normalizePathObservation = pathScopedIdentity and
    record.kind in {mrFileOpen, mrFileRead, mrPathProbe}
  var encodedResult = record.result
  var encodedFlags = record.flags
  if normalizePathObservation:
    case record.kind
    of mrFileRead:
      # Byte count and descriptor number do not alter the content dependency.
      encodedResult = 0
      encodedFlags = 0
    of mrFileOpen, mrPathProbe:
      # Preserve success versus failure; successful descriptor numbers are
      # process-local. Open flags and ProbeResult remain part of the key.
      encodedResult = if record.result < 0: -1 else: 0
    else:
      discard
  putU16(buf, pos, uint16(ord(record.kind)))
  putU16(buf, pos, uint16(ord(record.observationKind)))
  putU64(buf, pos, seqValue)
  putU64(buf, pos, if normalizePathObservation: 0'u64 else: record.osPid)
  putU64(buf, pos, if normalizePathObservation: 0'u64 else: record.parentOsPid)
  putU64(buf, pos, if normalizePathObservation: 0'u64 else: record.threadId)
  putU64(buf, pos, if normalizePathObservation: 0'u64 else: record.childOsPid)
  putU64(buf, pos, cast[uint64](encodedResult))
  putU32(buf, pos, encodedFlags)
  putU32(buf, pos, uint32(ord(record.probeResult)))
  if not putVarint(buf, pos, uint64(record.path.len)):
    return -1
  if record.path.len > 0:
    if pos + record.path.len > buf.len:
      return -1
    for i in 0 ..< record.path.len:
      buf[pos + i] = byte(record.path[i])
    pos += record.path.len
  if not putVarint(buf, pos, uint64(record.detail.len)):
    return -1
  if record.detail.len > 0:
    if pos + record.detail.len > buf.len:
      return -1
    for i in 0 ..< record.detail.len:
      buf[pos + i] = byte(record.detail[i])
    pos += record.detail.len
  pos

proc encodeDepRecord*(record: MonitorRecord; buf: var openArray[byte]): int =
  ## Encode `record` into `buf` carrying its real `seq`. Returns the byte length
  ## written, or -1 if the record does not fit. The real-`seq` variant of the
  ## codec (the SET transport uses `encodeDepRecordIdentity`, which drops `seq`);
  ## retained as the codec's stream-ordinal encoder and for round-trip tests.
  encodeDepRecordWithSeq(record, buf, record.seq)

proc encodeDepRecordIdentity*(record: MonitorRecord; buf: var openArray[byte]): int =
  ## io-mon-Lossless-Event-Capture M3 (part 2a) — the DEDUP element-key encoder for
  ## the nim-shm-gset SET transport (the M1-winning Candidate-C channel). Identical
  ## to `encodeDepRecord` except that the per-record monotonic `seq` is forced to
  ## 0 and path-scoped observations discard process-local coordinates, so the
  ## encoded bytes describe the dependency identity rather than an event ordinal.
  ##
  ## FIELD CLASSIFICATION for the set dedup key (see the milestone report). The key
  ## must (a) collapse exact-duplicate probe-storm observations — "same path
  ## re-stat'd -> one element", the real Candidate-C dedup — and (b) NEVER collapse
  ## two semantically-distinct observations (the cardinal sin — a dropped dep):
  ##
  ##   PROCESS/COMPLETENESS IDENTITY: every field except `seq` remains in the key.
  ##   `childOsPid`/`osPid`/`parentOsPid` are load-bearing for start/exec/spawn/IPC
  ##   accounting and are never normalized on those records.
  ##
  ##   PATH-SCOPED IDENTITY (`mrFileOpen`, `mrFileRead`, `mrPathProbe`): process and
  ##   thread ids are zeroed. File-read byte count/fd are zeroed. Open/probe result
  ##   is reduced to success/failure, while open flags, observation kind,
  ##   `probeResult`, path, and detail remain in the key. The caller's appended
  ##   exec-image/generation suffix also remains, so observations from distinct
  ##   executable incarnations do not collapse. This folds compiler include-search
  ##   storms across thousands of same-image workers without losing a distinct
  ##   path, access mode, existence outcome, probe outcome, or run scope.
  ##
  ##   DROPPED (excluded from the key — noise for the dependency): `seq` (this
  ##   proc's whole point: the per-record monotonic ordinal is EXACTLY what
  ##   distinguishes exact-duplicate storm EVENTS from each other; it is renumbered
  ##   densely in the canonical depfile so its value never reaches the output, so
  ##   dropping it is what ENABLES source-dedup). The part-1 8-byte incarnation
  ##   nonce is also gone (replaced by the real exec-incarnation identity the caller
  ##   appends — see `appendFragmentRecord`).
  ##
  ## `decodeDepRecord` reconstructs a `MonitorRecord` with `seq = 0` from this key
  ## (plus ignores any trailing incarnation-identity bytes the caller appends), so
  ## the consumer feeds the SAME `mergeFragments` canonicalization the file path
  ## uses. Ordering determinism (two distinct keys that tie in `canonicalOrder`
  ## because `seq` is 0) is restored by the consumer sorting the snapshot by raw
  ## element bytes before decode (see fs_snoop).
  encodeDepRecordWithSeq(record, buf, 0'u64, pathScopedIdentity = true)

proc decodeDepRecord*(buf: openArray[byte]; ok: var bool): MonitorRecord =
  ## Decode a record produced by `encodeDepRecord`. `ok` is false on any
  ## malformed / truncated buffer (the consumer then drops that slot — it can
  ## never corrupt the depfile because the file fallback still carries the
  ## record's authoritative copy on any oversize/failure path).
  ok = false
  if buf.len < DepFixedHeaderLen:
    return
  var pos = 0
  let kindOrd = getU16(buf, pos)
  let obsOrd = getU16(buf, pos)
  if kindOrd.int < ord(low(MonitorRecordKind)) or
      kindOrd.int > ord(high(MonitorRecordKind)):
    return
  if obsOrd.int < ord(low(MonitorObservationKind)) or
      obsOrd.int > ord(high(MonitorObservationKind)):
    return
  result.kind = MonitorRecordKind(kindOrd.int)
  result.observationKind = MonitorObservationKind(obsOrd.int)
  result.seq = getU64(buf, pos)
  result.osPid = getU64(buf, pos)
  result.parentOsPid = getU64(buf, pos)
  result.threadId = getU64(buf, pos)
  result.childOsPid = getU64(buf, pos)
  result.result = cast[int64](getU64(buf, pos))
  result.flags = getU32(buf, pos)
  let probeOrd = getU32(buf, pos)
  if probeOrd.int > ord(high(ProbeResult)):
    return
  result.probeResult = ProbeResult(probeOrd.int)
  var pathLen: uint64
  if not getVarint(buf, pos, pathLen):
    return
  if pos + int(pathLen) > buf.len:
    return
  if pathLen > 0:
    result.path = newString(int(pathLen))
    for i in 0 ..< int(pathLen):
      result.path[i] = char(buf[pos + i])
    pos += int(pathLen)
  var detailLen: uint64
  if not getVarint(buf, pos, detailLen):
    return
  if pos + int(detailLen) > buf.len:
    return
  if detailLen > 0:
    result.detail = newString(int(detailLen))
    for i in 0 ..< int(detailLen):
      result.detail[i] = char(buf[pos + i])
    pos += int(detailLen)
  ok = true
