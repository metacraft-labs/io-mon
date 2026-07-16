## Shared-memory MPSC dependency queue (milestone io-mon-DEP-SHM).
##
## The PRIMARY channel for communicating discovered input dependencies from the
## many monitored producer PROCESSES/THREADS to the single reprobuild engine /
## io-mon run driver (the consumer). It reuses — in shape, verbatim — the proven
## lock-free ticket-CAS MPSC ring from reprobuild's action-cache hot tier
## (`repro_shm_index/ring.nim` + `segment.nim`, Action-Cache-Per-Edge-Store.md
## §4.4): many producers CAS-bump a `tail` ticket to reserve a slot, write the
## payload, then publish via a release-store of `ready = ticket+1`; the single
## consumer spins on `ready`, reads the payload, advances `head`, and clears
## `ready`. Drop-on-full is SIGNALLED via an atomic `dropped` counter — NEVER
## silent. The segment is versioned + boot-guarded like `segment.nim` so a stale
## post-reboot region is recreated empty.
##
## The lock-free MPSC ring mechanism now lives in the extracted, shared
## `shm_queue/ring` library (metacraft-labs/nim-shm-queue, Layer 1 — the ring as
## a coordination device over BYTE BLOBS). This module keeps ONLY the
## dep-specific `MonitorRecord` codec (below) and wraps an `ShmRing`: it does NOT
## re-implement the ticket-CAS reservation, the release/acquire publish/drain,
## the drop-on-full signal, or the boot-guarded segment header — those are
## `shm_queue`'s single copy, consumed identically by reprobuild's action-cache
## submission ring. Layer 1 has NO serialization dependency (pure std/posix), so
## the LD_PRELOAD shim that imports this module stays serialization-free.
##
## Platform: Linux + macOS (POSIX mmap MAP_SHARED). On every other platform this
## module still compiles but `depQueueSupported` is false and every op is a
## no-op / unavailable, so the shim + engine fall back to the file-based RMDF
## fragment path (the correctness FALLBACK). macOS keeps files for now too (its
## producer arm is future work); the datastructures here compile on macOS so the
## pure unit test runs there.

import io_mon/types

const depQueueSupported* = defined(linux) or defined(macosx)

# ---------------------------------------------------------------------------
# Record codec: a fixed header + varint-length path/detail encoding of the SAME
# `MonitorRecord` the RMDF frames carry. We encode EVERY field the file path
# preserves (not only the spec's illustrative subset) so a record that travels
# the ring is byte-for-byte the same record as one that travels the file — the
# HARD byte-identical-final-depfile invariant (DEP-SHM-3) depends on it, because
# `mergeFragments` folds `detail` (run token / read-tail markers), `childOsPid`,
# `result` and `flags` into the canonical output.
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

proc encodeDepRecord*(record: MonitorRecord; buf: var openArray[byte]): int =
  ## Encode `record` into `buf`. Returns the byte length written, or -1 if the
  ## record does not fit (the caller then falls back to the file path — the
  ## queue is a fast path, not the only path). NO heap allocation: the caller
  ## supplies a stack buffer, keeping this fork/orc-safe on the shim hot path.
  var pos = 0
  let need = DepFixedHeaderLen
  if buf.len < need:
    return -1
  putU16(buf, pos, uint16(ord(record.kind)))
  putU16(buf, pos, uint16(ord(record.observationKind)))
  putU64(buf, pos, record.seq)
  putU64(buf, pos, record.osPid)
  putU64(buf, pos, record.parentOsPid)
  putU64(buf, pos, record.threadId)
  putU64(buf, pos, record.childOsPid)
  putU64(buf, pos, cast[uint64](record.result))
  putU32(buf, pos, record.flags)
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

# ---------------------------------------------------------------------------
# The segment + ring themselves (POSIX only).
# ---------------------------------------------------------------------------

when depQueueSupported:
  import std/os
  import shm_queue/ring as shmring

  const
    DepRingCap* = 2048                        ## MPSC ring capacity (power of two).
    DepSlotRecCap* = 4000
      ## Fixed slot payload capacity, sized for the p99 dependency path + detail.
      ## A record whose encoding exceeds this falls back to the file path.

  static:
    doAssert (DepRingCap and (DepRingCap - 1)) == 0

  type
    DepQueue* = object
      ## An attached view of one edge's dep-queue segment. `available` is false
      ## on a non-POSIX host or on any attach/create failure — the caller then
      ## uses the file fallback. The lock-free ring itself is an `shm_queue`
      ## `ShmRing` (Layer 1); this wrapper adds ONLY the `MonitorRecord` codec.
      available*: bool
      isConsumer: bool
      ring: shmring.ShmRing[shmring.opDropSignalled]
        ## Pinned to the drop-on-full policy: the dependency queue keeps its
        ## historical `opDropSignalled` behaviour here (the lossless
        ## `opBlockProducer` transport switch is io-mon-Lossless-Event-Capture
        ## M3). `nim-shm-queue` made `ShmRing` generic over `OverflowPolicy`.
      path*: string

  proc depQueuePath*(dir, edgeKey: string): string =
    dir / ("repro-dep-queue." & edgeKey)

  proc createDepQueueAtPath*(path: string): DepQueue =
    ## CONSUMER side: create + map a fresh, zero-filled ring segment at `path`.
    ## The engine calls this BEFORE launching the edge's process tree and passes
    ## `path` to producers via `REPRO_MONITOR_DEP_SHM`. The versioned, boot-
    ## guarded segment + the atomic-rename fresh-init discipline are provided by
    ## `shm_queue` (createRing).
    result.available = false
    result.isConsumer = true
    result.path = path
    result.ring = shmring.createRing(path, DepRingCap, DepSlotRecCap,
      shmring.bootId())
    result.available = result.ring.isValid

  proc createDepQueue*(dir, edgeKey: string): DepQueue =
    ## Convenience wrapper: create the segment at `depQueuePath(dir, edgeKey)`.
    createDepQueueAtPath(depQueuePath(dir, edgeKey))

  proc attachDepQueueAtPath*(path: string): DepQueue =
    ## PRODUCER side: attach to the consumer-created segment at `path`. Returns
    ## an unavailable queue (so the caller falls back to files) when the file is
    ## missing / wrong size / stale (wrong boot or version). Never CREATES the
    ## region — a producer must not race the consumer's fresh init. The
    ## magic/version/boot guard is `shm_queue`'s (attachRing).
    result.available = false
    result.isConsumer = false
    result.path = path
    result.ring = shmring.attachRing(path)
    result.available = result.ring.isValid

  proc attachDepQueue*(dir, edgeKey: string): DepQueue =
    ## Convenience wrapper: attach the segment at `depQueuePath(dir, edgeKey)`.
    attachDepQueueAtPath(depQueuePath(dir, edgeKey))

  proc detach*(q: var DepQueue) =
    ## Unmap + close. A default-constructed DepQueue holds an invalid ring, so
    ## `detach` on a never-attached queue is a no-op (shm_queue guards the unmap).
    shmring.detach(q.ring)
    q.available = false

  type
    DepPushStatus* = enum
      dpsPushed        ## reserved + published
      dpsDropped       ## ring full: SIGNALLED drop (the `dropped` counter bumped)
      dpsOversized     ## encoded record > DepSlotRecCap: not enqueueable
      dpsUnavailable   ## queue not attached (caller uses the file fallback)

  proc tryPushRecord*(q: var DepQueue; record: MonitorRecord): DepPushStatus =
    ## Multi-producer append. Encodes `record` into a stack buffer (NO heap alloc
    ## on the hot path — fork/orc-safe), then hands the encoded bytes to the
    ## shm_queue ring's lock-free `tryPush` (CAS ticket reserve + release-store
    ## publish). Bounded: a full ring is a SIGNALLED drop (`dpsDropped`); an
    ## encoding that does not fit the slot is `dpsOversized`. The caller MUST fall
    ## back to the file path on any status other than `dpsPushed`.
    if not q.available:
      return dpsUnavailable
    var recBuf: array[DepSlotRecCap, byte]
    let recLen = encodeDepRecord(record, recBuf)
    if recLen < 0 or recLen > DepSlotRecCap:
      return dpsOversized
    # NB: `prConsumerGone` is unreachable on this drop-on-full ring (the default
    # `opDropSignalled` policy never blocks/waits, so it never reports a gone
    # consumer); it is mapped to `dpsDropped` only to keep the `case` exhaustive
    # after `nim-shm-queue` added the `opBlockProducer` policy status. The
    # lossless block-producer path is io-mon-Lossless-Event-Capture M3.
    case q.ring.tryPush(recBuf.toOpenArray(0, recLen - 1))
    of prPushed: dpsPushed
    of prDropped: dpsDropped
    of prOversize: dpsOversized
    of prConsumerGone: dpsDropped

  proc tryDrainOne*(q: var DepQueue; outRec: var MonitorRecord): bool =
    ## SINGLE-consumer non-blocking drain of the next ready ticket. Returns
    ## false when the head slot is not yet published (empty / producer
    ## mid-write) OR when a slot decodes malformed (skipped — its authoritative
    ## copy is on the file fallback). On true, `outRec` holds the decoded record.
    ## The ring coordination (head/tail/ready) is shm_queue's; this adds the
    ## `decodeDepRecord` step. A drained-but-malformed slot still returns false
    ## but the slot HAS been retired (head advanced) so the consumer never wedges.
    if not q.available:
      return false
    var recBuf: array[DepSlotRecCap, byte]
    var recLen = 0
    if q.ring.tryDrainOne(recBuf, recLen) != drGot:
      return false
    var ok = false
    if recLen > 0:
      outRec = decodeDepRecord(recBuf.toOpenArray(0, recLen - 1), ok)
    ok

  proc droppedCount*(q: DepQueue): uint64 {.inline.} =
    ## Number of SIGNALLED ring-full drops. The consumer surfaces this as a loud
    ## diagnostic (DEP-SHM-4) — the dropped records still travel the file path.
    if not q.available: return 0
    q.ring.droppedCount()

  proc pendingCount*(q: DepQueue): uint64 {.inline.} =
    if not q.available: return 0
    q.ring.pendingCount()

else:
  # Non-POSIX: compiles but reports unavailable so callers use the file path.
  type
    DepQueue* = object
      available*: bool
      path*: string
    DepPushStatus* = enum
      dpsPushed
      dpsDropped
      dpsOversized
      dpsUnavailable

  proc depQueuePath*(dir, edgeKey: string): string =
    dir & "/repro-dep-queue." & edgeKey
  proc createDepQueueAtPath*(path: string): DepQueue =
    DepQueue(available: false, path: path)
  proc attachDepQueueAtPath*(path: string): DepQueue =
    DepQueue(available: false, path: path)
  proc createDepQueue*(dir, edgeKey: string): DepQueue =
    DepQueue(available: false, path: depQueuePath(dir, edgeKey))
  proc attachDepQueue*(dir, edgeKey: string): DepQueue =
    DepQueue(available: false, path: depQueuePath(dir, edgeKey))
  proc detach*(q: var DepQueue) = discard
  proc tryPushRecord*(q: var DepQueue; record: MonitorRecord): DepPushStatus =
    dpsUnavailable
  proc tryDrainOne*(q: var DepQueue; outRec: var MonitorRecord): bool = false
  proc droppedCount*(q: DepQueue): uint64 = 0
  proc pendingCount*(q: DepQueue): uint64 = 0
