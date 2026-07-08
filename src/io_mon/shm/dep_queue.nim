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
## This module deliberately does NOT depend on reprobuild's `repro_shm_index`
## library: the dependency direction is `reprobuild → io-mon` (the io-mon shim
## build only has `--path:src` + nim-stackable-hooks), so the reused ring
## PRIMITIVES live here, in io-mon, and reprobuild's consumer imports THIS
## module. The reservation/publication protocol, the drop signal, the release/
## acquire fences and the boot-guarded segment header are the same shape as
## `repro_shm_index`; only the record payload (a full `MonitorRecord` codec,
## below) is dep-specific.
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
  import std/[os, posix, times]

  type
    DepBase = ptr UncheckedArray[byte]

  const
    DepMagic = 0x51455044_5052'u64          ## "RPDPEQ"-derived magic tag.
    DepFormatVersion = 1'u32
    DepRingCap* = 2048                        ## MPSC ring capacity (power of two).
    DepSlotRecCap* = 4000
      ## Fixed slot payload capacity, sized for the p99 dependency path + detail.
      ## A record whose encoding exceeds this falls back to the file path.

  static:
    doAssert (DepRingCap and (DepRingCap - 1)) == 0

  # --- fixed byte layout (offset-only, mapping-base-independent) ------------
  const
    DepOffMagic          = 0                          # u64
    DepOffFormatVersion  = DepOffMagic + 8            # u32
    DepOffFlags          = DepOffFormatVersion + 4    # u32
    DepOffCreatorBootId  = DepOffFlags + 4            # u64
    DepOffConsumerPid    = DepOffCreatorBootId + 8    # u64
    DepOffHeartbeat      = DepOffConsumerPid + 8      # u64
    DepOffHead           = DepOffHeartbeat + 8        # u64 (consumer-owned)
    DepOffTail           = DepOffHead + 8             # u64 (producers CAS)
    DepOffDropped        = DepOffTail + 8             # u64 (drop-on-full count)
    DepSlotsBase         = ((DepOffDropped + 8) + 7) and not 7

    DepSlotOffReady      = 0                          # u64 publication ticket
    DepSlotOffRecLen     = DepSlotOffReady + 8        # u32
    DepSlotOffPad        = DepSlotOffRecLen + 4       # u32 pad
    DepSlotOffRec        = DepSlotOffPad + 4          # byte[DepSlotRecCap]
    DepSlotStride        = ((DepSlotOffRec + DepSlotRecCap) + 7) and not 7

    DepRegionSize = (((DepSlotsBase + DepRingCap * DepSlotStride) + 4095) and
      not 4095)

  type
    DepQueue* = object
      ## An attached view of one edge's dep-queue segment. `available` is false
      ## on a non-POSIX host or on any attach/create failure — the caller then
      ## uses the file fallback.
      available*: bool
      isConsumer: bool
      base: DepBase
      fd: cint
      path*: string

  # --- offset-addressed atomics (C11/GCC builtins, no process-shared mutex) --
  template atField[T](base: DepBase; offset: int): ptr T =
    cast[ptr T](addr base[offset])

  proc loadU64Acq(base: DepBase; off: int): uint64 {.inline.} =
    atomicLoadN(atField[uint64](base, off), ATOMIC_ACQUIRE)
  proc loadU64Rlx(base: DepBase; off: int): uint64 {.inline.} =
    atomicLoadN(atField[uint64](base, off), ATOMIC_RELAXED)
  proc storeU64Rel(base: DepBase; off: int; v: uint64) {.inline.} =
    atomicStoreN(atField[uint64](base, off), v, ATOMIC_RELEASE)
  proc storeU64Rlx(base: DepBase; off: int; v: uint64) {.inline.} =
    atomicStoreN(atField[uint64](base, off), v, ATOMIC_RELAXED)
  proc casU64(base: DepBase; off: int; expected: var uint64;
      desired: uint64): bool {.inline.} =
    atomicCompareExchangeN(atField[uint64](base, off), addr expected, desired,
      false, ATOMIC_ACQ_REL, ATOMIC_ACQUIRE)
  proc fetchAddU64(base: DepBase; off: int; d: uint64): uint64 {.inline.} =
    atomicAddFetch(atField[uint64](base, off), d, ATOMIC_SEQ_CST)
  proc loadU32Acq(base: DepBase; off: int): uint32 {.inline.} =
    atomicLoadN(atField[uint32](base, off), ATOMIC_ACQUIRE)
  proc storeU32Rel(base: DepBase; off: int; v: uint32) {.inline.} =
    atomicStoreN(atField[uint32](base, off), v, ATOMIC_RELEASE)

  proc bootId(): uint64 =
    ## Per-boot identity (invalidates a stale post-reboot region). Same shape as
    ## `repro_shm_index.bootId`. Never returns zero.
    when defined(linux):
      try:
        let raw = readFile("/proc/sys/kernel/random/boot_id")
        var h: uint64 = 1469598103934665603'u64
        for ch in raw:
          if ch != '-' and ch != '\n':
            h = (h xor uint64(ord(ch))) * 1099511628211'u64
        return (h or 1'u64)
      except CatchableError:
        discard
    let secs = uint64(epochTime().int64)
    (secs or 1'u64)

  proc slotOff(ticket: uint64): int {.inline.} =
    DepSlotsBase + int(ticket mod uint64(DepRingCap)) * DepSlotStride

  proc mapFd(fd: cint; size: int): DepBase =
    let p = mmap(nil, size, PROT_READ or PROT_WRITE, MAP_SHARED, fd, 0)
    if p == MAP_FAILED:
      return nil
    cast[DepBase](p)

  proc headerLooksValid(base: DepBase; expectBoot: uint64): bool =
    loadU64Acq(base, DepOffMagic) == DepMagic and
      loadU32Acq(base, DepOffFormatVersion) == DepFormatVersion and
      loadU64Rlx(base, DepOffCreatorBootId) == expectBoot

  proc initHeader(base: DepBase; boot: uint64) =
    storeU64Rlx(base, DepOffHead, 0)
    storeU64Rlx(base, DepOffTail, 0)
    storeU64Rlx(base, DepOffDropped, 0)
    storeU32Rel(base, DepOffFormatVersion, DepFormatVersion)
    storeU32Rel(base, DepOffFlags, 0)
    storeU64Rlx(base, DepOffCreatorBootId, boot)
    storeU64Rel(base, DepOffConsumerPid, uint64(getpid()))
    storeU64Rel(base, DepOffHeartbeat, uint64(epochTime().int64))
    # Publish the magic LAST (release) so a concurrent producer that observes
    # the magic also observes the zeroed ring header.
    storeU64Rel(base, DepOffMagic, DepMagic)

  proc depQueuePath*(dir, edgeKey: string): string =
    dir / ("repro-dep-queue." & edgeKey)

  proc createDepQueueAtPath*(path: string): DepQueue =
    ## CONSUMER side: create + map a fresh, zero-filled segment at `path`. The
    ## engine calls this BEFORE launching the edge's process tree and passes
    ## `path` to producers via `REPRO_MONITOR_DEP_SHM`.
    result.available = false
    result.isConsumer = true
    result.fd = -1
    result.path = path
    try:
      let dir = parentDir(path)
      if dir.len > 0:
        createDir(dir)
    except CatchableError:
      return
    # Fresh region via unique temp + atomic rename (a concurrent attacher never
    # sees a half-initialised file — same discipline as mapping.nim).
    let uniq = int(epochTime() * 1_000_000) mod 1_000_000
    let tmp = path & ".tmp." & $getpid() & "." & $uniq
    let tfd = open(tmp.cstring, O_RDWR or O_CREAT or O_EXCL, 0o600)
    if tfd < 0:
      return
    if ftruncate(tfd, Off(DepRegionSize)) != 0:
      discard close(tfd); removeFile(tmp); return
    discard close(tfd)
    try:
      moveFile(tmp, path)
    except OSError:
      removeFile(tmp); return
    let fd = open(path.cstring, O_RDWR)
    if fd < 0:
      return
    let p = mapFd(fd, DepRegionSize)
    if p.isNil:
      discard close(fd); return
    result.fd = fd
    result.base = p
    initHeader(p, bootId())
    result.available = true

  proc createDepQueue*(dir, edgeKey: string): DepQueue =
    ## Convenience wrapper: create the segment at `depQueuePath(dir, edgeKey)`.
    createDepQueueAtPath(depQueuePath(dir, edgeKey))

  proc attachDepQueueAtPath*(path: string): DepQueue =
    ## PRODUCER side: attach to the consumer-created segment at `path`. Returns
    ## an unavailable queue (so the caller falls back to files) when the file is
    ## missing / wrong size / stale (wrong boot or version). Never CREATES the
    ## region — a producer must not race the consumer's fresh init.
    result.available = false
    result.isConsumer = false
    result.fd = -1
    result.path = path
    if not fileExists(path):
      return
    try:
      if int(getFileSize(path)) != DepRegionSize:
        return
    except CatchableError:
      return
    let fd = open(path.cstring, O_RDWR)
    if fd < 0:
      return
    let p = mapFd(fd, DepRegionSize)
    if p.isNil:
      discard close(fd); return
    if not headerLooksValid(p, bootId()):
      discard munmap(cast[pointer](p), DepRegionSize)
      discard close(fd)
      return
    result.fd = fd
    result.base = p
    result.available = true

  proc attachDepQueue*(dir, edgeKey: string): DepQueue =
    ## Convenience wrapper: attach the segment at `depQueuePath(dir, edgeKey)`.
    attachDepQueueAtPath(depQueuePath(dir, edgeKey))

  proc detach*(q: var DepQueue) =
    # A default-constructed DepQueue has base=nil and fd=0; guard both unmap and
    # close on a real mapping so `detach` on a never-attached queue is a no-op
    # (never closes fd 0 / stdin).
    if not q.base.isNil:
      discard munmap(cast[pointer](q.base), DepRegionSize)
      q.base = nil
      if q.fd > 0:
        discard close(q.fd)
    q.fd = -1
    q.available = false

  type
    DepPushStatus* = enum
      dpsPushed        ## reserved + published
      dpsDropped       ## ring full: SIGNALLED drop (the `dropped` counter bumped)
      dpsOversized     ## encoded record > DepSlotRecCap: not enqueueable
      dpsUnavailable   ## queue not attached (caller uses the file fallback)

  proc tryPushRecord*(q: var DepQueue; record: MonitorRecord): DepPushStatus =
    ## Multi-producer lock-free append (CAS `tail`). Encodes `record` into a
    ## stack buffer (NO heap alloc on the hot path — fork/orc-safe), reserves a
    ## ticket, writes the slot, and publishes via `ready = ticket+1` (release).
    ## Bounded: a full ring bumps the atomic `dropped` counter and returns
    ## `dpsDropped` (SIGNALLED, never silent). The caller MUST fall back to the
    ## file path on any status other than `dpsPushed`.
    if not q.available:
      return dpsUnavailable
    var recBuf: array[DepSlotRecCap, byte]
    let recLen = encodeDepRecord(record, recBuf)
    if recLen < 0 or recLen > DepSlotRecCap:
      return dpsOversized
    let base = q.base
    var tail = loadU64Acq(base, DepOffTail)
    while true:
      let head = loadU64Acq(base, DepOffHead)
      if tail - head >= uint64(DepRingCap):
        let tailNow = loadU64Acq(base, DepOffTail)
        if tailNow != tail:
          tail = tailNow
          continue
        discard fetchAddU64(base, DepOffDropped, 1)
        return dpsDropped
      if casU64(base, DepOffTail, tail, tail + 1):
        break
    let so = slotOff(tail)
    if recLen > 0:
      copyMem(addr base[so + DepSlotOffRec], addr recBuf[0], recLen)
    storeU32Rel(base, so + DepSlotOffRecLen, uint32(recLen))
    storeU64Rel(base, so + DepSlotOffReady, tail + 1)
    dpsPushed

  proc tryDrainOne*(q: var DepQueue; outRec: var MonitorRecord): bool =
    ## SINGLE-consumer non-blocking drain of the next ready ticket. Returns
    ## false when the head slot is not yet published (empty / producer
    ## mid-write) OR when a slot decodes malformed (skipped — its authoritative
    ## copy is on the file fallback). On true, `outRec` holds the decoded record.
    if not q.available:
      return false
    let base = q.base
    let head = loadU64Rlx(base, DepOffHead)
    let tail = loadU64Acq(base, DepOffTail)
    if head >= tail:
      return false
    let so = slotOff(head)
    let ready = loadU64Acq(base, so + DepSlotOffReady)
    if ready != head + 1:
      return false
    let recLen = int(loadU32Acq(base, so + DepSlotOffRecLen))
    var ok = false
    if recLen > 0 and recLen <= DepSlotRecCap:
      var recBuf = newSeq[byte](recLen)
      copyMem(addr recBuf[0], addr base[so + DepSlotOffRec], recLen)
      outRec = decodeDepRecord(recBuf, ok)
    # Retire the slot regardless (advance head) so the consumer never wedges on
    # a malformed slot — the file fallback still carries that record.
    storeU64Rel(base, so + DepSlotOffReady, 0)
    storeU64Rel(base, DepOffHead, head + 1)
    ok

  proc droppedCount*(q: DepQueue): uint64 {.inline.} =
    ## Number of SIGNALLED ring-full drops. The consumer surfaces this as a loud
    ## diagnostic (DEP-SHM-4) — the dropped records still travel the file path.
    if not q.available: return 0
    loadU64Acq(q.base, DepOffDropped)

  proc pendingCount*(q: DepQueue): uint64 {.inline.} =
    if not q.available: return 0
    loadU64Acq(q.base, DepOffTail) - loadU64Acq(q.base, DepOffHead)

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
