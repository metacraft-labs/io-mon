import std/[algorithm, atomics, monotimes, os, sets, strutils, tables, times]
from io_mon/paths import extendedPath

import io_mon/codec
import io_mon/capabilities
import io_mon/types

const
  CanonicalFileKind = 1'u16
  FnvOffset = 14695981039346656037'u64
  FnvPrime = 1099511628211'u64

# DSL-port M9.R.15c.1 (fs-snoop fragment-log perf): the fragment log
# was opened, written, and closed once per emitted record. cmake's
# qt6-base configure issues tens of thousands of probes, so the per-
# record open/close traffic itself doubled the syscalls the monitor
# was supposed to observe — qt6-base configure wall-clock became
# impractical on Linux/macOS hosts (the fragment-dir lookup also
# touched ``createDir`` on every record).
#
# Fix: cache the fragment-log file handle per thread. The fragment
# path is a deterministic function of ``(fragmentDir, osPid,
# threadId)`` and each emitting thread only ever writes to its own
# fragment, so a threadvar slot avoids any cross-thread contention.
# We open lazily with ``fmAppend`` on first emit, encode the record
# into a stack-sized buffer, write the whole frame in a single
# ``writeBuffer`` call, and ``flushFile`` so a SIGKILL leaves any
# committed bytes intact in the OS page cache.
#
# Crash recovery: ``mergeFragments`` uses ``decodeFragmentRecordsTolerant``
# (NEW), which stops at the first truncated frame instead of raising.
# The fragment-log frame format already starts with a u32 length
# prefix, so a partial write is detected by ``pos + length > bytes.len``.
#
# DSL-port M9.R.15f.1 (fs-snoop fragment-log write batching): qt6-base
# configure issues millions of file probes, and even with the
# M9.R.15c.1 single-fd-per-thread cache the per-record
# ``writeBuffer`` + ``flushFile`` call pair drives two syscalls per
# emit (write + fdatasync-style fflush). Throughput plateaued around
# 946K emits/s in the M9.R.15c.1 microbench; for qt6-base + the KF6
# cascade we need another 10x.
#
# Fix: accumulate up to ``FragmentBatchBufLen`` bytes (64 KiB) of
# encoded frames in a per-thread stack-resident byte buffer and flush
# the entire batch in a single ``writeBuffer`` (followed by a single
# ``flushFile``). The encoded-frame protocol is unchanged so the
# tolerant reader continues to recover whole frames from a crash-
# truncated tail. A monotone-clock check on each emit forces a flush
# every ``FragmentBatchMaxAgeNs`` (default 100 ms) so a long-running
# producer with sparse emits doesn't lose more than the most recent
# ~6.4 ms of frames on SIGKILL (per the 64 KiB / 10 MB/s estimate),
# and never more than 100 ms regardless of write rate.
#
# Determinism guard: each batch flush is a contiguous append to the
# per-thread fragment file. Order within a thread is preserved by the
# in-batch buffer order (frames are appended bottom-to-top to a flat
# byte array). Cross-thread order is irrelevant — each thread writes
# to its own fragment file under a deterministic path
# (``fragmentPath(dir, osPid, threadId)``) and the merge step sorts
# by ``(osPid, threadId, seq, kind, path)`` in ``canonicalOrder``, so
# the on-disk batch boundaries leave the canonical depfile byte-
# identical regardless of when each thread flushed.
#
# Crash safety: ``writeBuffer`` of a 64 KiB block is not atomic with
# respect to SIGKILL (POSIX ``write`` may complete partially before
# a kill signal preempts the process). The tolerant reader handles
# this — any partial frame at the tail of the buffer is dropped at
# the next length-prefix boundary that overruns the file. Every
# frame ahead of the partial-tail boundary is byte-identical to what
# the producer wrote.
const
  FragmentDirBufLen = 4096
  FragmentBatchBufLen = 64 * 1024
  FragmentBatchMaxAgeNs = 100_000_000'i64  # 100 ms
  BatchStalenessProbeInterval = 64        # check time every 64 emits
  ReadingSentinelExt* = ".io-mon-reading"
    ## ROUND-2 R5 — extension of the per-thread "un-flushed read tail" sentinel
    ## file (see `FragmentSlot.readingSentinelActive`). Distinct from `.rmdf-frag`
    ## and `.io-mon-report` so the merge's fragment / report scans never collide
    ## with it.

type
  FragmentSlot = object
    # M9.R.15c.3 — the slot is a threadvar; with ``--mm:orc`` + the
    # ``--app:lib`` LD_PRELOAD shim build, a Nim ``string`` field on
    # a threadvar can trip the orc collector when cmake spawns and
    # tears down hundreds of worker threads (the qtbase configure
    # forks aggressively to run feature probes). Storing the
    # ``fragmentDir`` as a fixed-size POD char buffer plus a length
    # counter keeps the threadvar free of any Nim-runtime heap
    # pointer — every field is a flat value type whose destruction
    # at thread exit is a no-op. The buffer is sized for typical
    # absolute paths plus PATH_MAX headroom; an overrun aborts
    # cleanly before writing anything.
    isOpen: bool
    file: File
    fragmentDirLen: int
    fragmentDirBuf: array[FragmentDirBufLen, char]
    osPid: uint64
    threadId: uint64
    # M9.R.15f.1 — per-thread batch buffer. ``batchLen`` records how
    # many bytes of ``batchBuf`` are currently populated; flush
    # consumes the populated prefix and resets ``batchLen`` to 0.
    # ``batchOpenedAtNs`` records the monotone-clock timestamp at
    # which the first frame of the current batch was appended; the
    # next emit forces a flush when ``now - batchOpenedAtNs`` exceeds
    # ``FragmentBatchMaxAgeNs``.
    batchLen: int
    batchOpenedAtNs: int64
    # M9.R.15f.1 — amortise the staleness clock-read over many emits.
    # Reading the monotone clock on every emit costs ~20 ns/call which
    # is the dominant per-record cost once the inlined encoder lands;
    # we instead skip the staleness check entirely until at least
    # ``BatchStalenessProbeInterval`` records have been buffered. The
    # worst-case staleness window is bounded above by 100 ms +
    # (interval * per-emit-cost), still well below the SIGKILL data-
    # loss budget for any realistic emit rate.
    batchProbeCountdown: int
    # ROUND-2 R5 (kill-before-flush): `readingSentinelActive` tracks whether this
    # thread currently has a NON-DURABLE (un-flushed) batch tail on disk-backing.
    # When the batch transitions empty→dirty we drop a tiny sidecar sentinel file
    # next to the fragment; when the batch is flushed (overflow / 100 ms age /
    # explicit flush / clean exit) we remove it. A SIGKILL runs NO destructor, so
    # a process that buffered reads and was killed before its tail flushed leaves
    # the sentinel behind — `mergeFragments` then injects an event-loss and the
    # build downgrades to `mcIncomplete` instead of falsely publishing `mcComplete`
    # minus the lost reads (the round-2 r2_machinery/kill_probe.c defeat). The flag
    # makes the create/remove cost ONE pair of file ops per dirty→clean cycle (≈ per
    # 64 KiB batch on the main thread), not per record.
    readingSentinelActive: bool
    batchBuf: array[FragmentBatchBufLen, byte]

var
  fragmentSlot {.threadvar.}: FragmentSlot
  fragmentOpenCount: Atomic[uint64]
  fragmentWriteCount: Atomic[uint64]
  fragmentFlushCount: Atomic[uint64]

proc slotFragmentDirEquals(slot: var FragmentSlot; s: string): bool =
  if slot.fragmentDirLen != s.len:
    return false
  for i in 0 ..< s.len:
    if slot.fragmentDirBuf[i] != s[i]:
      return false
  true

proc slotFragmentDirAssign(slot: var FragmentSlot; s: string): bool =
  if s.len >= FragmentDirBufLen:
    return false
  for i in 0 ..< s.len:
    slot.fragmentDirBuf[i] = s[i]
  slot.fragmentDirBuf[s.len] = '\0'
  slot.fragmentDirLen = s.len
  true

proc slotFragmentDir(slot: FragmentSlot): string =
  ## Recover the slot's fragment directory as a string from its POD char buffer.
  result = newString(slot.fragmentDirLen)
  for i in 0 ..< slot.fragmentDirLen:
    result[i] = slot.fragmentDirBuf[i]

proc readingSentinelPath*(fragmentDir: string; osPid, threadId: uint64): string =
  ## ROUND-2 R5 — deterministic path of a thread's "un-flushed read tail" sentinel
  ## file inside `fragmentDir`. Keyed on (osPid, threadId) like the fragment file
  ## itself so one process's worker threads never clobber each other's sentinel.
  fragmentDir / ("repro-reading-" & $osPid & "-" & $threadId & ReadingSentinelExt)

proc markReadingSentinel() =
  ## ROUND-2 R5 — record that this thread's batch now holds non-durable bytes, by
  ## creating the sentinel file ONCE per dirty cycle. Best-effort: a failed create
  ## merely loses the kill-before-flush guard for this cycle (degrades to the
  ## pre-round-2 behaviour); it never aborts the monitored process.
  if fragmentSlot.readingSentinelActive or not fragmentSlot.isOpen:
    return
  let p = readingSentinelPath(slotFragmentDir(fragmentSlot),
    fragmentSlot.osPid, fragmentSlot.threadId)
  try:
    writeFile(extendedPath(p), "")
    fragmentSlot.readingSentinelActive = true
  except IOError, OSError:
    discard

proc clearReadingSentinel() =
  ## ROUND-2 R5 — the batch just became durable (flushed); remove the sentinel so
  ## a clean continuation / exit is NOT mistaken for a kill-before-flush.
  if not fragmentSlot.readingSentinelActive:
    return
  let p = readingSentinelPath(slotFragmentDir(fragmentSlot),
    fragmentSlot.osPid, fragmentSlot.threadId)
  try:
    removeFile(extendedPath(p))
  except OSError:
    discard
  fragmentSlot.readingSentinelActive = false

proc fragmentLogOpenCount*(): uint64 =
  ## DSL-port M9.R.15c.1 — return the lifetime number of fragment-log
  ## ``open()`` calls observed in this process. Tests assert this stays
  ## constant across a burst of ``appendFragmentRecord`` calls on the
  ## same (osPid, threadId, fragmentDir) — the previous implementation
  ## incremented this once per call; the cached implementation
  ## increments it exactly once per (thread, fragmentDir) pair.
  fragmentOpenCount.load(moRelaxed)

proc resetFragmentLogOpenCount*() =
  ## Test-only — reset the open counter between scenarios.
  fragmentOpenCount.store(0, moRelaxed)

proc fragmentLogWriteCount*(): uint64 =
  ## DSL-port M9.R.15f.1 — return the lifetime number of underlying
  ## ``writeBuffer`` calls the batched fragment writer issued. Tests
  ## assert this rises slowly relative to record count (a burst of N
  ## records that fit in the batch buffer should issue ceil(N / B)
  ## writes, not N).
  fragmentWriteCount.load(moRelaxed)

proc resetFragmentLogWriteCount*() =
  ## Test-only — reset the write counter between scenarios.
  fragmentWriteCount.store(0, moRelaxed)

proc fragmentLogFlushCount*(): uint64 =
  ## DSL-port M9.R.15f.1 — return the lifetime number of
  ## ``flushFile`` calls the batched writer issued. One flush per
  ## batch write.
  fragmentFlushCount.load(moRelaxed)

proc resetFragmentLogFlushCount*() =
  ## Test-only — reset the flush counter between scenarios.
  fragmentFlushCount.store(0, moRelaxed)

proc flushFragmentBatch*() =
  ## DSL-port M9.R.15f.1 — flush the in-flight batch buffer (if any)
  ## to the cached fragment file. Public so external code (close,
  ## merge, test teardown) can force a sync point without closing the
  ## file handle. If the slot is not open or the batch is empty, the
  ## call is a no-op.
  if not fragmentSlot.isOpen or fragmentSlot.batchLen == 0:
    return
  let bufLen = fragmentSlot.batchLen
  let written = fragmentSlot.file.writeBuffer(
    addr fragmentSlot.batchBuf[0], bufLen)
  if written != bufLen:
    # Drain whatever we managed, reset the buffer so we don't replay
    # bytes on the next flush, and raise — the producer cannot
    # recover from a short write.
    fragmentSlot.batchLen = 0
    fragmentSlot.batchOpenedAtNs = 0
    raiseEnvelopeError(eeMalformed,
      "short write to RMDF fragment for osPid=" & $fragmentSlot.osPid &
      " threadId=" & $fragmentSlot.threadId)
  flushFile(fragmentSlot.file)
  discard fragmentWriteCount.fetchAdd(1, moRelaxed)
  discard fragmentFlushCount.fetchAdd(1, moRelaxed)
  fragmentSlot.batchLen = 0
  fragmentSlot.batchOpenedAtNs = 0
  fragmentSlot.batchProbeCountdown = 0
  # ROUND-2 R5 — the buffered tail is now on disk; the kill-before-flush window
  # is closed for this batch, so retire the sentinel.
  clearReadingSentinel()

proc closeFragmentSlot*() =
  ## Force the calling thread's cached fragment-log handle (if any) to
  ## close. Called on shim shutdown / thread exit / test teardown.
  ## M9.R.15f.1 — flush any in-flight batch buffer before closing so
  ## the on-disk fragment includes every appended frame.
  if fragmentSlot.isOpen:
    try:
      flushFragmentBatch()
    except EnvelopeError, IOError, OSError:
      discard
    # Defensive: flush above clears the sentinel on the normal path; ensure no
    # stale sentinel survives a flush that raised / early-returned.
    clearReadingSentinel()
    try:
      close(fragmentSlot.file)
    except IOError, OSError:
      discard
    fragmentSlot.isOpen = false
    fragmentSlot.fragmentDirLen = 0
    fragmentSlot.fragmentDirBuf[0] = '\0'
    fragmentSlot.osPid = 0
    fragmentSlot.threadId = 0
    fragmentSlot.batchLen = 0
    fragmentSlot.batchOpenedAtNs = 0
    fragmentSlot.batchProbeCountdown = 0
    fragmentSlot.readingSentinelActive = false

proc discardFragmentSlotAfterFork*() =
  ## Reset the calling thread's fragment slot in a fork CHILD WITHOUT flushing
  ## the in-flight batch. The child inherited the slot copy-on-write; its
  ## buffered frames belong to the PARENT (which flushes its own copy), so
  ## flushing here would duplicate them and interleave the parent's fragment
  ## file. Drop the batch and close the inherited handle so the child's next
  ## append opens a fresh fragment under the child's own (osPid, threadId).
  ## (Between batches the stdio buffer is already empty — flushFragmentBatch
  ## ends with flushFile — so close() writes none of the parent's frames.)
  if fragmentSlot.isOpen:
    try:
      close(fragmentSlot.file)
    except IOError, OSError:
      discard
  fragmentSlot.isOpen = false
  fragmentSlot.fragmentDirLen = 0
  fragmentSlot.fragmentDirBuf[0] = '\0'
  fragmentSlot.osPid = 0
  fragmentSlot.threadId = 0
  fragmentSlot.batchLen = 0
  fragmentSlot.batchOpenedAtNs = 0
  fragmentSlot.batchProbeCountdown = 0

proc checksum*(bytes: openArray[byte]): uint64 =
  result = FnvOffset
  for b in bytes:
    result = result xor uint64(b)
    result = result * FnvPrime

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
    raiseEnvelopeError(eeUnknownType, "unknown RMDF record kind")
  if obsOrd < uint16(ord(low(MonitorObservationKind))) or
      obsOrd > uint16(ord(high(MonitorObservationKind))):
    raiseEnvelopeError(eeUnknownType, "unknown RMDF observation kind")

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
    raiseEnvelopeError(eeUnknownType, "unknown RMDF probe result")
  result.probeResult = ProbeResult(probeOrd.int)
  result.path = readString(payload, pos)
  result.detail = readString(payload, pos)
  if pos != payload.len:
    raiseEnvelopeError(eeMalformed, "RMDF record has trailing bytes")

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
      raiseEnvelopeError(eeMalformed, "truncated RMDF record frame")
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
  ## could not be decoded as a complete frame — a partial RMDF write (e.g.
  ## a SIGKILL'd shim) or outright corruption. Per Monitor-Hook-Shim.md
  ## §"Failure Semantics" ("partial RMDF writes MUST fail reader
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

proc fragmentPath*(fragmentDir: string; osPid, threadId: uint64): string =
  fragmentDir / ("repro-monitor-" & $osPid & "-" & $threadId & ".rmdf-frag")

proc openFragmentSlot(fragmentDir: string; osPid, threadId: uint64;
                      path: string): bool =
  if not open(fragmentSlot.file, extendedPath(path), fmAppend):
    return false
  if not slotFragmentDirAssign(fragmentSlot, fragmentDir):
    # fragmentDir overflows the fixed-size buffer — close and bail out;
    # the caller falls back to the no-cache (raise) path.
    try: close(fragmentSlot.file)
    except IOError, OSError: discard
    return false
  fragmentSlot.isOpen = true
  fragmentSlot.osPid = osPid
  fragmentSlot.threadId = threadId
  fragmentSlot.batchLen = 0
  fragmentSlot.batchOpenedAtNs = 0
  fragmentSlot.batchProbeCountdown = 0
  fragmentSlot.readingSentinelActive = false
  discard fragmentOpenCount.fetchAdd(1, moRelaxed)
  true

proc monoNowNs(): int64 =
  ## DSL-port M9.R.15f.1 — monotone-clock read used to time-bound
  ## batch staleness. ``std/monotimes.getMonoTime`` calls
  ## ``clock_gettime(CLOCK_MONOTONIC)`` on POSIX and
  ## ``QueryPerformanceCounter`` on Windows; both are vDSO-resolved /
  ## userspace-fast and add ~ns of overhead to the hot path.
  cast[int64]((getMonoTime() - MonoTime()).inNanoseconds)

proc appendFragmentRecord*(fragmentDir: string; record: MonitorRecord) =
  ## DSL-port M9.R.15c.1 — emit ``record`` to the (osPid, threadId)
  ## fragment under ``fragmentDir``. The file handle is cached in a
  ## per-thread slot; the directory is only ``createDir``-ed on the
  ## open path. Truncated trailing bytes are tolerated by
  ## ``decodeFragmentRecordsTolerant`` (used by ``mergeFragments``).
  ##
  ## DSL-port M9.R.15f.1 — frames are appended to a per-thread
  ## ``FragmentBatchBufLen``-byte stack buffer; the batch is flushed
  ## to the file in a single ``writeBuffer`` + ``flushFile`` pair
  ## when (a) the next frame would overflow the buffer, (b) the
  ## (osPid, threadId, fragmentDir) key changes (so each fragment
  ## file receives only its own frames), (c) ``flushFragmentBatch``
  ## / ``closeFragmentSlot`` / ``mergeFragments`` is invoked, or
  ## (d) the current batch has been open for longer than
  ## ``FragmentBatchMaxAgeNs`` (default 100 ms) — bounding the worst-
  ## case data-loss window on SIGKILL.
  let needsReopen = not fragmentSlot.isOpen or
    not slotFragmentDirEquals(fragmentSlot, fragmentDir) or
    fragmentSlot.osPid != record.osPid or
    fragmentSlot.threadId != record.threadId
  if needsReopen:
    if fragmentSlot.isOpen:
      # Flush the in-flight batch BEFORE we close — otherwise the
      # buffered frames belong to the previous (osPid, threadId)
      # fragment but the close path drops them on the floor.
      try: flushFragmentBatch()
      except EnvelopeError, IOError, OSError: discard
      try: close(fragmentSlot.file)
      except IOError, OSError: discard
      fragmentSlot.isOpen = false
    createDir(extendedPath(fragmentDir))
    let path = fragmentPath(fragmentDir, record.osPid, record.threadId)
    if not openFragmentSlot(fragmentDir, record.osPid, record.threadId, path):
      raiseEnvelopeError(eeMalformed,
        "cannot open RMDF fragment for append: " & path)

  # M9.R.15f.1 — compute exact frame size first (4-byte length prefix
  # + fixed 58-byte header + 4 + path-bytes + 4 + detail-bytes) so we
  # can encode straight into the batch buffer without an intermediate
  # ``seq[byte]`` allocation. The frame layout matches
  # ``encodeFrame`` byte-for-byte; the unit tests assert the on-disk
  # bytes stay byte-identical to what the legacy ``encodeFrame`` +
  # ``copyMem`` path produced (the determinism test) so the inlined
  # encode is observably equivalent.
  const RecordHeaderBytes = 2 + 2 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4
  let pathLen = record.path.len
  let detailLen = record.detail.len
  let payloadLen = RecordHeaderBytes + 4 + pathLen + 4 + detailLen
  let frameLen = 4 + payloadLen
  if frameLen == 0:
    return

  if frameLen > FragmentBatchBufLen:
    # Pathological case — a single frame larger than the batch buf.
    # Flush whatever is pending, then write the giant frame directly
    # via the legacy ``encodeFrame`` path to keep the file's frame-
    # boundary invariant.
    flushFragmentBatch()
    let frame = encodeFrame(record)
    let n = fragmentSlot.file.writeBuffer(unsafeAddr frame[0], frame.len)
    if n != frame.len:
      raiseEnvelopeError(eeMalformed,
        "short write to RMDF fragment for osPid=" & $record.osPid &
        " threadId=" & $record.threadId)
    flushFile(fragmentSlot.file)
    discard fragmentWriteCount.fetchAdd(1, moRelaxed)
    discard fragmentFlushCount.fetchAdd(1, moRelaxed)
    return

  if fragmentSlot.batchLen + frameLen > FragmentBatchBufLen:
    flushFragmentBatch()
  elif fragmentSlot.batchLen > 0:
    # Buffer non-empty + frame fits — but is the batch stale? If the
    # first frame of this batch landed more than ``FragmentBatchMaxAgeNs``
    # ago, force a flush so a sparse-emit producer doesn't sit on
    # buffered frames forever.
    #
    # The staleness check reads the monotone clock once per
    # ``BatchStalenessProbeInterval`` emits to amortise the vDSO
    # call cost across the steady-state hot path. ``batchProbeCountdown``
    # is initialised to 0 on batch-start so the FIRST post-start emit
    # always probes (catches the sparse-emit producer that lingers
    # past 100 ms between calls), then refreshes the countdown to the
    # full interval on a not-stale result.
    if fragmentSlot.batchProbeCountdown <= 0:
      let nowNs = monoNowNs()
      if nowNs - fragmentSlot.batchOpenedAtNs > FragmentBatchMaxAgeNs:
        flushFragmentBatch()
      else:
        fragmentSlot.batchProbeCountdown = BatchStalenessProbeInterval
    else:
      dec fragmentSlot.batchProbeCountdown

  if fragmentSlot.batchLen == 0:
    fragmentSlot.batchOpenedAtNs = monoNowNs()
    # Countdown starts at 0 so the first post-batch-start emit always
    # probes the clock — this catches sparse-emit producers whose
    # inter-emit gap exceeds the 100 ms staleness threshold and
    # ensures bounded data loss on SIGKILL.
    fragmentSlot.batchProbeCountdown = 0

  # Inline little-endian encode straight into the batch buffer at the
  # current offset. ``cursor`` is a local copy so we can store it
  # back to ``batchLen`` as a single write at the end.
  var cursor = fragmentSlot.batchLen
  template putByte(b: byte) =
    fragmentSlot.batchBuf[cursor] = b
    inc cursor
  template putU16Le(v: uint16) =
    putByte(byte(v and 0xFF'u16))
    putByte(byte((v shr 8) and 0xFF'u16))
  template putU32Le(v: uint32) =
    putByte(byte(v and 0xFF'u32))
    putByte(byte((v shr 8) and 0xFF'u32))
    putByte(byte((v shr 16) and 0xFF'u32))
    putByte(byte((v shr 24) and 0xFF'u32))
  template putU64Le(v: uint64) =
    putByte(byte(v and 0xFF'u64))
    putByte(byte((v shr 8) and 0xFF'u64))
    putByte(byte((v shr 16) and 0xFF'u64))
    putByte(byte((v shr 24) and 0xFF'u64))
    putByte(byte((v shr 32) and 0xFF'u64))
    putByte(byte((v shr 40) and 0xFF'u64))
    putByte(byte((v shr 48) and 0xFF'u64))
    putByte(byte((v shr 56) and 0xFF'u64))
  template putString(s: string) =
    putU32Le(uint32(s.len))
    if s.len > 0:
      copyMem(addr fragmentSlot.batchBuf[cursor], unsafeAddr s[0], s.len)
      cursor += s.len

  # Frame length prefix.
  putU32Le(uint32(payloadLen))
  # Record header — order MUST match encodeRecordPayload exactly.
  putU16Le(uint16(ord(record.kind)))
  putU16Le(uint16(ord(record.observationKind)))
  putU64Le(record.seq)
  putU64Le(record.osPid)
  putU64Le(record.parentOsPid)
  putU64Le(record.threadId)
  putU64Le(record.childOsPid)
  putU64Le(cast[uint64](record.result))
  putU32Le(record.flags)
  putU32Le(uint32(ord(record.probeResult)))
  putString(record.path)
  putString(record.detail)

  fragmentSlot.batchLen = cursor
  # ROUND-2 R5 — the batch now holds a non-durable tail; mark the kill-before-flush
  # sentinel (once per dirty cycle). A subsequent flush retires it; an uncatchable
  # SIGKILL leaves it behind for `mergeFragments` to detect.
  markReadingSentinel()

proc readFragmentRecords*(path: string): seq[MonitorRecord] =
  let raw = readFile(extendedPath(path)).toBytes()
  decodeFrames(raw)

proc readFragmentRecordsTolerant*(path: string; cleanEof: var bool):
    seq[MonitorRecord] =
  ## DSL-port M9.R.15c.1 — crash-recovery sibling of
  ## ``readFragmentRecords``. Stops at the first truncated frame
  ## instead of raising, so a SIGKILL'd producer's fragment can still
  ## be merged into the canonical depfile. ``cleanEof`` reports whether
  ## the fragment decoded fully (see ``decodeFramesTolerant``); a
  ## ``false`` value MUST block cache publication (fail-closed).
  let raw = readFile(extendedPath(path)).toBytes()
  decodeFramesTolerant(raw, cleanEof)

proc readFragmentRecordsTolerant*(path: string): seq[MonitorRecord] =
  ## Records-only overload; discards the clean-EOF signal.
  var cleanEof: bool
  readFragmentRecordsTolerant(path, cleanEof)

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
  var processPids: seq[uint64] = @[]
  for record in records:
    if record.osPid != 0 and processPids.find(record.osPid) < 0:
      processPids.add(record.osPid)
    if record.kind == mrEventLoss or record.observationKind == moEventLoss:
      inc result.eventLossCount
    else:
      inc result.observationCount
  result.processCount = uint64(processPids.len)

proc depFileFromRecords*(records: openArray[MonitorRecord]): MonitorDepFile =
  let summary = summarizeRecords(records)
  var profile = profileFromRecords(records)
  if summary.eventLossCount != 0:
    profile.evidenceComplete = false
  MonitorDepFile(
    version: RmdfVersion,
    producerVersion: ReproMonitorDepfileProducer,
    backendFamily: profile.backendFamily,
    requiredFeatures: profile.requiredCapabilities,
    completeness: if profile.evidenceComplete and summary.eventLossCount == 0:
        mcComplete
      else:
        mcIncomplete,
    profile: profile,
    capabilityGaps: profile.gaps,
    summary: summary,
    records: @records)

proc encodeCanonical*(records: openArray[MonitorRecord]): seq[byte] =
  var ordered = @records
  ordered.sort(canonicalOrder)
  for i in 0 ..< ordered.len:
    ordered[i].seq = uint64(i + 1)

  var body: seq[byte] = @[]
  for record in ordered:
    body.add encodeFrame(record)

  result = @[]
  result.add RmdfMagic.toBytes()
  result.writeU16Le(RmdfVersion)
  result.writeU16Le(CanonicalFileKind)
  result.writeU64Le(uint64(ordered.len))
  result.writeU64Le(uint64(body.len))
  result.add body
  result.add RmdfTrailerMagic.toBytes()
  result.writeU64Le(uint64(ordered.len))
  result.writeU64Le(checksum(body))

proc monitoredStartPids*(records: openArray[MonitorRecord]): HashSet[uint64] =
  ## The set of osPids that emitted an `mrProcessStart` — i.e. every process that
  ## actually loaded the shim and is therefore INSIDE the monitored injected tree.
  ## Shared by the subtree-loss check and the breakaway-report folding (DRY).
  result = initHashSet[uint64]()
  for r in records:
    if r.kind == mrProcessStart:
      result.incl r.osPid

const
  # ROUND-2 R7/R8 — identity metadata is carried as space-separated `key=value`
  # tokens APPENDED to a record's free-form `detail` field rather than as new
  # struct fields, so the RMDF wire format (magic/version/payload layout) stays
  # BYTE-STABLE and every existing reader/codec path is untouched (the
  # dgNoRuntimeDependencies / mrIpcConnect "append, never renumber" lesson applied
  # to record metadata). A record that predates these tokens simply lacks them and
  # the merge degrades to the pre-round-2 bare-pid matching for it — never a false
  # downgrade. See `detailToken`.
  StartTimeToken = "start"          ## process-start: this pid's kernel start usec
  ChildStartTimeToken = "childstart" ## spawn: the CHILD pid's kernel start usec
  PeerStartTimeToken = "peerstart"  ## ipc-connect: the PEER pid's kernel start usec
  RunIdToken = "run"                ## process-start / ipc-connect: invocation run id
  NonceToken = "nonce"              ## ipc-connect: per-connection nonce (R8)
  ChanToken = "chan"                ## ROUND-3 S1: external-content channel class
  RoleToken = "role"                ## ROUND-3 S1: external-content channel side

proc detailToken*(detail, key: string): string =
  ## Extract the value of a `key=value` token from a record's `detail` field
  ## (ROUND-2 R7/R8). Tokens are whitespace-separated and values contain no
  ## whitespace (pids, start-usec, run ids and nonces are all bare integers/ids).
  ## Returns "" when the key is absent. Single source of truth so every identity
  ## read is consistent (DRY).
  let needle = key & "="
  for tok in detail.splitWhitespace():
    if tok.len > needle.len and tok.startsWith(needle):
      return tok[needle.len .. ^1]
  ""

type
  ProcIdentity = tuple[pid: uint64, startTime: string]
    ## ROUND-2 R7 — a process is identified by (osPid, kernel-start-time), NOT the
    ## bare osPid, because macOS pids wrap and a recycled pid otherwise false-matches
    ## a stale monitored process-start. `startTime` is the decimal start-usec token
    ## ("" when the producer could not obtain it — then we fall back to bare-pid).

proc processStartIdentities(records: openArray[MonitorRecord]):
    tuple[idents: HashSet[ProcIdentity]; pids: HashSet[uint64]] =
  ## ROUND-2 R7 — collect the (pid, start-time) identities of every monitored
  ## process (those that emitted `mrProcessStart`) plus the bare-pid set used as a
  ## fallback when a counterpart record carries no start-time token. Shared by the
  ## spawn-child and IPC-peer checks (DRY).
  result.idents = initHashSet[ProcIdentity]()
  result.pids = initHashSet[uint64]()
  for r in records:
    if r.kind == mrProcessStart:
      result.pids.incl r.osPid
      result.idents.incl (r.osPid, detailToken(r.detail, StartTimeToken))

proc childIsMonitored(childPid: uint64; childStart: string;
    idents: HashSet[ProcIdentity]; pids: HashSet[uint64]): bool =
  ## ROUND-2 R7 — is a spawned child / IPC peer one of THIS run's monitored
  ## processes? With a known start-time we require an EXACT (pid, start-time)
  ## match, so a recycled pid whose start-time differs from the stale monitored
  ## process is correctly seen as un-monitored. With no start-time (the producer
  ## could not query it, or a pre-round-2 record) we degrade to bare-pid membership
  ## — preserving the original behaviour and never introducing a false downgrade.
  if childStart.len > 0:
    (childPid, childStart) in idents
  else:
    childPid in pids

proc unmonitoredSubtreeLossCount*(records: openArray[MonitorRecord];
    trustedPeerPids: HashSet[uint64] = initHashSet[uint64]()): int =
  ## T0 — EARN mcComplete (MacOS-Monitoring-Adversarial-Hardening.milestones.org
  ## §"T0 — Earn mcComplete"; Monitor-Hook-Shim.md §"Failure Semantics":
  ## "successful child exit MUST NOT hide monitor failure").
  ##
  ## The monitor must not ASSERT `mcComplete`; it must EARN it. The cross-process
  ## merge sees every monitored process's fragments, so it can PROVE the process
  ## tree was fully monitored. This returns the number of synthetic event-loss
  ## records to inject — one per piece of DIRECT EVIDENCE that some child/exec
  ## subtree ran UN-monitored — so the existing event-loss → `mcIncomplete` path
  ## (`summarizeRecords` → `depFileFromRecords`) downgrades completeness to a
  ## CONSERVATIVE RE-RUN instead of a silent false skip (the cardinal sin).
  ##
  ## THREE independent signals, all keyed purely on records io-mon already emits.
  ## The machinery is deliberately generic, so Phase 2's IPC break (#1) reuses it:
  ## a `connect` to a peer with NO `process-start` in the injected set is
  ## structurally identical to an un-injected spawn child here.
  ##
  ## (c) IPC-CONNECT to an out-of-tree / opaque peer (T3a, findings-doc break #1 —
  ##     the DAEMON-OVER-SOCKET breakaway that DEFEATS the subtree fail-safe). A
  ##     monitored client `connect`s to a persistent daemon (sccache/ccache server,
  ##     distcc/icecc, the Gradle daemon, a Bazel persistent worker, tsserver,
  ##     watchman, the nix daemon, …) started OUTSIDE the invocation; the daemon
  ##     opens+reads files on the client's behalf and returns the bytes, so the
  ##     real file dependency is invisible AND there is no spawn to anchor the
  ##     subtree check on. Each `mrIpcConnect` carries the PEER PID in `childOsPid`
  ##     (AF_UNIX via LOCAL_PEERPID; 0/unknown for INET). The peer is INSIDE the
  ##     tree iff its pid has a matching `mrProcessStart` — then two MONITORED
  ##     processes are legitimately talking over a socket and we must NOT downgrade
  ##     (the cardinal-sin guard). Otherwise (peer pid known but NOT in the set, OR
  ##     peer pid UNKNOWN) the peer is an out-of-tree breakaway ⇒ one loss ⇒
  ##     `mcIncomplete` (a conservative re-run). `trustedPeerPids` exempts peers a
  ##     COOPERATING daemon has reported its reads for (BuildXL Trusted-Tools /
  ##     Shared-Compilation breakaway compensation; see `mergeFragments` +
  ##     `loadBreakawayReports`): an accounted-for daemon need not force a re-run.
  ##
  ## (a) SPAWN with no child process-start. Every INJECTED process emits an
  ##     `mrProcessStart` with its own osPid. A recorded `mrProcessSpawn`
  ##     (fork/posix_spawn) names the child in `childOsPid`; if NO `mrProcessStart`
  ##     with `osPid == childOsPid` exists, that child never loaded the shim — its
  ##     whole subtree (and every file it read) ran unmonitored (a posix_spawn into
  ##     a hardened/notarized binary, or break #1's spawn arm). A fork child is
  ##     safe: it inherits the loaded shim and emits its OWN process-start, so it
  ##     is always matched.
  ##
  ## (b) EXEC into an un-injectable image. An exec — `execve`, or a
  ##     POSIX_SPAWN_SETEXEC spawn (break #2) — REPLACES the current image in the
  ##     SAME pid. If the new image is injectable, the re-loaded shim emits a fresh
  ##     `mrProcessStart` for that pid; so while every image in a pid stays
  ##     monitored, that pid's `process-start` count is exactly one greater than
  ##     its exec count. The instant an exec lands in an un-injectable image (no
  ##     post-exec start), the exec count CATCHES UP. Hence
  ##     `execCount(pid) >= startCount(pid)` (with execCount > 0) means the LAST
  ##     exec in that pid ran un-monitored — catching a SETEXEC into a hardened
  ##     binary (break #2, which the subtree fail-safe alone misses) AND a plain
  ##     execve into one.
  # ROUND-2 R7 — match on (pid, kernel-start-time), not the bare pid, so a wrapped
  # (recycled) child/peer pid cannot false-match a stale monitored process-start.
  let (startIdents, startPids) = processStartIdentities(records)
  var startCount = initCountTable[uint64]()
  var execCount = initCountTable[uint64]()
  for r in records:
    case r.kind
    of mrProcessStart:
      startCount.inc r.osPid
    of mrProcessExec:
      execCount.inc r.osPid
    else: discard
  result = 0
  # (a) spawned children with no matching process-start (count each child once).
  # Keyed on the child's (pid, start-time) identity: a recycled pid whose
  # start-time differs from a stale monitored process is correctly un-monitored.
  var flaggedChildren: HashSet[ProcIdentity]
  for r in records:
    if r.kind == mrProcessSpawn and r.childOsPid != 0 and
        r.childOsPid != r.osPid:
      let childStart = detailToken(r.detail, ChildStartTimeToken)
      let ident = (r.childOsPid, childStart)
      if not childIsMonitored(r.childOsPid, childStart, startIdents, startPids) and
          ident notin flaggedChildren:
        flaggedChildren.incl ident
        inc result
  # (b) execs whose last image was un-injectable (one loss per such pid).
  for pid, execs in execCount:
    if execs > 0 and execs >= startCount.getOrDefault(pid):
      inc result
  # (c) IPC-connect to an out-of-tree / opaque / un-reported peer (break #1).
  # Dedup so a client that connects to the same daemon many times counts once:
  # key on the peer pid when known, else on the destination (an unknown-peer
  # socket is keyed by its address/path). A peer that is a monitored in-tree
  # process (its pid emitted process-start) OR a trusted daemon that reported its
  # reads is fully accounted for and never downgrades — the cardinal-sin guard.
  var flaggedPeers: HashSet[string]
  for r in records:
    if r.kind == mrIpcConnect:
      let peer = r.childOsPid
      let peerStart = detailToken(r.detail, PeerStartTimeToken)
      # A peer is INSIDE the tree iff its (pid, start-time) identity matches a
      # monitored process-start (R7 — a recycled peer pid with a different start
      # time is NOT in-tree), OR a trusted daemon accounted for its reads. Either
      # way: no downgrade (the cardinal-sin guard for legitimate intra-tree IPC).
      if peer != 0 and
          (childIsMonitored(peer, peerStart, startIdents, startPids) or
           peer in trustedPeerPids):
        continue
      let key = if peer != 0: "pid:" & $peer & "@" & peerStart
                else: "dest:" & r.path
      if key in flaggedPeers:
        continue
      flaggedPeers.incl key
      inc result

proc nonDeterminismLossCount*(records: openArray[MonitorRecord]): int =
  ## ROUND-2 R-D (break R10) — the AUTO-DOWNGRADE arm of the three-way non-file
  ## determinism split. Returns the number of synthetic event-loss records to
  ## inject so the merge downgrades to `mcIncomplete` (a conservative RE-RUN, never
  ## a cache hit) when the build CONSUMED ENTROPY and is therefore genuinely
  ## non-reproducible.
  ##
  ## Keyed PURELY on `mrNonDeterministic` records, which the shim emits for the
  ## program's own DIRECT entropy use — getentropy / arc4random* — and ONLY when the
  ## call's CALLER is in the program's own main-executable __TEXT range (caller
  ## attribution; see `ct_macos_addr_in_program`). That gate is essential: an
  ## interpose hook ALSO sees cross-dylib libsystem/libobjc/libswift entropy
  ## (malloc cookies, stack-guard, hash seeds) which would otherwise downgrade every
  ## real cc/clang/bash run (the cardinal sin). A /dev/random or /dev/urandom open is
  ## NOT flagged (mktemp opens /dev/urandom for a random temp name on most builds).
  ## The shim DEDUPES per-process by source, so a tight `arc4random()` loop counts
  ## once, not millions of times. Counting one loss per distinct source record is
  ## enough to force the downgrade.
  ##
  ## CARDINAL-SIN GUARD: ONLY `mrNonDeterministic` downgrades. `mrEnvRead` /
  ## `mrSysctlRead` are OBSERVED INPUTS (folded into the consumer's cache key, never
  ## a downgrade) and `mrTimeRead` is recorded-not-downgraded (almost every program
  ## reads a clock for benign timing). A normal deterministic build that reads
  ## env vars and calls clock_gettime therefore stays `mcComplete` — see
  ## `mergeFragments` and the R-D design note.
  result = 0
  for r in records:
    if r.kind == mrNonDeterministic:
      inc result

proc externalContentLossCount*(records: openArray[MonitorRecord]): int =
  ## ROUND-3 S1 (content-channel downgrade) — returns the number of synthetic
  ## event-loss records to inject because the merged evidence proves the build
  ## CONSUMED CONTENT from a channel whose producer is OUTSIDE the monitored tree:
  ## a POSIX shm object it did not create in-tree (S1b), a FIFO with no in-tree
  ## writer (S1d), or an inherited socket/pipe (S1c). Each is an INVISIBLE input
  ## (no read(2) of a named file), so — reusing the IPC-breakaway machinery — one
  ## loss forces `mcIncomplete`, a conservative re-run.
  ##
  ## THE CARDINAL-SIN GUARD is cross-process PAIRING (the whole point of routing
  ## this through the merge rather than downgrading at the shim): a channel a
  ## MONITORED process itself created/fed is fully accounted for and must NEVER
  ## downgrade —
  ##   * shm: an `attach` (consume) whose name has a matching in-tree `create`
  ##     (shm_open with O_CREAT) is self-produced ⇒ no loss. Only an UNPAIRED
  ##     attach (the out-of-tree producer of probeC) downgrades.
  ##   * fifo: a `read` whose path has a matching in-tree `write` open is an
  ##     in-tree pipeline ⇒ no loss. Only a read with no in-tree writer (the
  ##     out-of-tree feeder of probeD) downgrades.
  ## Dedup keys collapse a channel touched many times to a single loss.
  ##
  ## DELIBERATELY NOT a downgrade signal: `chan=opaque` (an inherited socket/pipe
  ## read with no in-tree open). Socket provenance is OWNED by the IPC-connect
  ## machinery (`unmonitoredSubtreeLossCount`), which correctly leaves INTRA-TREE
  ## socket IPC `mcComplete` while downgrading an out-of-tree breakaway peer — so
  ## a second downgrade here would FALSE-FLAG every legitimate intra-tree socket
  ## IPC / anonymous pipeline (the cardinal sin; see the macOS ipc-breakaway
  ## intra-tree test). An inherited socket/pipe from an OUT-OF-TREE parent is
  ## already caught by the un-injected-subtree check. The opaque marker is
  ## therefore RECORD-not-downgrade (a diagnostic a consumer MAY act on), mirroring
  ## the round-2 `mrTimeRead` stance.
  var shmCreates = initHashSet[string]()
  var fifoWrites = initHashSet[string]()
  for r in records:
    if r.kind == mrExternalContent and
        detailToken(r.detail, ChanToken) == "shm" and
        detailToken(r.detail, RoleToken) == "create":
      shmCreates.incl r.path
    elif r.kind == mrExternalContent and
        detailToken(r.detail, ChanToken) == "fifo" and
        detailToken(r.detail, RoleToken) == "write":
      fifoWrites.incl r.path
  result = 0
  var flagged = initHashSet[string]()
  for r in records:
    if r.kind != mrExternalContent:
      continue
    let chan = detailToken(r.detail, ChanToken)
    let role = detailToken(r.detail, RoleToken)
    var key = ""
    if chan == "shm" and role == "attach":
      if r.path notin shmCreates:
        key = "shm:" & r.path
    elif chan == "fifo" and role == "read":
      if r.path notin fifoWrites:
        key = "fifo:" & r.path
    if key.len > 0 and key notin flagged:
      flagged.incl key
      inc result

const
  BreakawayReportExt* = ".io-mon-report"
    ## File extension a COOPERATING daemon writes its breakaway report under,
    ## inside the `IO_MON_BREAKAWAY_REPORT_DIR`. Distinct from `.rmdf-frag` so the
    ## report scan never collides with the per-process fragment files.
  IoMonBreakawayReportDirEnv* = "IO_MON_BREAKAWAY_REPORT_DIR"
    ## Env var naming the directory a trusted daemon drops breakaway reports into
    ## (and that the merge folds them from). See `loadBreakawayReports` and the
    ## T3a design notes in MacOS-Monitoring-Adversarial-Hardening.milestones.org.

type
  BreakawayFold = object
    ## Result of folding a directory of cooperating-daemon breakaway reports into
    ## a merge: synthetic file-read records to ADD to the depfile (so the
    ## daemon-served files become visible dependencies) and the set of daemon pids
    ## that accounted for their reads (so the IPC-connect check does NOT downgrade
    ## a connection to such a trusted daemon).
    reads: seq[MonitorRecord]
    trustedPeerPids: HashSet[uint64]

  BreakawayAuthContext* = object
    ## ROUND-2 R8 — the per-invocation facts a breakaway report must be checked
    ## against before it is trusted. Derived purely from the merged records, so the
    ## authentication uses what the SHIM observed, not what a report CLAIMS.
    runId*: string
      ## This invocation's run id (the `run=` token the shim stamped on its
      ## `mrProcessStart` / `mrIpcConnect` records, sourced from
      ## REPRO_MONITOR_SESSION). Empty when no monitored process recorded one.
    connectedPeers*: HashSet[string]
      ## "client:daemon" pid pairs the shim OBSERVED the client connect to (from
      ## `mrIpcConnect`). A report is bound to a real, recorded connection.
    validNonces*: HashSet[string]
      ## The per-connection nonces the shim recorded on `mrIpcConnect`. A report
      ## that carries a `nonce` must echo one of these.

const
  BreakawayReportCompleteToken* = "complete"
    ## ROUND-2 R8 — a cooperating daemon MUST emit a bare `complete` line to assert
    ## "this report fully accounts for everything I did on this client's behalf".
    ## A report lacking it (the round-2 malicious_client.c forgery, which lists NO
    ## reads and makes no completeness claim) is treated as untrusted, so the
    ## client's connect still downgrades.

proc breakawayAuthContext*(records: openArray[MonitorRecord]):
    BreakawayAuthContext =
  ## ROUND-2 R8 — extract the report-authentication context from the merged
  ## records (DRY: one source of truth shared by `mergeFragments`).
  result.connectedPeers = initHashSet[string]()
  result.validNonces = initHashSet[string]()
  for r in records:
    case r.kind
    of mrProcessStart:
      if result.runId.len == 0:
        let run = detailToken(r.detail, RunIdToken)
        if run.len > 0:
          result.runId = run
    of mrIpcConnect:
      if r.childOsPid != 0:
        result.connectedPeers.incl($r.osPid & ":" & $r.childOsPid)
      let nonce = detailToken(r.detail, NonceToken)
      if nonce.len > 0:
        result.validNonces.incl nonce
      if result.runId.len == 0:
        let run = detailToken(r.detail, RunIdToken)
        if run.len > 0:
          result.runId = run
    else: discard

proc loadBreakawayReports*(reportDir: string; monitored: HashSet[uint64];
    auth: BreakawayAuthContext): BreakawayFold =
  ## BuildXL-style TRUSTED-DAEMON breakaway compensation (T3a), AUTHENTICATED
  ## (ROUND-2 R8). A cooperating daemon (e.g. a future io-mon-aware sccache) that
  ## serves a monitored client writes a small text report into `reportDir`:
  ##
  ##   io-mon-breakaway-report v1
  ##   run <run-id>            # this invocation's REPRO_MONITOR_SESSION
  ##   client <client-pid>
  ##   daemon <daemon-pid>
  ##   nonce <nonce>           # optional: a per-connection nonce the shim recorded
  ##   read <abs-path>
  ##   read <abs-path>
  ##   complete                # asserts the report fully accounts for its reads
  ##
  ## (BuildXL prior art: "Trusted Tools / Shared Compilation" + breakaway-process
  ## compensation, PR #1175.)
  ##
  ## ROUND-2 R8 — a round-2 adversarial campaign DEFEATED the un-authenticated
  ## fold two ways (research/.../r2_machinery):
  ##   (3b) an in-tree UNTRUSTED tool dropped a report naming itself as client and
  ##        the out-of-tree daemon as daemon, with ZERO read lines — suppressing the
  ##        IPC downgrade and yielding a false `mcComplete` with the served file
  ##        missing (malicious_client.c);
  ##   (3c) a STALE report from a PREVIOUS run was folded into a later run via pid
  ##        collision.
  ## A report is now trusted ONLY when ALL hold (else it is ignored, so the
  ## client's connect still downgrades — fail-closed, a conservative re-run):
  ##   1. its CLIENT pid is one of THIS invocation's monitored processes;
  ##   2. it carries a `run` matching this invocation's run id — and the run id is
  ##      known (defeats 3c: a stale/cross-run report carries a different run id);
  ##   3. the shim actually OBSERVED the client connect to that daemon pid
  ##      (`mrIpcConnect` peer binding) — a report cannot be fabricated for a
  ##      connection the monitor never saw;
  ##   4. if it carries a `nonce`, the nonce matches one the shim recorded for an
  ##      observed connection (per-connection binding strengthening);
  ##   5. it explicitly asserts `complete` AND lists ≥1 `read` — a report that makes
  ##      no completeness claim or accounts for nothing is not evidence of coverage
  ##      (defeats 3b: the no-reads forgery).
  ##
  ## HONEST LIMITATION (documented, not hidden): criteria 2–4 bind a report to this
  ## run and to an observed connection, but an in-tree process can read
  ## REPRO_MONITOR_SESSION from its environment and could, in principle, forge a
  ## `complete` report that lists DIFFERENT reads than the daemon truly performed
  ## (omitting the real dependency). Fully closing that requires either a secret
  ## per-connection nonce HANDED to the daemon over an out-of-band channel the
  ## client cannot read (a shim↔daemon handshake), or out-of-band kernel
  ## observation (the EndpointSecurity backend). Both are tracked follow-ups; the
  ## checks here close the round-2 probes and every report that does not
  ## non-trivially and run-correctly account for an observed connection.
  result.reads = @[]
  result.trustedPeerPids = initHashSet[uint64]()
  if reportDir.len == 0 or not dirExists(extendedPath(reportDir)):
    return
  for kind, path in walkDir(extendedPath(reportDir)):
    if kind != pcFile or not path.endsWith(BreakawayReportExt):
      continue
    var content = ""
    try:
      content = readFile(extendedPath(path))
    except IOError, OSError:
      # A report that vanished / is unreadable carries no evidence; skip it
      # rather than abort the whole merge (benign producer race).
      continue
    var clientPid, daemonPid: uint64 = 0
    var reportRun, reportNonce: string = ""
    var declaredComplete = false
    var readPaths: seq[string] = @[]
    for rawLine in content.splitLines():
      let line = rawLine.strip()
      if line == BreakawayReportCompleteToken:
        declaredComplete = true
        continue
      let toks = line.splitWhitespace()
      if toks.len < 2:
        continue
      case toks[0]
      of "client":
        try: clientPid = uint64(parseBiggestUInt(toks[1]))
        except ValueError: discard
      of "daemon":
        try: daemonPid = uint64(parseBiggestUInt(toks[1]))
        except ValueError: discard
      of "run":
        reportRun = toks[1]
      of "nonce":
        reportNonce = toks[1]
      of "read":
        # A read path may itself contain spaces, so take everything after the
        # directive verbatim rather than relying on the whitespace split.
        readPaths.add line[("read".len) .. ^1].strip()
      else:
        discard
    # ---- ROUND-2 R8 authentication (fail-closed: any unmet criterion ⇒ ignore) --
    # 1. client must be a monitored process of THIS invocation.
    if clientPid == 0 or clientPid notin monitored:
      continue
    # 2. run-id scoping — defeats stale / cross-run folding (3c).
    if auth.runId.len == 0 or reportRun != auth.runId:
      continue
    # 3. the connection must have been OBSERVED by the shim.
    if daemonPid == 0 or
        ($clientPid & ":" & $daemonPid) notin auth.connectedPeers:
      continue
    # 4. a supplied nonce must match a recorded one (optional strengthening).
    if reportNonce.len > 0 and reportNonce notin auth.validNonces:
      continue
    # 5. explicit completeness + non-trivial coverage — defeats the no-reads
    #    forgery (3b). A report that lists nothing accounts for nothing.
    var hasRead = false
    for rp in readPaths:
      if rp.len > 0:
        hasRead = true
        break
    if not declaredComplete or not hasRead:
      continue
    # Authenticated — trust the daemon and fold its reads in as real dependencies.
    result.trustedPeerPids.incl daemonPid
    for rp in readPaths:
      if rp.len == 0:
        continue
      result.reads.add MonitorRecord(kind: mrFileRead,
        observationKind: moFileRead, osPid: clientPid, path: rp,
        detail: "breakaway-daemon-report daemon=" & $daemonPid)

proc mergeFragments*(fragmentDir, outputPath: string;
    breakawayReportDir = ""; expectedRootPid: uint64 = 0): MonitorDepFile =
  ## ROUND-2 R1 (ROOT-process completeness guard) — `expectedRootPid` is the pid of
  ## the top-level process the LAUNCHER spawned (io-mon's own `run` driver, the
  ## reprobuild engine's `monitoredAction`, or the codetracer runner). The shim
  ## NEVER loads into a SIP/hardened/notarized root binary (e.g. `/bin/cat`):
  ## DYLD_INSERT_LIBRARIES is stripped, so NO `mrProcessStart` is emitted and the
  ## fragment set is EMPTY — yet the old merge asserted `mcComplete` for an empty
  ## record set (processes=0), a zero-effort false cache hit for the ROOT.
  ##
  ## When `expectedRootPid != 0`, the merge injects a synthetic `mrProcessSpawn`
  ## naming the root as its child, so the EXISTING un-injected-spawn-child check
  ## (`unmonitoredSubtreeLossCount`) fires unless the root actually emitted a
  ## process-start — downgrading an un-monitored root to `mcIncomplete` instead of
  ## a false skip. A root that DID load the shim has a matching process-start, so
  ## the synthetic spawn is matched and there is NO false downgrade.
  ##
  ## CONTRACT FOR LAUNCHERS: any launcher that wraps a root command MUST pass the
  ## pid it spawned as `expectedRootPid` (io-mon's `runMonitoredCommand` already
  ## does). Passing 0 (the default) preserves the legacy behaviour for callers that
  ## merge fragment dirs without having spawned a single known root (e.g. tests
  ## merging hand-built fragments).
  #
  # DSL-port M9.R.15c.1 — close the calling thread's cached fragment
  # handle before merging so any post-SIGKILL or pre-close buffered
  # bytes are visible to the read path. ``readFragmentRecordsTolerant``
  # then surfaces all complete frames, dropping only the last partial
  # frame (if any).
  closeFragmentSlot()
  var records: seq[MonitorRecord] = @[]
  # Fail-closed accounting: any fragment that does not decode cleanly to EOF
  # is a partial or corrupt RMDF write. Per Monitor-Hook-Shim.md §"Failure
  # Semantics" ("partial RMDF writes MUST fail reader validation"; "shim
  # crash MUST reject cache publication"; "successful child exit MUST NOT
  # hide monitor failure"), such evidence MUST NOT be published. We surface
  # it in-band as event-loss so the existing completeness machinery
  # (``summarizeRecords`` → ``depFileFromRecords``) marks the depfile
  # ``mcIncomplete``, which the build engine already rejects for caching.
  # Recovered complete frames are still kept for diagnostics/streaming.
  var corruptFragments = 0
  if dirExists(extendedPath(fragmentDir)):
    for kind, path in walkDir(extendedPath(fragmentDir)):
      if kind == pcFile and path.endsWith(".rmdf-frag"):
        # TOCTOU tolerance: a monitored build spawns many short-lived children,
        # each writing its own .rmdf-frag. A producer can remove/rotate its
        # fragment (or its whole per-process fragment dir) between this walkDir
        # enumeration and the read below — `readFile` then raises IOError
        # ("cannot open"). A vanished fragment carries no recoverable records, so
        # skip it rather than abort the WHOLE merge (which would fail the entire
        # monitored run on a benign cleanup race). OSError covers a directory
        # entry that disappeared underneath the walk.
        try:
          var cleanEof = true
          records.add readFragmentRecordsTolerant(path, cleanEof)
          if not cleanEof:
            inc corruptFragments
        except IOError, OSError:
          discard
  if corruptFragments > 0:
    # One synthetic event-loss record per corrupt fragment. ``mrEventLoss``
    # makes ``summarizeRecords`` count event loss, forcing ``mcIncomplete``.
    for _ in 0 ..< corruptFragments:
      records.add MonitorRecord(kind: mrEventLoss,
        observationKind: moEventLoss,
        detail: "corrupt or partial RMDF fragment in " & fragmentDir)
  # ROUND-2 R5 (kill-before-flush) — a leftover ``.io-mon-reading`` sentinel means
  # a monitored process buffered read records on its MAIN thread and was killed by
  # an uncatchable signal before the tail flushed (no dyld destructor ran). The
  # early-flushed process-start survived but the unflushed reads were lost, so the
  # depfile would otherwise publish ``mcComplete`` minus those reads. One synthetic
  # event-loss per leftover sentinel forces ``mcIncomplete`` (the same conservative
  # re-run machinery as a corrupt fragment). The sentinel is consumed (removed) so a
  # warm-restart merge does not double-count it. See research/.../kill_probe.c.
  var killedReaders = 0
  if dirExists(extendedPath(fragmentDir)):
    for kind, path in walkDir(extendedPath(fragmentDir)):
      if kind == pcFile and path.endsWith(ReadingSentinelExt):
        inc killedReaders
        try: removeFile(extendedPath(path))
        except OSError: discard
  for _ in 0 ..< killedReaders:
    records.add MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
      detail: "process killed with an un-flushed read batch (kill-before-flush)")
  # ROUND-2 R1 (ROOT-process completeness guard) — inject a synthetic spawn naming
  # the launcher-spawned root as its child, BEFORE the breakaway fold and the
  # subtree-loss check, so a root that never loaded the shim (no process-start) is
  # caught by the existing un-injected-spawn-child path. See the proc doc.
  if expectedRootPid != 0:
    records.add MonitorRecord(kind: mrProcessSpawn, observationKind: moExecute,
      osPid: 0, childOsPid: expectedRootPid,
      detail: "io-mon-root-spawn launcher-expected-root")
  # T3a — TRUSTED-DAEMON breakaway compensation (BuildXL Trusted-Tools prior
  # art). Fold any cooperating-daemon reports from `breakawayReportDir` (an
  # explicit arg, else the `IO_MON_BREAKAWAY_REPORT_DIR` env var) into the merge
  # BEFORE the completeness check: the daemon-reported reads become real
  # dependencies in the depfile, and the reporting daemons' pids are exempted
  # from the IPC-connect downgrade so an accounted-for daemon need not force a
  # re-run. See loadBreakawayReports.
  let reportDir =
    if breakawayReportDir.len > 0: breakawayReportDir
    else: getEnv(IoMonBreakawayReportDirEnv)
  var trustedPeerPids = initHashSet[uint64]()
  if reportDir.len > 0:
    # ROUND-2 R8 — authenticate reports against what the shim actually observed
    # (run id, connected peers, recorded nonces) so a forged / partial / stale
    # report can no longer suppress the downgrade. See loadBreakawayReports.
    let fold = loadBreakawayReports(reportDir, monitoredStartPids(records),
      breakawayAuthContext(records))
    for rd in fold.reads:
      records.add rd
    trustedPeerPids = fold.trustedPeerPids
  # T0/T3a — downgrade completeness when the merged evidence proves some
  # spawn/exec subtree ran UN-monitored (un-injectable spawn child or a
  # SETEXEC/execve into a hardened image) OR a client talked to an out-of-tree
  # breakaway daemon over a socket (IPC break #1). One synthetic event-loss per
  # piece of evidence forces `mcIncomplete` via the SAME event-loss machinery as
  # the corrupt-fragment path, so the breakaway becomes a conservative re-run
  # rather than a false skip — self-flagged by io-mon, not left solely to the
  # consumer (Monitor-Hook-Shim.md §"Failure Semantics"). See
  # unmonitoredSubtreeLossCount.
  let subtreeLosses = unmonitoredSubtreeLossCount(records, trustedPeerPids)
  for _ in 0 ..< subtreeLosses:
    records.add MonitorRecord(kind: mrEventLoss,
      observationKind: moEventLoss,
      detail: "unmonitored subtree/peer (un-injectable spawn child, SETEXEC " &
        "into a hardened image, or IPC connect to an out-of-tree breakaway " &
        "daemon)")
  # ROUND-2 R-D (break R10) — AUTO-DOWNGRADE on entropy consumption. A build whose
  # OWN code drew randomness (getentropy / arc4random*) is genuinely non-reproducible:
  # its output cannot be cached on a depfile of FILE deps alone. One synthetic
  # event-loss per `mrNonDeterministic` source forces `mcIncomplete` via the SAME
  # machinery as a corrupt fragment / un-injected subtree — a conservative re-run.
  # ONLY caller-attributed program entropy downgrades here; mrEnvRead/mrSysctlRead
  # are observed inputs, mrTimeRead is recorded-not-downgraded, and a /dev/urandom
  # open is NOT flagged (the cardinal-sin guard). See nonDeterminismLossCount.
  let nonDeterministicLosses = nonDeterminismLossCount(records)
  for _ in 0 ..< nonDeterministicLosses:
    records.add MonitorRecord(kind: mrEventLoss,
      observationKind: moEventLoss,
      detail: "non-deterministic input consumed (the program's own code called " &
        "getentropy/arc4random) — build is not reproducible, always re-run")
  # ROUND-3 S1 — DOWNGRADE on out-of-tree CONTENT CHANNELS: a POSIX shm object not
  # created in-tree, or a FIFO with no in-tree writer. The producer is outside the
  # monitored tree so the consumed content is an invisible input. One synthetic
  # event-loss per unpaired channel forces `mcIncomplete` via the SAME machinery as
  # the IPC-breakaway / non-determinism downgrades — a conservative re-run. A
  # channel a monitored process itself created+fed is paired and does NOT downgrade
  # (the cardinal-sin guard); an inherited socket/pipe is record-not-downgrade
  # (socket provenance is owned by the IPC-connect machinery). See
  # externalContentLossCount.
  let externalContentLosses = externalContentLossCount(records)
  for _ in 0 ..< externalContentLosses:
    records.add MonitorRecord(kind: mrEventLoss,
      observationKind: moEventLoss,
      detail: "out-of-tree content channel consumed (POSIX shm not created " &
        "in-tree, or FIFO with no in-tree writer) — the real input is " &
        "invisible, re-run")
  records.add profileRecords(defaultHooksMonitorProfile(
    when defined(linux): LinuxPreloadSupportedCapabilities
    else: MacosMonitorShimTaxonomyCapabilities))

  let canonical = encodeCanonical(records)
  writeFile(extendedPath(outputPath), canonical.fromBytes())
  depFileFromRecords(records)

proc writeCanonical*(outputPath: string; records: openArray[MonitorRecord]) =
  let canonical = encodeCanonical(records)
  writeFile(extendedPath(outputPath), canonical.fromBytes())
