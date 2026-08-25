import std/[algorithm, atomics, locks, monotimes, os, sets, strutils, tables, times]
from io_mon/paths import extendedPath

import io_mon/codec
import io_mon/capabilities
import io_mon/types
import io_mon/shm/dep_queue
# io-mon-Lossless-Event-Capture M3 (part 1) — the SET transport (nim-shm-gset,
# Candidate C / the M1 winner) is the new PRIMARY Linux dependency channel. The
# producer publishes each observed record into a consumer-owned grow-only set via
# the §5 transport surface; the DEP-SHM ring (`dep_queue`) is retained only for
# the legacy ring tests / any non-`.shard0` segment. We still reuse `dep_queue`'s
# `encodeDepRecord` codec to turn a `MonitorRecord` into the opaque element bytes.
import shm_gset/transport as shmset

const
  hostUsesFileFallback* = not defined(linux)
    ## io-mon-Lossless-Event-Capture M7 (Linux slice) — the platform boundary for
    ## the ``.rmdf-frag`` FILE producer / DEP-FLUSH read-tail / ``.io-mon-reading``
    ## sentinel / sig-safe committed frame / ``FragmentMaxBytesDefault`` byte-cap
    ## and ``mergeFragments``' fragment-dir SCAN + netting.
    ##
    ## ``true``  on macOS / Windows — those shims (``macos_interpose.nim`` /
    ##           ``windows_interpose.nim``) still PRODUCE ``.rmdf-frag`` fragments
    ##           (their shm producer arms are M4/M5), so the whole file subsystem is
    ##           live for them and the reader still SCANS + NETS the fragment dir.
    ## ``false`` on Linux — the producer publishes into the consumer-owned
    ##           ``nim-shm-gset`` (part 2a) and, as of M7, the CONSUMER's launcher-
    ##           side event-loss also goes into that set (``fs_snoop`` no longer
    ##           writes a ``.rmdf-frag``), so the REAL Linux shim flow is file-free
    ##           end-to-end and never scans a fragment dir it did not fill.
    ##
    ## RETIREMENT (per platform, as each arm lands): flip the corresponding OS out
    ## of this predicate and DELETE its file writer + reader scan. Until then the
    ## shared file writer / merge-scan machinery stay COMPILED on every platform —
    ## macOS/Windows NEED them, and io-mon's Linux-run PORTABLE unit tests
    ## (``t0_completeness`` / ``s1_external_content`` / ``parity_with_fs_snoop`` /
    ## ``rd_classification`` / ``sig_safe_committed_frame`` / ``post_fork_sentinel_
    ## hygiene``) drive ``appendFragmentRecord`` / ``mergeFragments`` DIRECTLY as
    ## pure-logic coverage of that shared code, so guarding the symbols off the
    ## Linux build would delete ~90 [OK] of verifiable coverage. Leaving that code
    ## compiled-but-runtime-dead on Linux is deliberate conservative under-guarding.
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
  FragmentMaxBytesDefault = 2'i64 * 1024 * 1024 * 1024  # 2 GiB
    ## LEAK-GUARD — default hard cap on the on-disk size of a SINGLE
    ## (osPid, threadId) `.rmdf-frag` file. The batch buffer above bounds only
    ## the in-MEMORY tail; nothing bounded the FILE, so a monitored process that
    ## OUTLIVES its monitor (a daemon the launcher gave up waiting for — see
    ## `fs_snoop.waitForLinuxInjectedDescendants`, whose grace-period timeout
    ## then removes the fragment dir) kept appending to its cached fd forever.
    ## With the dir gone the fragment inode is UNLINKED but still open, so the
    ## blocks are never reclaimed while the daemon lives — the live-workstation
    ## incident grew ONE such fragment to ~61 GiB and filled the tmpfs. Once a
    ## fragment reaches this cap the producer writes a single event-loss marker
    ## (`mergeFragments` ⇒ `mcIncomplete`, the fail-incomplete contract) and
    ## CLOSES the fd (releasing a deleted inode's blocks); further records for
    ## that producer thread are dropped rather than reopened. The file path is
    ## only the FALLBACK for the shared-memory dep queue, so a well-behaved run
    ## never approaches this. Overridable per process via
    ## `IO_MON_FRAGMENT_MAX_BYTES` (bytes) or `setFragmentByteCap` (tests).
  SigSafeCommittedBufLen* = 256
    ## M9.R.62.2 — max bytes of the pre-encoded async-signal-safe
    ## `read-tail-committed` marker frame stored per fragment slot. The
    ## frame is `4 (length prefix) + 58 (fixed record header) + 4
    ## (empty path len) + 4 (detail len) + detail-bytes`. With
    ## `read-tail-committed run=<64-char-token>`, the detail fits
    ## comfortably under this cap (< 100 bytes); the extra headroom
    ## covers longer run tokens without risking silent truncation.
  ReadingSentinelExt* = ".io-mon-reading"
    ## ROUND-2 R5 — extension of the per-thread "un-flushed read tail" sentinel
    ## file (see `FragmentSlot.readingSentinelActive`). Distinct from `.rmdf-frag`
    ## and `.io-mon-report` so the merge's fragment / report scans never collide
    ## with it. RETAINED for warm-restart cleanup of any stale round-2 sidecars;
    ## the live kill-before-flush guard is now the in-fragment marker below.
  ReadTailPendingDetail* = "read-tail-pending"
    ## ROUND-5 F — the in-fragment kill-before-flush marker. A monitored process
    ## that buffers read records writes THIS marker (an `mrEventLoss` frame)
    ## DIRECTLY to its fragment file and flushes it the instant a batch goes
    ## empty→dirty — BEFORE the buffered reads are durable. A matching
    ## `ReadTailCommittedDetail` marker is written after the batch flush makes the
    ## reads durable. `mergeFragments` NETS pending vs committed per (osPid,
    ## threadId): an unmatched pending means the process was killed (SIGKILL / raw
    ## exit / abort — no destructor) with reads still buffered, so the reads were
    ## lost and a real kill-before-flush event-loss is injected (downgrade).
    ##
    ## This replaces the round-2 sidecar sentinel FILE, which a monitored process
    ## could DEFEAT: its path was world-predictable (`repro-reading-<pid>-<tid>`
    ## in the inherited `REPRO_MONITOR_FRAGMENT_DIR`) so a tracee could `unlink`
    ## it, and its create was best-effort so a tracee could `chmod` the dir to make
    ## the create silently fail (research/adversarial-2026-07-round5/machinery
    ## sab_overflow/sab_unlink/sab_chmod). The in-fragment marker rides in the same
    ## file whose truncation/corruption ALREADY fails closed (the corrupt-fragment
    ## downgrade), and it is written through the ALREADY-OPEN fragment fd so a dir
    ## chmod cannot block it. Removing the marker requires corrupting the fragment
    ## (fails closed) or forging a committed frame through the shim's private,
    ## unpredictable fragment fd — far beyond `unlink(predictable-path)`.
  ReadTailCommittedDetail* = "read-tail-committed"
    ## ROUND-5 F — the durability-confirming counterpart of ReadTailPendingDetail;
    ## written directly to the fragment (and flushed) AFTER a batch flush makes the
    ## buffered reads durable. See ReadTailPendingDetail.
  FragmentCapReachedDetail* = "fragment-byte-cap-reached "
    ## LEAK-GUARD — detail prefix of the event-loss marker written when a fragment
    ## reaches `FragmentMaxBytesDefault`/`fragmentByteCap`. It deliberately does
    ## NOT start with `ReadTailPendingDetail`/`ReadTailCommittedDetail`, so the
    ## read-tail netting in `mergeFragments` leaves it in the record set as a REAL
    ## `mrEventLoss`, forcing `mcIncomplete` (fail-incomplete): the capped run is
    ## honestly reported as needing a re-run rather than a false `mcComplete`.

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
    fileDevice: uint64
    fileId: uint64
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
    # M9.R.62.2 — async-signal-safe kill-before-flush recovery. The
    # `committedFrame` buffer holds a pre-encoded `read-tail-committed`
    # marker frame for THIS slot's (osPid, threadId), sized to hold the
    # header + a modest run-token suffix. `openFragmentSlot` fills it
    # once; a signal handler can then write it verbatim via raw
    # `write(2)` on the slot's fd — no allocation, no fflush, no locks.
    # A signal-death path uses `committedFrameLen` to bound the write.
    committedFrameLen: int32
    committedFrame: array[SigSafeCommittedBufLen, byte]
    # DEP-FLUSH-1 — index (1-based) of this slot's entry in the process-
    # global open-slot registry, or 0 when the slot is not registered. The
    # registry lets `repro_monitor_shim_shutdown` reach EVERY live thread's
    # batch at process exit (a single call otherwise sees only its own
    # threadvar). Storing the index (not a pointer) keeps the unregister
    # path O(1) and the threadvar free of any Nim runtime heap pointer.
    registryIndex: int
    # LEAK-GUARD — running total of bytes this thread has written to the CURRENT
    # (osPid, threadId) fragment file. `openFragmentSlot` resets it to 0; each
    # successful flush / giant-frame write adds the bytes committed. Once it
    # reaches `fragmentByteCap` the slot is retired (fd closed, `overCap` set).
    fragmentBytes: int64
    # LEAK-GUARD — true once this fragment hit the byte cap and its fd was
    # closed. While set (for the SAME osPid/threadId/fragmentDir) further
    # `appendFragmentRecord` calls are DROPPED instead of reopening the fragment
    # and resuming unbounded growth. A key change (fork child, new thread id)
    # opens a fresh slot via `openFragmentSlot`, which clears this.
    overCap: bool
    batchBuf: array[FragmentBatchBufLen, byte]

const
  # DEP-FLUSH-1 — fixed-size process-global registry of open fragment
  # slots. A fixed table (per the milestone spec's "fixed table" option)
  # allocates NO Nim heap on the hot path: registration happens once per
  # thread at first slot open, and each entry is a raw `ptr FragmentSlot`
  # into that thread's TLS. The cap is generous relative to any realistic
  # monitored-process thread count (cmake/ninja worker pools top out in
  # the low thousands); an overflow simply leaves the extra thread
  # unregistered — its batch still flushes on the eager per-record path
  # and via its own pthread-key thread-exit destructor, so correctness is
  # preserved (only the process-exit sweep can't reach it).
  MaxFragmentSlots = 8192

var
  fragmentSlot {.threadvar.}: FragmentSlot
  fragmentOpenCount: Atomic[uint64]
  fragmentWriteCount: Atomic[uint64]
  fragmentFlushCount: Atomic[uint64]
  # DEP-FLUSH-1 — the registry itself. Guarded by `registryLock`; entries
  # hold the address of a thread's `fragmentSlot` threadvar (nil == free).
  # `registryCount` is the high-water mark of used indices so the sweep
  # only scans the populated prefix.
  registryLock: Lock
  registryLockReady = false
  registrySlots: array[MaxFragmentSlots, ptr FragmentSlot]
  registryCount: int
  # io-mon-Lossless-Event-Capture M3 — the process-global producer view of the
  # edge's shared-memory SET (nim-shm-gset), the PRIMARY dependency transport.
  # Attached by `attachDepQueueForShim` when REPRO_MONITOR_DEP_SHM names a
  # `.shard0` path (a set) rather than a legacy ring segment.
  #
  # M3 part 2a — LF-7 + LF-2. `appendFragmentRecord` publishes each record here
  # UNBUFFERED and returns; a durable insert (`emInserted`/`emExists`) does NOT
  # travel the file path. On the ACTIVE set path (any `.shard0` REPRO_MONITOR_DEP_SHM,
  # even one that failed to map) the producer NEVER spills to a `.rmdf-frag` file
  # (LF-2): a capture that cannot be published is surfaced as `mcIncomplete` (a
  # loss-marker element for oversize, the SIGNALLED `growthFailures` counter for
  # OOM saturation, or — when the shim could not attach at all — the absence of the
  # root process-start that the consumer's root-spawn guard downgrades on). The
  # dormant `.rmdf-frag` writer + DEP-FLUSH machinery below stay COMPILED but are
  # reachable only via the legacy ring path or REPRO_MONITOR_DEP_SHM_DISABLE (the
  # golden pure-file baseline). Their deletion is part 2b.
  setProducer: shmset.SetProducer
  setProducerAttached = false
  # M3 part 2a — the per-process-INCARNATION identity appended to every SET element:
  # the process's real on-disk image path (`/proc/self/exe`, set by the shim via
  # `setDepSetIncarnationImage` at init and re-captured after every exec). This is
  # the REAL exec identity, NOT a synthetic nonce. It exists to keep the pre-exec
  # and post-exec `process-start` of ONE pid distinct: those two records are
  # byte-identical (both reset `seq` to 1, same pid/ppid/tid, empty path), so the
  # identity element-key alone would DEDUP the second and break the completeness
  # invariant `startCount == 1 + execCount` — the exec-collision part 1 patched with
  # a random tag. Because the image is per-INCARNATION-constant, a probe storm
  # WITHIN one incarnation still collapses (Candidate-C source-dedup), while a
  # DIFFERENT exec'd image yields a distinct element. It is NOT part of the decoded
  # `MonitorRecord` (`decodeDepRecord` ignores the trailing bytes). M3 (exec-gen):
  # the shim now also folds a per-pid EXEC GENERATION (REPRO_MONITOR_EXEC_GEN,
  # incremented across each exec through the child env) into this identity, so a
  # pid that re-execs the SAME image path (the Nix gcc/rustc bash-wrapper that
  # re-execs the real compiler in-place) keeps those byte-identical process-starts
  # DISTINCT — closing the part-2a over-downgrade to `mcIncomplete` that defeated
  # caching for every Nix-toolchain build. The generation is opaque identity bytes
  # here (the shim composes `<image>\x1f<gen>`); the writer stays image-agnostic.
  setElemImage: string
  # M3 part 2a — a pre-encoded event-loss SET element (built once at attach, so the
  # rare oversize/hard-fail path allocates nothing): inserted when a real record
  # cannot be framed for the set, so the consumer's merge sees `mrEventLoss` and
  # downgrades the edge to `mcIncomplete` (LF-2), never a silent drop.
  setLossElem: array[DepFixedHeaderLen + 64, byte]
  setLossElemLen = 0
  # LEAK-GUARD — process-global per-fragment on-disk byte cap. Resolved ONCE
  # from IO_MON_FRAGMENT_MAX_BYTES on the first fragment open (never from a
  # signal handler) or forced by `setFragmentByteCap`.
  fragmentByteCap: int64 = FragmentMaxBytesDefault
  fragmentByteCapResolved = false

# A generous stack buffer for `encodeDepRecordIdentity` + the incarnation-image
# suffix on the insert hot path — no heap. A record whose encoding exceeds it (a
# pathological path+detail) is surfaced as a loss element (LF-2), never a file spill.
const SetProducerBufBytes = 16384

proc resolveFragmentByteCap() =
  ## LEAK-GUARD — resolve the per-fragment byte cap ONCE per process from
  ## `IO_MON_FRAGMENT_MAX_BYTES` (a positive byte count; absent / <= 0 /
  ## unparseable ⇒ the built-in default). Called on the first fragment open, so
  ## never from signal context.
  if fragmentByteCapResolved:
    return
  fragmentByteCapResolved = true
  let raw = getEnv("IO_MON_FRAGMENT_MAX_BYTES")
  if raw.len > 0:
    try:
      let n = parseBiggestInt(raw)
      if n > 0: fragmentByteCap = int64(n)
    except ValueError:
      discard

proc setFragmentByteCap*(n: int64) =
  ## LEAK-GUARD — override the per-fragment on-disk byte cap. `n <= 0` restores
  ## the built-in default. Public so regression tests can exercise the cap
  ## without writing gigabytes; also marks the cap resolved so a later open does
  ## not clobber it from the environment.
  fragmentByteCap = if n > 0: n else: FragmentMaxBytesDefault
  fragmentByteCapResolved = true

proc fragmentByteCapValue*(): int64 =
  ## Test/introspection — the currently-effective per-fragment byte cap.
  fragmentByteCap

proc fragmentSlotIsOverCap*(): bool =
  ## Test/introspection — true once the calling thread's fragment hit the byte
  ## cap and its fd was closed (LEAK-GUARD retirement). `sigSafeSlotIsOpen`
  ## reads false in the same state.
  fragmentSlot.overCap

proc rebuildDepSetLossElem() =
  ## M3 part 2a (LF-2) — pre-encode the event-loss SET element ONCE per attach so
  ## the hot oversize/hard-fail path allocates nothing. The element is a compact
  ## `mrEventLoss` identity record plus the incarnation-image suffix; when a real
  ## record cannot be framed for the set, the producer inserts this so the
  ## consumer's merge downgrades the edge to `mcIncomplete` (never a silent drop).
  let lossRec = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
    detail: "dep-set-capture-loss")
  var buf {.noinit.}: array[DepFixedHeaderLen + 64, byte]
  let n = encodeDepRecordIdentity(lossRec, buf)
  setLossElemLen = 0
  if n < 0: return
  # Fold in only as much of the incarnation image as still fits the loss buffer;
  # the loss marker's exactness does not matter (any distinct mrEventLoss element
  # forces mcIncomplete), so a truncated suffix is harmless.
  var total = n
  var i = 0
  while i < setElemImage.len and total < setLossElem.len:
    buf[total] = byte(setElemImage[i]); inc total; inc i
  for k in 0 ..< total:
    setLossElem[k] = buf[k]
  setLossElemLen = total

proc setDepSetIncarnationImage*(image: string) =
  ## M3 part 2a — record THIS incarnation's real on-disk image path
  ## (`/proc/self/exe`), the per-incarnation identity appended to every SET
  ## element key (see `setElemImage`). Called by the shim at init and after every
  ## exec (the constructor re-runs), BEFORE the incarnation's process-start is
  ## emitted, so the pre/post-exec process-starts land as DISTINCT set elements
  ## without any synthetic tag. Rebuilds the pre-encoded loss element to carry the
  ## fresh image suffix.
  setElemImage = image
  if setProducerAttached:
    rebuildDepSetLossElem()

proc attachDepQueueForShim*(segmentPath: string) =
  ## Attach the calling PROCESS to the edge's shared-memory dependency SET at
  ## `segmentPath` (the value of `REPRO_MONITOR_DEP_SHM`). Called from
  ## `repro_monitor_shim_init`, and from the fork-child atfork handler after a
  ## detach, so the child maps the segment FRESH rather than inheriting the
  ## parent's fd/mapping. Idempotent.
  ##
  ## io-mon-Lossless-Event-Capture M3 — TRANSPORT SELECTION by segment name. The
  ## io-mon consumer (fs_snoop) creates a nim-shm-gset and names it via
  ## REPRO_MONITOR_DEP_SHM = its shard0 path (ends `.shard0`), so a `.shard0` value
  ## ⇒ attach the SET (the sole Linux dependency channel; part 2b removed the
  ## superseded DEP-SHM ring). A non-`.shard0` value names no transport this
  ## producer understands, so the shim stays on the file path (macOS/Windows arms).
  if segmentPath.len == 0:
    return
  if segmentPath.endsWith(".shard0"):
    if setProducerAttached and setProducer.available:
      return
    setProducer = shmset.attachProducer(segmentPath)
    setProducerAttached = true
    rebuildDepSetLossElem()

proc discardDepQueueAfterFork*(segmentPath: string) =
  ## A fork CHILD inherited the parent's dep-SET mapping COW. Detach it and (if a
  ## segment path is known) re-attach FRESH so the child never publishes through
  ## the parent's inherited fd. Coordinated with the DEP-FLUSH atfork handler
  ## (`discardFragmentSlotAfterFork`) on the platforms that still use the file arm.
  if setProducerAttached:
    setProducer.detach()
    setProducerAttached = false
  attachDepQueueForShim(segmentPath)

proc depSetIsActive*(): bool =
  ## io-mon-Lossless-Event-Capture M3 (part 1) — true when the producer attached
  ## to a live nim-shm-gset (the new primary transport). Test/introspection.
  setProducerAttached and setProducer.available

proc ensureRegistryLock() {.raises: [].} =
  ## DEP-FLUSH-1 — lazily initialise the registry lock. Idempotent; called
  ## under the same one-time-init discipline as the shim's other locks.
  if not registryLockReady:
    initLock(registryLock)
    registryLockReady = true

proc registerFragmentSlot() {.raises: [].} =
  ## DEP-FLUSH-1 — self-register the CALLING thread's slot in the process-
  ## global registry on first open. Idempotent (a slot already carrying a
  ## registryIndex is left untouched). One lock acquisition per thread per
  ## open, never per emit, so the hot path stays alloc- and contention-free.
  if fragmentSlot.registryIndex != 0:
    return
  ensureRegistryLock()
  acquire(registryLock)
  var idx = -1
  # Reuse a freed slot if one exists in the populated prefix.
  for i in 0 ..< registryCount:
    if registrySlots[i] == nil:
      idx = i
      break
  if idx < 0 and registryCount < MaxFragmentSlots:
    idx = registryCount
    inc registryCount
  if idx >= 0:
    registrySlots[idx] = addr fragmentSlot
    fragmentSlot.registryIndex = idx + 1   # 1-based; 0 == unregistered.
  release(registryLock)

proc unregisterFragmentSlot() {.raises: [].} =
  ## DEP-FLUSH-1 — self-unregister the calling thread's slot (close /
  ## fork-child reset / thread-exit). Clears the table entry so the
  ## process-exit sweep never dereferences a stale TLS pointer.
  if fragmentSlot.registryIndex == 0:
    return
  ensureRegistryLock()
  acquire(registryLock)
  let idx = fragmentSlot.registryIndex - 1
  if idx >= 0 and idx < registryCount and
      registrySlots[idx] == addr fragmentSlot:
    registrySlots[idx] = nil
  fragmentSlot.registryIndex = 0
  release(registryLock)

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

proc encodeFrame*(record: MonitorRecord): seq[byte] {.raises: [].}
  ## Forward declaration — `writeReadTailMarker` (the in-fragment kill-before-flush
  ## marker, ROUND-5 F) encodes a single frame; the full definition is below. The
  ## explicit `{.raises: [].}` keeps effect inference from pessimistically assuming
  ## the not-yet-seen body can raise (which would poison every caller's raises list).

proc fragmentPath*(fragmentDir: string; osPid, threadId: uint64): string
    {.raises: [].}
  ## Forward declaration for cached-handle recovery.

var fragmentRunToken: string
  ## ROUND-5 F — the ` run=<id>` suffix (from the shim's REPRO_MONITOR_SESSION) that
  ## the read-tail markers carry so `dropStaleRunRecords` scopes them to their run,
  ## exactly like process-start. Without it an unstamped marker for a pid that spans
  ## two runs in a REUSED fragment dir is "ambiguous" (dropped + a spurious
  ## downgrade), and a stale killed run could false-downgrade the current one. Set
  ## once by the shim at init via `setFragmentRunToken`; empty for legacy callers.

proc setFragmentRunToken*(token: string) =
  ## Publish the current invocation's ` run=<id>` token (or "") to the fragment
  ## writer so the kill-before-flush markers are run-scoped. Idempotent; call once.
  fragmentRunToken = token

# M9.R.62.1 — precise-attribution diagnostic for kill-before-flush residuals.
#
# The two shim-side upstream fixes (direct-exit + pre-exec flush) cover ONE
# class of escape. Pixman's __repro_provider_compile reproducibly leaves 182
# unmatched read-tail-pending markers. To bisect between the two remaining
# candidates without speculation:
#
#   Candidate 2 (execve flush-vs-exec-transition race): shim's execve hook
#     bailed on shouldBypass() BEFORE flushing, or the flush raced the kernel
#     exec transition. Escape signature: pending marker's ctx carries
#     `phase=execve`.
#
#   Candidate 3 (TLS-inherited shouldBypass gating): child inherits
#     `inForkChild=true` or `disabled>0` after a fork; every hook (including
#     repro_hook_exit) bails, so closeFragmentSlot / matching committed
#     marker are never written. Escape signature: pending marker's ctx
#     carries `bypassed=1` at the last-hook-context sample.
#
# Mechanism: the shim publishes a per-thread "diagnostic context" string via
# setKillDiagContext (called on every hook enter that could alter shouldBypass
# state). writeReadTailMarker embeds it in the marker's detail when
# IO_MON_KILL_DIAG=1 is set. mergeFragments extracts the last-seen ctx from
# each mismatched pending and copies it into the synthetic event-loss detail.
# The M9.R.62 evidence file then counts markers by ctx to identify the
# dominant candidate.

const
  KillDiagEnvVar* = "IO_MON_KILL_DIAG"
  KillDiagDeepEnvVar* = "IO_MON_KILL_DIAG_DEEP"
    ## M9.R.64.1 — opt-in super-set of KillDiagEnvVar. When set, the shim's
    ## per-thread diagnostic ctx is augmented with much richer state:
    ## argv[0] + full-argv snapshot at shim init, per-thread last-emit
    ## `record.kind` + `record.path` head, per-thread emit counter,
    ## pid/ppid/tid snapshot. Enables killDiag as well, so a single env
    ## var enables the full attribution path.
  KillDiagCtxTag* = " ctx="
    ## Prefix used in the pending marker's detail to carry the shim's
    ## last-observed diagnostic context; matches `mergeFragments`' regex-free
    ## split so the tag survives the ` run=<id>` suffix.

var killDiagEnabled: bool
var killDiagDeepEnabled: bool
var killDiagChecked: bool

proc killDiagIsOn*(): bool =
  if not killDiagChecked:
    killDiagChecked = true
    let v = getEnv(KillDiagEnvVar)
    let vDeep = getEnv(KillDiagDeepEnvVar)
    killDiagDeepEnabled = vDeep.len > 0 and vDeep != "0"
    # Deep implies base (deep is a super-set of the base ctx sampling).
    killDiagEnabled = killDiagDeepEnabled or (v.len > 0 and v != "0")
  killDiagEnabled

proc killDiagDeepIsOn*(): bool =
  ## M9.R.64.1 — TRUE when `IO_MON_KILL_DIAG_DEEP` was set to a non-empty,
  ## non-`0` value at first `killDiagIsOn()` evaluation. Same
  ## check-once-cache semantics as `killDiagIsOn`.
  discard killDiagIsOn()
  killDiagDeepEnabled

var killDiagContext {.threadvar.}: string
  ## Per-thread diagnostic context sampled by the shim on every hook entry
  ## that could change shouldBypass()'s value. writeReadTailMarker embeds
  ## this into the pending marker so kill-before-flush event-loss records
  ## carry attribution when the process later dies un-flushed.

# M9.R.64.1 — extra per-thread deep-attribution slots. All fixed-size POD
# so they survive on threadvar without any Nim runtime allocation and
# they refresh cheaply on every emitRecord. Each is opt-in behind
# `killDiagDeepIsOn()` so the base kill-diag path stays cheap.
const
  DeepArgvBufLen* = 240
    ## Fixed buffer for a cmdline snapshot ("argv0 \x00 argv1 \x00 ..."
    ## as pulled from /proc/self/cmdline, NULs rewritten to spaces).
  DeepLastPathBufLen* = 160
    ## Fixed buffer for the last-observed captured-dependency record's
    ## path prefix.

var killDiagDeepArgvBuf {.threadvar.}: array[DeepArgvBufLen, char]
var killDiagDeepArgvLen {.threadvar.}: int
var killDiagDeepArgvSampled {.threadvar.}: bool
var killDiagDeepLastPathBuf {.threadvar.}: array[DeepLastPathBufLen, char]
var killDiagDeepLastPathLen {.threadvar.}: int
var killDiagDeepLastKind {.threadvar.}: int
var killDiagDeepEmitCount {.threadvar.}: uint32
var killDiagDeepLastHook {.threadvar.}: array[32, char]
var killDiagDeepLastHookLen {.threadvar.}: int
var killDiagDeepSignalCode {.threadvar.}: int
var killDiagDeepShimState {.threadvar.}: int
  ## Bit flags — see `KillDiagShimState*` below. Refreshed at init.

const
  KillDiagShimStateInitialized* = 0x1
  KillDiagShimStateSigHandlersInstalled* = 0x2
  KillDiagShimStateInlinePatchesInstalled* = 0x4

proc setKillDiagContext*(ctx: string) =
  ## Publish the calling thread's diagnostic context. Cheap no-op when
  ## `IO_MON_KILL_DIAG` is off. Callers pass short tokens like
  ## "hook=read bypassed=0" — space-separated key=value pairs.
  if not killDiagIsOn():
    return
  killDiagContext = ctx

proc setKillDiagDeepArgv*(cstrBuf: ptr UncheckedArray[byte]; len: int)
    {.raises: [].} =
  ## M9.R.64.1 — copy up to DeepArgvBufLen-1 bytes of the raw
  ## /proc/self/cmdline snapshot into the thread's argv slot. NUL bytes
  ## are rewritten to spaces on copy so the resulting string is a
  ## single space-separated token. `sampled` toggles TRUE so subsequent
  ## re-invocations are no-ops (argv doesn't change post-exec).
  if not killDiagDeepIsOn():
    return
  if killDiagDeepArgvSampled:
    return
  var n = len
  if n < 0: n = 0
  if n >= DeepArgvBufLen: n = DeepArgvBufLen - 1
  for i in 0 ..< n:
    let b = cstrBuf[i]
    killDiagDeepArgvBuf[i] = (if b == 0'u8: ' ' else: char(b))
  killDiagDeepArgvBuf[n] = '\0'
  killDiagDeepArgvLen = n
  killDiagDeepArgvSampled = true

proc setKillDiagDeepLastPath*(path: string; kind: int) {.raises: [].} =
  ## M9.R.64.1 — remember the last captured-dependency path (up to
  ## DeepLastPathBufLen-1 bytes) + the record kind, so a subsequent
  ## pending marker carries the last-seen emit target. Overwrites on
  ## every call (the marker only needs the latest one).
  if not killDiagDeepIsOn():
    return
  var n = path.len
  if n >= DeepLastPathBufLen: n = DeepLastPathBufLen - 1
  for i in 0 ..< n:
    killDiagDeepLastPathBuf[i] = path[i]
  if n < DeepLastPathBufLen:
    killDiagDeepLastPathBuf[n] = '\0'
  killDiagDeepLastPathLen = n
  killDiagDeepLastKind = kind
  inc killDiagDeepEmitCount

proc setKillDiagDeepLastHook*(hook: string) {.raises: [].} =
  ## M9.R.64.1 — remember the last shim hook the thread entered.
  ## Kept separate from the string ctx (phase=) so a hook that
  ## doesn't own a sampleKillDiag call site can still populate this.
  if not killDiagDeepIsOn():
    return
  var n = hook.len
  if n >= killDiagDeepLastHook.len: n = killDiagDeepLastHook.len - 1
  for i in 0 ..< n:
    killDiagDeepLastHook[i] = hook[i]
  if n < killDiagDeepLastHook.len:
    killDiagDeepLastHook[n] = '\0'
  killDiagDeepLastHookLen = n

proc setKillDiagDeepSignalCode*(signum: int) {.raises: [].} =
  ## M9.R.64.1 — remember the last terminating-signal number the
  ## async-signal-safe handler saw before flushing. Zero means no
  ## signal has arrived.
  if not killDiagDeepIsOn():
    return
  killDiagDeepSignalCode = signum

proc setKillDiagDeepShimState*(state: int) {.raises: [].} =
  ## M9.R.64.1 — refresh the shim's state bitmap (initialized /
  ## sig-handlers installed / inline patches installed) at each
  ## setup milestone in the shim's constructor.
  if not killDiagDeepIsOn():
    return
  killDiagDeepShimState = state

proc appendDeepAscii(buf: var string; src: openArray[char]; maxLen: int) =
  ## Local helper — append at most `maxLen` chars from `src`, replacing
  ## any character NOT in {printable-ASCII except `[` `]`} with `?` so
  ## the ctx string stays regex-safe on the merge side.
  var i = 0
  while i < src.len and i < maxLen:
    let c = src[i]
    if c == '\0': break
    if c >= ' ' and c < 127.char and c != '[' and c != ']':
      buf.add c
    else:
      buf.add '?'
    inc i

proc killDiagContextForMarker(): string =
  if not killDiagIsOn():
    return ""
  if killDiagContext.len == 0 and not killDiagDeepIsOn():
    return ""
  result = KillDiagCtxTag
  if killDiagContext.len > 0:
    result.add killDiagContext
  if killDiagDeepIsOn():
    result.add " emits=" & $killDiagDeepEmitCount
    result.add " shimState=0x" & toHex(killDiagDeepShimState, 2)
    if killDiagDeepSignalCode != 0:
      result.add " sig=" & $killDiagDeepSignalCode
    if killDiagDeepLastKind != 0:
      result.add " lastKind=" & $killDiagDeepLastKind
    if killDiagDeepLastHookLen > 0:
      result.add " lastHook="
      appendDeepAscii(result, killDiagDeepLastHook, killDiagDeepLastHookLen)
    if killDiagDeepLastPathLen > 0:
      result.add " lastPath="
      appendDeepAscii(result, killDiagDeepLastPathBuf,
        killDiagDeepLastPathLen)
    if killDiagDeepArgvLen > 0:
      result.add " argv="
      appendDeepAscii(result, killDiagDeepArgvBuf, killDiagDeepArgvLen)

# M9.R.62.2 — async-signal-safe accessors. A shim signal handler (see
# `installTerminatingSignalHandlers` in linux_preload.nim) can query these
# to write the calling thread's pre-encoded committed-marker frame + any
# in-flight batch buffer to the fragment fd via raw write(2), then close
# the fd — all without allocation, without fflush, without lock acquisition.
# Every accessor returns fixed-size data or bounded pointers into the
# threadvar; no code path in these accessors triggers heap allocation
# once the slot is open.

proc sigSafeSlotIsOpen*(): bool {.raises: [].} =
  fragmentSlot.isOpen

proc sigSafeSlotFd*(): cint {.raises: [].} =
  ## Returns the OS-level file descriptor of the calling thread's
  ## fragment slot, or -1 if no slot is open. `File.getFileHandle` on
  ## POSIX is a thin wrapper around `fileno(3)` — signal-safe per
  ## POSIX.1-2017 Table 2-4.
  if not fragmentSlot.isOpen:
    return cint(-1)
  try:
    result = cint(fragmentSlot.file.getFileHandle())
  except IOError:
    result = cint(-1)

proc sigSafeSlotDevice*(): uint64 {.raises: [].} =
  fragmentSlot.fileDevice

proc sigSafeSlotFileId*(): uint64 {.raises: [].} =
  fragmentSlot.fileId

proc sigSafeBatchPtr*(): pointer {.raises: [].} =
  addr fragmentSlot.batchBuf[0]

proc sigSafeBatchLen*(): int {.raises: [].} =
  fragmentSlot.batchLen

proc sigSafeCommittedPtr*(): pointer {.raises: [].} =
  addr fragmentSlot.committedFrame[0]

proc sigSafeCommittedLen*(): int {.raises: [].} =
  int(fragmentSlot.committedFrameLen)

proc sigSafeMarkSlotClosed*() {.raises: [].} =
  ## Called by the signal handler AFTER it has written the batch +
  ## committed marker + closed the fd via raw syscalls. Marks the slot
  ## bookkeeping as closed so any post-recovery code path (unlikely on
  ## a terminating signal) sees a consistent view. Does NOT close the
  ## Nim `File` handle — the raw `close(2)` already did — so the finalizer
  ## is a POD-only reset. All assignments to fixed-size fields are
  ## async-signal-safe.
  fragmentSlot.isOpen = false
  fragmentSlot.batchLen = 0
  fragmentSlot.readingSentinelActive = false
  fragmentSlot.committedFrameLen = 0

proc fragmentHandleIsCurrent(): bool {.raises: [].}
proc reopenFragmentHandle(): bool {.raises: [].}

proc writeReadTailMarker(detail: string) =
  ## ROUND-5 F — write a kill-before-flush bookkeeping marker (`mrEventLoss` with
  ## `detail`, stamped with the current run token) DIRECTLY to the calling thread's
  ## already-open fragment file and flush it, so it is durable independently of the
  ## batch buffer. Keyed on the slot's (osPid, threadId) — and run-scoped via the
  ## token — so `mergeFragments` can net pending vs committed per thread within the
  ## run. Best-effort at the syscall level (a short write / flush failure is
  ## swallowed — it never aborts the monitored process), but UNLIKE the round-2
  ## sidecar it does not depend on a writable directory: the fd is already open, so a
  ## tracee that chmod's the fragment dir cannot block it.
  if not fragmentSlot.isOpen:
    return
  if not fragmentHandleIsCurrent() and not reopenFragmentHandle():
    return
  let marker = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
    osPid: fragmentSlot.osPid, threadId: fragmentSlot.threadId,
    detail: detail & fragmentRunToken & killDiagContextForMarker())
  let frame = encodeFrame(marker)
  try:
    let n = fragmentSlot.file.writeBuffer(unsafeAddr frame[0], frame.len)
    if n == frame.len:
      flushFile(fragmentSlot.file)
  except IOError, OSError:
    discard

proc kindCarriesCapturedDependency(k: MonitorRecordKind): bool {.inline.} =
  ## M9.R.62.2 — the kill-before-flush pending sentinel is a CACHE-KEY
  ## soundness guard: an unmatched pending means the process died with
  ## un-flushed CAPTURED-DEPENDENCY records, so `mergeFragments`
  ## downgrades to `mcIncomplete` (re-run the build). But process-
  ## lifecycle records (mrProcessStart, mrProcessExec, mrProcessSpawn,
  ## mrBackendProfile, mrCapabilityGap) DO NOT carry captured
  ## dependencies — losing one only omits a redundant restatement of
  ## the process tree already recorded via its parent's process-spawn
  ## + the ancestor exec events. Firing the pending sentinel for those
  ## records over-nets: a fresh-exec'd process that ONLY got as far as
  ## its shim constructor (`recordProcessStart`) before dying via a
  ## path outside our reach (raw syscall(SYS_exit_group), etc.) writes
  ## a pending it never retires, and mergeFragments false-downgrades
  ## the whole build to mcIncomplete on 182 identical shim-only pids in
  ## the pixman workload (see recipes/reproos-image/run-evidence/m9r62/
  ## m9r62_phaseA_attribution.txt for the empirical characterisation).
  ##
  ## Fire the pending sentinel ONLY for records that would actually
  ## lose captured dependencies. The dependency-emitting kinds are the
  ## ones a downstream consumer folds into its cache key:
  ##   mrFileOpen, mrFileRead, mrPathProbe, mrDirectoryEnumerate,
  ##   mrFileWrite, mrIpcConnect, mrLibraryLoad, mrEnvRead,
  ##   mrSysctlRead, mrTimeRead, mrNonDeterminismConsume.
  ## Lifecycle + backend + explicit-loss kinds are excluded.
  case k
  of mrProcessStart, mrProcessExec, mrProcessSpawn,
     mrBackendProfile, mrCapabilityGap, mrEventLoss:
    false
  else:
    true

const LocalFdCreateDetailPrefix* = "chan=localfd role=create"
  ## IoMon-Pipeline-Capture IM-3 — the exact `detail` prefix the shims stamp on a
  ## local-IPC-fd CREATE record. The run token is appended AFTER the existing
  ## detail (`stampRunId`), so a prefix match identifies the class unambiguously.

proc recordSuppressesOnlyADowngrade(record: MonitorRecord): bool {.inline.} =
  ## IM-3 — true for a record whose ONLY effect downstream is to SUPPRESS a
  ## downgrade, never to add a dependency or to cause one.
  ##
  ## `chan=localfd role=create` is the sole member today: `externalContentLossCount`
  ## consults it exclusively as the right-hand side of a pairing, so losing one can
  ## only leave a consume UNPAIRED — a conservative extra re-run. It can never
  ## produce a false `mcComplete`. Contrast the other `mrExternalContent` roles
  ## (`opaque read`, `shm attach`, `fifo read`), each of which is the thing that
  ## CAUSES a downgrade: losing one of those DOES risk the cardinal sin, so they
  ## stay fully sentinel-guarded.
  record.kind == mrExternalContent and
    record.detail.startsWith(LocalFdCreateDetailPrefix)

proc markReadingSentinel(record: MonitorRecord) =
  ## ROUND-5 F — record that this thread's batch now holds non-durable
  ## CAPTURED-DEPENDENCY bytes, by writing a durable `read-tail-pending`
  ## marker INTO the fragment ONCE per dirty cycle (see
  ## ReadTailPendingDetail for why in-fragment, not a sidecar file).
  ##
  ## M9.R.62.2 refinement: gate on `kindCarriesCapturedDependency` so a
  ## process-lifecycle-only batch (e.g. shim init emitted its
  ## process-start and the process then died via raw exit_group) does
  ## not fire a pending sentinel it can never retire. The flag itself
  ## still switches only ONCE per dirty→clean cycle (any subsequent
  ## dep-emitting record in the same cycle is a no-op).
  ##
  ## IM-3 extends the same reasoning from record KIND to a record whose loss is
  ## provably fail-safe: a `localfd create` (see
  ## `recordSuppressesOnlyADowngrade`). Without this, arming the sentinel for a
  ## create re-creates the M9.R.62.2 over-netting in a new place — a process that
  ## calls `pipe()` and then loses its fragment descriptor (the
  ## `test_io_mon_linux_fragment_fd_reuse` tracee hijacks it with `dup2`) writes a
  ## pending it can never retire, and the run false-downgrades on a record that
  ## could not have mattered.
  if not kindCarriesCapturedDependency(record.kind):
    return
  if recordSuppressesOnlyADowngrade(record):
    return
  if fragmentSlot.readingSentinelActive or not fragmentSlot.isOpen:
    return
  writeReadTailMarker(ReadTailPendingDetail)
  fragmentSlot.readingSentinelActive = true

proc clearReadingSentinel() =
  ## ROUND-5 F — the batch just became durable (flushed); write a matching
  ## `read-tail-committed` marker so `mergeFragments` nets this cycle to zero (a
  ## clean continuation / exit is NOT mistaken for a kill-before-flush).
  if not fragmentSlot.readingSentinelActive:
    return
  writeReadTailMarker(ReadTailCommittedDetail)
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

proc captureFragmentHandleIdentity(): bool {.raises: [].} =
  try:
    let info = getFileInfo(fragmentSlot.file)
    fragmentSlot.fileDevice = uint64(info.id.device)
    fragmentSlot.fileId = uint64(info.id.file)
    result = true
  except IOError, OSError:
    result = false

proc fragmentHandleIsCurrent(): bool {.raises: [].} =
  if not fragmentSlot.isOpen or fragmentSlot.file.isNil:
    return false
  try:
    let info = getFileInfo(fragmentSlot.file.getFileHandle())
    result = uint64(info.id.device) == fragmentSlot.fileDevice and
      uint64(info.id.file) == fragmentSlot.fileId
  except IOError, OSError:
    result = false

proc reopenFragmentHandle(): bool {.raises: [].} =
  ## The descriptor may have been replaced through a hidden libc call or raw
  ## syscall. Do not fclose the stale FILE because that descriptor number may
  ## now belong to the tracee; detach it and reopen the same fragment instead.
  let path = fragmentPath(slotFragmentDir(fragmentSlot),
    fragmentSlot.osPid, fragmentSlot.threadId)
  fragmentSlot.file = nil
  try:
    if not open(fragmentSlot.file, extendedPath(path), fmAppend):
      fragmentSlot.isOpen = false
      unregisterFragmentSlot()
      return false
  except IOError, OSError, ValueError:
    fragmentSlot.isOpen = false
    unregisterFragmentSlot()
    return false
  if not captureFragmentHandleIdentity():
    try: close(fragmentSlot.file)
    except IOError, OSError: discard
    fragmentSlot.file = nil
    fragmentSlot.isOpen = false
    unregisterFragmentSlot()
    return false
  discard fragmentOpenCount.fetchAdd(1, moRelaxed)
  true

proc accountFragmentBytes(written: int) =
  ## LEAK-GUARD — record `written` on-disk bytes against the calling thread's
  ## current fragment and, once the running total reaches `fragmentByteCap`,
  ## RETIRE the fragment: write a single event-loss marker so `mergeFragments`
  ## downgrades the run to `mcIncomplete` (fail-incomplete), then CLOSE the fd.
  ##
  ## Closing the fd is the load-bearing half of the fix: if the launcher already
  ## removed the fragment dir (the daemon-outlives-monitor case), the fragment
  ## inode is unlinked and only this fd keeps its blocks alive; closing releases
  ## them and stops all further growth. The slot keeps its
  ## (osPid, threadId, fragmentDir) key plus `overCap`, so `appendFragmentRecord`
  ## drops later records for this producer thread instead of reopening and
  ## resuming unbounded growth. A different key (fork child / new thread) opens a
  ## fresh, uncapped fragment via `openFragmentSlot`.
  if fragmentSlot.overCap or not fragmentSlot.isOpen:
    return
  fragmentSlot.fragmentBytes += int64(written)
  if fragmentSlot.fragmentBytes < fragmentByteCap:
    return
  # Cap reached — mark the run incomplete through the already-open fd (a dir
  # chmod / removal cannot block it), then retire the fd.
  writeReadTailMarker(FragmentCapReachedDetail)
  fragmentSlot.overCap = true
  clearReadingSentinel()
  try:
    close(fragmentSlot.file)
  except IOError, OSError:
    discard
  fragmentSlot.isOpen = false
  fragmentSlot.batchLen = 0
  fragmentSlot.batchOpenedAtNs = 0
  fragmentSlot.batchProbeCountdown = 0
  fragmentSlot.readingSentinelActive = false
  # Leave osPid/threadId/fragmentDir set so the drop guard in
  # `appendFragmentRecord` recognises this retired producer key.
  unregisterFragmentSlot()

proc flushFragmentBatch*() =
  ## DSL-port M9.R.15f.1 — flush the in-flight batch buffer (if any)
  ## to the cached fragment file. Public so external code (close,
  ## merge, test teardown) can force a sync point without closing the
  ## file handle. If the slot is not open or the batch is empty, the
  ## call is a no-op.
  if not fragmentSlot.isOpen or fragmentSlot.batchLen == 0:
    return
  if not fragmentHandleIsCurrent() and not reopenFragmentHandle():
    raiseEnvelopeError(eeMalformed,
      "cannot recover externally replaced RMDF fragment handle")
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
  # LEAK-GUARD — account the just-committed bytes; retires the fragment (closes
  # the fd, drops further records) once it reaches `fragmentByteCap`.
  accountFragmentBytes(bufLen)

proc closeFragmentSlot*() =
  ## Force the calling thread's cached fragment-log handle (if any) to
  ## close. Called on shim shutdown / thread exit / test teardown.
  ## M9.R.15f.1 — flush any in-flight batch buffer before closing so
  ## the on-disk fragment includes every appended frame.
  if fragmentSlot.isOpen:
    if not fragmentHandleIsCurrent() and not reopenFragmentHandle():
      return
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
    # LEAK-GUARD — a normal close clears the cap bookkeeping too.
    fragmentSlot.fragmentBytes = 0
    fragmentSlot.overCap = false
    # DEP-FLUSH-1 — leave the registry; the slot is now closed.
    unregisterFragmentSlot()

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
  # LEAK-GUARD — the child gets a clean byte budget under its own identity; a
  # parent that hit the cap must not leave the child stuck dropping records.
  fragmentSlot.fragmentBytes = 0
  fragmentSlot.overCap = false
  # ROUND-5 F (post-fork sentinel-state hygiene) — the child inherits the
  # parent's `readingSentinelActive` value via copy-on-write. Without
  # resetting it here, the child's first `markReadingSentinel` bails on
  # the "already active" guard and NEVER writes its own pending marker;
  # then the child's subsequent flush retires a phantom "cycle" by
  # writing an orphan committed marker under the CHILD's (osPid,
  # threadId). mergeFragments' pending-vs-committed netting is
  # per-(osPid, threadId), so the orphan committed is harmless
  # (max(0, -1) clamps to 0), but every intermediate child batch cycle
  # is UN-BOOKKEEPED — a kill-before-flush IN the child on any of
  # those cycles goes silently un-detected. Reset the flag so the
  # child's first read faithfully re-marks the sentinel under its own
  # identity. `closeFragmentSlot` (line 346) already does this on the
  # parent's flush path; parity below matches it on the fork-child path.
  fragmentSlot.readingSentinelActive = false
  # DEP-FLUSH-4 — the child inherited a COW copy of the WHOLE registry
  # table (holding the addresses of the PARENT's per-thread slots, which
  # in the child are stale TLS the child must never sweep). Reset the
  # entire registry to empty so a shutdown sweep in the child can only
  # ever reach the child's OWN re-registered slot. The registry lock is
  # also reset: a sibling parent thread could have held it at fork time,
  # leaving the inherited copy locked forever (classic fork-in-locked
  # state). The single-threaded-parent fork path is the only caller, so a
  # bare re-init is safe.
  registryLockReady = false
  for i in 0 ..< registryCount:
    registrySlots[i] = nil
  registryCount = 0
  fragmentSlot.registryIndex = 0

proc flushAllRegisteredSlots*() =
  ## DEP-FLUSH-1 — flush the in-flight batch of EVERY slot currently in the
  ## process-global registry (including the caller's), then, for the
  ## caller's own slot, close it. Invoked by `repro_monitor_shim_shutdown`
  ## on the process-exit path so a short-lived multi-threaded process does
  ## not strand any thread's buffered tail. Best-effort: a slot whose owning
  ## thread already exited went through the pthread-key destructor
  ## (DEP-FLUSH-3) and is no longer registered, so the sweep only touches
  ## still-live threads' batches.
  ##
  ## Cross-thread flush safety: each entry is a raw `ptr FragmentSlot` into
  ## another thread's TLS. Flushing it issues `writeBuffer`+`flushFile` on
  ## that slot's already-open fd. At a true process-exit point (destructor /
  ## exit hook) no other thread is making forward progress, so the sweep is
  ## quiescent; the append-only fd + length-prefixed frames + tolerant
  ## reader mean even a rare overlap can at worst re-flush already-durable
  ## bytes, never lose or duplicate a committed frame.
  ensureRegistryLock()
  acquire(registryLock)
  for i in 0 ..< registryCount:
    let slot = registrySlots[i]
    if slot == nil:
      continue
    if slot == addr fragmentSlot:
      # Defer the caller's own slot to the close below so it gets ONE
      # consistent teardown (flush + close + unregister).
      continue
    if slot.isOpen and slot.batchLen > 0:
      let bufLen = slot.batchLen
      try:
        let written = slot.file.writeBuffer(addr slot.batchBuf[0], bufLen)
        if written == bufLen:
          flushFile(slot.file)
          discard fragmentWriteCount.fetchAdd(1, moRelaxed)
          discard fragmentFlushCount.fetchAdd(1, moRelaxed)
        slot.batchLen = 0
        slot.batchOpenedAtNs = 0
        slot.batchProbeCountdown = 0
      except IOError, OSError:
        slot.batchLen = 0
  release(registryLock)
  # Close the caller's own slot (flushes its batch + retires its sentinel +
  # unregisters) on the normal path.
  closeFragmentSlot()

proc threadExitFlushSlot*() =
  ## DEP-FLUSH-3 — flush + close + unregister the CALLING thread's slot.
  ## Wired to a `pthread_key_create` destructor in the shim so a worker
  ## thread that emits records then exits (returns from its start routine
  ## or calls `pthread_exit`) durably writes its batch BEFORE its TLS is
  ## torn down — the process-exit destructor (main thread) cannot reach an
  ## already-dead worker's slot. `closeFragmentSlot` already flushes the
  ## batch, retires the reading sentinel, closes the fd and unregisters, so
  ## this is a thin, intention-revealing wrapper the shim can name.
  closeFragmentSlot()

proc fragmentSlotIsRegistered*(): bool =
  ## Test/introspection helper — true when the calling thread's slot holds
  ## a live registry index.
  fragmentSlot.registryIndex != 0

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
    raiseEnvelopeError(eeMalformed, "short write to RMDF depfile")

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

proc precomputeSigSafeCommittedFrame(slot: var FragmentSlot) =
  ## M9.R.62.2 — pre-encode the `read-tail-committed` marker frame for
  ## this slot's (osPid, threadId) into a fixed byte buffer inside the
  ## slot itself. An async-signal-safe kill-before-flush recovery handler
  ## can then write this frame verbatim via raw `write(2)` — no
  ## allocation, no fflush, no lock acquisition. The detail carries the
  ## current run token (`read-tail-committed run=<id>`); diag context is
  ## intentionally omitted because a signal-death path has no way to
  ## sample it safely, and the ctx-tag is only used for pending markers
  ## anyway (`mergeFragments` extracts it from unmatched pending, not
  ## from committed).
  const RecordHeaderBytes = 2 + 2 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4
  let detail = ReadTailCommittedDetail & fragmentRunToken
  let detailLen = detail.len
  let payloadLen = RecordHeaderBytes + 4 + 0 + 4 + detailLen
  let frameLen = 4 + payloadLen
  if frameLen > SigSafeCommittedBufLen:
    # Would overflow the async-signal-safe buffer; leave len=0 so the
    # signal handler skips the committed emit. Netting will remain
    # "one unmatched pending" for such an extreme run token — safer to
    # under-net (a spurious event-loss, mcIncomplete) than to
    # over-write past the buffer.
    slot.committedFrameLen = 0
    return
  var cursor = 0
  template putByte(b: byte) =
    slot.committedFrame[cursor] = b
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
  # Frame length prefix.
  putU32Le(uint32(payloadLen))
  # Record header — MUST match encodeRecordPayload / appendFragmentRecord.
  putU16Le(uint16(ord(mrEventLoss)))
  putU16Le(uint16(ord(moEventLoss)))
  putU64Le(0'u64)                          # seq
  putU64Le(slot.osPid)
  putU64Le(0'u64)                          # parentOsPid
  putU64Le(slot.threadId)
  putU64Le(0'u64)                          # childOsPid
  putU64Le(0'u64)                          # result
  putU32Le(0'u32)                          # flags
  putU32Le(0'u32)                          # probeResult
  putU32Le(0'u32)                          # path len
  putU32Le(uint32(detailLen))
  if detailLen > 0:
    copyMem(addr slot.committedFrame[cursor],
            unsafeAddr detail[0], detailLen)
    cursor += detailLen
  slot.committedFrameLen = int32(cursor)

proc openFragmentSlot(fragmentDir: string; osPid, threadId: uint64;
                      path: string): bool =
  if not open(fragmentSlot.file, extendedPath(path), fmAppend):
    return false
  if not captureFragmentHandleIdentity():
    try: close(fragmentSlot.file)
    except IOError, OSError: discard
    fragmentSlot.file = nil
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
  # LEAK-GUARD — a fresh fragment starts with a clean byte budget and no
  # cap-retirement carried over from a previous (osPid, threadId).
  resolveFragmentByteCap()
  fragmentSlot.fragmentBytes = 0
  fragmentSlot.overCap = false
  precomputeSigSafeCommittedFrame(fragmentSlot)
  # DEP-FLUSH-1 — join the process-global registry so a shutdown sweep on
  # ANY thread can reach this batch. No-op after the first open per thread.
  registerFragmentSlot()
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
  # io-mon-Lossless-Event-Capture M3 part 2a — PRIMARY path is the SET transport
  # (nim-shm-gset, the M1-winning Candidate-C channel). Part 2b removed the
  # superseded DEP-SHM ring, so the only channels are the SET (Linux) and the
  # `.rmdf-frag` file writer below (the retained macOS/Windows arm + the Linux
  # launcher-side loss marker).
  #
  # LF-7 (unbuffered publish-before-return): encode the record's DEDUP element-key
  # with `encodeDepRecordIdentity` (drops `seq`, so exact-duplicate probe storms
  # collapse) into a STACK buffer (no heap — fork/orc-safe), append this
  # incarnation's real image path (`setElemImage`, the per-exec identity that keeps
  # the pre/post-exec process-starts distinct without any synthetic tag), then
  # `emit` the opaque bytes with a SINGLE idempotent insert. No batch, no flush:
  # the hook has already run the syscall but returns the result to the process only
  # AFTER this publish, so the dependency is recorded before the observed data is
  # handed back.
  #
  # LF-2 (unattached ⇒ hard fail, NO file spill): once we are on the active set
  # path (`setProducerAttached` — REPRO_MONITOR_DEP_SHM named a `.shard0`), a record
  # NEVER falls through to the `.rmdf-frag` writer. A durable insert returns; any
  # capture failure is surfaced as `mcIncomplete` instead of a silent file spill:
  #   * emInserted/emExists  — durable in consumer-owned memory (LF-3). Return.
  #   * emSaturated          — OOM growth failure, SIGNALLED via `growthFailures()`;
  #                            the consumer reads it and downgrades. Return.
  #   * emConsumerGone       — the consumer marked itself gone (run teardown / the
  #                            orphan class, LF-4). The run's depfile is already
  #                            written; drop, bounded. Return.
  #   * emOversize/emUnavailable, or an unframable record — insert the pre-encoded
  #                            loss element so the merge sees `mrEventLoss` and
  #                            downgrades. Return.
  # If the set was named but could not be MAPPED (`not setProducer.available`), the
  # shim emitted nothing at all — including no root process-start — and the
  # consumer's root-spawn completeness guard downgrades the edge. Still no file.
  if setProducerAttached:
    if setProducer.available:
      var recBuf {.noinit.}: array[SetProducerBufBytes, byte]
      let recLen = encodeDepRecordIdentity(record, recBuf)
      if recLen >= 0 and recLen + setElemImage.len <= SetProducerBufBytes:
        # `decodeDepRecord` reads only the record's own fields (seq reconstructs as
        # 0) and IGNORES these trailing image bytes, so a decoded element is a
        # faithful MonitorRecord for the merge.
        var total = recLen
        for i in 0 ..< setElemImage.len:
          recBuf[total] = byte(setElemImage[i]); inc total
        case setProducer.emit(recBuf.toOpenArray(0, total - 1))
        of emInserted, emExists, emSaturated, emConsumerGone:
          return
        of emOversize, emUnavailable:
          discard   # signal loss below
      # Unframable (path+detail too large) or a non-durable emit status: surface a
      # loss element so the edge is honestly `mcIncomplete` (LF-2), never a spill.
      if setLossElemLen > 0:
        discard setProducer.emit(setLossElem.toOpenArray(0, setLossElemLen - 1))
    # Active set path: do NOT fall through to the dormant file writer (LF-2).
    return

  # LEAK-GUARD — this producer thread already blew the per-fragment byte cap for
  # THIS (osPid, threadId, fragmentDir); its fd is closed. Drop the record rather
  # than reopen the fragment and resume unbounded growth (the run is already
  # flagged incomplete by the cap marker). A DIFFERENT key (fork child / new
  # thread) falls through and opens a fresh, uncapped fragment below.
  if fragmentSlot.overCap and
      slotFragmentDirEquals(fragmentSlot, fragmentDir) and
      fragmentSlot.osPid == record.osPid and
      fragmentSlot.threadId == record.threadId:
    return

  if fragmentSlot.isOpen and not fragmentHandleIsCurrent() and
      not reopenFragmentHandle():
    raiseEnvelopeError(eeMalformed,
      "cannot recover externally replaced RMDF fragment handle")

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
    # LEAK-GUARD — a single oversize frame counts toward the cap too.
    accountFragmentBytes(frame.len)
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
  #
  # M9.R.62.2 — only mark the sentinel when the record actually carries
  # captured-dependency evidence (mrFileRead / mrFileOpen / mrPathProbe /
  # …). A process-lifecycle-only batch (e.g. shim init emitted only
  # recordProcessStart before the process died via raw exit_group) does
  # NOT need to be nettable: losing the batch omits only a redundant
  # restatement of the process tree already recorded via its parent's
  # process-spawn + the ancestor exec chain. Fixes the pixman M9.R.62
  # residual of 182 shim-only escapees; regression pin in
  # tests/portable/test_io_mon_sig_safe_committed_frame.nim.
  markReadingSentinel(record)

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

when defined(windows):
  const
    FragmentReadRetryMs = 2_000
    FragmentReadPollMs = 20

proc readFragmentRecordsForMerge(path: string; cleanEof: var bool):
    seq[MonitorRecord] =
  ## Windows scanners and recently-exited producers can retain a non-sharing
  ## handle briefly after the root process signals. Wait for that bounded race;
  ## all other errors remain visible to the fail-closed merge accounting.
  when defined(windows):
    var waitedMs = 0
    while true:
      try:
        return readFragmentRecordsTolerant(path, cleanEof)
      except IOError:
        # std/syncio.readFile reports every failed fopen as IOError without the
        # underlying GetLastError code. Retry that open failure only here; the
        # merge converts a persistent failure into explicit event loss below.
        if waitedMs >= FragmentReadRetryMs:
          raise
        let delayMs = min(FragmentReadPollMs, FragmentReadRetryMs - waitedMs)
        sleep(delayMs)
        inc(waitedMs, delayMs)
      except OSError as error:
        if (error.errorCode != 32'i32 and error.errorCode != 33'i32) or
            waitedMs >= FragmentReadRetryMs:
          raise
        let delayMs = min(FragmentReadPollMs, FragmentReadRetryMs - waitedMs)
        sleep(delayMs)
        inc(waitedMs, delayMs)
  else:
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

proc depFileFromOwnedRecords*(records: sink seq[MonitorRecord]): MonitorDepFile =
  let summary = summarizeRecords(records)
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
    summary: summary)
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
  result.add RmdfMagic.toBytes()
  result.writeU16Le(RmdfVersion)
  result.writeU16Le(CanonicalFileKind)
  result.writeU64Le(uint64(ordered.len))
  result.writeU64Le(uint64(body.len))
  result.add body
  result.add RmdfTrailerMagic.toBytes()
  result.writeU64Le(uint64(ordered.len))
  result.writeU64Le(checksum(body))

proc writeCanonicalInPlace(outputPath: string; records: var seq[MonitorRecord]) =
  ## Write the canonical RMDF envelope without materializing the full body/file.
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
    raiseEnvelopeError(eeMalformed, "cannot open RMDF depfile for write: " &
      outputPath)
  try:
    var header: seq[byte] = @[]
    header.add RmdfMagic.toBytes()
    header.writeU16Le(RmdfVersion)
    header.writeU16Le(CanonicalFileKind)
    header.writeU64Le(uint64(records.len))
    header.writeU64Le(bodyLen)
    outp.writeBytes(header)

    for record in records:
      outp.writeBytes(encodeFrame(record))

    var trailer: seq[byte] = @[]
    trailer.add RmdfTrailerMagic.toBytes()
    trailer.writeU64Le(uint64(records.len))
    trailer.writeU64Le(bodyChecksum)
    outp.writeBytes(trailer)
  finally:
    close(outp)

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
  ExecStatusToken = "execstatus"    ## M9.R.68.3: process-exec follow-up marker
                                    ## (``failed`` = execve returned an error,
                                    ## e.g. ENOENT for bash configure's platform
                                    ## probes into /bin/uname, /usr/bin/oslevel,
                                    ## etc.)

proc detailHasTokenSyntax(detail: string): bool {.inline.} =
  detail.find('=') >= 0

proc isDetailSpace(c: char): bool {.inline.} =
  c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '\v' or c == '\f'

template detailTokens(detail: string; body: untyped) =
  var i = 0
  while i < detail.len:
    while i < detail.len and isDetailSpace(detail[i]):
      inc i
    let tokStart {.inject.} = i
    while i < detail.len and not isDetailSpace(detail[i]):
      inc i
    let tokEnd {.inject.} = i
    if tokStart < tokEnd:
      body

proc tokenStartsWith(detail: string; tokStart, tokEnd: int;
                     needle: string): bool =
  let tokLen = tokEnd - tokStart
  if tokLen <= needle.len:
    return false
  if tokStart + needle.len > detail.len:
    return false
  for j in 0 ..< needle.len:
    if detail[tokStart + j] != needle[j]:
      return false
  true

proc detailToken*(detail, key: string): string =
  ## Extract the value of a `key=value` token from a record's `detail` field
  ## (ROUND-2 R7/R8). Tokens are whitespace-separated and values contain no
  ## whitespace (pids, start-usec, run ids and nonces are all bare integers/ids).
  ## Returns "" when the key is absent. Single source of truth so every identity
  ## read is consistent (DRY).
  if not detailHasTokenSyntax(detail):
    return ""
  let needle = key & "="
  detailTokens(detail):
    if tokenStartsWith(detail, tokStart, tokEnd, needle):
      return detail[tokStart + needle.len ..< tokEnd]
  ""

proc detailTokenDuplicate(detail, key: string): bool =
  ## True when `detail` carries more than one `key=value` token. Identity tokens
  ## with duplicates are ambiguous attacker-controlled evidence: callers that use
  ## them for trust decisions must fail closed instead of accepting the first one.
  if not detailHasTokenSyntax(detail):
    return false
  let needle = key & "="
  var seen = false
  detailTokens(detail):
    if tokenStartsWith(detail, tokStart, tokEnd, needle):
      if seen:
        return true
      seen = true
  false

proc trustedDetailToken(detail, key: string): string =
  ## Extract a detail token only when it is unique. Duplicate identity tokens are
  ## not equivalent to "missing": most trust checks must avoid falling back to a
  ## weaker bare-pid match when this returns "" because a duplicate was present.
  if detailTokenDuplicate(detail, key):
    ""
  else:
    detailToken(detail, key)

proc hasDuplicateIdentityToken(detail: string): bool =
  for key in [RunIdToken, StartTimeToken, ChildStartTimeToken,
      PeerStartTimeToken, NonceToken]:
    if detailTokenDuplicate(detail, key):
      return true
  false

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
      if hasDuplicateIdentityToken(r.detail):
        continue
      result.pids.incl r.osPid
      result.idents.incl (r.osPid, trustedDetailToken(r.detail, StartTimeToken))

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

proc unmonitoredSubtreeLossDetails*(records: openArray[MonitorRecord];
    trustedPeerPids: HashSet[uint64] = initHashSet[uint64]()): seq[string] =
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
  var execFailedCount = initCountTable[uint64]()
  for r in records:
    case r.kind
    of mrProcessStart:
      startCount.inc r.osPid
    of mrProcessExec:
      # M9.R.68.3 — a follow-up mrProcessExec with
      # ``execstatus=failed`` is emitted by the shim WHEN execve
      # returned to the caller (i.e. failed). Successful execve
      # replaces the address space so control never returns; those
      # exec records have no follow-up. Track failed execs separately
      # so the T0 signal (b) `execs >= starts` invariant subtracts
      # them from the pid's exec tally. Without this, bash configure's
      # 12+ platform probes (fork → execve /bin/uname etc. that don't
      # exist on NixOS) each falsely trip signal (b) even though the
      # exec never landed in an un-injectable image — it failed
      # ENOENT before landing anywhere.
      if detailToken(r.detail, ExecStatusToken) == "failed":
        execFailedCount.inc r.osPid
      else:
        execCount.inc r.osPid
    else: discard
  result = @[]
  # (a) spawned children with no matching process-start (count each child once).
  # Keyed on the child's (pid, start-time) identity: a recycled pid whose
  # start-time differs from a stale monitored process is correctly un-monitored.
  var flaggedChildren: HashSet[ProcIdentity]
  for r in records:
    if r.kind == mrProcessSpawn and r.childOsPid != 0 and
        r.childOsPid != r.osPid:
      let duplicateChildStart = detailTokenDuplicate(r.detail, ChildStartTimeToken)
      let childStart = trustedDetailToken(r.detail, ChildStartTimeToken)
      let ident = (r.childOsPid, childStart)
      if (duplicateChildStart or
          not childIsMonitored(r.childOsPid, childStart, startIdents, startPids)) and
          ident notin flaggedChildren:
        flaggedChildren.incl ident
        result.add("spawn child missing process-start parent=" & $r.osPid &
          " child=" & $r.childOsPid & " childstart=" & childStart &
          " path=" & r.path)
  # (b) execs whose last image was un-injectable (one loss per such pid).
  #
  # Semantic invariant: for a monitored pid, `startCount == 1 + execCount`
  # (the +1 accounts for the initial shim init on process image load).
  # `execCount >= startCount` means the last exec had no post-exec shim
  # reload → un-injectable image.
  #
  # M9.R.66.3: this invariant assumed the initial process-image load
  # always emits a mrProcessStart. In practice, Python's
  # `_posixsubprocess.fork_exec` uses `vfork+execve` on Linux which —
  # because vfork temporarily shares the parent's memory and Python's
  # C code short-circuits the exec discovery loop — can produce a child
  # whose recorded starts + execs come out matched (starts == execs)
  # for a fully-monitored wrapper chain (bash-wrapping-gcc → real gcc).
  # See reprobuild recipes/reproos-image/run-evidence/m9r66/
  # m9r66_phaseB_subtree.txt for the pixman mesonbin-setup evidence.
  #
  # Distinguish the vfork case from the classical un-injectable case
  # (`start(100), exec(100)` in tests) by whether the pid has a
  # matching monitored-parent SPAWN record:
  #
  #   * Spawn record exists (classical fork/posix_spawn): the parent
  #     recorded the spawn, so we KNOW the initial-shim-load start
  #     should have fired. If `execs >= starts`, the last exec
  #     was un-injectable — trip.
  #
  #   * No spawn record (vfork or other non-hooked spawn mechanism):
  #     we cannot rely on the initial-shim-load start being present,
  #     so require strict `execs > starts`. A monitored wrapper chain
  #     with 2 execs + 2 starts passes; a genuinely un-injectable exec
  #     with 1 exec + 0 starts still trips (via signal (a) if the
  #     parent's spawn was recorded, or here if the pid emitted only
  #     an exec and no start).
  # Build the set of pids for which the initial-shim-load start invariant
  # holds — either the pid is the root (has an `io-mon-root-spawn`
  # synthetic spawn record with osPid=0) or a monitored parent recorded a
  # spawn for it (osPid != 0). For those pids, the strict `execs >=
  # starts` T0 signal (b) applies.
  #
  # For pids with no spawn record at all (vfork'd by an unhooked
  # mechanism like Python's `_posixsubprocess.fork_exec`), the initial-
  # start assumption doesn't hold. In addition, Python's PATH-search
  # loop emits N failed `execve()` calls per PATH candidate before the
  # successful one — each of those hits our LD_PRELOAD execve
  # interposer OUTSIDE our dispatch_execvp bracket (Python doesn't call
  # libc's execvp), so N-1 spurious `mrProcessExec` records land in the
  # depfile per successful transition. See reprobuild
  # recipes/reproos-image/run-evidence/m9r66/m9r66_phaseB_subtree.txt
  # for pixman meson data (pid emits 4 execs for 1 real transition
  # because $PATH has ~4 candidates).
  #
  # Rather than pre-check execs in the shim (M9.R.66.3's access(X_OK)
  # attempt regressed gcc-14.3.0's cc1 startup with an internal
  # compiler error), disable T0 signal (b) entirely for unanchored
  # pids. The classical un-injectable-exec case that signal (b)
  # originally caught (root monitored process execs into hardened
  # image) is still detected via anchored pids. The residual coverage
  # gap — an unanchored pid that legitimately execs into a hardened
  # image — is bounded because:
  #   * Signal (a) still catches un-injectable SPAWNS from monitored
  #     parents (mrProcessSpawn childOsPid with no matching start).
  #   * Signal (c) still catches breakaway-daemon IPC connects.
  #   * The unanchored+un-injectable case requires Python-style
  #     vfork+execve into a hardened image, which is rare in build
  #     workloads and would still show up as an out-of-tree IPC
  #     connect if the child does any real I/O.
  var pidsWithAnchoredSpawn = initHashSet[uint64]()
  for r in records:
    if r.kind == mrProcessSpawn and r.childOsPid != 0 and
        r.childOsPid != r.osPid:
      pidsWithAnchoredSpawn.incl r.childOsPid
  for pid, execs in execCount:
    if pid notin pidsWithAnchoredSpawn:
      continue
    # M9.R.68.3 — subtract failed execs (execve returned an error) from
    # the tally: the exec never landed in an un-injectable image, so
    # it must not falsely trip signal (b). The pre-flush mrProcessExec
    # record is always emitted (needed for durability across a
    # successful address-space swap); the shim emits a follow-up
    # ``execstatus=failed`` record iff control returned from callNext,
    # proving the exec failed.
    let failedExecs = execFailedCount.getOrDefault(pid)
    let effectiveExecs = execs - failedExecs
    if effectiveExecs <= 0:
      continue
    let starts = startCount.getOrDefault(pid)
    if effectiveExecs >= starts:
      result.add("exec without post-exec process-start pid=" & $pid &
        " execs=" & $effectiveExecs & " starts=" & $starts)
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
      let duplicatePeerStart = detailTokenDuplicate(r.detail, PeerStartTimeToken)
      let peerStart = trustedDetailToken(r.detail, PeerStartTimeToken)
      # A peer is INSIDE the tree iff its (pid, start-time) identity matches a
      # monitored process-start (R7 — a recycled peer pid with a different start
      # time is NOT in-tree), OR a trusted daemon accounted for its reads. Either
      # way: no downgrade (the cardinal-sin guard for legitimate intra-tree IPC).
      if peer != 0 and not duplicatePeerStart and
          (childIsMonitored(peer, peerStart, startIdents, startPids) or
           peer in trustedPeerPids):
        continue
      let key = if peer != 0: "pid:" & $peer & "@" & peerStart
                else: "dest:" & r.path
      if key in flaggedPeers:
        continue
      flaggedPeers.incl key
      result.add("ipc peer outside monitored tree pid=" & $r.osPid &
        " peer=" & $peer & " peerstart=" & peerStart &
        " path=" & r.path)

proc unmonitoredSubtreeLossCount*(records: openArray[MonitorRecord];
    trustedPeerPids: HashSet[uint64] = initHashSet[uint64]()): int =
  unmonitoredSubtreeLossDetails(records, trustedPeerPids).len

proc nonDeterminismObservationCount*(records: openArray[MonitorRecord]): int =
  ## Count observed non-deterministic inputs without making a cache policy
  ## decision. `mrNonDeterministic` means io-mon saw the entropy source; it is not
  ## evidence that monitoring was incomplete.
  result = 0
  for r in records:
    if r.kind == mrNonDeterministic:
      inc result

proc nonDeterminismLossCount*(records: openArray[MonitorRecord]): int
    {.deprecated: "mrNonDeterministic is policy evidence, not monitoring loss; use nonDeterminismObservationCount".} =
  ## Compatibility shim for older callers. Non-file observations no longer inject
  ## event-loss or force `mcIncomplete`; callers decide whether entropy, clock,
  ## environment, or system-configuration observations invalidate their cache key.
  discard records
  0

proc externalContentLossCount*(records: openArray[MonitorRecord];
    trustedPeerPids: HashSet[uint64] = initHashSet[uint64]()): int =
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
  ## ROUND-4 IP1 — `chan=opaque` (an inherited socket/pipe read with no in-tree
  ## open) is NOW a downgrade signal WHEN UNPAIRED, paired against an in-tree
  ## `chan=localfd role=create` (a pipe/socketpair/socket/accept a monitored
  ## process made itself, keyed by the fd's `dev:ino` identity). This closes the
  ## round-4 IP1 re-break: an inherited pipe from an OUT-OF-TREE writer
  ## (r4_residual/pipe_launcher) has NO in-tree create ⇒ it downgrades; an entirely
  ## in-tree pipeline — the clang driver↔cc1 pipes, an in-tree `pipe()+fork`, an
  ## intra-tree socket IPC whose parent accept()s — IS paired ⇒ NO downgrade (the
  ## cardinal-sin guard). The round-3 stance ("socket provenance is owned by the
  ## IPC-connect machinery") still holds for the out-of-tree-PEER socket case: the
  ## socket fd a monitored client created itself is paired here (no IP1 downgrade),
  ## while `unmonitoredSubtreeLossCount` independently downgrades a connect to an
  ## out-of-tree breakaway peer. An opaque read whose fd's (dev,ino) was
  ## unobtainable carries an EMPTY key and is NOT downgraded (fail-safe toward
  ## mcComplete — a possible missed dep, never a false re-run of a normal build).
  ##
  ## IoMon-Pipeline-Capture IM-4 — PROCESS-TREE MEMBERSHIP, not only fd pairing.
  ## The create/write pairing above is a PROXY for the question that actually
  ## matters, "was the producer one of us?", and the proxy is only as good as the
  ## set of channel-creating calls somebody has interposed. Every channel class
  ## with no create hook (on Linux: `socket`/`accept`, which macOS does record)
  ## re-breaks it in exactly the way IM-3 fixed for `pipe`, and the NEXT
  ## uninterposed class would break it again.
  ##
  ## So ask the question directly whenever the channel can answer it: an
  ## `mrExternalContent` consume carries its producer's pid in `childOsPid` when
  ## the kernel could name one (`SO_PEERCRED` / `LOCAL_PEERPID` on a unix socket;
  ## 0 for a pipe, a FIFO or an inet socket). A consume whose producer emitted an
  ## `mrProcessStart` — or is a `trustedPeerPids` daemon that accounted for its own
  ## reads — is inside the monitored tree, its inputs were captured with it, and it
  ## must NOT downgrade, PAIRED OR NOT. This is the same cardinal-sin guard, and
  ## the same (pid, start-time) identity test, that `unmonitoredSubtreeLossCount`
  ## case (c) already applies to `mrIpcConnect` peers.
  ##
  ## Both directions still fail safe. An unknown producer (`childOsPid == 0`) falls
  ## through to the unchanged pairing logic, so a genuinely external channel — an
  ## inherited pipe, or a socket whose creator is out of the tree — still
  ## downgrades. The suppression fires only on kernel-supplied evidence that the
  ## bytes came from a process io-mon was already watching.
  let (startIdents, startPids) = processStartIdentities(records)
  var shmCreates = initHashSet[string]()
  var fifoWrites = initHashSet[string]()
  var localFdCreates = initHashSet[string]()
  for r in records:
    if r.kind != mrExternalContent:
      continue
    let chan = detailToken(r.detail, ChanToken)
    let role = detailToken(r.detail, RoleToken)
    if chan == "shm" and role == "create":
      shmCreates.incl r.path
    elif chan == "fifo" and role == "write":
      fifoWrites.incl r.path
    elif chan == "localfd" and role == "create":
      localFdCreates.incl r.path
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
    elif chan == "opaque" and role == "read":
      # ROUND-4 IP1 — an inherited pipe/socket read. Downgrade ONLY when it has a
      # resolved (dev,ino) key (r.path non-empty) AND no in-tree create produced
      # that object. An empty key (fstat failed) never downgrades (fail-safe).
      if r.path.len > 0 and r.path notin localFdCreates:
        key = r.path
    if key.len == 0:
      continue
    # IM-4 — the producer is a monitored in-tree process ⇒ nothing is invisible,
    # whether or not anyone interposed the call that made this channel. Mirrors
    # the `mrIpcConnect` peer check: identity is (pid, kernel start-time) when the
    # producer supplied one, bare pid otherwise, and a DUPLICATE `peerstart` token
    # is ambiguous attacker-controlled evidence that must fail CLOSED (downgrade)
    # rather than silently degrade to the weaker bare-pid match.
    let producer = r.childOsPid
    if producer != 0 and not detailTokenDuplicate(r.detail, PeerStartTimeToken):
      let producerStart = detailToken(r.detail, PeerStartTimeToken)
      if childIsMonitored(producer, producerStart, startIdents, startPids) or
          producer in trustedPeerPids:
        continue
    if key notin flagged:
      flagged.incl key
      inc result

const
  BreakawayReportExt* = ".io-mon-report"
    ## File extension a COOPERATING daemon writes its breakaway report under,
    ## inside the `IO_MON_BREAKAWAY_REPORT_DIR`. Distinct from `.rmdf-frag` so the
    ## report scan never collides with the per-process fragment files.
  BreakawayReportMagic* = "io-mon-breakaway-report v1"
    ## Required first non-empty line of a trusted-daemon breakaway report.
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
    inTreeOutputPaths*: HashSet[string]
      ## ROUND-3 S3a — every path WRITTEN by a monitored in-tree process
      ## (`observationKind == moFileWrite`, both the raw and the F_GETPATH-canonical
      ## spelling the shim records). A breakaway report whose OWN file path is in
      ## this set was AUTHORED INSIDE the monitored tree — but a genuine
      ## out-of-tree daemon's report write is INVISIBLE to the shim — so such a
      ## report is a SELF-AUTHORED FORGERY and is rejected. This is the structural
      ## discriminator that closes res4_forge: an in-tree client can read the run id
      ## / nonce and forge every field, but it cannot write its report file without
      ## the shim recording that write.
    inTreeOutputInos*: HashSet[string]
      ## ROUND-3 S3a — `dev:ino` identities of in-tree-written files (the shim
      ## stamps `dev=`/`ino=` on write opens). An alias-proof backstop to the path
      ## set so a `/tmp` vs `/private/tmp` (or symlink) spelling of the report path
      ## is still recognised as in-tree-authored.

const
  BreakawayReportCompleteToken* = "complete"
    ## ROUND-2 R8 — a cooperating daemon MUST emit a bare `complete` line to assert
    ## "this report fully accounts for everything I did on this client's behalf".
    ## A report lacking it (the round-2 malicious_client.c forgery, which lists NO
    ## reads and makes no completeness claim) is treated as untrusted, so the
    ## client's connect still downgrades.

proc comparableReportPath(path: string): string =
  ## Filesystem iteration uses extended paths on Windows, while monitor records
  ## deliberately retain ordinary paths. Normalize both spellings before using
  ## them as report-authentication identities.
  when defined(windows):
    var ordinary = path
    if ordinary.startsWith("\\\\?\\UNC\\"):
      ordinary = "\\\\" & ordinary[8 .. ^1]
    elif ordinary.startsWith("\\\\?\\"):
      ordinary = ordinary[4 .. ^1]
    normalizedPath(absolutePath(ordinary)).toLowerAscii()
  else:
    path

proc breakawayAuthContext*(records: openArray[MonitorRecord]):
    BreakawayAuthContext =
  ## ROUND-2 R8 — extract the report-authentication context from the merged
  ## records (DRY: one source of truth shared by `mergeFragments`).
  result.connectedPeers = initHashSet[string]()
  result.validNonces = initHashSet[string]()
  result.inTreeOutputPaths = initHashSet[string]()
  result.inTreeOutputInos = initHashSet[string]()
  for r in records:
    # ROUND-3 S3a — any path a monitored process WROTE is an in-tree-authored
    # identity. A breakaway report file with such an identity is a self-authored
    # forgery (an honest out-of-tree daemon's report write is never recorded). Both
    # the raw and the F_GETPATH-canonical write records carry `moFileWrite`, so this
    # captures both spellings; the (dev, ino) the shim stamps gives an alias-proof
    # backstop.
    if r.observationKind == moFileWrite and r.path.len > 0:
      result.inTreeOutputPaths.incl r.path
      result.inTreeOutputPaths.incl comparableReportPath(r.path)
      let dev = detailToken(r.detail, "dev")
      let ino = detailToken(r.detail, "ino")
      if dev.len > 0 and ino.len > 0:
        result.inTreeOutputInos.incl(dev & ":" & ino)
    case r.kind
    of mrProcessStart:
      if result.runId.len == 0:
        let run = trustedDetailToken(r.detail, RunIdToken)
        if run.len > 0:
          result.runId = run
    of mrIpcConnect:
      if r.childOsPid != 0:
        result.connectedPeers.incl($r.osPid & ":" & $r.childOsPid)
      let nonce = trustedDetailToken(r.detail, NonceToken)
      if nonce.len > 0:
        result.validNonces.incl nonce
      if result.runId.len == 0:
        let run = trustedDetailToken(r.detail, RunIdToken)
        if run.len > 0:
          result.runId = run
    else: discard

proc reportAuthoredInTree(reportPath: string;
    auth: BreakawayAuthContext): bool =
  ## ROUND-3 S3a — true iff `reportPath` was WRITTEN by a monitored in-tree process
  ## (and is therefore a self-authored forgery, not a genuine out-of-tree daemon's
  ## report). Matches on the path in any spelling (the verbatim walked path, plus
  ## its realpath, against the raw AND F_GETPATH-canonical write paths the shim
  ## records) and, as an alias-proof backstop, on the file's (dev, ino) identity.
  ## Defensive: a stat/realpath failure (a vanished report, a permission quirk) is
  ## treated as NOT-in-tree so a benign race never spuriously rejects an honest
  ## report — the fail-safe direction here is to fall through to the existing R8
  ## auth criteria, which still gate the report.
  if auth.inTreeOutputPaths.len == 0 and auth.inTreeOutputInos.len == 0:
    return false
  if reportPath in auth.inTreeOutputPaths:
    return true
  if comparableReportPath(reportPath) in auth.inTreeOutputPaths:
    return true
  # Realpath the report so a /tmp vs /private/tmp (or symlink) spelling matches the
  # shim's F_GETPATH-canonical write record.
  try:
    let real = expandFilename(reportPath)
    if real in auth.inTreeOutputPaths:
      return true
  except OSError, IOError, ValueError:
    discard
  if auth.inTreeOutputInos.len > 0:
    try:
      let info = getFileInfo(extendedPath(reportPath), followSymlink = true)
      let key = $cast[uint64](info.id.device) & ":" & $cast[uint64](info.id.file)
      if key in auth.inTreeOutputInos:
        return true
    except OSError, IOError:
      discard
  false

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
  ## ROUND-3 S3a — criteria 1–5 were DEFEATED by the res4_forge probe
  ## (research/.../r3_residual): an in-tree client reads REPRO_MONITOR_SESSION from
  ## its env, REALLY connects to the daemon (so the connection is observed), then
  ## forges a `complete` report that lists a DECOY read and OMITS the file the daemon
  ## truly served — a false `mcComplete` with the real input invisible. The nonce
  ## (criterion 4) did not help: the shim records the nonce in the CLIENT's own
  ## fragment, which the in-tree client can read, so no client-side nonce is ever a
  ## secret from an in-tree forger. We close this STRUCTURALLY instead
  ## (`reportAuthoredInTree`, applied FIRST): a genuine cooperating daemon is OUT OF
  ## TREE, so the shim never sees it WRITE its report; an in-tree forger IS
  ## monitored, so the shim DID record it writing this very report file. A report
  ## whose own file is an in-tree output write is therefore rejected as a forgery.
  ##
  ## HONEST LIMITATION (documented, not hidden): this closes a forger that writes the
  ## report through the ordinary file API the shim hooks. A forger that writes its
  ## report via a RAW write(2) syscall (bypassing the libsystem entry the shim
  ## interposes — the structurally-unfixable raw-syscall gap, finding #6), or that
  ## delegates the report write to an out-of-tree helper it spawns, would still slip
  ## a forged report past this check. Fully closing those requires out-of-band kernel
  ## observation (the EndpointSecurity backend, which accounts the daemon's reads
  ## directly and needs no client-authored report at all). That is the tracked
  ## structural endgame; the checks here reject the res4_forge probe and every report
  ## that does not non-trivially and run-correctly account for an observed connection.
  result.reads = @[]
  result.trustedPeerPids = initHashSet[uint64]()
  if reportDir.len == 0 or not dirExists(extendedPath(reportDir)):
    return
  for kind, path in walkDir(extendedPath(reportDir)):
    if kind != pcFile or not path.endsWith(BreakawayReportExt):
      continue
    # ---- ROUND-3 S3a: reject a SELF-AUTHORED (in-tree-written) report ----------
    # The strongest in-process closure of the res4_forge break: a genuine
    # cooperating daemon is OUT OF TREE, so the shim never records it writing its
    # report file; an in-tree forger, by contrast, IS monitored, so the shim DID
    # record the write of this very report file. If this report's path (in any
    # spelling) — or its (dev, ino) identity — appears among the in-tree output
    # writes, it was authored inside the monitored tree and is a forgery, so we skip
    # it (the client's connect then still downgrades). See the HONEST LIMITATION
    # note below for the residual (a raw-syscall / out-of-tree-helper write).
    if reportAuthoredInTree(path, auth):
      continue
    var content = ""
    try:
      content = readFile(extendedPath(path))
    except IOError, OSError:
      # A report that vanished / is unreadable carries no evidence; skip it
      # rather than abort the whole merge (benign producer race).
      continue
    var hasMagic = false
    for rawLine in content.splitLines():
      if rawLine.strip().len == 0:
        continue
      hasMagic = rawLine == BreakawayReportMagic
      break
    if not hasMagic:
      continue
    var clientPid, daemonPid: uint64 = 0
    var reportRun, reportNonce: string = ""
    var declaredComplete = false
    var sawClient, sawDaemon, sawRun, sawNonce = false
    var malformedReport = false
    var readPaths: seq[string] = @[]
    for rawLine in content.splitLines():
      let line = rawLine.strip()
      if line.len == 0 or line == BreakawayReportMagic:
        continue
      if line == BreakawayReportCompleteToken:
        if declaredComplete:
          malformedReport = true
          break
        declaredComplete = true
        continue
      let toks = line.splitWhitespace()
      if toks.len < 2:
        malformedReport = true
        break
      if toks[0] != "read" and toks.len != 2:
        malformedReport = true
        break
      if toks[0] == "read":
        # A read path may itself contain spaces, so take everything after the
        # directive verbatim rather than relying on the whitespace split.
        let readPath = line[("read".len) .. ^1].strip()
        if readPath.len == 0:
          malformedReport = true
          break
        readPaths.add readPath
        continue
      case toks[0]
      of "client":
        if sawClient:
          malformedReport = true
          break
        sawClient = true
        try: clientPid = uint64(parseBiggestUInt(toks[1]))
        except ValueError:
          malformedReport = true
          break
      of "daemon":
        if sawDaemon:
          malformedReport = true
          break
        sawDaemon = true
        try: daemonPid = uint64(parseBiggestUInt(toks[1]))
        except ValueError:
          malformedReport = true
          break
      of "run":
        if sawRun:
          malformedReport = true
          break
        sawRun = true
        reportRun = toks[1]
      of "nonce":
        if sawNonce:
          malformedReport = true
          break
        sawNonce = true
        reportNonce = toks[1]
      else:
        malformedReport = true
        break
    if malformedReport:
      continue
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

proc fragmentRunIds(records: openArray[MonitorRecord]): Table[uint64, HashSet[string]] =
  ## ROUND-3 S3c — map each monitored osPid to the run id its `mrProcessStart`
  ## carries (the `run=` token the shim stamps from REPRO_MONITOR_SESSION). Used by
  ## the warm-restart stale-fragment guard to recognise records left in a REUSED
  ## fragment dir by a PRIOR invocation. A pid can appear under more than one run
  ## when the OS recycles it and a caller reuses a fragment dir, so keep every run
  ## id instead of collapsing pid ownership to one value.
  result = initTable[uint64, HashSet[string]]()
  for r in records:
    if r.kind == mrProcessStart:
      if hasDuplicateIdentityToken(r.detail):
        continue
      let run = trustedDetailToken(r.detail, RunIdToken)
      if run.len == 0:
        continue
      if not result.hasKey(r.osPid):
        result[r.osPid] = initHashSet[string]()
      result[r.osPid].incl run

proc dropStaleRunRecords(records: seq[MonitorRecord];
    currentRunId: string): seq[MonitorRecord] =
  ## ROUND-3 S3c — drop records left in a REUSED fragment dir by a PRIOR run.
  ##
  ## `mergeFragments` consumes the `.io-mon-reading` kill-sentinels but does NOT
  ## delete the `.rmdf-frag` fragment files, so a caller that RE-MERGES a fragment
  ## dir (a warm restart, a library `mergeFragments` over a reused dir) would fold a
  ## prior run's records into THIS verdict (research/.../r3_merge/merge_attack.nim:
  ## a stale run-1 process-start makes a run-2 out-of-tree breakaway peer look
  ## in-tree ⇒ a FALSE mcComplete, plus the stale reads pollute the depfile). We
  ## namespace by the invocation run id (approach (b), non-destructive and
  ## re-merge-idempotent). Records that carry their own run token are kept only
  ## when it matches `currentRunId`. Records without a per-record token are scoped
  ## through their pid's run-stamped process-starts. If a reused dir contains the
  ## same pid under both OLD and CURRENT runs, an unstamped record for that pid is
  ## ambiguous: it might be stale, so we drop it and inject event-loss to fail
  ## closed rather than fold a prior run's file reads into a false mcComplete.
  ##
  ## Records with no determinable run at all (no run-stamped process-start for
  ## their pid, e.g. legacy/no-run fresh-dir callers) are KEPT, preserving the
  ## existing no-run behavior. Duplicate identity tokens are never kept: accepting
  ## the first value would let stale records masquerade as current-run evidence.
  if currentRunId.len == 0:
    result = @[]
    var duplicateIdentityLossPids = initHashSet[uint64]()
    for r in records:
      if hasDuplicateIdentityToken(r.detail):
        duplicateIdentityLossPids.incl r.osPid
        continue
      result.add r
    for pid in duplicateIdentityLossPids:
      result.add MonitorRecord(kind: mrEventLoss,
        observationKind: moEventLoss,
        osPid: pid,
        detail: "duplicate identity token in fragment record")
    return
  let runsByPid = fragmentRunIds(records)
  var ambiguousLossPids = initHashSet[uint64]()
  var duplicateIdentityLossPids = initHashSet[uint64]()
  result = @[]
  for r in records:
    if hasDuplicateIdentityToken(r.detail):
      duplicateIdentityLossPids.incl r.osPid
      continue
    let recordRun = trustedDetailToken(r.detail, RunIdToken)
    if recordRun.len > 0:
      if recordRun != currentRunId:
        continue
      result.add r
      continue
    if r.osPid != 0 and runsByPid.hasKey(r.osPid):
      let pidRuns = runsByPid[r.osPid]
      if currentRunId notin pidRuns:
        continue # stale prior-run record in a reused dir — do not fold
      if pidRuns.len > 1:
        ambiguousLossPids.incl r.osPid
        continue
    result.add r
  for pid in ambiguousLossPids:
    result.add MonitorRecord(kind: mrEventLoss,
      observationKind: moEventLoss,
      osPid: pid,
      detail: "ambiguous unstamped fragment record for reused pid in run " &
        currentRunId)
  for pid in duplicateIdentityLossPids:
    result.add MonitorRecord(kind: mrEventLoss,
      observationKind: moEventLoss,
      osPid: pid,
      detail: "duplicate identity token in fragment record for run " &
        currentRunId)

proc mergeFragments*(fragmentDir, outputPath: string;
    breakawayReportDir = ""; expectedRootPid: uint64 = 0;
    currentRunId = "";
    setRecords: openArray[MonitorRecord] = @[]): MonitorDepFile =
  ## io-mon-Lossless-Event-Capture M3 — `setRecords` are the DISTINCT records the
  ## consumer decoded from the edge's shared-memory SET (nim-shm-gset) snapshot
  ## (the sole Linux dependency transport; see fs_snoop). They are folded into the
  ## SAME record set as the file fragments BEFORE the run-scoping, read-tail
  ## netting, and canonical ordering — so a record that travelled the set is
  ## indistinguishable in the output from one that travelled the file path, and the
  ## final depfile is reprobuild-invariant (LF-6). Set records are the SAME
  ## `MonitorRecord` shape (run-stamped detail included, since `stampRunId` runs
  ## before the producer emits); they carry no read-tail bookkeeping markers (those
  ## are file-only, macOS/Windows arm), so the netting below is unaffected. Empty
  ## (the default) preserves the pure-file behaviour.
  ##
  ## ROUND-3 S3c (warm-restart stale-fragment guard) — `currentRunId` scopes the
  ## merge to THIS invocation's run id (the value the launcher put in
  ## REPRO_MONITOR_SESSION). When non-empty (or, if empty, when the env var is set),
  ## records left in a REUSED fragment dir by a PRIOR run are dropped before the
  ## completeness check, so a re-merge / warm restart cannot fold a stale
  ## process-start (masking an out-of-tree breakaway) or stale reads. Empty + no env
  ## var ⇒ legacy behaviour (no filtering), which is correct for the CLI's fresh
  ## per-run temp dir. CONTRACT FOR LIBRARY CALLERS that REUSE a fragment dir
  ## (reprobuild's `monitoredAction`, the codetracer runner): pass the invocation's
  ## run id as `currentRunId` (or export REPRO_MONITOR_SESSION) so the guard engages.
  ##
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
  var unreadableFragments = 0
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
          records.add readFragmentRecordsForMerge(path, cleanEof)
          if not cleanEof:
            inc corruptFragments
        except IOError, OSError:
          # A vanished entry is the benign walk/read race described above. Any
          # fragment that still exists but cannot be read is missing evidence,
          # so retain the recovered fragments and force this depfile incomplete.
          var vanished = false
          try:
            vanished = not fileExists(extendedPath(path))
          except OSError:
            discard
          if not vanished:
            inc unreadableFragments
  # io-mon-Lossless-Event-Capture M3 — fold the SET-decoded records into the SAME
  # set as the file fragments. They are appended AS-IS (already run-stamped by the
  # producer) so they pass through the identical run-scoping / read-tail-net /
  # canonical-order pipeline below; the merged output is reprobuild-invariant
  # whether a record arrived via the set or the file.
  if setRecords.len > 0:
    for r in setRecords:
      records.add r
  # ROUND-3 S3c — warm-restart stale-fragment guard. `mergeFragments` does not
  # delete `.rmdf-frag` files, so a REUSED fragment dir can carry a PRIOR run's
  # records (merge_attack.nim). Drop records whose owning process started under a
  # DIFFERENT run id before any completeness reasoning sees them. The run id is the
  # explicit `currentRunId` arg, else REPRO_MONITOR_SESSION.
  #
  # PASS `currentRunId`; do NOT rely on the env fallback. Since
  # IoMon-Decomposed-Host-API DH-1 ALL THREE arms of `runMonitored` publish the
  # injection variables to the CHILD's environment only, so REPRO_MONITOR_SESSION
  # is no longer set in the MERGING process on any platform. (The Windows arm was
  # the last to stop `putEnv`-ing it, once `runWithMonitorShim` gained an `env`
  # parameter.) The fallback now engages only for a caller that exports the
  # variable itself. `runMonitored`'s Linux arm passes `currentRunId` explicitly;
  # its macOS and Windows arms do not, which is safe only because each merges a
  # fragment dir it created moments earlier and deletes on the way out, so no
  # prior run's records can be in it.
  #
  # Empty ⇒ no filtering (the CLI's fresh-dir case). This
  # runs BEFORE the corrupt-fragment loss injection below so a real corrupt fragment
  # of the CURRENT run is still counted.
  let runScope =
    if currentRunId.len > 0: currentRunId else: getEnv("REPRO_MONITOR_SESSION")
  records = dropStaleRunRecords(records, runScope)
  if corruptFragments > 0:
    # One synthetic event-loss record per corrupt fragment. ``mrEventLoss``
    # makes ``summarizeRecords`` count event loss, forcing ``mcIncomplete``.
    for _ in 0 ..< corruptFragments:
      records.add MonitorRecord(kind: mrEventLoss,
        observationKind: moEventLoss,
        detail: "corrupt or partial RMDF fragment in " & fragmentDir)
  if unreadableFragments > 0:
    for _ in 0 ..< unreadableFragments:
      records.add MonitorRecord(kind: mrEventLoss,
        observationKind: moEventLoss,
        detail: "unreadable RMDF fragment in " & fragmentDir)
  # ROUND-5 F (kill-before-flush) — net the IN-FRAGMENT read-tail markers. A
  # monitored process that buffered read records wrote a durable `read-tail-pending`
  # marker to its fragment the instant a batch went dirty, and a `read-tail-committed`
  # marker after the batch flush made those reads durable. Netting per (osPid,
  # threadId): an UNMATCHED pending means the process was killed by an uncatchable
  # path (SIGKILL / raw exit / abort — no destructor) with reads still buffered, so
  # the early-flushed process-start survived but the reads were lost — a false
  # `mcComplete` minus those reads. One synthetic kill-before-flush event-loss per
  # unmatched pending forces `mcIncomplete` (the conservative re-run machinery). The
  # bookkeeping markers are STRIPPED from the record set FIRST — they are `mrEventLoss`
  # frames and `summarizeRecords` would otherwise count each pending/committed pair as
  # real loss and false-downgrade EVERY normal build (the cardinal-sin inverse). The
  # mark/clear alternate strictly per thread, so the leftover is 0 or 1 per thread.
  #
  # This replaces the round-2 sidecar sentinel FILE (defeatable by unlink / dir chmod
  # — research/adversarial-2026-07-round5/machinery sab_*). A stale `.io-mon-reading`
  # sidecar from an OLD-version run is still honoured (removed + counted) as the SAFE
  # direction for a warm restart — never a false mcComplete.
  block readTailNet:
    var pendingByThread = initCountTable[(uint64, uint64)]()
    var committedByThread = initCountTable[(uint64, uint64)]()
    # M9.R.62.1 — remember the most-recent ctx tag observed on each thread's
    # pending markers so an unmatched leftover carries the shim's last-seen
    # diagnostic attribution into the synthetic event-loss detail. Empty when
    # IO_MON_KILL_DIAG was off at capture time.
    var lastPendingCtx = initTable[(uint64, uint64), string]()
    var cleaned = newSeqOfCap[MonitorRecord](records.len)
    # The marker detail is "<kind> run=<id>[ ctx=<...>]" (run-stamped + optional
    # diagnostic context suffix), so match by PREFIX. The run scoping is already
    # applied by dropStaleRunRecords above, so only this run's markers reach here.
    for r in records:
      if r.kind == mrEventLoss and r.detail.startsWith(ReadTailPendingDetail):
        pendingByThread.inc((r.osPid, r.threadId))
        let ctxAt = r.detail.find(KillDiagCtxTag)
        if ctxAt >= 0:
          lastPendingCtx[(r.osPid, r.threadId)] =
            r.detail[ctxAt + KillDiagCtxTag.len .. ^1]
      elif r.kind == mrEventLoss and r.detail.startsWith(ReadTailCommittedDetail):
        committedByThread.inc((r.osPid, r.threadId))
      else:
        cleaned.add r
    records = cleaned
    for key, pcount in pendingByThread:
      let leftover = pcount - committedByThread.getOrDefault(key, 0)
      for _ in 0 ..< max(0, leftover):
        var detail =
          "process killed with an un-flushed read batch (kill-before-flush)"
        let ctx = lastPendingCtx.getOrDefault(key, "")
        if ctx.len > 0:
          detail.add " diag-ctx=[" & ctx & "]"
        records.add MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
          osPid: key[0], threadId: key[1],
          detail: detail)
  # Legacy: consume + honour any stale round-2 `.io-mon-reading` sidecar (a warm
  # restart from a pre-round-5 shim). Removing it and counting it is the SAFE
  # direction; the current shim writes no sidecars, so this is dormant in steady use.
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
  let subtreeLosses = unmonitoredSubtreeLossDetails(records, trustedPeerPids)
  for loss in subtreeLosses:
    records.add MonitorRecord(kind: mrEventLoss,
      observationKind: moEventLoss,
      detail: "unmonitored subtree/peer (un-injectable spawn child, SETEXEC " &
        "into a hardened image, or IPC connect to an out-of-tree breakaway " &
        "daemon): " & loss)
  # ROUND-3 S1 — DOWNGRADE on out-of-tree CONTENT CHANNELS: a POSIX shm object not
  # created in-tree, or a FIFO with no in-tree writer. The producer is outside the
  # monitored tree so the consumed content is an invisible input. One synthetic
  # event-loss per unpaired channel forces `mcIncomplete` via the SAME machinery as
  # the IPC-breakaway downgrade — a conservative re-run. A
  # channel a monitored process itself created+fed is paired and does NOT downgrade
  # (the cardinal-sin guard); an inherited socket/pipe is record-not-downgrade
  # (socket provenance is owned by the IPC-connect machinery). IM-4: a consume
  # whose PRODUCER is a monitored pid (or a trusted reporting daemon) does not
  # downgrade either, pairing or no pairing — hence `trustedPeerPids` is threaded
  # in, exactly as it is for the subtree check above. See
  # externalContentLossCount.
  let externalContentLosses = externalContentLossCount(records, trustedPeerPids)
  for _ in 0 ..< externalContentLosses:
    records.add MonitorRecord(kind: mrEventLoss,
      observationKind: moEventLoss,
      detail: "out-of-tree content channel consumed (POSIX shm not created " &
        "in-tree, FIFO with no in-tree writer, or an inherited pipe/socket with " &
        "no in-tree create) — the real input is invisible, re-run")
  records.add profileRecords(defaultHooksMonitorProfile(
    when defined(linux): LinuxPreloadSupportedCapabilities
    elif defined(windows): WindowsInterposeSupportedCapabilities
    else: MacosMonitorShimTaxonomyCapabilities))

  writeCanonicalInPlace(outputPath, records)
  depFileFromOwnedRecords(move(records))

proc writeCanonical*(outputPath: string; records: openArray[MonitorRecord]) =
  var owned = @records
  writeCanonicalInPlace(outputPath, owned)
