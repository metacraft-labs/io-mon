## test_io_mon_fragment_batch_syscall_amortization — the batched fragment
## writer's append hot path must not issue a syscall per record.
##
## M9.R.15f.1 batches frames in a per-thread 64 KiB buffer so a burst of N
## records costs O(N / batch) ``writeBuffer`` + ``flushFile`` pairs instead
## of N. The replaced-descriptor recovery (``fragmentHandleIsCurrent``, one
## ``fstat`` per call) was later added at the top of ``appendFragmentRecord``,
## which put one syscall per record back on that path: on macOS / APFS the
## batched writer then ran only ~2.2x faster than the unbatched one (reprobuild
## ``t_m9r15f_1_io_monitor_batched_writes`` requires 4x) although the write and
## flush counts were still amortised.
##
## The throughput gate in reprobuild is a wall-clock ratio. This test pins the
## cause deterministically instead, by counting syscalls the writer issues:
##
## 1. **Probe amortisation** — every identity probe precedes a descriptor
##    touch: the batch flush, plus the ``read-tail-pending`` /
##    ``read-tail-committed`` markers that open and close each dirty cycle
##    (``markReadingSentinel`` / ``clearReadingSentinel``). So the probe count
##    is at most ``3 * flushes`` (pending marker + flush + committed marker per
##    batch), independent of how many records each batch holds.
## 2. **Replaced-descriptor safety** — moving the probe off the per-record path
##    must not let frames reach a descriptor the tracee has since replaced
##    (``dup2`` over the fragment fd, as ``tests/linux/
##    test_io_mon_linux_fragment_fd_reuse.nim`` does through a live shim). The
##    flush still detects the replacement, reopens the fragment, and writes the
##    buffered frames there; the replacing file receives nothing.
##
## No mocks: both cases drive the real writer against real files in a temp dir.

import std/[os, strutils, tempfiles, unittest]

when defined(posix):
  import std/posix

import io_mon
import io_mon/writer

proc shortRecord(seq: uint64; osPid, threadId: uint64;
                 path: string): MonitorRecord =
  MonitorRecord(kind: mrFileOpen, observationKind: moFileOpen, seq: seq,
    osPid: osPid, parentOsPid: 1, threadId: threadId, result: 3,
    probeResult: prUnknown, path: path)

proc resetCounters() =
  resetFragmentLogOpenCount()
  resetFragmentLogWriteCount()
  resetFragmentLogFlushCount()
  resetFragmentLogHandleProbeCount()

suite "io-mon fragment writer — no per-record syscall on the append path":

  test "descriptor-identity probes scale with flushes, not records":
    closeFragmentSlot()
    let dir = createTempDir("io_mon_batch_amort_", "")
    defer:
      closeFragmentSlot()
      try: removeDir(dir)
      except CatchableError: discard

    const N = 10_000
    let osPid = 3131'u64
    let threadId = 17'u64
    # Open the slot first so the counters below see only the steady state.
    appendFragmentRecord(dir, shortRecord(0, osPid, threadId, "/warm"))
    flushFragmentBatch()
    resetCounters()

    for i in 1 .. N:
      appendFragmentRecord(dir,
        shortRecord(uint64(i), osPid, threadId, "/usr/include/h-" & $i & ".h"))
    flushFragmentBatch()

    let writes = fragmentLogWriteCount()
    let flushes = fragmentLogFlushCount()
    let probes = fragmentLogHandleProbeCount()
    checkpoint("records=" & $N & " writes=" & $writes & " flushes=" &
      $flushes & " identity-probes=" & $probes)

    # ~100-byte frames: a 64 KiB batch holds several hundred of them, so even
    # with a few extra time-based (100 ms staleness) flushes on a loaded host
    # the write count stays far below one per 64 records.
    check fragmentLogOpenCount() == 0
    check writes >= 1
    check writes == flushes
    check writes <= uint64(N div 64)
    # The property this test exists for: one identity probe per flush and per
    # read-tail marker — never one per record.
    check probes >= flushes
    check probes <= 3 * flushes

    closeFragmentSlot()
    var opened = 0
    for record in readFragmentRecords(fragmentPath(dir, osPid, threadId)):
      if record.kind == mrFileOpen and record.path.startsWith("/usr/include/"):
        inc opened
    check opened == N

  when defined(posix):
    test "a descriptor replaced between appends is detected at flush":
      closeFragmentSlot()
      let dir = createTempDir("io_mon_batch_replaced_", "")
      defer:
        closeFragmentSlot()
        try: removeDir(dir)
        except CatchableError: discard

      let osPid = 4141'u64
      let threadId = 23'u64
      appendFragmentRecord(dir, shortRecord(1, osPid, threadId, "/r/1"))
      flushFragmentBatch()
      appendFragmentRecord(dir, shortRecord(2, osPid, threadId, "/r/2"))

      # Replace the fragment descriptor with an unrelated file, the way a
      # tracee's dup2 / raw close+open can, while frame 2 is still buffered.
      let monitorFd = sigSafeSlotFd()
      check monitorFd >= 0
      let decoy = dir / "decoy.bin"
      let decoyFd = posix.open(decoy.cstring, O_WRONLY or O_CREAT or O_TRUNC,
        Mode(0o600))
      check decoyFd >= 0
      check dup2(decoyFd, monitorFd) == monitorFd
      discard posix.close(decoyFd)

      resetCounters()
      for i in 3 .. 10:
        appendFragmentRecord(dir,
          shortRecord(uint64(i), osPid, threadId, "/r/" & $i))
      # Appends into an open batch touch no descriptor, so they probe nothing.
      check fragmentLogHandleProbeCount() == 0
      flushFragmentBatch()
      # The flush probed, saw the replacement, and reopened the fragment.
      check fragmentLogHandleProbeCount() >= 1
      check fragmentLogOpenCount() == 1

      closeFragmentSlot()
      # The tracee's file got none of the monitor's bytes ...
      check getFileSize(decoy) == 0
      # ... and every frame reached the fragment, in order.
      var paths: seq[string]
      for record in readFragmentRecords(fragmentPath(dir, osPid, threadId)):
        if record.kind == mrFileOpen:
          paths.add(record.path)
      var expected: seq[string]
      for i in 1 .. 10:
        expected.add("/r/" & $i)
      check paths == expected
      # The stale descriptor number now belongs to the "tracee"; the writer
      # must have detached it rather than closed it.
      check fcntl(monitorFd, F_GETFD) != -1
      discard posix.close(monitorFd)

    test "a replaced descriptor number is not claimed by a close hook":
      # The Linux shim's `close` hook routes a tracee's `close(fd)` through
      # `closeFragmentSlot` when `fd` is the slot's descriptor. With no
      # per-record identity probe, the slot can still name a number the
      # tracee has since `dup2`-ed its own file over; the hook must then let
      # the tracee's close through, and the writer must stop naming that
      # number.
      closeFragmentSlot()
      let dir = createTempDir("io_mon_batch_close_", "")
      defer:
        closeFragmentSlot()
        try: removeDir(dir)
        except CatchableError: discard

      let osPid = 5151'u64
      let threadId = 29'u64
      appendFragmentRecord(dir, shortRecord(1, osPid, threadId, "/c/1"))
      let monitorFd = sigSafeSlotFd()
      check monitorFd >= 0
      # Still the fragment: the hook may close it through the writer.
      check fragmentSlotOwnsDescriptor(monitorFd)
      check not fragmentSlotOwnsDescriptor(cint(-1))
      check not fragmentSlotOwnsDescriptor(monitorFd + 1)

      # Batch a record, then replace the descriptor under the writer.
      appendFragmentRecord(dir, shortRecord(2, osPid, threadId, "/c/2"))
      let decoy = dir / "decoy.bin"
      let decoyFd = posix.open(decoy.cstring, O_WRONLY or O_CREAT or O_TRUNC,
        Mode(0o600))
      check decoyFd >= 0
      check dup2(decoyFd, monitorFd) == monitorFd
      discard posix.close(decoyFd)
      appendFragmentRecord(dir, shortRecord(3, osPid, threadId, "/c/3"))

      resetCounters()
      # The number is the tracee's now: not owned, and the writer detached
      # the stale handle onto a fresh descriptor without closing the number.
      check not fragmentSlotOwnsDescriptor(monitorFd)
      check fragmentLogOpenCount() == 1
      check sigSafeSlotIsOpen()
      check sigSafeSlotFd() != monitorFd
      check fcntl(monitorFd, F_GETFD) != -1
      # The tracee's close of its own file then succeeds normally.
      check posix.close(monitorFd) == 0

      closeFragmentSlot()
      check getFileSize(decoy) == 0
      var paths: seq[string]
      for record in readFragmentRecords(fragmentPath(dir, osPid, threadId)):
        if record.kind == mrFileOpen:
          paths.add(record.path)
      check paths == @["/c/1", "/c/2", "/c/3"]
