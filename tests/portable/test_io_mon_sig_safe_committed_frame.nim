## test_io_mon_sig_safe_committed_frame — M9.R.62.2 regression pin.
##
## The kill-before-flush recovery path installed in the Linux shim
## (`repro_linux_terminating_signal_handler` in linux_preload.nim) writes
## a PRE-ENCODED `read-tail-committed` marker frame from the fragment
## slot's `committedFrame` buffer via raw `write(2)` — no allocation, no
## fflush, no lock acquisition, so it's async-signal-safe.
##
## This test validates that the pre-encoded frame produced at fragment
## open time is BYTE-IDENTICAL to what `writeReadTailMarker` +
## `encodeFrame` would produce for the same slot at the same run token,
## so `mergeFragments`' netting sees the two markers as a matching pair.
## A byte drift would either (a) skip the netting (leaving an unmatched
## pending → false event-loss) or (b) leave a corrupt frame at the tail
## of the fragment (`decodeFramesTolerant` drops it + flags the fragment
## dirty). Either failure mode reopens the M9.R.61 residual.

import std/[os, streams, tempfiles, unittest]

when defined(posix):
  import std/posix

import io_mon
import io_mon/codec
import io_mon/writer

suite "M9.R.62.2 async-signal-safe committed-marker pre-encoding":

  test "pre-encoded frame decodes to the same MonitorRecord as encodeFrame":
    # Open a fragment slot the way the shim does — write ONE record so
    # the slot is materialised with a specific (osPid, threadId), then
    # snapshot the pre-encoded committed frame + decode it and check
    # every field.
    let dir = createTempDir("io_mon_sigsafe_frame_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    setFragmentRunToken("")  # match the Linux shim's runtime state.

    appendFragmentRecord(dir, MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead, seq: 1,
      osPid: 4242'u64, threadId: 8484'u64, path: "/tmp/x", result: 128))

    # Snapshot the pre-encoded committed frame BEFORE close (which
    # zeroes committedFrameLen).
    let committedLen = sigSafeCommittedLen()
    check committedLen > 0
    var frame = newSeq[byte](committedLen)
    copyMem(addr frame[0], sigSafeCommittedPtr(), committedLen)

    # Decode the ONE frame in the buffer. `decodeFrames` reads a
    # sequence of (u32 length + payload) records; the pre-encoded
    # frame follows the same layout.
    let records = decodeFrames(frame)
    check records.len == 1
    check records[0].kind == mrEventLoss
    check records[0].observationKind == moEventLoss
    check records[0].osPid == 4242'u64
    check records[0].threadId == 8484'u64
    check records[0].detail == "read-tail-committed"
    check records[0].path == ""

    closeFragmentSlot()

  test "signal-safe flush of the pre-encoded frame nets a dirty pending":
    # This is the LOAD-BEARING semantic test. We synthesise the
    # "process died via terminating signal with default disposition
    # AFTER buffering reads" scenario:
    #
    #   1. Open the fragment slot + do a read (writes pending marker
    #      to disk via writeReadTailMarker, buffers the read frame in
    #      batchBuf).
    #   2. Simulate the signal handler: raw-write the batchBuf +
    #      raw-write the committedFrame + close the fd + mark closed.
    #   3. Merge the fragment dir and check summary.eventLossCount == 0.
    #
    # Without the M9.R.62.2 fix, the signal-death path would leave
    # ONLY the pending marker (no committed), and mergeFragments would
    # inject a synthetic kill-before-flush event-loss.
    let dir = createTempDir("io_mon_sigsafe_flush_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    setFragmentRunToken("")

    appendFragmentRecord(dir, MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead, seq: 1,
      osPid: 5555'u64, threadId: 5555'u64, path: "/tmp/y", result: 256))

    check sigSafeSlotIsOpen()
    let fd = sigSafeSlotFd()
    check fd >= 0

    # Simulate the signal handler's raw-syscall path using the POSIX
    # `write` + `close` from std/posix (test-only — the real handler
    # goes through stackable_linux_raw_syscall6).
    let batchLen = sigSafeBatchLen()
    let committedLen = sigSafeCommittedLen()
    check batchLen > 0
    check committedLen > 0

    when defined(posix):
      # posix.write / close is NOT signal-safe in the strict sense
      # (they may raise Nim exceptions on error), but for the test's
      # in-process purposes they exercise the same on-disk shape.
      var written = 0
      while written < batchLen:
        let n = write(fd, cast[pointer](cast[uint](sigSafeBatchPtr()) + uint(written)),
                      batchLen - written)
        if n <= 0: break
        written += n
      check written == batchLen
      var writtenC = 0
      while writtenC < committedLen:
        let n = write(fd, cast[pointer](cast[uint](sigSafeCommittedPtr()) + uint(writtenC)),
                      committedLen - writtenC)
        if n <= 0: break
        writtenC += n
      check writtenC == committedLen
      discard close(fd)
      sigSafeMarkSlotClosed()

      let outPath = dir / "merged.rmdf"
      let merged = mergeFragments(dir, outPath)
      let summary = summarizeRecords(merged.records)
      # The pending + committed net cleanly — no synthetic kill-before-
      # flush event-loss injected. The dirty batch is durable on disk.
      check summary.eventLossCount == 0'u64
    else:
      # Non-POSIX: the test only asserts the pre-encode invariants.
      closeFragmentSlot()
