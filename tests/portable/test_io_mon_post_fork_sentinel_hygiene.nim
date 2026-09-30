## test_io_mon_post_fork_sentinel_hygiene — ROUND-5 F post-fork
## sentinel-state hygiene: after `discardFragmentSlotAfterFork`, the
## per-thread `fragmentSlot.readingSentinelActive` MUST be reset so the
## child's first read faithfully re-marks the pending sentinel under
## the CHILD's own (osPid, threadId).
##
## Regression pin for the pre-fix behaviour where
## `discardFragmentSlotAfterFork` reset osPid / threadId / batch
## bookkeeping but NOT `readingSentinelActive`. Consequence: after a
## fork+recordProcessStart pair, the child inherited
## `readingSentinelActive = true` from the parent's copy-on-write; the
## child's next `markReadingSentinel` bailed on the "already active"
## guard and NEVER wrote the child's own pending marker. The child's
## first flush then wrote an orphan `read-tail-committed` marker under
## the child's identity, leaving every intermediate child batch cycle
## un-bookkeeped — a kill-before-flush in the child on any of those
## cycles went silently un-detected.

import std/[os, tempfiles, unittest]

import io_mon
import io_mon/writer

suite "ROUND-5 F post-fork sentinel-state hygiene":

  test "child's post-fork clean flush writes a matching committed sentinel":
    # Simulate the "parent had dirty batch when fork happened, child
    # inherits the slot copy-on-write, does its own read, then EXITS
    # CLEANLY through the flush path" sequence. The parent side is
    # not simulated in this test because in-process we cannot spawn a
    # separate osPid; the parent's dangling sentinel is a real loss
    # by design and IS expected to be counted (that's what
    # ROUND-5 F is for). The load-bearing claim here is: the CHILD's
    # cycle nets cleanly WITH the sentinel-state hygiene fix (the
    # child's markReadingSentinel actually fires + the child's
    # clearReadingSentinel actually fires).
    let dir = createTempDir("io_mon_postfork_sentinel_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    # Parent: one read + close cleanly. This flushes the parent's
    # cycle: pending + committed both written under parent's identity.
    appendFragmentRecord(dir, MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead, seq: 1,
      osPid: 100'u64, threadId: 200'u64, path: "/tmp/p", result: 512))
    closeFragmentSlot()  # parent flushes its own cycle

    # Fork. Simulate the child's post-fork hygiene path.
    discardFragmentSlotAfterFork()

    # Child does its read + clean flush.
    appendFragmentRecord(dir, MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead, seq: 2,
      osPid: 101'u64, threadId: 201'u64, path: "/tmp/c", result: 256))
    closeFragmentSlot()

    # With the hygiene fix, both cycles net cleanly.
    let outPath = dir / "merged.iomon"
    let merged = mergeFragments(dir, outPath)
    let summary = summarizeRecords(merged.records)
    check summary.eventLossCount == 0'u64

  test "child's post-fork flush writes a matching pending sentinel":
    # This is the load-bearing behaviour test. We prove that AFTER
    # `discardFragmentSlotAfterFork`, the child's first
    # `appendFragmentRecord` opens a fresh slot AND that slot's
    # `readingSentinelActive` is CLEARED at open (line 524 of
    # writer.nim), so the subsequent `markReadingSentinel` DOES
    # write a pending marker (not bail on the inherited-true flag).
    let dir = createTempDir("io_mon_postfork_sentinel_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    # Parent primes the slot + sentinel.
    appendFragmentRecord(dir, MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead, seq: 1,
      osPid: 100'u64, threadId: 200'u64, path: "/tmp/p", result: 1))

    # Fork-child hygiene path.
    discardFragmentSlotAfterFork()

    # Child does one read + IMMEDIATELY dies without going through
    # closeFragmentSlot. This models a child that was SIGKILL'd
    # after its first dirty batch — the exact class ROUND-5 F is
    # designed to catch.
    appendFragmentRecord(dir, MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead, seq: 2,
      osPid: 101'u64, threadId: 201'u64, path: "/tmp/c", result: 1))
    # No closeFragmentSlot — simulate the SIGKILL escape.

    # Merge — expect ONE synthetic event-loss for the child's
    # un-flushed pending. Without the sentinel-state hygiene fix,
    # the child never wrote a pending marker (inherited-active
    # flag suppressed it), so merge would report ZERO losses even
    # though the child died mid-batch — a soundness hole.
    let outPath = dir / "merged.iomon"
    let merged = mergeFragments(dir, outPath)
    let summary = summarizeRecords(merged.records)
    # Exactly one un-matched pending for the child (osPid=101).
    check summary.eventLossCount == 1'u64
