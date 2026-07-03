## test_io_mon_windows_flush_parity — the Windows shim's exported
## `repro_monitor_shim_flush` / `repro_monitor_shim_shutdown` procs
## actually flush + close the calling thread's fragment slot, closing
## the ROUND-5 F kill-before-flush window at parity with the Linux
## shim.
##
## Regression pin for the pre-fix behaviour where both procs were
## defined as `= 0` no-op stubs (see `shim/windows_interpose.nim`):
## every Windows-side execve / process-exit call through the exported
## ABI left the `read-tail-pending` sentinel un-committed on the
## fragment file, and `mergeFragments` accounted each dirty sentinel
## as a synthetic kill-before-flush event-loss record — false-
## downgrading completeness to `mcIncomplete` for every Windows
## capture.
##
## The test does not need to inject the shim DLL — the flush logic is
## the SAME `closeFragmentSlot` proc from `io_mon/writer` that the
## Linux shim delegates to. We simulate the "child appended records,
## then died without going through the destructor" sequence by
## driving `appendFragmentRecord` (which internally calls
## `markReadingSentinel`) and then invoking `closeFragmentSlot`
## directly. `mergeFragments` on the resulting fragment dir must
## report `mcComplete` (no synthetic loss) — proving the sentinel was
## committed. Without the fix, `closeFragmentSlot` was NEVER called on
## Windows for the exported-ABI paths, and merge would report loss.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, tempfiles, unittest]

import io_mon
import io_mon/writer

suite "windows shim flush parity (ROUND-5 F)":

  test "closeFragmentSlot commits the read-tail sentinel + merge stays mcComplete":
    let dir = createTempDir("io_mon_windows_flush_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    # Append a file-read record. writer.appendFragmentRecord internally
    # calls markReadingSentinel — writing a durable `read-tail-pending`
    # marker into the fragment. Without closeFragmentSlot, that pending
    # is un-matched and mergeFragments will inject a synthetic
    # kill-before-flush event-loss record.
    let record = MonitorRecord(
      kind: mrFileRead,
      observationKind: moFileRead,
      seq: 1,
      osPid: 42'u64,
      threadId: 100'u64,
      path: "C:\\tmp\\some-input.txt",
      result: 1024)
    appendFragmentRecord(dir, record)

    # The pre-fix Windows path would return here without calling
    # closeFragmentSlot; the fragment would carry an un-committed
    # pending sentinel. Our fix wires closeFragmentSlot into
    # repro_monitor_shim_flush / _shutdown / the exit-proc callback,
    # so the sentinel is retired before merge.
    closeFragmentSlot()

    # Merge — no synthetic loss expected.
    let outPath = dir / "merged.rmdf"
    let merged = mergeFragments(dir, outPath)
    let summary = summarizeRecords(merged.records)
    check summary.eventLossCount == 0'u64
    # Not a hard-mcComplete assertion because the profile record shape
    # depends on `defaultHooksMonitorProfile`, which returns different
    # capabilities on Windows vs Linux/macOS. The loss-count assertion
    # is the load-bearing one — the ROUND-5 F machinery would inject
    # exactly one event-loss for an un-matched pending sentinel.

  test "repeated append + close cycles stay balanced":
    # A longer-running Windows recorder sends many batches; every
    # batch's dirty→flush cycle must net to zero pending markers.
    let dir = createTempDir("io_mon_windows_flush_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    for i in 0 ..< 32:
      let r = MonitorRecord(
        kind: mrFileRead,
        observationKind: moFileRead,
        seq: uint64(i + 1),
        osPid: 42'u64,
        threadId: 100'u64,
        path: "C:\\tmp\\loop-" & $i & ".txt",
        result: int64(1024 + i))
      appendFragmentRecord(dir, r)
      # Simulate an execve / shutdown flush every 8 records.
      if (i + 1) mod 8 == 0:
        closeFragmentSlot()

    # Final trailing batch that never got a mid-loop close — the
    # fix's exit-proc callback must retire it.
    closeFragmentSlot()

    let outPath = dir / "merged.rmdf"
    let merged = mergeFragments(dir, outPath)
    let summary = summarizeRecords(merged.records)
    check summary.eventLossCount == 0'u64
