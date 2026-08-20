## The shim's own process-start record must survive into the merged depfile.
##
## This is a live test on purpose. The existing Windows fragment tests drive
## the writer with synthetic fragments written by the test process itself,
## which is why none of them could see this: the defect was not in the writer
## but in WHERE the shim emits from.
##
## Fragment frames are batched per (osPid, threadId) and flushed on a key
## change, an explicit flush, or a 100 ms age bound. On Windows the shim is
## initialised by the injector through CreateRemoteThread ->
## repro_runtime_init, so `recordProcessStart` runs on a remote thread whose
## ONLY record is that one, and which then exits. None of the three flush
## triggers fires, so the record was dropped -- in every injected process,
## which is every process, root and children alike. A full nim+gcc link
## produced 57880 records across 5 pids and not one mrProcessStart.
##
## The consequence was not a missing diagnostic. `processStartIdentities`
## builds its monitored-process set purely from mrProcessStart, so with none
## surviving, `childIsMonitored` answered false for every spawn and the writer
## synthesised "spawn child missing process-start" for children that were in
## fact fully monitored. That is an unknown-scope loss, which grades the
## evidence mcIncomplete, which makes a consumer skip action-cache publication
## for the whole session. Hence the two assertions below: the record is
## present, AND the run is complete.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, strutils, tempfiles, unittest]

import io_mon
import io_mon/fs_snoop

proc monitorSimpleCommand(depFilePath: string): MonitorResult =
  ## Run the most trivial child we can and collect its evidence. `cmd /c exit`
  ## spawns nothing of its own, so anything reported here comes from the shim
  ## in the root child -- which is the case that was broken.
  var request = FsSnoopRequest(
    command: @[getEnv("ComSpec", r"C:\Windows\System32\cmd.exe"), "/c", "exit"],
    depFilePath: depFilePath,
    passthroughChildStdout: false,
    passthroughChildStderr: false,
    captureChildStdio: true)
  runMonitored(request)

suite "Windows process-start survives the merge":
  test "an injected process emits a process-start record that reaches the depfile":
    let dir = createTempDir("io_mon_process_start_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    let depFilePath = dir / "run.rdep"
    let result = monitorSimpleCommand(depFilePath)

    var processStarts = 0
    for r in result.records:
      if r.kind == mrProcessStart:
        inc processStarts

    # Before the fix this was 0 for every process on Windows.
    check processStarts >= 1

  test "the run is not downgraded to incomplete by a missing process-start":
    let dir = createTempDir("io_mon_process_start_complete_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    let depFilePath = dir / "run.rdep"
    let result = monitorSimpleCommand(depFilePath)

    # A dropped process-start does not merely lose a record: it makes every
    # spawn unmatchable, and an unmatched spawn is an unknown-scope loss. The
    # completeness grade is what a consumer keys its publish decision on, so
    # assert the grade and not just the record count.
    check result.completeness == mcComplete

    for r in result.records:
      if r.kind == mrEventLoss:
        check "missing process-start" notin r.detail
