## Windows fragment finalization must tolerate a short non-sharing file handle
## without either dropping dependency evidence or replacing the command result
## with a cleanup error. A handle that remains locked past the bounded retry is
## missing evidence and must force the merged depfile incomplete.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, osproc, sequtils, strutils, tempfiles, unittest]
import std/winlean

import io_mon
import io_mon/writer

proc openExclusiveRead(path: string): Handle =
  result = createFileW(newWideCString(path), DWORD(GENERIC_READ), DWORD(0), nil,
    DWORD(OPEN_EXISTING), DWORD(0), Handle(0))
  if result == INVALID_HANDLE_VALUE:
    raiseOSError(osLastError(), "cannot lock fragment " & path)

proc runLockHelper(): bool =
  if paramCount() != 4 or paramStr(1) != "--hold-exclusive-read":
    return false
  let handle = openExclusiveRead(paramStr(2))
  try:
    writeFile(paramStr(3), "ready")
    sleep(parseInt(paramStr(4)))
  finally:
    discard closeHandle(handle)
  true

if runLockHelper():
  quit(0)

proc onlyFragment(dir: string): string =
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".iomon-frag"):
      if result.len > 0:
        raise newException(ValueError, "expected exactly one fragment in " & dir)
      result = path
  if result.len == 0:
    raise newException(ValueError, "no fragment found in " & dir)

proc startLocker(fragment, readyPath: string; holdMs: int): Process =
  result = startProcess(getAppFilename(),
    args = @["--hold-exclusive-read", fragment, readyPath, $holdMs],
    options = {poParentStreams})
  for _ in 0 ..< 200:
    if fileExists(readyPath):
      return
    sleep(25)
  terminate(result)
  discard waitForExit(result)
  close(result)
  raise newException(IOError, "lock helper did not become ready")

proc writeFragment(dir, inputPath: string) =
  appendFragmentRecord(dir, MonitorRecord(
    kind: mrFileRead,
    observationKind: moFileRead,
    seq: 1,
    osPid: 42'u64,
    threadId: 100'u64,
    path: inputPath,
    result: 1))
  closeFragmentSlot()

suite "Windows fragment finalization":
  test "a transient sharing violation preserves the fragment records":
    let dir = createTempDir("io_mon_fragment_finalization_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    let inputPath = dir / "input.txt"
    writeFragment(dir, inputPath)
    let readyPath = dir / "locker.ready"
    let locker = startLocker(onlyFragment(dir), readyPath, 200)
    defer:
      discard waitForExit(locker)
      close(locker)

    let merged = mergeFragments(dir, dir / "merged.iomon")
    check merged.records.anyIt(it.path == inputPath)
    check summarizeRecords(merged.records).eventLossCount == 0'u64

  test "a persistently locked fragment fails the evidence closed":
    let dir = createTempDir("io_mon_fragment_finalization_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    writeFragment(dir, dir / "input.txt")
    let readyPath = dir / "locker.ready"
    let locker = startLocker(onlyFragment(dir), readyPath, 10_000)
    defer:
      terminate(locker)
      discard waitForExit(locker)
      close(locker)

    let merged = mergeFragments(dir, dir / "merged.iomon")
    check merged.completeness == mcIncomplete
    check summarizeRecords(merged.records).eventLossCount > 0'u64
