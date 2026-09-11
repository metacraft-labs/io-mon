## test_io_mon_windows_read_capture - reads are captured ONCE, at the layer
## the process actually read through.
##
## Two entry points reach the same kernel read on Windows:
## `kernel32!ReadFile`, and `ntdll!NtReadFile`, which the former lowers to.
## The shim hooked only the first, and that was not a coverage detail -- it
## was the reason an MSYS2/Cygwin child produced NO read evidence at all.
## `msys-2.0.dll` imports BOTH and uses the NT export for ordinary disk
## files, so a monitored `bash -c 'grep foo data.txt'` recorded the OPEN of
## `data.txt` and never a READ of it. Reads are what an action cache keys on.
##
## Hooking both without care would count every NATIVE read twice, which is
## worse than not hooking it: a doubled read set is the evidence a cache
## decides on. `snoopNtReadFile` therefore stays silent while nested inside
## the real `kernel32!ReadFile` (`win32ReadDepth`).
##
## Both properties are asserted here, each against the process class it
## governs:
##
##   * NATIVE arm -- N explicit `ReadFile` calls on a known file produce
##     EXACTLY N read records for that file, and ZERO of them come from the
##     NT layer.
##   * MSYS arm -- the file the Cygwin child read is recorded as a read
##     ATTRIBUTED TO THAT CHILD's own pid: the pid has its own
##     `mrProcessStart`, and a `mrProcessSpawn` names it as a child. A read
##     the root shell made would satisfy neither.

import std/[os, osproc, strutils, tempfiles, unittest, widestrs]

import io_mon
import stackable_hooks/windows_injector

const
  NativeReadProbeArg = "--native-read-probe"
  NativeReaderArg = "--native-reader"
  MsysReadProbeArg = "--msys-read-probe"
  ProbeFileName = "iomon-read-probe.txt"
  ProbeNeedle = "needle-io-mon-read"
  NativeReadCount = 3
  NativeChunk = 4

let BuiltShim = currentSourcePath.parentDir.parentDir.parentDir / "build" /
  "lib" / "librepro_monitor_shim.dll"

# --- the native reader: kernel32!ReadFile, an exact number of times -------

type WinHandle = pointer

proc CreateFileW(lpFileName: WideCString; dwDesiredAccess, dwShareMode: uint32;
                 lpSecurityAttributes: pointer;
                 dwCreationDisposition, dwFlagsAndAttributes: uint32;
                 hTemplateFile: WinHandle): WinHandle
  {.importc, stdcall, dynlib: "kernel32".}
proc ReadFile(hFile: WinHandle; lpBuffer: pointer; nNumberOfBytesToRead: uint32;
              lpNumberOfBytesRead: ptr uint32; lpOverlapped: pointer): int32
  {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(hObject: WinHandle): int32
  {.importc, stdcall, dynlib: "kernel32".}

proc runNativeReader(path: string): int =
  ## GENERIC_READ | FILE_SHARE_READ | OPEN_EXISTING, then exactly
  ## `NativeReadCount` ReadFile calls. Deliberately raw Win32 rather than
  ## `readFile`: the CRT is free to coalesce or buffer, and this arm's whole
  ## claim is a KNOWN number of kernel32-layer reads.
  let wide = newWideCString(path)
  let h = CreateFileW(wide, 0x80000000'u32, 0x1'u32, nil, 3'u32, 0'u32, nil)
  if h == nil or cast[uint](h) == high(uint):
    return 2
  var buf: array[64, byte]
  var got: uint32 = 0
  for _ in 0 ..< NativeReadCount:
    if ReadFile(h, addr buf[0], uint32(NativeChunk), addr got, nil) == 0:
      discard CloseHandle(h)
      return 3
  discard CloseHandle(h)
  0

proc readsOfProbeFile(records: seq[MonitorRecord]; detail: string): int =
  for record in records:
    if record.kind == mrFileRead and record.detail == detail and
        record.path.toLowerAscii.endsWith(ProbeFileName.toLowerAscii):
      inc result

# --- arm 1: a native child's reads are counted once ----------------------

proc runNativeReadProbe(): int =
  if not fileExists(BuiltShim):
    return 78
  let work = createTempDir("io-mon-", "-native-read")
  defer:
    try: removeDir(work)
    except OSError: discard
  let probeFile = work / ProbeFileName
  writeFile(probeFile, ProbeNeedle & "\n")
  putEnv("REPRO_MONITOR_SHIM_LIB", BuiltShim)

  let monitored = runMonitored(FsSnoopRequest(
    command: @[getAppFilename(), NativeReaderArg, probeFile],
    depFilePath: work / "evidence.iomon"))
  if monitored.exitCode != 0:
    return 2

  # The reads were seen at all...
  let win32Reads = readsOfProbeFile(monitored.records, "ReadFile")
  if win32Reads != NativeReadCount:
    return 10 + win32Reads
  # ...and the NT layer under them did NOT record them a second time.
  let ntReads = readsOfProbeFile(monitored.records, "NtReadFile")
  if ntReads != 0:
    return 30 + ntReads
  0

# --- arm 2: an MSYS child's reads exist and are attributed to it ---------

proc runMsysReadProbe(): int =
  let shell = findExe("sh")
  if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
    return 77
  if not fileExists(BuiltShim):
    return 78
  let work = createTempDir("io-mon-", "-msys-read")
  defer:
    try: removeDir(work)
    except OSError: discard
  let probeFile = work / ProbeFileName
  writeFile(probeFile, ProbeNeedle & "\n")
  putEnv("REPRO_MONITOR_SHIM_LIB", BuiltShim)

  # `grep` is a SEPARATE Cygwin image, so the read has to come from a CHILD
  # of the shell rather than from the shell itself -- which is the whole
  # point of the attribution assertion below. Forward slashes because Cygwin
  # accepts them unambiguously in a shell word.
  let posixDir = work.replace('\\', '/')
  let script = "cd '" & posixDir & "' && grep -c " & ProbeNeedle & " " &
    ProbeFileName
  let monitored = runMonitored(FsSnoopRequest(
    command: @[shell, "-c", script],
    depFilePath: work / "evidence.iomon"))
  if monitored.exitCode != 0:
    return 2

  # Which pids read the probe file?
  var readerPids: seq[uint64] = @[]
  for record in monitored.records:
    if record.kind == mrFileRead and record.osPid != 0 and
        record.path.toLowerAscii.endsWith(ProbeFileName.toLowerAscii) and
        record.osPid notin readerPids:
      readerPids.add record.osPid
  if readerPids.len == 0:
    return 4

  # At least one of them must be a SPAWNED CHILD that reported for itself:
  # it has its own process-start, and some process-spawn record names it.
  var startedPids: seq[uint64] = @[]
  var spawnedPids: seq[uint64] = @[]
  for record in monitored.records:
    if record.kind == mrProcessStart and record.osPid != 0:
      startedPids.add record.osPid
    elif record.kind == mrProcessSpawn and record.childOsPid != 0:
      spawnedPids.add record.childOsPid
  var attributed = false
  for pid in readerPids:
    if pid in startedPids and pid in spawnedPids:
      attributed = true
  if not attributed:
    return 5

  # And the run must grade honestly complete over that evidence: every child
  # reported, and nothing was rescued without being netted.
  if monitored.completeness != mcComplete:
    return 6
  0

if paramCount() >= 1:
  case paramStr(1)
  of NativeReaderArg:
    quit(runNativeReader(paramStr(2)))
  of NativeReadProbeArg:
    quit(runNativeReadProbe())
  of MsysReadProbeArg:
    quit(runMsysReadProbe())
  else:
    discard

proc runProbeWithTimeout(probeArg: string): int =
  ## Same containment as the MSYS fallback probes: a wedged Cygwin child must
  ## fail the test, never hang the suite and never be left behind.
  let probe = startProcess(getAppFilename(), args = @[probeArg],
    options = {poUsePath, poParentStreams})
  result = -1
  for _ in 0 ..< 400:
    result = peekExitCode(probe)
    if result != -1:
      break
    sleep(50)
  if result == -1:
    terminate(probe)
    discard waitForExit(probe, 5000)
  close(probe)

suite "Windows read capture":
  test "a native child's reads are recorded once, at the Win32 layer":
    require fileExists(BuiltShim)
    check runProbeWithTimeout(NativeReadProbeArg) == 0

  test "an MSYS child's read is recorded and attributed to that child":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      require fileExists(BuiltShim)
      check runProbeWithTimeout(MsysReadProbeArg) == 0
