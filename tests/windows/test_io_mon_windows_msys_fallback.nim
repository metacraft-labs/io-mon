import std/[os, osproc, strutils, tempfiles, unittest]

import io_mon
import stackable_hooks/windows_injector

const
  DirectProbeArg = "--msys-monitor-fallback-probe"
  NestedProbeArg = "--nested-msys-monitor-fallback-probe"
  NativeSpawnerArg = "--native-msys-child-spawner"

let BuiltShim = currentSourcePath.parentDir.parentDir.parentDir / "build" /
  "lib" / "librepro_monitor_shim.dll"

proc runDirectFallbackProbe(): int =
  let shell = findExe("sh")
  if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
    return 77

  let work = createTempDir("io-mon-", "-msys-fallback")
  defer:
    try: removeDir(work)
    except OSError: discard
  let systemRoot = getEnv("SystemRoot", r"C:\Windows")
  putEnv("REPRO_MONITOR_SHIM_LIB", systemRoot / "System32" / "kernel32.dll")

  let monitored = runMonitored(FsSnoopRequest(
    command: @[shell, "-c", "/usr/bin/true; echo io-mon-msys-fallback-ok"],
    depFilePath: work / "evidence.iomon",
    captureChildStdio: true,
    captureStdioPath: work / "stdio.log"))
  if monitored.exitCode != 0:
    return 2
  if monitored.completeness != mcIncomplete:
    return 3
  for record in monitored.records:
    if record.kind == mrEventLoss and
        record.detail.startsWith("unmonitored subtree/peer") and
        windowsForkRuntimeForExecutable(shell) in record.detail:
      return 0
  4

proc runNativeMsysChild(): int =
  let shell = findExe("sh")
  if shell.len == 0:
    return 77
  let child = startProcess(shell,
    args = @["-c", "/usr/bin/true; echo io-mon-nested-msys-fallback-ok"],
    options = {poParentStreams})
  result = waitForExit(child)
  close(child)

proc runNestedFallbackProbe(): int =
  let shell = findExe("sh")
  if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
    return 77

  if not fileExists(BuiltShim):
    return 78

  let work = createTempDir("io-mon-", "-nested-msys-fallback")
  defer:
    try: removeDir(work)
    except OSError: discard
  putEnv("REPRO_MONITOR_SHIM_LIB", BuiltShim)
  let stdioPath = work / "stdio.log"

  let monitored = runMonitored(FsSnoopRequest(
    command: @[getAppFilename(), NativeSpawnerArg],
    depFilePath: work / "evidence.iomon",
    captureChildStdio: true,
    captureStdioPath: stdioPath))
  if monitored.exitCode != 0:
    if fileExists(stdioPath):
      stderr.writeLine(readFile(stdioPath))
    return 2
  if monitored.completeness != mcIncomplete:
    return 3
  for record in monitored.records:
    if record.kind == mrProcessSpawn and
        "fork-runtime=" & windowsForkRuntimeForExecutable(shell) in
          record.detail:
      return 0
  4

if paramCount() == 1:
  case paramStr(1)
  of DirectProbeArg:
    quit(runDirectFallbackProbe())
  of NestedProbeArg:
    quit(runNestedFallbackProbe())
  of NativeSpawnerArg:
    quit(runNativeMsysChild())
  else:
    discard

proc runProbeWithTimeout(probeArg: string): int =
  let probe = startProcess(getAppFilename(), args = @[probeArg],
    options = {poUsePath, poParentStreams})
  result = -1
  for _ in 0 ..< 200:
    result = peekExitCode(probe)
    if result != -1:
      break
    sleep(50)
  if result == -1:
    terminate(probe)
    discard waitForExit(probe, 5000)
  close(probe)

suite "Windows MSYS/Cygwin monitor fallback":
  test "compound shell command completes with explicit incomplete evidence":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      check runProbeWithTimeout(DirectProbeArg) == 0

  test "native parent leaves an MSYS child uninstrumented and completes":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      require fileExists(BuiltShim)
      check runProbeWithTimeout(NestedProbeArg) == 0
