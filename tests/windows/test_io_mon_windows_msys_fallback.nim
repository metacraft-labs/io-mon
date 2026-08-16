import std/[os, osproc, strutils, tempfiles, unittest]

import io_mon
import stackable_hooks/windows_injector

const ProbeArg = "--msys-monitor-fallback-probe"

proc runFallbackProbe(): int =
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
    depFilePath: work / "evidence.rdep",
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

if paramCount() == 1 and paramStr(1) == ProbeArg:
  quit(runFallbackProbe())

suite "Windows MSYS/Cygwin monitor fallback":
  test "compound shell command completes with explicit incomplete evidence":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      let probe = startProcess(getAppFilename(), args = @[ProbeArg],
        options = {poUsePath, poParentStreams})
      var exitCode = -1
      for _ in 0 ..< 200:
        exitCode = peekExitCode(probe)
        if exitCode != -1:
          break
        sleep(50)
      if exitCode == -1:
        terminate(probe)
        discard waitForExit(probe, 5000)
      close(probe)
      check exitCode == 0
