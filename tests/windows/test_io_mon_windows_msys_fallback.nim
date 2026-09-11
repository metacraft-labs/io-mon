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
  # THE PROPERTY IS THE EXPLICIT LOSS, NOT THE SENTENCE THAT EXPLAINS IT.
  # There are now two ways an MSYS2/Cygwin root reaches "incomplete", and
  # both have to be accepted here or this case would pin an implementation
  # detail of the injector rather than the contract a consumer reads.
  #
  #   * REFUSED. Where the entry-point park is unavailable (ARM64, a 32-bit
  #     child), the injector still declines a fork-runtime image outright
  #     and names the runtime in the loss.
  #   * INJECTED AND SILENT. Where the park works, the root IS injected --
  #     that is the whole point of the park -- and this probe deliberately
  #     points `REPRO_MONITOR_SHIM_LIB` at `kernel32.dll`, a library with no
  #     `repro_runtime_init`, so the child comes up with nothing hooked and
  #     emits no records. The merge then finds the root pid the launcher
  #     said to expect and no `process-start` for it, and reports the same
  #     unmonitored-subtree loss. (That pairing is io-mon's own
  #     "an injected child that reports nothing is not an uninjected
  #     child"; without it this arm would grade COMPLETE over a subtree
  #     nothing watched, which is the one outcome that must never happen.)
  #
  # What is NOT relaxed: there must still be an `mrEventLoss` that says
  # `unmonitored subtree/peer`, and `completeness` above must still be
  # `mcIncomplete`. A run that simply stopped reporting the loss fails here
  # exactly as it did before.
  for record in monitored.records:
    if record.kind == mrEventLoss and
        record.detail.startsWith("unmonitored subtree/peer") and
        (windowsForkRuntimeForExecutable(shell) in record.detail or
         "missing process-start" in record.detail):
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

proc runNestedInstrumentedProbe(): int =
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

  # The child really is a fork-runtime image -- otherwise this probe proves
  # nothing about MSYS at all, it just spawned some native exe.
  var forkRuntimeChildren: seq[uint64] = @[]
  for record in monitored.records:
    if record.kind == mrProcessSpawn and record.childOsPid != 0 and
        "fork-runtime=" & windowsForkRuntimeForExecutable(shell) in
          record.detail:
      forkRuntimeChildren.add record.childOsPid
  if forkRuntimeChildren.len == 0:
    return 4

  # THE CLAIM THAT CHANGED. This case used to require `mcIncomplete` and a
  # spawn record naming the runtime: an MSYS child was refused injection
  # outright (the shim's own `childForkRuntime.len == 0` guard), so the only
  # honest grade was "subtree lost". With the entry-point park the child is
  # attachable, and refusing it would now be throwing away evidence we can
  # have. So the property is inverted, and DELIBERATELY strengthened from
  # the grade to the thing that earns it: the fork-runtime child must have
  # reported its OWN `process-start`.
  #
  # That ordering matters. Asserting only `mcComplete` would be satisfied by
  # a merge that had simply stopped noticing the missing child -- the one
  # regression that must never ship. Asserting the child's own record first
  # means the grade below is checked over evidence we have already confirmed
  # is there.
  var startedPids: seq[uint64] = @[]
  for record in monitored.records:
    if record.kind == mrProcessStart and record.osPid != 0:
      startedPids.add record.osPid
  var instrumented = false
  for pid in forkRuntimeChildren:
    if pid in startedPids:
      instrumented = true
  if not instrumented:
    return 5
  if monitored.completeness != mcComplete:
    return 6
  0

if paramCount() == 1:
  case paramStr(1)
  of DirectProbeArg:
    quit(runDirectFallbackProbe())
  of NestedProbeArg:
    quit(runNestedInstrumentedProbe())
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

  test "native parent gets its MSYS child instrumented, and completes":
    let shell = findExe("sh")
    if shell.len == 0 or windowsForkRuntimeForExecutable(shell).len == 0:
      checkpoint("MSYS2/Cygwin shell is not installed; integration probe skipped")
    else:
      require fileExists(BuiltShim)
      check runProbeWithTimeout(NestedProbeArg) == 0
