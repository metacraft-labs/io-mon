## test_io_mon_macos_debug_logging — verifies that io-mon is silent on stderr by default
## and logs to a file only when IO_MON_DEBUG_LOG_FILE is opt-in.

import std/[os, osproc, streams, strtabs, unittest, strutils]

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc compileProbe(work: string): string =
    let src = work / "probe.c"
    writeFile(src, """
#include <stdio.h>
int main(void) {
  printf("hello from probe\n");
  return 0;
}
""")
    let bin = work / "probe"
    let cc = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(cc) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(bin))
    doAssert code == 0, "probe compile failed: " & output
    doAssert fileExists(bin)
    bin

suite "io-mon macOS debug logging":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-log-test-" & $getCurrentProcessId())
    createDir(work)
    let probe = compileProbe(work)

    test "io-mon is completely silent on stderr by default":
      let fragmentDir = work / "frags_silent"
      createDir(fragmentDir)
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["DYLD_INSERT_LIBRARIES"] = shim
      env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir

      let p = startProcess(probe, args = @[], env = env,
        options = {poStdErrToStdOut})
      let output = p.outputStream.readAll()
      let code = p.waitForExit()
      p.close()

      check code == 0
      # Output should only contain "hello from probe\n" and NO "io-mon:" lines
      check "hello from probe" in output
      check "io-mon:" notin output

    test "io-mon writes to IO_MON_DEBUG_LOG_FILE when opt-in is active":
      let fragmentDir = work / "frags_log"
      createDir(fragmentDir)
      let logFile = work / "io-mon-debug.log"
      if fileExists(logFile): removeFile(logFile)

      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["DYLD_INSERT_LIBRARIES"] = shim
      env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
      env["IO_MON_DEBUG_LOG_FILE"] = logFile

      let p = startProcess(probe, args = @[], env = env,
        options = {poStdErrToStdOut})
      let output = p.outputStream.readAll()
      let code = p.waitForExit()
      p.close()

      check code == 0
      check "hello from probe" in output
      check "io-mon:" notin output  # Stderr is still silent

      # Check that the log file was created and populated
      check fileExists(logFile)
      let logContent = readFile(logFile)
      check "io-mon: macOS body-patch installed" in logContent

    removeDir(work)
  else:
    test "debug logging test is macOS-only (no-op on this platform)":
      check true
