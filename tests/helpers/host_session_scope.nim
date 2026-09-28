## Real host-API session regression, shared by POSIX and Windows entrypoints.
## No mocks: build the production shim, execute this test binary as a reader,
## and inspect its actual captured file access. The control clears the ambient
## session; the regression arm sets the launcher's session to an unrelated run.
## Both must retain their child's evidence and leave the launcher's environment
## unchanged. This isolates merge scoping from recursive shim injection; the
## Reprobuild suite separately exercises the enclosing monitor itself.

import std/[os, osproc, strtabs, strutils, tempfiles, unittest]
import io_mon

if paramCount() == 2 and paramStr(1) == "--session-scope-reader":
  doAssert readFile(paramStr(2)) == "host-session-scope-input"
  quit(0)

const repoRoot = currentSourcePath().parentDir.parentDir.parentDir

proc capture(ambient, shim: string): tuple[exitCode, starts, reads: int;
    completeness: MonitorCompleteness; parentUnchanged: bool] =
  let work = createTempDir("io-mon-session-", "-scope")
  defer: removeDir(work)
  let input = expandFilename(work) / "input.txt"
  writeFile(input, "host-session-scope-input")
  let hadSession = existsEnv("REPRO_MONITOR_SESSION")
  let oldSession = getEnv("REPRO_MONITOR_SESSION")
  let hadShim = existsEnv(ShimLibOverrideEnv)
  let oldShim = getEnv(ShimLibOverrideEnv)
  if ambient.len == 0: delEnv("REPRO_MONITOR_SESSION")
  else: putEnv("REPRO_MONITOR_SESSION", ambient)
  putEnv(ShimLibOverrideEnv, shim)
  try:
    let monitored = runMonitored(FsSnoopRequest(
      command: @[getAppFilename(), "--session-scope-reader", input],
      depFilePath: work / "capture.iomon"))
    result.exitCode = monitored.exitCode
    result.completeness = monitored.completeness
    result.parentUnchanged = getEnv("REPRO_MONITOR_SESSION") == ambient and
      existsEnv("REPRO_MONITOR_SESSION") == (ambient.len > 0)
    for record in monitored.records:
      if record.kind == mrProcessStart: inc result.starts
      if record.observationKind in {moFileRead, moFileOpen}:
        when defined(windows):
          let same = record.path.replace('\\', '/').toLowerAscii() ==
            input.replace('\\', '/').toLowerAscii()
        else:
          let same = record.path == input
        if same: inc result.reads
  finally:
    if hadSession: putEnv("REPRO_MONITOR_SESSION", oldSession)
    else: delEnv("REPRO_MONITOR_SESSION")
    if hadShim: putEnv(ShimLibOverrideEnv, oldShim)
    else: delEnv(ShimLibOverrideEnv)

suite "host monitor session scope":
  # Other tests may have the shipping shim loaded concurrently. Rebuilding
  # that shared file races their loader (and Windows refuses the write).
  let shimWork = createTempDir("io-mon-session-shim-", "-build")
  defer: removeDir(shimWork)
  var buildEnv = newStringTable(modeCaseSensitive)
  for key, value in envPairs(): buildEnv[key] = value
  buildEnv["IO_MON_SHIM_OUT_DIR"] = shimWork / "lib"
  buildEnv["IO_MON_SHIM_NIMCACHE_DIR"] = shimWork / "nimcache"
  let built = execCmdEx("bash " & quoteShell(repoRoot / "scripts/build_shim.sh"),
    env = buildEnv)
  doAssert built.exitCode == 0, built.output
  let shim = shimWork / "lib" / (
    when defined(windows): "librepro_monitor_shim.dll"
    elif defined(macosx): "librepro_monitor_shim.dylib"
    else: "librepro_monitor_shim.so")

  test "a child records real file reads without an ambient session":
    let observed = capture("", shim)
    checkpoint($observed)
    check observed.exitCode == 0
    check observed.starts > 0
    check observed.reads > 0
    check observed.completeness == mcComplete
    check observed.parentUnchanged

  test "an inherited session cannot filter out this monitor's child":
    let observed = capture("enclosing-monitor-session", shim)
    checkpoint($observed)
    check observed.exitCode == 0
    check observed.starts > 0
    check observed.reads > 0
    check observed.completeness == mcComplete
    check observed.parentUnchanged
