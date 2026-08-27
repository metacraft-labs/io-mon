## `REPRO_MONITOR_SHIM_LIB` is documented as an "Operator override … honoured
## first". Before this test it was honoured only when it happened to be right:
## a value naming a nonexistent file fell through to the next discovery
## candidate, the run captured under a DIFFERENT shim than the one pinned, and
## the depfile reported `mcComplete` with no diagnostic anywhere.
##
## Why that matters more than it looks: the override is how a consumer pins a
## specific shim build (reprobuild's `monitoredAction` seeds it, so the
## daemon-spawned capture does not depend on the user's shell environment). A
## stale pin — a path into a previous Nix store generation, a typo, a shim that
## failed to build — then silently produces evidence from some other shim. The
## capture is not wrong in a way anyone can see; it is just not the capture that
## was asked for. "Honoured first" has to mean honoured, not preferred.
##
## NO MOCKS: the real `findShimLibrary` against the real filesystem, plus the
## real `io-mon run` driver for the end-to-end arm.

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon shim-library override is honoured or fails":
  let work = getTempDir() / ("io-mon-shim-override-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)

  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(shimBuild.output)
  require shimBuild.code == 0

  let savedOverride = getEnv("REPRO_MONITOR_SHIM_LIB")
  let hadOverride = existsEnv("REPRO_MONITOR_SHIM_LIB")
  proc restoreOverride() =
    if hadOverride: putEnv("REPRO_MONITOR_SHIM_LIB", savedOverride)
    else: delEnv("REPRO_MONITOR_SHIM_LIB")

  test "a discoverable shim is still found when no override is set":
    # The control. Without it, "raises on a bad override" would also be
    # satisfied by a resolver that raised on everything.
    delEnv("REPRO_MONITOR_SHIM_LIB")
    defer: restoreOverride()
    let found = findShimLibrary()
    checkpoint("discovered: " & found)
    check found.len > 0
    check fileExists(found)

  test "a good override is returned verbatim, ahead of discovery":
    let realShim = block:
      delEnv("REPRO_MONITOR_SHIM_LIB")
      findShimLibrary()
    require realShim.len > 0

    # A copy at a DIFFERENT path, so "the override won" is distinguishable from
    # "discovery happened to return the same file".
    let pinned = work / "pinned-shim.so"
    copyFile(realShim, pinned)
    putEnv("REPRO_MONITOR_SHIM_LIB", pinned)
    defer: restoreOverride()
    check findShimLibrary() == absolutePath(pinned)
    check findShimLibrary() != realShim

  test "an override naming a nonexistent file raises instead of falling back":
    let bogus = work / "no" / "such" / "shim.so"
    require not fileExists(bogus)
    putEnv("REPRO_MONITOR_SHIM_LIB", bogus)
    defer: restoreOverride()

    # THE REGRESSION: this used to return the discovered
    # `build/lib/librepro_monitor_shim.so` and the caller never learned that the
    # pin had been ignored.
    var raised = false
    var message = ""
    try:
      discard findShimLibrary()
    except IOError as e:
      raised = true
      message = e.msg
    check raised
    # The diagnostic must name the offending value, or an operator debugging a
    # stale pin learns nothing from it.
    check bogus in message
    check "REPRO_MONITOR_SHIM_LIB" in message

  test "io-mon run fails loudly rather than capturing under a different shim":
    # End-to-end through the real driver: the operator-visible behaviour, not
    # just the library call.
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    require cli.code == 0

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = work / "no" / "such" / "shim.so"

    let depfile = work / "bogus.iomon"
    let res = run(snoopBin,
      @["run", "--depfile", depfile, "--", "/bin/sh", "-c", "true"], childEnv)
    checkpoint("driver output: " & res.output)

    # Non-zero exit AND a diagnostic naming the variable. Previously this run
    # exited 0 and wrote a depfile reporting mcComplete.
    check res.code != 0
    check "REPRO_MONITOR_SHIM_LIB" in res.output
