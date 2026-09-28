## Build the real production shim in storage owned by this test process.
## No mocks: each fixture compiles the same source and flags as the product.
## Private outputs and compiler caches prevent one fixture's relink from
## removing a dylib another fixture is about to load. Exit cleanup removes
## only this process's temporary tree, after its test children have finished.
import std/[exitprocs, os, osproc, strtabs, tempfiles]

var shimWork: string

proc cleanupShim() {.noconv.} =
  if shimWork.len > 0:
    try: removeDir(shimWork)
    except OSError: discard

proc buildPrivateMacosShim*(repoRoot: string): string =
  if shimWork.len == 0:
    shimWork = createTempDir("io-mon-fixture-shim-", "")
    addExitProc(cleanupShim)
  result = shimWork / "lib" / "librepro_monitor_shim.dylib"
  if fileExists(result):
    return
  var buildEnv = newStringTable(modeCaseSensitive)
  for key, value in envPairs(): buildEnv[key] = value
  buildEnv["IO_MON_SHIM_OUT_DIR"] = shimWork / "lib"
  buildEnv["IO_MON_SHIM_NIMCACHE_DIR"] = shimWork / "nimcache"
  let built = execCmdEx("bash " & quoteShell(repoRoot / "scripts/build_shim.sh"),
    env = buildEnv)
  if built.exitCode != 0:
    raise newException(IOError, "private build_shim.sh failed: " & built.output)
  doAssert fileExists(result), "shim not produced at " & result
