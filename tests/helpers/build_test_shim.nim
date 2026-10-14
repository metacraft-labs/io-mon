## Build the real production shim in storage owned by this test process.
## No mocks: each fixture compiles the same source and flags as the product.
## Private outputs and compiler caches prevent one fixture's relink from
## removing a dylib another fixture is about to load. Exit cleanup removes
## only this process's temporary tree, after its test children have finished.
import std/[exitprocs, os, osproc, strtabs, tempfiles]

var shimWork: string
var shimBuiltToolsDir: string

proc buildPrivateShim(repoRoot, libraryName, builtToolsDir: string): string =
  # Keep a no-bundle control distinct if one fixture also builds the packaged
  # positive. Reusing a previously embedded library would invalidate it.
  if shimWork.len == 0 or shimBuiltToolsDir != builtToolsDir:
    shimWork = createTempDir("io-mon-fixture-shim-", "")
    shimBuiltToolsDir = builtToolsDir
    # Exit callbacks run after module globals are destroyed under ORC. Keep
    # the path in the callback closure, whose lifetime exitprocs owns, rather
    # than reading a global string/sequence after its destructor.
    let cleanupWork = shimWork
    addExitProc(proc() =
      try: removeDir(cleanupWork)
      except OSError: discard)
  result = shimWork / "lib" / libraryName
  if fileExists(result):
    return
  var buildEnv = newStringTable(modeCaseSensitive)
  for key, value in envPairs(): buildEnv[key] = value
  buildEnv["STACKABLE_HOOKS_BUILT_TOOLS_DIR"] = builtToolsDir
  buildEnv["IO_MON_SHIM_OUT_DIR"] = shimWork / "lib"
  buildEnv["IO_MON_SHIM_NIMCACHE_DIR"] = shimWork / "nimcache"
  let built = execCmdEx("bash " & quoteShell(repoRoot / "scripts/build_shim.sh"),
    env = buildEnv)
  if built.exitCode != 0:
    raise newException(IOError, "private build_shim.sh failed: " & built.output)
  doAssert fileExists(result), "shim not produced at " & result

proc buildPrivateMacosShim*(repoRoot: string;
    builtToolsDir = getEnv("STACKABLE_HOOKS_BUILT_TOOLS_DIR")): string =
  buildPrivateShim(repoRoot, "librepro_monitor_shim.dylib", builtToolsDir)

proc buildPrivateLinuxShim*(repoRoot: string): string =
  buildPrivateShim(repoRoot, "librepro_monitor_shim.so", "")
