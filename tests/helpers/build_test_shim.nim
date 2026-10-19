## Build the real production shim in storage owned by this test process.
## No mocks: each fixture compiles the same source and flags as the product.
## Private outputs and compiler caches prevent one fixture's relink from
## removing a dylib another fixture is about to load. Exit cleanup removes
## only this process's temporary tree, after its test children have finished.
import std/[exitprocs, os, osproc, strtabs, strutils, tempfiles]

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

proc buildPrivateLinuxShimWithFlags*(repoRoot: string;
                                     flags: openArray[string]): string =
  ## The production Linux shim built with extra compiler flags (a test-only
  ## `-d:` define), in its own private tree so it never replaces the plain
  ## shim another fixture of this process loads.
  let work = createTempDir("io-mon-fixture-shim-flags-", "")
  addExitProc(proc() =
    try: removeDir(work)
    except OSError: discard)
  var buildEnv = newStringTable(modeCaseSensitive)
  for key, value in envPairs(): buildEnv[key] = value
  buildEnv["STACKABLE_HOOKS_BUILT_TOOLS_DIR"] = ""
  buildEnv["IO_MON_SHIM_OUT_DIR"] = work / "lib"
  buildEnv["IO_MON_SHIM_NIMCACHE_DIR"] = work / "nimcache"
  var cmd = "bash " & quoteShell(repoRoot / "scripts/build_shim.sh")
  for flag in flags: cmd.add " " & quoteShell(flag)
  let built = execCmdEx(cmd, env = buildEnv)
  if built.exitCode != 0:
    raise newException(IOError, "private build_shim.sh failed: " & built.output)
  result = work / "lib" / "librepro_monitor_shim.so"
  doAssert fileExists(result), "shim not produced at " & result

proc copyMacosShimAsDistinctImage*(shim, dest: string) =
  ## Copy `shim` to `dest` as a second, separately identified shim image, the
  ## way two monitors meet in production (a development build outside, an
  ## installed package inside). A plain byte copy keeps the original's install
  ## name, and with it nested two-shim fixtures did not reproduce the two-shim
  ## failure they exist for: every case passed at io-mon 6e7d2cf, where the
  ## same fixture with a renamed copy fails. The copy therefore gets its own
  ## install name, and the ad-hoc signature arm64 requires after the edit.
  copyFile(shim, dest)
  for cmd in ["install_name_tool -id " & quoteShell(dest) & " " & quoteShell(dest),
              "codesign --force --sign - " & quoteShell(dest)]:
    let (output, code) = execCmdEx(cmd)
    doAssert code == 0, cmd & ": " & output
  let (id, idCode) = execCmdEx("otool -D " & quoteShell(dest))
  doAssert idCode == 0 and id.splitLines().len >= 2 and
    id.splitLines()[1] == dest, "install name of " & dest & ": " & id
