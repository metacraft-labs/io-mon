## The preload runtime must load in a hook library built without the shim.
##
## WHY. `hooks/linux_preload_runtime.nim` is also built on its own: a hook
## library imports it, supplies `repro_linux_sig_safe_flush` (the one shim
## entry point the runtime requires of an embedder) and is preloaded without
## `librepro_monitor_shim.so`. Any other strong reference the runtime makes to
## a symbol only `shim/linux_preload.nim` defines leaves such a library with an
## undefined symbol, and the dynamic loader refuses the preload: the monitored
## program exits 127 before it runs. Symbols the runtime reaches only when the
## shim is present are declared weak and checked for null before each call.
##
## HOW. Build a minimal hook library the way an embedder does (`--app:lib`
## over the runtime, the runtime's own version script, a no-op
## `repro_linux_sig_safe_flush`), then run `true` with it preloaded and
## `LD_BIND_NOW=1`, so every undefined reference is resolved at load rather
## than on the first call that happens to reach it. The preload must succeed
## and the program must exit 0.

import std/[os, osproc, streams, strtabs, strutils, unittest]

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc siblingPath(envName, relative: string): string =
  let override = getEnv(envName)
  if override.len > 0: override else: repoRoot / relative

const hookLibrarySource = """
import io_mon/hooks/linux_preload_runtime

proc repro_linux_sig_safe_flush() {.exportc, dynlib, cdecl, raises: [].} =
  discard
"""

suite "the preload runtime without the shim":
  test "a hook library built on the runtime alone preloads and runs":
    let dir = repoRoot / "build" / "preload-runtime-without-shim"
    removeDir(dir)
    createDir(dir)
    let source = dir / "hook_library.nim"
    let library = dir / "libhook_library.so"
    writeFile(source, hookLibrarySource)
    let versionScript =
      repoRoot / "src" / "io_mon" / "hooks" / "linux_preload_versions.map"
    let build = execCmdEx(quoteShellCommand([getEnv("NIM", "nim"), "c",
      "--hints:off", "--warnings:off", "--app:lib", "--threads:on",
      "--nimcache:" & (dir / "cache"),
      "--path:" & (repoRoot / "src"),
      "--path:" & siblingPath("STACKABLE_HOOKS_SRC",
                              "../nim-stackable-hooks/src"),
      "--path:" & siblingPath("SHM_QUEUE_SRC", "../nim-shm-queue/src"),
      "--path:" & siblingPath("SHM_GSET_SRC", "../nim-shm-gset/src"),
      "--passL:-Wl,--version-script=" & versionScript,
      "--out:" & library, source]), workingDir = repoRoot)
    checkpoint(build.output)
    require build.exitCode == 0

    let program = findExe("true", followSymlinks = false)
    require program.len > 0
    var env = newStringTable(modeCaseSensitive)
    for key, value in envPairs():
      env[key] = value
    env["LD_PRELOAD"] = library
    env["LD_BIND_NOW"] = "1"
    let run = startProcess(program, env = env,
                           options = {poStdErrToStdOut})
    let output = run.outputStream.readAll()
    let code = run.waitForExit()
    run.close()
    checkpoint(output)
    check "undefined symbol" notin output
    check code == 0
