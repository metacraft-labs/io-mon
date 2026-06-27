## test_io_mon_macos_library_load — T3b: capture LIBRARY-LOAD dependencies — the
## dependent-dylib closure (findings-doc break #4) and the dlopen arm of break #7.
## See reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org §T3b.
##
## # The break (research/adversarial-2026-06/adv_realbuild/)
##
## dyld maps an executable's dependent dylibs — and any dlopen'd image — DIRECTLY
## via low-level kernel mmap, BYPASSING the interposed/body-patched open/openat.
## A real clang-21 + ld64 build loaded 620 dylibs while io-mon recorded ZERO; the
## non-system toolchain dylibs missed (libLLVM, libclang-cpp, libcrypto.3, …) are
## genuine inputs, so a content-addressed cache fingerprinting only the depfile
## would serve a STALE result after an in-place compiler-library upgrade. A
## runtime dlopen("./plugin.dylib") of a not-otherwise-opened file was likewise
## invisible.
##
## # The fix
##
## The shim registers `_dyld_register_func_for_add_image`; dyld invokes the
## callback for every already-loaded image AND every future dlopen, the only path
## that sees these maps. Each non-system, real-on-disk image is recorded as an
## `mrLibraryLoad` content dependency (observationKind `moFileRead`, so existing
## read-dep consumers fingerprint the dylib bytes). An aggressive filter drops the
## ~600-image system baseline (our shim, /usr/lib + /System, shared-cache-only
## images, anything not on disk).
##
## This suite proves three things on the REAL shim:
##   1. REGRESSION (dlopen, break #7 arm): a dlopen'd plugin that is otherwise
##      never opened now appears as a library-load dependency (was absent).
##   2. DEPENDENT DYLIB (break #4): a program linked against a non-system dylib
##      built under /tmp records that dylib, while the /usr/lib/libSystem baseline
##      is NOT recorded (the filter works — no 600-record flood).
##   3. NO FLOODING: a trivial program yields only a small, bounded number of
##      library-load records (its few non-system deps — here zero), never ~600.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  corpus = repoRoot / "research" / "adversarial-2026-06" / "adv_realbuild"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc run(cmd: string) =
    let (output, code) = execCmdEx(cmd)
    doAssert code == 0, "command failed (" & cmd & "): " & output

  proc ccDylib(src, outDylib: string) =
    ## Build a NON-SYSTEM dylib whose install_name is its own absolute path, so a
    ## linker/dlopen resolves it from there and dladdr reports that path.
    let ccBin = getEnv("CC", "cc")
    run(quoteShell(ccBin) & " -arch arm64 -dynamiclib " & quoteShell(src) &
      " -install_name " & quoteShell(outDylib) & " -o " & quoteShell(outDylib))

  proc ccExe(src, outBin: string; extra = "") =
    let ccBin = getEnv("CC", "cc")
    run(quoteShell(ccBin) & " -arch arm64 " & extra & " " & quoteShell(src) &
      " -o " & quoteShell(outBin))

  proc shimEnv(shim, fragmentDir: string): seq[(string, string)] =
    ## Environment that runs a child UNDER the shim with direct DYLD injection and
    ## NO sandbox-tools rewrite (mirrors the build engine launching an action).
    result = @[]
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      result.add (k, v)
    result.add ("DYLD_INSERT_LIBRARIES", shim)
    result.add ("REPRO_MONITOR_SHIM_LIB", shim)
    result.add ("REPRO_MONITOR_FRAGMENT_DIR", fragmentDir)
    # macos_backend_toggle.applyMacosBackendToggle works on a StringTableRef; build
    # one, apply, then flatten back to the (k, v) pairs startProcess expects.
    var tbl = newStringTable(modeCaseSensitive)
    for (k, v) in result: tbl[k] = v
    applyMacosBackendToggle(tbl, "both")
    result = @[]
    for k, v in tbl: result.add (k, v)

  proc runUnderShim(shim, prog: string; args: seq[string];
      fragmentDir, workingDir: string): string =
    ## Run `prog args` under the shim from `workingDir` (the dlopen probe needs its
    ## cwd to hold ./plugin.dylib). Returns the merged child stdout+stderr.
    var env = newStringTable(modeCaseSensitive)
    for (k, v) in shimEnv(shim, fragmentDir): env[k] = v
    let p = startProcess(prog, workingDir = workingDir, args = args, env = env,
      options = {poStdErrToStdOut})
    let outText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    doAssert code == 0, "child should exit 0 (out=" & outText & ")"
    outText

  proc libraryLoads(dep: MonitorDepFile): seq[string] =
    ## Paths of every captured library-load record.
    result = @[]
    for r in dep.records:
      if r.kind == mrLibraryLoad:
        result.add r.path

suite "io-mon macOS library-load / dependent-dylib + dlopen (T3b, breaks #4/#7)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-libload-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    test "REGRESSION (dlopen, break #7 arm): a dlopen'd plugin is now captured":
      # plugin.dylib is loaded ONLY via dlopen("./plugin.dylib") and is never
      # opened by anything else, so before T3b it appeared in NO record. The
      # dependent-dylib path of dyld now records it as a library-load dependency.
      let pluginDylib = work / "plugin.dylib"
      let loaderBin = work / "dlopen_main"
      ccDylib(corpus / "plugin.c", pluginDylib)
      ccExe(corpus / "dlopen_main.c", loaderBin)
      let frag = work / "dlopenFrag"
      createDir(frag)
      let outText = runUnderShim(shim, loaderBin, @[], frag, work)
      checkpoint("loader stdout: " & outText)
      let dep = mergeFragments(frag, work / "dlopen.rdep")
      let loads = libraryLoads(dep)
      checkpoint("library-loads: " & $loads)
      # The plugin now appears as a library-load…
      var sawPlugin = false
      for path in loads:
        if path.endsWith("plugin.dylib"):
          sawPlugin = true
      check sawPlugin
      # …classified as a CONTENT (read) dependency so a consumer fingerprints the
      # dylib bytes (the crux of busting the stale cache).
      var pluginIsRead = false
      for r in dep.records:
        if r.kind == mrLibraryLoad and r.path.endsWith("plugin.dylib") and
            r.observationKind == moFileRead:
          pluginIsRead = true
      check pluginIsRead

    test "DEPENDENT DYLIB (break #4): a /tmp-built dep is captured, libSystem is NOT":
      # main_dep is linked against libdep.dylib (a non-system dylib under the work
      # dir). dyld maps it via kernel mmap at launch — the shape of break #4.
      let depDylib = work / "libdep.dylib"
      let depBin = work / "dep_main"
      ccDylib(corpus / "libdep.c", depDylib)
      # Link against libdep.dylib by its full path so the install_name resolves.
      ccExe(corpus / "dep_main.c", depBin, quoteShell(depDylib))
      let frag = work / "depFrag"
      createDir(frag)
      let outText = runUnderShim(shim, depBin, @[], frag, work)
      checkpoint("dep stdout: " & outText)
      let dep = mergeFragments(frag, work / "dep.rdep")
      let loads = libraryLoads(dep)
      checkpoint("library-loads: " & $loads)
      # The non-system dependent dylib is recorded…
      var sawDep = false
      for path in loads:
        if path.endsWith("libdep.dylib"):
          sawDep = true
      check sawDep
      # …while the system baseline is NOT — the filter drops /usr/lib + /System
      # and shared-cache-only images, so there is no 600-record flood.
      for path in loads:
        check not path.startsWith("/usr/lib/")
        check not path.startsWith("/System/")
        check not path.contains("libSystem")

    test "NO FLOODING: a trivial program yields only a small, bounded set":
      # t.c links only libSystem (shared-cache, filtered), so its non-system
      # library-load set is essentially empty — categorically not the ~600 system
      # images. We bound generously to stay robust across toolchains.
      let trivialBin = work / "trivial"
      ccExe(corpus / "t.c", trivialBin)
      let frag = work / "trivialFrag"
      createDir(frag)
      discard runUnderShim(shim, trivialBin, @[], frag, work)
      let dep = mergeFragments(frag, work / "trivial.rdep")
      let loads = libraryLoads(dep)
      checkpoint("trivial library-loads (" & $loads.len & "): " & $loads)
      # A trivial program must never flood the depfile with the system baseline.
      check loads.len <= 4
      for path in loads:
        check not path.startsWith("/usr/lib/")
        check not path.startsWith("/System/")

    removeDir(work)
  else:
    test "library-load capture is macOS-only (no-op on this platform)":
      check true
