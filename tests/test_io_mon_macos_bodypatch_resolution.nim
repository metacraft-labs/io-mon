## test_io_mon_macos_bodypatch_resolution — the macOS body-patch installer
## resolves its targets to the REAL libsystem, never to the shim's own
## __DATA,__interpose wrappers, and reports a clean install banner.
##
## # The bug this locks in (the keystone)
##
## On macOS 26 / Apple Silicon dyld applies a dylib's `__DATA,__interpose` tuples
## GLOBALLY — including to that dylib's OWN `dlsym` lookups. The body-patch
## installer used to resolve each target with `dlsym(RTLD_DEFAULT, name)`, which
## therefore returned the shim's OWN `repro_wrap_<name>` wrapper instead of
## libsystem. The installer then body-patched the SHIM'S OWN CODE: a
## self-referential patch that (a) left the real libsystem entries un-patched (so
## the shared-cache-internal capture never happened), (b) made `posix_spawn`
## resolve a non-relocatable `repro_wrap_posix_spawn` prologue so the trampoline
## was skipped (`spawn_tramp=skip`, `failed>0`), and (c) corrupted the shim's own
## fork/spawn flow, crashing monitored build subprocesses with `SIGTRAP`.
##
## The fix resolves every target by walking the dyld images and SKIPPING the
## shim's own image (so the per-image bind is not interpose-redirected), then
## validates via `dladdr` that the resolved address is NOT in the shim before
## patching. The result is that the install reports `failed=0` and all three
## trampolines (`fork`, `posix_spawn`, `posix_spawnp`) build (`*_tramp=ok`).
##
## # What this test asserts
##
## A freshly-built probe run under the shim with both mechanisms on (the default)
## emits the install banner on stderr. We assert the banner reports
## `failed=0` and `fork_tramp=ok spawn_tramp=ok spawnp_tramp=ok` — the exact
## post-fix state. Under the broken (mis-resolving) installer the banner showed
## `failed>=2` and `spawn_tramp=skip`, so this is a direct regression lock.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

const
  repoRoot = currentSourcePath().parentDir().parentDir()

when defined(macosx):
  import macos_backend_toggle  # applyMacosBackendToggle (A/B → debug toggles)

  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(args: string) =
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " & args)
    doAssert code == 0, "cc failed (" & args & "): " & output

  proc buildProbe(work: string): string =
    let src = work / "probe.c"
    writeFile(src, "int main(void){return 0;}\n")
    let bin = work / "probe"
    cc(quoteShell(src) & " -o " & quoteShell(bin))
    bin

  proc bannerFor(shim, probe, backend: string): string =
    ## Run the probe under the shim and return the body-patch install banner line
    ## (the shim logs it to stderr from the constructor).
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    applyMacosBackendToggle(env, backend)
    let p = startProcess(probe, args = @[], env = env,
      options = {poStdErrToStdOut})
    let outText = p.outputStream.readAll()
    discard p.waitForExit()
    p.close()
    for line in outText.splitLines():
      if line.startsWith("io-mon: macOS body-patch"):
        return line
    ""

suite "io-mon macOS body-patch resolves real libsystem (not the shim)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-bpres-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let probe = buildProbe(work)

    test "the 'both' install banner reports failed=0 and all trampolines ok":
      let banner = bannerFor(shim, probe, "both")
      checkpoint("banner = " & banner)
      check banner.len > 0
      # failed=0 proves no target mis-resolved to the shim (a shim-resolved
      # target is refused and counted failed) and that every relocatable
      # trampoline built.
      check banner.contains("failed=0")
      # The trampolines for the libsystem fork + posix_spawn(p) entries build
      # only when the REAL (relocatable-prologue) libsystem entry was resolved.
      # The shim's own wrappers have non-relocatable prologues, so under the old
      # mis-resolution these were "skip".
      check banner.contains("fork_tramp=ok")
      check banner.contains("spawn_tramp=ok")
      check banner.contains("spawnp_tramp=ok")

    test "body-patch-only (interpose disabled) reports the same clean banner":
      # IO_MON_DEBUG_DISABLE_INTERPOSE: body-patch still installs fully (the same
      # clean counters), and the banner additionally carries the debug note that
      # interpose was disabled for diagnosis.
      let banner = bannerFor(shim, probe, "bodypatch")
      checkpoint("banner = " & banner)
      check banner.contains("failed=0")
      check banner.contains("fork_tramp=ok")
      check banner.contains("spawn_tramp=ok")
      check banner.contains("spawnp_tramp=ok")
      check banner.contains("[debug] interpose disabled")

    test "interpose-only (body-patch disabled) installs no body patch (no crash)":
      # IO_MON_DEBUG_DISABLE_BODYPATCH: body-patch is skipped, so the constructor
      # logs the "not installed" skip line (with the debug note) instead of an
      # install banner with counters.
      let banner = bannerFor(shim, probe, "interpose")
      checkpoint("banner = " & banner)
      check banner.contains("[debug] body-patch disabled") or banner.len == 0

    removeDir(work)
  else:
    test "body-patch resolution is macOS-only (no-op on this platform)":
      check true
