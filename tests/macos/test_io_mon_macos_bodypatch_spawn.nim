## test_io_mon_macos_bodypatch_spawn — the macOS body-patch SPAWN family closes
## the shared-cache-INTERNAL spawn propagation blind spot that
## ``__DATA,__interpose`` cannot reach (spec §16.7.8).
##
## # The gap this proves (spec §16.7.8)
##
## A test's invalidation set must be transitive over the WHOLE process tree,
## including sub-processes spawned from INSIDE system libraries
## (``system``/``popen``/``NSTask`` → ``posix_spawn``/``fork``+``execve`` issued
## inside libsystem). The static ``__DATA,__interpose`` section only rewrites the
## MAIN executable's OWN import bindings, so a spawn issued through a DIFFERENT
## image's binding (a ``dlopen``'d dylib here, structurally identical to a
## shared-cache-internal libsystem spawn) bypasses interpose entirely. The child
## then gets NEITHER re-propagation (DYLD_INSERT_LIBRARIES) NOR SIP-rewrite, so
## its whole subtree — and every file it reads — runs UNMONITORED (a FALSE SKIP).
##
## The body-patch mechanism replaces the libsystem ``posix_spawn`` / ``fork`` /
## ``execve`` ENTRY points themselves (the ``mach_vm_remap`` overwrite technique,
## with a relocatable-prologue TRAMPOLINE so the original ``posix_spawn``
## marshalling body still runs — see
## ``stackable_hooks/platform/macos_bodypatch.nim``).
## Patching the callee catches the internal caller, re-applies env-propagation +
## SIP-rewrite, and so the child IS injected and monitored.
##
## # What this test asserts (the both-on vs interpose-only contrast)
##
## A probe ``dlopen``s a helper dylib whose ``posix_spawn`` call originates from
## the dylib's OWN binding (NOT the executable's import table — so it is OUTSIDE
## the executable's ``__interpose`` section, exactly like a libsystem-internal
## spawn). That spawn launches a freshly-built, NON-SIP grandchild helper which
## reads a marker file.
##
##   * default (both mechanisms on, body-patch active): the grandchild is
##     injected (the body-patched ``posix_spawn`` re-added DYLD_INSERT_LIBRARIES),
##     so the marker READ and the spawn/exec record ARE captured.
##   * body-patch disabled for diagnosis (``IO_MON_DEBUG_DISABLE_BODYPATCH=1``,
##     the interpose-only arm): the dylib-originated spawn bypasses the
##     executable's ``__interpose`` section, the grandchild is NOT injected, and
##     the marker read is ABSENT — locking in that the spawn body-patch is what
##     closes the gap.
##
## # Honest platform note (the SIP path on this host)
##
## The spec's PREFERRED demonstration redirects a SIP-protected sub-target
## (``/bin/sh``, ``/bin/cat``) to an injectable ``CT_SANDBOX_TOOLS_DIR`` copy. On
## this host (macOS 26 / Apple Silicon, SIP enabled) AMFI SIGKILLs a relocated
## copy of a ``restricted`` platform binary on launch — EVEN ad-hoc re-signed,
## EVEN with no shim injected — so the sandbox-copy of ``/bin/sh`` cannot run
## here. We therefore use the documented FALLBACK: a freshly-built NON-SIP
## grandchild reached through an INTERNAL (dylib-originated) spawn. This proves
## the same machinery — the body-patched spawn intercepts an internal spawn the
## interpose section misses and PROPAGATES injection into the grandchild — which
## is precisely the §16.7.8 contract. The SIP-rewrite call itself is exercised by
## the runtime helper's unit tests (``rewriteExecPathForSip``); what AMFI blocks
## is only the launch of a copied platform binary, not our interception/rewrite.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon  # readMonitorDepFile, mergeFragments, MonitorObservationKind
  import macos_backend_toggle  # applyMacosBackendToggle (A/B → debug toggles)

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc buildShim(): string =
    ## Build the fat (arm64+arm64e) shim and return its path. Fails loudly.
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(args: string) =
    ## Compile a C artifact for this host's primary arm64 slice. Fails loudly.
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " & args)
    doAssert code == 0, "cc failed (" & args & "): " & output

  type SpawnFixture = object
    work: string
    probe: string
    markerPath: string

  proc buildSpawnFixture(): SpawnFixture =
    ## Build the three-layer fixture proving INTERNAL-spawn propagation:
    ##   probe  — dlopen()s libspawner and calls do_spawn().
    ##   libspawner.dylib — issues posix_spawn through ITS OWN binding (outside
    ##     the probe executable's __interpose section — the shared-cache-internal
    ##     analogue), launching the helper grandchild.
    ##   helper — a NON-SIP grandchild that fopen()s the marker file.
    ## The marker read in the helper is the signal that injection PROPAGATED
    ## through the internal spawn.
    let work = getTempDir() / ("io-mon-bps-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let markerPath = work / "marker.txt"
    writeFile(markerPath, "marker-content\n")

    let helperSrc = work / "helper.c"
    writeFile(helperSrc, """
#include <stdio.h>
int main(void) {
  FILE *f = fopen(""" & "\"" & markerPath & "\"" & """, "r");
  if (f) fclose(f);
  return 0;
}
""")
    let helperBin = work / "helper"
    cc(quoteShell(helperSrc) & " -o " & quoteShell(helperBin))

    let spawnerSrc = work / "spawner.c"
    writeFile(spawnerSrc, """
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;
__attribute__((visibility("default")))
int do_spawn(void) {
  pid_t pid;
  char *argv[] = { """ & "\"" & helperBin & "\"" & """, 0 };
  if (posix_spawn(&pid, """ & "\"" & helperBin & "\"" & """, 0, 0, argv, environ))
    return 2;
  int st;
  waitpid(pid, &st, 0);
  return 0;
}
""")
    let spawnerLib = work / "libspawner.dylib"
    cc("-dynamiclib " & quoteShell(spawnerSrc) & " -o " & quoteShell(spawnerLib))

    let probeSrc = work / "probe.c"
    writeFile(probeSrc, """
#include <dlfcn.h>
int main(void) {
  void *h = dlopen(""" & "\"" & spawnerLib & "\"" & """, RTLD_NOW);
  if (!h) return 3;
  int (*f)(void) = (int (*)(void))dlsym(h, "do_spawn");
  if (!f) return 4;
  return f();
}
""")
    let probeBin = work / "probe"
    cc(quoteShell(probeSrc) & " -o " & quoteShell(probeBin))

    SpawnFixture(work: work, probe: probeBin, markerPath: markerPath)

  type SystemFixture = object
    work: string
    probe: string

  proc buildSystemFixture(): SystemFixture =
    ## Build a probe that calls the libc `system("/usr/bin/true")`. `system(3)`
    ## marshals and issues a GENUINE libsystem-INTERNAL `posix_spawn` of the
    ## shell (`/bin/sh -c ...`) from inside `libsystem_c` — the EXACT
    ## shared-cache-internal spawn §16.7.8 targets. The probe imports only
    ## `system`, never `posix_spawn`, so the posix_spawn call is made purely
    ## inside the shared cache.
    let work = getTempDir() / ("io-mon-bpsys-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let probeSrc = work / "sysprobe.c"
    writeFile(probeSrc, """
#include <stdlib.h>
int main(void) { return system("/usr/bin/true"); }
""")
    let probeBin = work / "sysprobe"
    cc(quoteShell(probeSrc) & " -o " & quoteShell(probeBin))
    SystemFixture(work: work, probe: probeBin)

  type SystemCapture = object
    bodypatchSpawnRecord: bool ## a record tagged "bodypatch-posix_spawn[p]"
    anySpawnRecord: bool       ## ANY moExecute spawn record for the shell
    shellPath: string          ## the path of the captured spawn (e.g. /bin/sh)

  proc runSystemCapture(shim: string; fx: SystemFixture;
                        backend: string): SystemCapture =
    ## Run the `system()` probe under the shim with the given backend and report
    ## whether (a) a body-patch-TAGGED posix_spawn record was captured (the
    ## signal unique to the body-patch backend) and (b) ANY spawn record for the
    ## shell was captured.
    let runWork = fx.work / ("run-" & backend)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)

    let p = startProcess(fx.probe, args = @[], env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] sysprobe exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "system() probe under shim should exit 0 (backend=" &
      backend & ")"

    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    if not fileExists(depfile):
      return SystemCapture()
    let dep = readMonitorDepFile(depfile)
    for rec in dep.records:
      if rec.observationKind != moExecute:
        continue
      # The libsystem `system(3)` posix_spawns the shell; its record path is the
      # shell binary. We do not hardcode `/bin/sh` strictly (defensive against an
      # OS that uses a different `_PATH_BSHELL`); any spawn record observed from
      # this probe — which itself only ever issues the one internal system()
      # spawn — is the shell spawn.
      result.anySpawnRecord = true
      if rec.path.len > 0:
        result.shellPath = rec.path
      # ROUND-2 R7 — a spawn record's `detail` is now a multi-token field: the
      # backend tag is the FIRST token, optionally FOLLOWED by appended identity
      # tokens (e.g. `childstart=<usec>`, see writer.detailToken /
      # macos_interpose.recordSpawn). Match the leading tag token, not the whole
      # string, so the body-patch tag is still recognised once R7 stamps the
      # child's (pid, start-time) identity onto the record.
      let detailTag = rec.detail.splitWhitespace()
      let tag = if detailTag.len > 0: detailTag[0] else: ""
      if tag == "bodypatch-posix_spawn" or tag == "bodypatch-posix_spawnp":
        result.bodypatchSpawnRecord = true

  type Capture = object
    markerRead: bool   ## a read observation whose path is the grandchild marker
    spawnRecord: bool  ## a spawn/exec (moExecute) record for the launched helper

  proc runCapture(shim: string; fx: SpawnFixture; backend: string): Capture =
    ## Run the probe under the shim with the given backend, merge the fragments,
    ## and report whether the grandchild's marker read AND a spawn/exec record
    ## for the launched binary were captured.
    let runWork = fx.work / ("run-" & backend)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)

    let p = startProcess(fx.probe, args = @[], env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] probe exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe under shim should exit 0 (backend=" & backend & ")"

    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    if not fileExists(depfile):
      return Capture(markerRead: false, spawnRecord: false)
    let dep = readMonitorDepFile(depfile)
    let helperName = fx.probe.parentDir() / "helper"
    for rec in dep.records:
      if rec.path.len > 0 and rec.path == fx.markerPath and
          (rec.observationKind == moFileOpen or
           rec.observationKind == moFileRead):
        result.markerRead = true
      if rec.observationKind == moExecute and rec.path.len > 0 and
          rec.path == helperName:
        result.spawnRecord = true

suite "io-mon macOS body-patch spawn family (§16.7.8 propagation)":
  when defined(macosx):
    let shim = buildShim()
    let fx = buildSpawnFixture()

    test "body-patch propagates injection through an internal spawn (both)":
      # The positive: the body-patched posix_spawn re-injects into the grandchild
      # reached via a dylib-originated (interpose-invisible) spawn, so its marker
      # READ and a spawn/exec record for the launched helper are captured.
      let cap = runCapture(shim, fx, "both")
      check cap.markerRead
      check cap.spawnRecord

    test "bodypatch backend also propagates through the internal spawn":
      let cap = runCapture(shim, fx, "bodypatch")
      check cap.markerRead
      check cap.spawnRecord

    test "interpose-only MISSES the internal-spawn grandchild read (the gap)":
      # The contrast that proves the spawn body-patch is what closes the gap:
      # under plain interpose the dylib-originated spawn bypasses the
      # executable's __interpose section, the grandchild is NOT injected, and its
      # marker read is ABSENT.
      let cap = runCapture(shim, fx, "interpose")
      check not cap.markerRead

    removeDir(fx.work)

    # ---------------------------------------------------------------------
    # The REAL §16.7.8 target: a GENUINE libsystem-internal posix_spawn issued
    # by `system(3)` (the shell launch from inside libsystem_c), proven via
    # RECORD PRESENCE (we cannot inject the SIP-protected /bin/sh child here —
    # AMFI SIGKILLs a relocated copy of a restricted platform binary — but we
    # CAN prove the internal posix_spawn was HOOKED by the body-patch).
    #
    # IMPORTANT empirical finding on this OS (macOS 26 / Apple Silicon):
    # dyld applies a dylib's `__DATA,__interpose` tuples GLOBALLY, across the
    # shared cache, so the static interpose section ALSO sees libsystem's
    # internal posix_spawn — i.e. a bare "spawn record present" is NOT, on this
    # OS, the discriminator. The discriminator unique to the body-patch backend
    # is the record TAGGED `bodypatch-posix_spawn` (emitted only by the
    # body-patched entry, never by the interpose wrapper). We therefore assert
    # the body-patch-TAGGED record is PRESENT under both/bodypatch and ABSENT
    # under interpose — directly proving the libsystem-internal posix_spawn is
    # intercepted by the body-patch (and confirming the spawn record's path is
    # the shell). The injection-propagation gap interpose actually leaves
    # (a child that does NOT get DYLD re-injected) is the one asserted by the
    # dylib-spawn marker-read tests above.
    let sysFx = buildSystemFixture()

    test "body-patch HOOKS the genuine libsystem-internal system() spawn (both)":
      let cap = runSystemCapture(shim, sysFx, "both")
      check cap.anySpawnRecord
      check cap.bodypatchSpawnRecord            # the body-patch-tagged record
      # The internal spawn is the shell launch (`/bin/sh -c ...`).
      check cap.shellPath.len > 0
      checkpoint("captured internal spawn path = " & cap.shellPath)

    test "bodypatch backend HOOKS the libsystem-internal system() spawn":
      let cap = runSystemCapture(shim, sysFx, "bodypatch")
      check cap.bodypatchSpawnRecord

    test "interpose-only emits NO body-patch-tagged internal spawn record":
      # The honest contrast: under interpose the body-patch is not installed, so
      # the `bodypatch-posix_spawn` tag is ABSENT — proving that tag (and the
      # interception it represents) comes from the body-patch backend alone.
      let cap = runSystemCapture(shim, sysFx, "interpose")
      check not cap.bodypatchSpawnRecord

    removeDir(sysFx.work)
  else:
    test "body-patch spawn backend is macOS-only (no-op on this platform)":
      check true
