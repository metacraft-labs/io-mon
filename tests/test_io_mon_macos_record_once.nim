## test_io_mon_macos_record_once — regression for the interpose-vs-body-patch
## DOUBLE-PROCESSING bug fixed by unifying the macOS hook set.
##
## # The bug this locks in
##
## The macOS shim used to carry TWO parallel hook sets for the same syscalls:
## the interpose `repro_hook_*` set (forwarding to the "real" by NAME via
## dlsym / NSLookupSymbolInImage) and a near-verbatim `repro_bodyhook_*` set
## (forwarding via the raw syscall / trampoline). Under the DEFAULT `both`
## backend the body-patch REPLACES the named entry, so the interpose
## `repro_hook_stat` / `repro_hook_posix_spawn` "real" forward (resolved by
## name) actually re-entered the OTHER hook (`repro_bodyhook_*`) — and the
## record was emitted TWICE for a single call (and env-propagation / SIP-rewrite
## applied twice for a spawn). It was only benign because records de-dup
## downstream and the rewrite is idempotent, but it was wrong and wasteful.
##
## The fix is a SINGLE unified hook per syscall, used by BOTH the `__interpose`
## tuples and the body-patch install, each forwarding via a body-patch-SAFE path
## that bypasses the (possibly) patched named entry. With one hook, a given call
## records EXACTLY ONCE on every backend.
##
## # What this test asserts
##
## A probe makes ONE direct `stat()` of a UNIQUE marker path and ONE direct
## `posix_spawn()` of a freshly-built helper, then exits. Run under the DEFAULT
## `both` backend, the captured depfile must contain EXACTLY ONE `mrPathProbe`
## record for the marker path and EXACTLY ONE spawn (`mrProcessSpawn`) record for
## the helper — count == 1, NOT >= 1. Under the prior duplicated-hook code the
## `both` backend would have produced TWO of each (the interpose hook's by-name
## forward re-entering the body-patched twin), so this test would have FAILED
## with a count of 2. The unified single-hook design makes it pass with 1.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, unittest]

when defined(macosx):
  import io_mon  # readMonitorDepFile, mergeFragments, record kinds

const
  repoRoot = currentSourcePath().parentDir().parentDir()

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

  type Fixture = object
    work: string
    probe: string
    markerPath: string
    helperBin: string

  proc buildFixture(): Fixture =
    ## Build a probe that makes EXACTLY one direct stat() of a unique marker and
    ## EXACTLY one direct posix_spawn() of a freshly-built helper. Both calls go
    ## through the probe's OWN import bindings, so both the static interpose
    ## section AND the body-patch see them — the precise condition under which the
    ## old duplicated-hook code double-recorded.
    let work = getTempDir() / ("io-mon-once-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let markerPath = work / "marker.txt"
    writeFile(markerPath, "marker-content\n")

    let helperSrc = work / "helper.c"
    writeFile(helperSrc, """
int main(void) { return 0; }
""")
    let helperBin = work / "helper"
    cc(quoteShell(helperSrc) & " -o " & quoteShell(helperBin))

    let probeSrc = work / "probe.c"
    writeFile(probeSrc, """
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
extern char **environ;
int main(void) {
  /* ONE direct stat() of the marker. */
  struct stat st;
  stat(""" & "\"" & markerPath & "\"" & """, &st);
  /* ONE direct posix_spawn() of the helper. */
  pid_t pid;
  char *argv[] = { """ & "\"" & helperBin & "\"" & """, 0 };
  if (posix_spawn(&pid, """ & "\"" & helperBin & "\"" & """, 0, 0, argv, environ))
    return 2;
  int wst;
  waitpid(pid, &wst, 0);
  return 0;
}
""")
    let probeBin = work / "probe"
    cc(quoteShell(probeSrc) & " -o " & quoteShell(probeBin))
    Fixture(work: work, probe: probeBin, markerPath: markerPath,
      helperBin: helperBin)

  type Counts = object
    pathProbe: int   ## mrPathProbe records whose path is the marker
    spawn: int       ## mrProcessSpawn records whose path is the helper

  var runSeq = 0
  proc runCounts(shim: string; fx: Fixture; backend: string): Counts =
    ## Run the probe under the shim, merge the per-thread fragments, and count
    ## the marker stat() probe records and the helper spawn records.
    ##
    ## Each invocation uses a FRESH fragment directory (the `runSeq` suffix): two
    ## runs with the same backend would otherwise share a fragment dir and the
    ## second merge would double-count the first run's records — a test artefact,
    ## not the production bug under test.
    inc runSeq
    let runWork = fx.work / ("run-" & backend & "-" & $runSeq)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    env["IO_MON_MACOS_BACKEND"] = backend

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
      return Counts()
    let dep = readMonitorDepFile(depfile)
    for rec in dep.records:
      if rec.kind == mrPathProbe and rec.path == fx.markerPath:
        inc result.pathProbe
      if rec.kind == mrProcessSpawn and rec.path == fx.helperBin:
        inc result.spawn

suite "io-mon macOS records EXACTLY once under 'both' (no double-processing)":
  when defined(macosx):
    let shim = buildShim()
    let fx = buildFixture()

    test "ONE stat() under 'both' yields EXACTLY ONE mrPathProbe record":
      # The unified single hook (raw stat64-syscall forward) records the probe
      # exactly once. Under the prior duplicated-hook code the interpose
      # repro_hook_stat forwarded BY NAME into a path that, under `both`, could
      # resolve to the body-patched repro_bodyhook_stat and re-record. (Honest
      # note: on THIS host the by-name `_stat` resolved to a non-patched libsystem
      # copy, so the stat double-record was LATENT here — it manifested for the
      # spawn family below, where the by-name resolve hit the patched entry. This
      # assertion still locks in the single-hook invariant that makes it
      # impossible on any backend.)
      let c = runCounts(shim, fx, "both")
      check c.pathProbe == 1

    test "ONE posix_spawn() under 'both' yields EXACTLY ONE spawn record":
      # The spawn double-record DID manifest with the old code: the interpose
      # repro_hook_posix_spawn forwarded by name into the body-patched twin (which
      # re-applied env-propagation + SIP-rewrite and re-recorded), so `both`
      # produced 2 spawn records. Verified by running this exact test against the
      # pre-fix shim — it failed with `c.spawn == 2`. The unified hook (with the
      # `inSpawnForward` re-entry guard) records once.
      let c = runCounts(shim, fx, "both")
      check c.spawn == 1

    removeDir(fx.work)
  else:
    test "record-once regression is macOS-only (no-op on this platform)":
      check true
