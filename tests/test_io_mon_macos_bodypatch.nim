## test_io_mon_macos_bodypatch — the macOS body-patch backend POSITIVELY
## captures a shared-cache-internal file open that ``__DATA,__interpose``
## CANNOT see, and the interpose-only backend demonstrably does NOT.
##
## # What this proves
##
## ``fopen("/etc/services","r")`` performs its ``open`` *inside* ``libsystem_c``
## (via ``open$NOCANCEL``), through libsystem's own call site — NOT through the
## test binary's import table. The ``__DATA,__interpose`` mechanism only
## rewrites the *binary's own* import bindings, so it never sees that internal
## open: with body-patch DISABLED for diagnosis
## (``IO_MON_DEBUG_DISABLE_BODYPATCH=1``, the "interpose-only" A/B arm) the
## ``/etc/services`` record is ABSENT.
##
## The body-patch mechanism replaces the libsystem ``open`` / ``open$NOCANCEL`` /
## ``__open_nocancel`` *entry points* themselves (the Dobby / substrate
## ``mach_vm_remap`` overwrite technique — see
## ``src/io_mon/hooks/macos_bodypatch.nim`` and
## ``research/macos-bodypatch/internal3.c``), so it catches the call regardless
## of who makes it. With interpose DISABLED for diagnosis
## (``IO_MON_DEBUG_DISABLE_INTERPOSE=1``, the "body-patch-only" arm) and under
## the DEFAULT (both mechanisms on) the ``/etc/services`` record is PRESENT.
##
## This test asserts BOTH directions — presence under body-patch / both,
## absence under interpose — to lock in that body-patch is precisely what
## closes the gap. It is macOS-only; on other platforms it is a no-op pass.

import std/[os, osproc, streams, strtabs, unittest]
from std/strutils import contains

when defined(macosx):
  import io_mon  # readMonitorDepFile, mergeFragments, MonitorObservationKind
  import macos_backend_toggle  # applyMacosBackendToggle (A/B → debug toggles)

const
  repoRoot = currentSourcePath().parentDir().parentDir()

when defined(macosx):
  # A shared-cache-internal target that exists on every macOS host and is read
  # via stdio (fopen → open$NOCANCEL inside libsystem_c).
  const internalTarget = "/etc/services"

  proc buildShim(): string =
    ## Build the fat (arm64+arm64e) shim and return its path. Fails loudly.
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc compileProbe(work: string): string =
    ## Compile a tiny C program that fopen()s the internal target. fopen's
    ## open happens shared-cache-internally — the crux of the test.
    let src = work / "fopen_probe.c"
    writeFile(src, """
#include <stdio.h>
int main(void) {
  FILE *f = fopen(""" & "\"" & internalTarget & "\"" & """, "r");
  if (f) fclose(f);
  return 0;
}
""")
    let bin = work / "fopen_probe"
    let cc = getEnv("CC", "cc")
    # Build arm64 explicitly so the probe matches this host's primary slice.
    let (output, code) = execCmdEx(quoteShell(cc) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(bin))
    doAssert code == 0, "probe compile failed: " & output
    doAssert fileExists(bin)
    bin

  proc captureInternalOpen(shim, probe, backend: string): bool =
    ## Run the probe under the shim with the given backend, merge the fragment
    ## directory into a depfile, and report whether a record for the internal
    ## target was captured (an open/read observation whose path is the target).
    let work = getTempDir() /
      ("io-mon-bp-" & backend & "-" & $getCurrentProcessId())
    createDir(work)
    defer: removeDir(work)
    let fragmentDir = work / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)

    let p = startProcess(probe, args = @[], env = env,
      options = {poStdErrToStdOut})
    let stderrOut = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] probe exit=" & $code & " stderr=" & stderrOut)
    doAssert code == 0, "probe under shim should exit 0"

    # Merge the per-thread fragments the child wrote into a single depfile and
    # decode it with the production reader (no string-grepping of raw bytes).
    let depfile = work / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    if not fileExists(depfile):
      return false
    let dep = readMonitorDepFile(depfile)
    for rec in dep.records:
      if rec.path.len > 0 and internalTarget in rec.path and
          (rec.observationKind == moFileOpen or
           rec.observationKind == moFileRead):
        return true
    false

suite "io-mon macOS body-patch backend":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-bp-probe-" & $getCurrentProcessId())
    createDir(work)
    let probe = compileProbe(work)

    test "body-patch captures the shared-cache-internal open interpose misses":
      # The positive capability: body-patch sees fopen's libsystem-internal
      # open of /etc/services.
      check captureInternalOpen(shim, probe, "bodypatch")

    test "the default 'both' backend also captures the internal open":
      check captureInternalOpen(shim, probe, "both")

    test "interpose-only does NOT capture the internal open (the closed gap)":
      # The contrast that proves body-patch is what closes the gap: under plain
      # interpose the internal open is invisible.
      check not captureInternalOpen(shim, probe, "interpose")

    removeDir(work)
  else:
    test "body-patch backend is macOS-only (no-op on this platform)":
      check true
