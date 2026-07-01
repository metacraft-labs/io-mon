## test_io_mon_macos_r5_kill_sentinel — ROUND-5 F: the kill-before-flush guard is no
## longer defeatable by a monitored process, LIVE under the shim.
##
## CONFIRMED ROUND-5 BREAKS (research/adversarial-2026-07-round5/machinery): the
## round-2 kill-before-flush guard was a per-thread SIDECAR FILE
## (`repro-reading-<pid>-<tid>.io-mon-reading`) in the inherited
## `REPRO_MONITOR_FRAGMENT_DIR`. A monitored process could DEFEAT it three ways and
## keep `mcComplete` with a read lost:
##   * sab_overflow / sab_unlink — the sidecar path is world-predictable, so the
##     tracee `unlink`s it after reading a marker, then SIGKILLs itself;
##   * sab_chmod — the sidecar create is best-effort, so the tracee `chmod`s the
##     fragment dir to make the create silently fail.
##
## ROUND-5 FIX: the guard is now an IN-FRAGMENT marker (a `read-tail-pending`
## mrEventLoss frame written straight to the fragment when a batch turns dirty,
## `read-tail-committed` after the flush; mergeFragments nets them). There is no
## sidecar to unlink; the marker is written through the ALREADY-OPEN fragment fd so a
## dir chmod cannot block it; removing it requires corrupting the fragment, which
## already fails closed. So all three defeats now DOWNGRADE to mcIncomplete.
##
## CARDINAL-SIN GUARD: a normal build with many batch cycles must stay mcComplete —
## the pending/committed markers net to zero and are stripped, never injecting a
## spurious kill-before-flush (a leak would re-run every build).
##
## macOS-only; a no-op pass elsewhere.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r5mach = repoRoot / "research" / "adversarial-2026-07-round5" / "machinery"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc ccExe(src, outBin: string) =
    let cc = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(cc) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(outBin))
    doAssert code == 0, "cc failed (" & src & "): " & output
    doAssert fileExists(outBin), "probe not produced: " & outBin

  proc runProbe(shim, probe, workDir: string; args: seq[string] = @[];
      expectExit0 = true): MonitorDepFile =
    ## Run `probe` under the shim in `workDir` (its cwd, where marker/secret live)
    ## and merge. A sab_* probe SIGKILLs itself, so exit is not 0 — expectExit0=false.
    let fragmentDir = workDir / "frags"
    createDir(fragmentDir)
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, "both")
    let p = startProcess(probe, workingDir = workDir, args = args, env = env,
      options = {poStdErrToStdOut})
    discard p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    if expectExit0:
      doAssert code == 0, "probe should exit 0 (" & probe & ")"
    # sab_chmod deliberately chmod's the fragment dir to 0500 and SIGKILLs before
    # restoring it, so the merge driver (here, the test) cannot read/clean the dir.
    # The FIX under test already won: the durable pending marker was written through
    # the shim's already-open fragment fd BEFORE/DESPITE the chmod. Restore owner
    # perms so this harness can merge — this is test-side recovery, not part of the
    # guarantee being asserted.
    try:
      setFilePermissions(fragmentDir,
        {fpUserRead, fpUserWrite, fpUserExec})
    except OSError, IOError: discard
    let depfile = workDir / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    readMonitorDepFile(depfile)

  proc hasKillBeforeFlush(dep: MonitorDepFile): bool =
    for r in dep.records:
      if r.kind == mrEventLoss and r.detail.contains("kill-before-flush"):
        return true

  proc readsMarker(dep: MonitorDepFile): bool =
    for r in dep.records:
      if r.kind == mrFileRead and r.path.contains("marker.txt"):
        return true

suite "io-mon macOS R5 kill-before-flush guard (sentinel-defeat probes)":
  when defined(macosx):
    let shim = buildShim()

    # Each sab_* probe reads marker.txt into a buffered batch, defeats the guard,
    # then SIGKILLs itself. Post-fix each must DOWNGRADE (marker lost + injected
    # kill-before-flush), not publish mcComplete.
    for probe in ["sab_overflow", "sab_unlink", "sab_chmod"]:
      test probe & " no longer keeps mcComplete after a kill-before-flush":
        let src = r5mach / (probe & ".c")
        if not fileExists(src):
          checkpoint(probe & " source absent — skipped")
          skip()
        else:
          let work = getTempDir() / ("io-mon-r5-" & probe & "-" &
            $getCurrentProcessId())
          removeDir(work); createDir(work)
          writeFile(work / "marker.txt", "R5-KILL-MARKER\n")
          writeFile(work / "secret.txt", "overflow-filler\n")
          let bin = work / probe
          ccExe(src, bin)
          let dep = runProbe(shim, bin, work, expectExit0 = false)
          # The read was buffered then lost to the kill; the guard now catches it.
          check hasKillBeforeFlush(dep)
          check dep.completeness == mcIncomplete
          # And the lost read is genuinely absent (that is what the guard covers).
          check not readsMarker(dep)
          removeDir(work)

    test "CARDINAL SIN: a normal cc compile (many batch cycles) stays mcComplete":
      # The netting must cancel every pending/committed pair across a real build's
      # many flush cycles — a leak would inject a spurious kill-before-flush and
      # re-run every compile.
      let work = getTempDir() / ("io-mon-r5-killclean-" & $getCurrentProcessId())
      removeDir(work); createDir(work)
      # A source big enough to drive many read batches through the compiler.
      var src = "#include <stdio.h>\n"
      for i in 0 ..< 1500: src.add("int f" & $i & "(int x){return x*" & $i & ";}\n")
      src.add("int main(){long s=0;\n")
      for i in 0 ..< 1500: src.add("s+=f" & $i & "(s&7);\n")
      src.add("return (int)s;}\n")
      writeFile(work / "big.c", src)
      var ccBin = getEnv("CC", "cc")
      if not ccBin.isAbsolute: ccBin = findExe(ccBin)
      let dep = runProbe(shim, ccBin, work,
        args = @["-O1", "-c", work / "big.c", "-o", work / "big.o"])
      check dep.completeness == mcComplete
      check not hasKillBeforeFlush(dep)
      var leaked = 0
      for r in dep.records:
        if r.detail == "read-tail-pending" or r.detail == "read-tail-committed":
          inc leaked
      check leaked == 0
      removeDir(work)
  else:
    test "R5 kill-before-flush guard is macOS-only (no-op here)":
      check true
