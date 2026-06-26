## test_io_mon_macos_setexec — POSIX_SPAWN_SETEXEC recording + env override (T1)
## and the EARNED-completeness downgrade (T0), closing findings-doc break #2 and
## making `mcComplete` conservative (MacOS-Monitoring-Adversarial-Hardening).
##
## # The gaps these prove
##
## * break #2 (SETEXEC): a `posix_spawn` with `POSIX_SPAWN_SETEXEC` REPLACES the
##   calling process image and NEVER returns on success. The old hook recorded
##   AFTER the forward, so a SETEXEC recorded NOTHING — its launched binary's
##   whole subtree ran with no exec record. The hook now emits + flushes the exec
##   record BEFORE forwarding (mirroring execve).
## * T1 env override: a caller that passes an EMPTY `DYLD_INSERT_LIBRARIES=`
##   previously BLOCKED re-propagation (skip-if-present), so the child ran
##   un-injected. The env builder now OVERRIDES it with our shim.
## * T0 earned-completeness: io-mon must not ASSERT `mcComplete`. When a SETEXEC
##   (or plain spawn) lands in an UN-INJECTABLE image — no matching post-exec /
##   child `process-start` — the merge injects an event-loss so completeness
##   downgrades to `mcIncomplete` (a conservative RE-RUN, not a false skip).
##
## All runs use DIRECT DYLD injection with NO fs-snoop sandbox-tools dir (and the
## test explicitly clears `CT_SANDBOX_TOOLS_DIR`), so a SIP binary like `/bin/cat`
## stays genuinely un-injectable — the precise condition that must downgrade.
## The probe is research/adversarial-2026-06/adv_inject/pspawn.c (+ reader.c).
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir()
  corpus = repoRoot / "research" / "adversarial-2026-06"

when defined(macosx):
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

  type Capture = object
    completeness: MonitorCompleteness
    markerRead: bool
    setexecRecord: bool

  proc runPspawn(shim, pspawn, markerPath: string;
      setexec: int; envMode, prog: string): Capture =
    ## Run `pspawn <setexec> <envMode> <prog> <markerPath>` under the shim with
    ## direct DYLD injection (no sandbox tools) and report the merged depfile's
    ## completeness, whether the marker read was captured, and whether a SETEXEC
    ## exec record was emitted.
    let tag = "se" & $setexec & "-" & envMode & "-" & prog.extractFilename()
    let runWork = pspawn.parentDir() / ("run-" & tag)
    removeDir(runWork)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    # The downgrade scenarios require a genuinely un-injectable SIP child, so the
    # sandbox-tools SIP-rewrite must NOT be active.
    env.del("CT_SANDBOX_TOOLS_DIR")
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, "both")

    let p = startProcess(pspawn,
      args = @[$setexec, envMode, prog, markerPath], env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & tag & "] exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "pspawn should exit 0 (" & tag & ", out=" & stdoutText & ")"

    let depfile = runWork / "cap.rdep"
    let dep = mergeFragments(fragmentDir, depfile)
    result.completeness = dep.completeness
    for rec in dep.records:
      if rec.path == markerPath and
          rec.observationKind in {moFileOpen, moFileRead}:
        result.markerRead = true
      if rec.observationKind == moExecute and rec.detail == "posix_spawn-setexec":
        result.setexecRecord = true

suite "io-mon macOS POSIX_SPAWN_SETEXEC + earned completeness (#2, T0/T1)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-setexec-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let markerPath = work / "setexec-marker.txt"
    writeFile(markerPath, "setexec-marker-content\n")

    proc compileProbe(src, name: string): string =
      let bin = work / name
      cc(quoteShell(src) & " -o " & quoteShell(bin))
      bin

    let pspawn = compileProbe(corpus / "adv_inject" / "pspawn.c", "pspawn")
    let reader = compileProbe(corpus / "adv_inject" / "reader.c", "reader")

    test "SETEXEC into an injectable child records the exec AND captures its read":
      # The exec record is now emitted+flushed BEFORE the (non-returning) forward,
      # and the injectable reader re-loads the shim so its marker read is captured
      # → completeness stays complete (no unnecessary re-run).
      let cap = runPspawn(shim, pspawn, markerPath, 1, "inherit", reader)
      check cap.setexecRecord
      check cap.markerRead
      check cap.completeness == mcComplete

    test "empty caller DYLD is OVERRIDDEN so the SETEXEC child is injected (T1)":
      # The probe forces DYLD_INSERT_LIBRARIES= (present-but-empty); the env
      # builder must REPLACE it with our shim so the child is still injected and
      # its read captured.
      let cap = runPspawn(shim, pspawn, markerPath, 1, "emptydyld", reader)
      check cap.markerRead
      check cap.completeness == mcComplete

    test "SETEXEC into an un-injectable /bin/cat downgrades to mcIncomplete (T0)":
      # /bin/cat is SIP-restricted: with no sandbox-tools rewrite it cannot be
      # injected, so it emits NO post-exec process-start. The SETEXEC exec record
      # is present but unmatched → the merge injects an event-loss → mcIncomplete
      # (a conservative re-run, the whole point of break #2's fix).
      let cap = runPspawn(shim, pspawn, markerPath, 1, "inherit", "/bin/cat")
      check cap.setexecRecord
      check cap.completeness == mcIncomplete

    test "plain posix_spawn into an un-injectable /bin/cat also downgrades (T0)":
      # The spawn arm: the child has no process-start, so the unmatched-child
      # check downgrades completeness.
      let cap = runPspawn(shim, pspawn, markerPath, 0, "inherit", "/bin/cat")
      check cap.completeness == mcIncomplete

    removeDir(work)
  else:
    test "SETEXEC handling is macOS-only (no-op on this platform)":
      check true
