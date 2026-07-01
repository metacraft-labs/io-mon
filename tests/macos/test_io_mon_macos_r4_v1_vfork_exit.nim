## test_io_mon_macos_r4_v1_vfork_exit — ROUND-4 RW4 V1: a vfork child that reads a
## dependency then `_exit`s WITHOUT exec, LIVE under the macOS interpose+body-patch
## shim.
##
## CONFIRMED ROUND-4 BREAK (research/.../r4_proc/vchild.c): a `vfork()` child shares
## the parent's address space — including the shim's per-thread fragment BATCH buffer.
## The child does open+read (appending the read record to that shared batch) then, as
## POSIX requires, leaves via `_exit`. `_exit` terminates immediately, running NEITHER
## libc atexit handlers NOR the dyld destructor whose fragment flush closes the
## kill-before-flush window for a normal `exit()`/return. The buffered read was then
## lost (~1/3 of runs, racy) while the merge still reported mcComplete — a
## FALSE-COMPLETENESS integrity gap (a swapped dependency would be a false cache hit).
##
## ROUND-4 FIX: hook `_exit`/`_Exit` (interpose + body-patch) to flush the in-flight
## fragment batch SYNCHRONOUSLY before forwarding via the raw `SYS_exit` trap. The
## flush is batch-only (writeBuffer into the already-open fragment fd, reset batchLen)
## — NOT closeFragmentSlot — so it does not yank the fd or slot state SHARED with the
## suspended parent. `_exit` (not `exit`) is hooked so a normal program's atexit +
## destructors still run unchanged (transparency).
##
## The gap is in fact BROADER than vfork: ANY process that does I/O then `_exit`s
## (bypassing the destructor, before the 100 ms age flush) loses its buffered tail.
## direct_exit_reader.c isolates that — a single process, open+read+`_exit(0)` — and
## fails DETERMINISTICALLY pre-fix (measured 0/20 captured on the RW3 shim), so it is
## the primary oracle. vchild.c is the racy vfork specialisation (its parent's
## destructor sometimes flushes the vfork-SHARED batch first, so a single vfork run is
## an unreliable oracle); it is exercised across many iterations as the realistic
## scenario.
##
## NO-REGRESSION: the realistic `vfork`+exec idiom (vexec.c) must still be captured —
## the exec hook already flushes first, and the V1 flush must not disturb it.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs, times]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r4Proc = repoRoot / "research" / "adversarial-2026-06-round4" / "r4_proc"
  testRunId = "io-mon-r4-v1-run"
  # The direct-`_exit` gap is deterministic, so a handful of runs suffices; the
  # vfork loss is racy, so it runs more iterations as a realistic-scenario check.
  directExitIterations = 8
  vforkIterations = 16

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
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " &
      "-Wno-deprecated-declarations " & quoteShell(src) & " -o " &
      quoteShell(outBin))
    doAssert code == 0, "cc failed (" & src & "): " & output

  proc shimEnv(shim, fragmentDir: string): StringTableRef =
    result = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      result[k] = v
    result["DYLD_INSERT_LIBRARIES"] = shim
    result["REPRO_MONITOR_SHIM_LIB"] = shim
    result["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    result["REPRO_MONITOR_SESSION"] = testRunId
    applyMacosBackendToggle(result, "both")

  proc runProbe(shim, probe: string; args: seq[string]): MonitorDepFile =
    let runWork = getTempDir() / ("io-mon-r4v1-run-" & probe.extractFilename() &
      "-" & $getCurrentProcessId() & "-" & $epochTime())
    removeDir(runWork)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)
    let env = shimEnv(shim, fragmentDir)
    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    doAssert code == 0, "probe should exit 0 (" & probe & ", out=" &
      stdoutText & ")"
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    result = readMonitorDepFile(depfile)
    removeDir(runWork)

  proc capturesRead(dep: MonitorDepFile; path: string): bool =
    ## True iff the depfile records a content read of `path` (the dependency the
    ## vfork child opened). A read is mrFileRead; the child also generates the
    ## open, but the READ is the content dependency that must survive `_exit`.
    for r in dep.records:
      if r.kind in {mrFileRead, mrFileOpen} and r.path == path:
        return true
    false

suite "io-mon macOS R4 V1 vfork-child _exit flush":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r4v1-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    let dexit = work / "dexit"
    ccExe(r4Proc / "direct_exit_reader.c", dexit)
    let vchild = work / "vchild"
    ccExe(r4Proc / "vchild.c", vchild)
    let vexec = work / "vexec"
    ccExe(r4Proc / "vexec.c", vexec)

    # The dependency file the probe reads. Its content is the "lost" input.
    let dep = work / "dep.txt"
    writeFile(dep, "exit-flush-dependency-content\n")

    test "REGRESSION: a read before a direct _exit(0) is captured (deterministic)":
      # The keystone oracle: a single process open+read+`_exit(0)`. Pre-fix the
      # destructor never runs and the buffered read is dropped on EVERY run (0/20
      # measured on the RW3 shim) while completeness stays mcComplete — a
      # deterministic false cache hit. The `_exit` flush hook makes it captured
      # every time. Unlike the vfork case this has no parent-destructor confound,
      # so even one failure is a true regression.
      var captured = 0
      for i in 0 ..< directExitIterations:
        let d = runProbe(shim, dexit, @[dep])
        if capturesRead(d, dep): inc captured
      checkpoint("direct-_exit read captured in " & $captured & "/" &
        $directExitIterations & " runs")
      check captured == directExitIterations

    test "REGRESSION: a vfork child's read survives _exit on EVERY run":
      # The realistic vfork specialisation. Its parent returns normally, so the
      # parent's destructor sometimes flushes the vfork-SHARED batch first and the
      # loss is racy (~1/3 pre-fix, but 0 on a quiet machine); asserted across many
      # iterations. The V1 `_exit` flush makes capture deterministic here too.
      var captured = 0
      for i in 0 ..< vforkIterations:
        let d = runProbe(shim, vchild, @[dep])
        if capturesRead(d, dep): inc captured
      checkpoint("vfork-child read captured in " & $captured & "/" &
        $vforkIterations & " runs")
      check captured == vforkIterations

    test "NO-REGRESSION: the realistic vfork+exec idiom is still captured":
      # vexec.c: vfork() then immediately execv() (the canonical fast-spawn). The
      # exec hook flushes + re-injects the shim into the new image, which emits its
      # own process-start; the V1 `_exit` flush must not disturb this path.
      let d = runProbe(shim, vexec, @["/bin/echo", "v1-ok"])
      var sawExec = false
      for r in d.records:
        if r.kind in {mrProcessExec, mrProcessSpawn} and
            r.path.contains("echo"):
          sawExec = true
      check sawExec

    removeDir(work)
  else:
    test "R4 V1 vfork-child _exit flush is macOS-only (no-op here)":
      check true
