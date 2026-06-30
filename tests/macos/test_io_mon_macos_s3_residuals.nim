## test_io_mon_macos_s3_residuals — ROUND 3 phase S3: close the weaponized
## earned-completeness RESIDUALS on the REAL shim. See
## reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org (ROUND 3,
## S3) and research/adversarial-2026-06-round3/r3_residual.
##
## S3b — DYLIB/PLUGIN ENTROPY ATTRIBUTION (break: a dlopen'd plugin's arc4random was
##   not flagged). The round-2 R-D caller-attribution flagged entropy ONLY from the
##   MAIN EXECUTABLE's __TEXT, so a NON-SYSTEM dylib the program loads that draws
##   entropy and bakes it into output was invisible ⇒ a false cache hit
##   (res1_dylib_entropy). The fix attributes entropy to a DLOPEN'd non-system image
##   too (a compiler pass-plugin). The CARDINAL-SIN guard: a trivial program — whose
##   only entropy is the libsystem startup baseline — STAYS mcComplete, and (covered
##   by test_io_mon_macos_rd) a real cc compile, whose link-time libLLVM/libc++ draw
##   benign temp-name entropy, also stays clean.
##
## S3a — SELF-AUTHORED BREAKAWAY-REPORT FORGERY (res4_forge): an in-tree client that
##   reads REPRO_MONITOR_SESSION and forges a `complete` report omitting the real
##   served file. A genuine cooperating daemon is OUT OF TREE, so the shim never
##   records it writing its report; an in-tree forger IS monitored, so the shim DID
##   record the write of its report file. Such a self-authored report is rejected.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs, times]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  residual = repoRoot / "research" / "adversarial-2026-06-round3" / "r3_residual"
  testRunId = "io-mon-s3-test-run"

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
      quoteShell(src) & " -o " & quoteShell(outBin))
    doAssert code == 0, "cc failed (" & src & "): " & output

  proc ccDylib(src, outDylib: string) =
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 -dynamiclib " &
      quoteShell(src) & " -o " & quoteShell(outDylib))
    doAssert code == 0, "cc -dynamiclib failed (" & src & "): " & output

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

  proc runProbe(shim, probe: string; args: seq[string];
      reportDir = ""; extraEnv: seq[(string, string)] = @[]): MonitorDepFile =
    ## Run `probe args` under the shim and return the merged depfile. A non-empty
    ## `reportDir` is passed to mergeFragments (the breakaway-report fold).
    let runWork = getTempDir() / ("io-mon-s3-run-" & probe.extractFilename() &
      "-" & $getCurrentProcessId() & "-" & $epochTime())
    removeDir(runWork)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)
    let env = shimEnv(shim, fragmentDir)
    for (k, v) in extraEnv:
      env[k] = v
    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(probe.extractFilename() & " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe should exit 0 (" & probe & ", out=" &
      stdoutText & ")"
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile, breakawayReportDir = reportDir)
    doAssert fileExists(depfile)
    readMonitorDepFile(depfile)

  proc countNonDeterministic(dep: MonitorDepFile): int =
    for r in dep.records:
      if r.kind == mrNonDeterministic: inc result

  proc waitForFile(path: string; timeoutMs = 5000): bool =
    var waited = 0
    while waited < timeoutMs:
      if fileExists(path): return true
      sleep(25); waited += 25
    fileExists(path)

suite "io-mon macOS S3b dylib/plugin entropy attribution (res1_dylib_entropy)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-s3b-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    # A "compiler pass-plugin" dylib that draws entropy and bakes it into output.
    let pluginSrc = work / "librnd.c"
    writeFile(pluginSrc,
      "#include <stdio.h>\n#include <stdlib.h>\n" &
      "void plugin_emit(const char* outpath){\n" &
      "  unsigned int r = arc4random();\n" &
      "  FILE* o = fopen(outpath, \"w\");\n" &
      "  if(o){ fprintf(o, \"rand=%08x\\n\", r); fclose(o);}\n}\n")
    let plugin = work / "librnd.dylib"
    ccDylib(pluginSrc, plugin)

    # A tool that DLOPENs the plugin at runtime (the real pass-plugin pattern).
    let dlopenSrc = work / "tool_dlopen.c"
    writeFile(dlopenSrc,
      "#include <stdio.h>\n#include <dlfcn.h>\n" &
      "int main(int argc, char** argv){\n" &
      "  void* h = dlopen(argv[1], RTLD_NOW);\n" &
      "  if(!h){ fprintf(stderr, \"dlopen: %s\\n\", dlerror()); return 1; }\n" &
      "  void(*emit)(const char*) = (void(*)(const char*))dlsym(h, \"plugin_emit\");\n" &
      "  if(!emit){ return 1; }\n" &
      "  emit(argv[2]);\n  return 0;\n}\n")
    let dlopenTool = work / "tool_dlopen"
    ccExe(dlopenSrc, dlopenTool)

    # A trivial program: its ONLY entropy is the libsystem startup baseline.
    let trivialSrc = work / "trivial.c"
    writeFile(trivialSrc, "int main(void){return 0;}\n")
    let trivial = work / "trivial"
    ccExe(trivialSrc, trivial)

    test "REGRESSION: a dlopen'd plugin's arc4random downgrades to mcIncomplete":
      let outPath = work / "plugin_out.txt"
      let dep = runProbe(shim, dlopenTool, @[plugin, outPath])
      # The plugin's OWN (non-system, dlopen'd image) entropy is now flagged…
      check countNonDeterministic(dep) >= 1
      var sawArc = false
      for r in dep.records:
        if r.kind == mrNonDeterministic and r.path == "arc4random": sawArc = true
      check sawArc
      # …so the build is non-reproducible ⇒ a conservative re-run.
      check dep.completeness == mcIncomplete

    test "CARDINAL SIN: a trivial program (libsystem-only entropy) stays mcComplete":
      let dep = runProbe(shim, trivial, @[])
      # NO non-determinism flag: the libsystem/libobjc startup arc4random baseline
      # lands in /usr/lib + the shared cache, which the attribution excludes.
      check countNonDeterministic(dep) == 0
      check dep.completeness == mcComplete

    removeDir(work)
  else:
    test "S3b dylib entropy attribution is macOS-only (no-op on this platform)":
      check true

suite "io-mon macOS S3a self-authored forged breakaway report (res4_forge)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-s3a-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    # The out-of-tree daemon + the in-tree forger from the round-3 corpus.
    let daemonBin = work / "daemon"
    let forgerBin = work / "forge_client"
    ccExe(residual / "daemon.c", daemonBin)
    ccExe(residual / "forge_client.c", forgerBin)

    test "REGRESSION: the forger's self-authored report is rejected (mcIncomplete)":
      # daemon.c writes its readiness to the fixed /tmp/adv_proctree/daemon.ready.
      createDir("/tmp/adv_proctree")
      let ready = "/tmp/adv_proctree/daemon.ready"
      removeFile(ready)
      let sock = work / "forge.sock"
      let reportDir = work / "reports"
      createDir(reportDir)
      let secret = work / "REAL_SECRET.txt"
      writeFile(secret, "R8-FORGE-marker\n")
      let daemon = startProcess(daemonBin, args = @[sock],
        options = {poStdErrToStdOut})
      doAssert waitForFile(ready), "daemon did not become ready"

      # The forger connects (observed), the daemon serves the REAL secret, then the
      # forger writes a `complete` report listing a DECOY and OMITTING the secret.
      let dep = runProbe(shim, forgerBin, @[sock, secret], reportDir = reportDir,
        extraEnv = @[("IO_MON_BREAKAWAY_REPORT_DIR", reportDir)])

      # A forged report was indeed written into the report dir…
      var sawReport = false
      for kind, p in walkDir(reportDir):
        if kind == pcFile and p.endsWith(".io-mon-report"): sawReport = true
      check sawReport
      # …but it was authored IN-TREE (the shim recorded the forger writing it), so it
      # is rejected: the out-of-tree daemon connection still downgrades.
      check dep.completeness == mcIncomplete
      # The decoy the forger substituted must NOT be folded as a dependency.
      for r in dep.records:
        check not r.path.endsWith("DECOY.txt")

      kill(daemon)               # the daemon loops on accept(); terminate it
      discard daemon.waitForExit()
      daemon.close()

    removeDir(work)
  else:
    test "S3a forged-report rejection is macOS-only (no-op on this platform)":
      check true
