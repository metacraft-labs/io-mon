## test_io_mon_macos_r4_s3b_linktime — ROUND-4 RW4 S3b: LINK-TIME dylib entropy
## attribution, LIVE under the macOS interpose+body-patch shim.
##
## CONFIRMED ROUND-4 BREAK (research/.../r4_residual/entropy_main_link.c +
## entropy_lib.c): a build tool LINKED (not dlopen'd) against a CUSTOM dylib that
## draws arc4random and bakes the value into its file output was NOT flagged — no
## entropy record was emitted at all. The round-3 attribution BLANKET-exempted the
## ENTIRE link-time add-image burst (to avoid attributing a real cc/clang compile's
## benign link-time libLLVM/libc++ temp-name entropy), so a custom link-time entropy
## dylib's draws produced NO evidence ⇒ a non-deterministic build looked identical to
## a deterministic one.
##
## ROUND-4 FIX: narrow the exemption from "all link-time images" to "link-time images
## under a recognized TOOLCHAIN prefix" (/nix/store, /opt/homebrew, /usr/local, the
## Xcode/Developer trees — ct_macos_path_is_toolchain). A link-time CUSTOM dylib in
## the BUILD/PROJECT tree (NOT under a toolchain prefix) is now registered for entropy
## caller-attribution, so its arc4random draws ARE recorded as an mrNonDeterministic
## EVIDENCE record.
##
## DETERMINISM MODEL (canonical, cross-platform): entropy is recorded as EVIDENCE, not
## a completeness loss — the depfile stays mcComplete (the monitor observed everything)
## and the CONSUMER folds the mrNonDeterministic record into its cache-key/invalidation
## policy (a build that drew entropy is not served from cache). S3b's contribution is
## therefore the EVIDENCE DISTINCTION: a custom link-time entropy dylib emits an
## arc4random evidence record; a toolchain compile emits NONE. Both stay mcComplete.
##
## CARDINAL SIN (dominates): a real cc compile MUST emit ZERO entropy evidence. cc here
## is a Nix clang whose libLLVM/libc++/libffi/libxml2 all live under /nix/store (under
## a toolchain prefix), so their benign startup entropy stays EXEMPT — no spurious
## evidence record that would make the consumer needlessly re-run every compile.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs, times]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r4Residual = repoRoot / "research" / "adversarial-2026-06-round4" / "r4_residual"
  testRunId = "io-mon-r4-s3b-run"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc ccExe(src, outBin: string; extra = "") =
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " & extra &
      " " & quoteShell(src) & " -o " & quoteShell(outBin))
    doAssert code == 0, "cc failed (" & src & "): " & output

  proc ccDylib(src, outDylib: string) =
    # The default install_name of a -dynamiclib is the (absolute) -o path, so a tool
    # LINKED against it records that absolute path and dyld loads it from the build
    # tree at runtime — exactly the link-time-custom-dylib threat we must attribute.
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 -dynamiclib " &
      "-install_name " & quoteShell(outDylib) & " " &
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

  proc runProbe(shim, probe: string; args: seq[string]): MonitorDepFile =
    let runWork = getTempDir() / ("io-mon-r4s3b-run-" & probe.extractFilename() &
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
    checkpoint(probe.extractFilename() & " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe should exit 0 (" & probe & ", out=" &
      stdoutText & ")"
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    readMonitorDepFile(depfile)

  proc countNonDeterministic(dep: MonitorDepFile): int =
    for r in dep.records:
      if r.kind == mrNonDeterministic: inc result

suite "io-mon macOS R4 S3b link-time dylib entropy attribution":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r4s3b-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    # The CUSTOM entropy dylib (entropy_lib.c: draw_entropy → arc4random) built into
    # the build tree, and the build tool LINKED against it (entropy_main_link.c bakes
    # the random value into argv[1]). The dylib lives under the work dir (a /tmp tree)
    # — NOT a toolchain prefix — so the round-4 fix attributes its entropy.
    let entropyDylib = work / "libentropy.dylib"
    ccDylib(r4Residual / "entropy_lib.c", entropyDylib)
    let linkTool = work / "entropy_main_link"
    ccExe(r4Residual / "entropy_main_link.c", linkTool,
      extra = quoteShell(entropyDylib))

    test "REGRESSION: a LINK-TIME custom entropy dylib emits an arc4random evidence record":
      let outPath = work / "linktime_out.txt"
      let dep = runProbe(shim, linkTool, @[outPath])
      doAssert fileExists(outPath), "tool produced no output"
      # The keystone: the linked custom dylib's OWN arc4random is now ATTRIBUTED and
      # recorded as an mrNonDeterministic EVIDENCE record (round-4 fix). This is the
      # cache-busting signal the consumer folds into its invalidation policy so a
      # non-deterministic build is not served from cache.
      check countNonDeterministic(dep) >= 1
      var sawArc = false
      for r in dep.records:
        if r.kind == mrNonDeterministic and r.path == "arc4random": sawArc = true
      check sawArc
      # Determinism model: entropy is evidence, not a completeness loss — the monitor
      # observed everything, so completeness stays mcComplete. The protection lives in
      # the EVIDENCE record above, contrasted with the toolchain compile's ZERO below.
      check dep.completeness == mcComplete

    test "CARDINAL SIN: a real cc compile (toolchain libLLVM entropy) emits NO evidence":
      # The keystone: cc is a Nix clang whose link-time libLLVM/libc++ live under
      # /nix/store (a toolchain prefix) and draw benign temp-name/hash entropy. The
      # round-4 fix keeps that exempt, so a normal compile emits ZERO entropy evidence
      # — a spurious evidence record here would make the consumer needlessly re-run
      # EVERY compile in a build. Completeness is mcComplete (monitor saw everything).
      let srcFile = work / "hello.c"
      writeFile(srcFile, "int main(void){ return 0; }\n")
      let objOut = work / "hello.o"
      # startProcess needs an ABSOLUTE program path (it does not search PATH).
      var ccBin = getEnv("CC", "cc")
      if not ccBin.isAbsolute: ccBin = findExe(ccBin)
      doAssert ccBin.len > 0 and fileExists(ccBin), "cc not found on PATH"
      let dep = runProbe(shim, ccBin,
        @["-arch", "arm64", "-c", srcFile, "-o", objOut])
      doAssert fileExists(objOut), "cc produced no object file"
      check countNonDeterministic(dep) == 0
      check dep.completeness == mcComplete

    removeDir(work)
  else:
    test "R4 S3b link-time entropy attribution is macOS-only (no-op here)":
      check true
