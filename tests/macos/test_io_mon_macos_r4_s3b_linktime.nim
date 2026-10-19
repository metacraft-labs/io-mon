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
## Xcode/Developer trees), so a link-time CUSTOM dylib in the build tree is attributed.
##
## That prefix exemption was itself the next hole (reprobuild-pm issue
## 2026-10-14-macos-monitoring-does-not-report-entropy-drawn-by-toolchain-dylibs): a
## Nix clang's libLLVM draws arc4random for the name of the temporary it writes `-o`
## through, the shim saw it and DISCARDED it, and a consumer edge with no entropy
## blessing published over it -- while the Linux preload shim reports the same draw.
## Every non-system image is now attributed, link-time or dlopen'd, wherever it is
## installed; whether a tool's entropy is harmless is the consumer's per-tool blessing.
##
## DETERMINISM MODEL (canonical, cross-platform): entropy is recorded as EVIDENCE, not
## a completeness loss — the depfile stays mcComplete (the monitor observed everything)
## and the CONSUMER folds the mrNonDeterministic record into its cache-key/invalidation
## policy (a build that drew entropy is not served from cache).
##
## CARDINAL SIN (still dominates): the libsystem/libobjc/libcorecrypto STARTUP baseline
## lives in /usr/lib and the dyld shared cache, never in a registered image, so a clang
## compile that draws nothing of its own (`-fno-temp-file`) emits ZERO evidence even
## though libLLVM and friends are now registered.
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
  from build_test_shim import buildPrivateMacosShim

  proc buildShim(): string =
    buildPrivateMacosShim(repoRoot)

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
    let depfile = runWork / "cap.iomon"
    discard mergeFragments(fragmentDir, depfile, currentRunId = testRunId)
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

    # The compiler under test: an ABSOLUTE path (startProcess does not search
    # PATH). In the dev shell it is the Nix clang wrapper, whose real clang links
    # libLLVM.dylib from /nix/store.
    var ccBin = getEnv("CC", "cc")
    if not ccBin.isAbsolute: ccBin = findExe(ccBin)
    doAssert ccBin.len > 0 and fileExists(ccBin), "cc not found on PATH"
    let srcFile = work / "hello.c"
    writeFile(srcFile, "int main(void){ return 0; }\n")

    proc loadsToolchainLibLLVM(dep: MonitorDepFile): bool =
      ## Vacuity guard: the compile really ran a clang whose libLLVM is a
      ## LINK-TIME dylib under a toolchain prefix -- the image class the old
      ## prefix exemption silenced. Without it the tests below would prove
      ## nothing about that class.
      for r in dep.records:
        if r.kind == mrLibraryLoad and r.path.startsWith("/nix/store/") and
            "libLLVM" in r.path.extractFilename():
          return true

    test "REGRESSION: a toolchain dylib's entropy (clang's temp-file name in libLLVM) is reported":
      # reprobuild-pm issue 2026-10-14-macos-monitoring-does-not-report-entropy-
      # drawn-by-toolchain-dylibs. clang names the temporary it writes `-o`
      # through with `llvm::sys::Process::GetRandomNumber`, which calls
      # arc4random from libLLVM.dylib -- a LINK-TIME dylib under /nix/store.
      # The shim used to exempt every link-time dylib under a "toolchain" prefix
      # (/nix/store, /opt/homebrew, /usr/local, the Xcode trees), so this draw
      # was seen and discarded: no record, and a consumer with no blessing for
      # the tool published over it. The Linux preload shim reports the same
      # draw. Whether a tool's entropy is harmless is the CONSUMER's blessing
      # decision (made per process image), not a path prefix's.
      let objOut = work / "hello.o"
      let dep = runProbe(shim, ccBin,
        @["-arch", "arm64", "-c", srcFile, "-o", objOut])
      doAssert fileExists(objOut), "cc produced no object file"
      check loadsToolchainLibLLVM(dep)
      var sawArc = false
      for r in dep.records:
        if r.kind == mrNonDeterministic and r.path == "arc4random": sawArc = true
      check sawArc
      # Evidence, not a completeness loss: the monitor observed the draw.
      check dep.completeness == mcComplete

    test "CARDINAL SIN: a clang compile that draws no entropy of its own emits NO evidence":
      # The same compile with `-fno-temp-file` writes the object directly, so
      # clang draws no randomness of its own. Everything the run still draws is
      # the libsystem/libobjc/libcorecrypto startup baseline in /usr/lib and the
      # shared cache, which the caller attribution excludes. A record here would
      # mean that baseline leaked, and every compile would look
      # non-deterministic.
      let objOut = work / "hello-no-temp.o"
      let dep = runProbe(shim, ccBin,
        @["-arch", "arm64", "-fno-temp-file", "-c", srcFile, "-o", objOut])
      doAssert fileExists(objOut), "cc produced no object file"
      check loadsToolchainLibLLVM(dep)
      check countNonDeterministic(dep) == 0
      check dep.completeness == mcComplete

    removeDir(work)
  else:
    test "R4 S3b link-time entropy attribution is macOS-only (no-op here)":
      check true
