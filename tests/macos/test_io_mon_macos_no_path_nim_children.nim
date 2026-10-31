## A real Nim C compilation must capture its /bin/sh children without PATH.
## No mocks: Nim, clang, the production shim and filesystem evidence all run
## normally. The host PATH is also emptied, so sandbox population cannot hide
## the missing packaged replacement by finding the development shell's sh.
import descendant_guard_expectations
import std/[os, osproc, strutils, tempfiles, unittest]
import io_mon
when defined(macosx):
  import build_test_shim
  import macos_injection_probe
  import stackable_hooks/propagation

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc verifyCapture(builtToolsDir: string; useLoaderControl = false) =
    # Preserve the installed launcher name: following its symlink can expose
    # .nim-wrapped, while the benign constructor correctly reports "nim".
    let nim = findExe("nim", followSymlinks = false)
    # The Apple compiler itself is injectable; /usr/bin/clang is only its
    # SIP-protected xcode-select launcher. Avoid an unrelated launcher loss.
    let clang = execCmdEx("/usr/bin/xcrun -f clang").output.strip()
    # The toolchain clang (unlike the xcrun launcher) has no default SDK, so
    # an isolated environment must name it, or the compile cannot find
    # <string.h>. The experiment is about PATH, not the SDK.
    let sdk = execCmdEx("/usr/bin/xcrun --show-sdk-path").output.strip()
    doAssert nim.len > 0
    doAssert fileExists(clang)
    doAssert dirExists(sdk)
    let shim = buildPrivateMacosShim(repoRoot, builtToolsDir)
    let work = createTempDir("io-mon-no-path-nim-", "")
    defer: removeDir(work)
    let source = work / "fixture.nim"
    let output = work / "fixture"
    let cache = work / "nimcache"
    let depfile = work / "capture.iomon"
    let emptyPath = work / "empty-path"
    createDir(emptyPath)
    writeFile(source, "echo \"captured Nim compiler children\"\n")
    let compileArgs = @["c", "--skipUserCfg", "--skipParentCfg",
      "--cc:clang", "--clang.exe:" & clang,
      "--clang.linkerexe:" & clang, "--parallelBuild:1"]
    var expected = mcComplete
    if useLoaderControl:
      # The benign constructor observes the SAME real Nim compile route with
      # no monitor or replacement resolver. Hosted Macs may permit injection
      # into native /bin/sh; use its evidence rather than assuming SIP policy.
      let oracleOutput = work / "oracle-fixture"
      let images = injectedImages(nim, compileArgs &
        @["--nimcache:" & (work / "oracle-cache"),
          "--out:" & oracleOutput, source], workRoot = work,
        envOverrides = [("PATH", emptyPath), ("HOME", work), ("SDKROOT", sdk)],
        isolateEnv = true)
      doAssert fileExists(oracleOutput)
      expected = if "sh" in images: mcComplete else: mcIncomplete

    let oldPath = getEnv("PATH")
    let oldSandbox = getEnv("CT_SANDBOX_TOOLS_DIR")
    let oldTools = getEnv("STACKABLE_HOOKS_TOOLS_DIR")
    let oldShim = getEnv("REPRO_MONITOR_SHIM_LIB")
    defer:
      putEnv("PATH", oldPath)
      for entry in [("CT_SANDBOX_TOOLS_DIR", oldSandbox),
                    ("STACKABLE_HOOKS_TOOLS_DIR", oldTools),
                    ("REPRO_MONITOR_SHIM_LIB", oldShim)]:
        if entry[1].len > 0: putEnv(entry[0], entry[1])
        else: delEnv(entry[0])
    putEnv("PATH", emptyPath)
    delEnv("CT_SANDBOX_TOOLS_DIR")
    delEnv("STACKABLE_HOOKS_TOOLS_DIR")
    putEnv("REPRO_MONITOR_SHIM_LIB", shim)
    let captured = runMonitored(FsSnoopRequest(
      command: @[nim] & compileArgs &
        @["--nimcache:" & cache, "--out:" & output, source],
      cwd: work, depFilePath: depfile, streamMode: fsoNone,
      isolateEnv: true,
      env: @[("PATH", emptyPath), ("HOME", work), ("SDKROOT", sdk)]))
    let evidence = readMonitorDepFile(depfile)
    for record in evidence.records:
      if record.kind == mrEventLoss: checkpoint(record.detail)
    doAssert captured.exitCode == 0
    doAssert subsystemEvidence(evidence).completeness == expected
    var compilerRead = false
    var shellStarted = false
    for record in evidence.records:
      if record.kind in {mrFileOpen, mrFileRead} and
          record.path.startsWith(cache) and record.path.endsWith(".c"):
        for image in evidence.records:
          if image.kind == mrProcessExec and image.osPid == record.osPid and
              "clang" in image.path.extractFilename:
            compilerRead = true
      if record.kind == mrProcessSpawn and record.path == "/bin/sh":
        for started in evidence.records:
          if started.kind == mrProcessStart and
              started.osPid == record.childOsPid:
            shellStarted = true
    if expected == mcComplete:
      doAssert compilerRead
      doAssert shellStarted
    else:
      doAssert not compilerRead
      doAssert not shellStarted
      var lostShell = false
      for record in evidence.records:
        if record.kind == mrEventLoss and "path=/bin/sh" in record.detail and
            "missing process-start" in record.detail:
          lostShell = true
      doAssert lostShell
    doAssert fileExists(output)
    doAssert execCmdEx(quoteShell(output)).output.strip() ==
      "captured Nim compiler children"

  suite "packaged macOS shell propagation without PATH":
    test "Nim C compiler children retain complete file capture":
      verifyCapture(StackableHooksBuiltToolsDir)

    test "native shell capture matches the independent loader control":
      verifyCapture("", useLoaderControl = true)
