## A real Nim C compilation must capture its /bin/sh children without PATH.
## No mocks: Nim, clang, the production shim and filesystem evidence all run
## normally. The host PATH is also emptied, so sandbox population cannot hide
## the missing packaged replacement by finding the development shell's sh.
import std/[os, osproc, strutils, tempfiles, unittest]
import io_mon
when defined(macosx):
  import build_test_shim
  import stackable_hooks/propagation

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc verifyCapture(builtToolsDir: string; expected: MonitorCompleteness) =
    let nim = findExe("nim")
    # The Apple compiler itself is injectable; /usr/bin/clang is only its
    # SIP-protected xcode-select launcher. Avoid an unrelated launcher loss.
    let clang = execCmdEx("/usr/bin/xcrun -f clang").output.strip()
    require nim.len > 0
    require fileExists(clang)
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
      command: @[nim, "c", "--skipUserCfg", "--skipParentCfg",
        "--cc:clang", "--clang.exe:" & clang,
        "--clang.linkerexe:" & clang, "--parallelBuild:1",
        "--nimcache:" & cache, "--out:" & output, source],
      cwd: work, depFilePath: depfile, streamMode: fsoNone,
      isolateEnv: true, env: @[("PATH", emptyPath), ("HOME", work)]))
    let evidence = readMonitorDepFile(depfile)
    for record in evidence.records:
      if record.kind == mrEventLoss: checkpoint(record.detail)
    check captured.exitCode == 0
    check evidence.completeness == expected
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
      check compilerRead
      check shellStarted
    else:
      check not compilerRead
      check not shellStarted
      var lostShell = false
      for record in evidence.records:
        if record.kind == mrEventLoss and "path=/bin/sh" in record.detail and
            "missing process-start" in record.detail:
          lostShell = true
      check lostShell
    require fileExists(output)
    check execCmdEx(quoteShell(output)).output.strip() ==
      "captured Nim compiler children"

  suite "packaged macOS shell propagation without PATH":
    test "Nim C compiler children retain complete file capture":
      verifyCapture(StackableHooksBuiltToolsDir, mcComplete)

    test "without shipped replacements real shell children remain incomplete":
      verifyCapture("", mcIncomplete)
