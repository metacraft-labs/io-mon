## A monitored ROOT that is itself a SIP-protected executable must be captured.
##
## # The defect this guards
##
## The shim's spawn hook rewrites every SIP-protected exec *inside* a monitored
## tree to its non-SIP drop-in, and `startMonitor` rewrote a root *script* whose
## shebang names a SIP interpreter. But a root whose own `command[0]` is a SIP
## Mach-O binary — `@["/bin/sh", "-c", …]`, the form many build recipes and
## reprobuild graph actions use — was spawned unrewritten. The kernel stripped
## `DYLD_INSERT_LIBRARIES` from `/bin/sh`, the root never wrote its
## process-start record, and the whole tree was lost: the merge reported
## `spawn child missing process-start` plus the tree-lifetime guard's "no entry
## for the root", and a consumer (reprobuild) withheld the result from its
## cache (`cache-skip-monitor-loss`).
##
## Spec: reprobuild-pm `spec/MacOS-Monitoring.md`, "Packaged SIP replacements
## without an ambient shell" — the root spawn uses the same propagation
## resolver as the spawn hook, and a tool without a valid replacement keeps its
## original path and the fail-incomplete accounting.
##
## # What it asserts
##
## 1. `/bin/sh -c 'cat in > out'` as the root, with the developer shell's PATH:
##    complete capture, no event loss, the read of `in` and the write of `out`
##    both observed.
## 2. A bare `sh` resolved through a PATH holding only the SIP directories, so
##    no PATH lookup can produce a drop-in: the build-embedded packaged bundle
##    supplies it, and capture is still complete.
## 3. Control: a SIP root with no replacement anywhere (`/usr/bin/sw_vers`,
##    which neither the packaged bundle nor PATH provides) still fails closed —
##    `mcIncomplete` with the missing process-start loss — so the rewrite cannot
##    hide a real loss.
##
## On a host with SIP disabled, `/bin/sh` is injectable without any rewrite;
## cases 1 and 2 still hold there (complete capture is the contract either
## way), and the control is graded against the measured SIP mode.
##
## No mocks: the production shim, the real `/bin/sh`, the real packaged tools
## bundle and the real filesystem are used throughout.
import std/[os, osproc, strutils, tempfiles, unittest]
import io_mon
when defined(macosx):
  import build_test_shim
  import stackable_hooks/propagation

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc sipEnabled(): bool =
    let (status, code) = execCmdEx("/usr/bin/csrutil status")
    doAssert code == 0, status
    checkpoint(status.strip())
    "status: enabled." in status

  proc logLosses(dep: MonitorDepFile) =
    for record in dep.records:
      if record.kind == mrEventLoss:
        checkpoint("event-loss: " & record.detail)

  proc observed(dep: MonitorDepFile; path: string;
                kinds: set[MonitorRecordKind]): bool =
    for record in dep.records:
      if record.kind in kinds and record.path.endsWith(path):
        return true
    false

  proc hasLoss(dep: MonitorDepFile): bool =
    for record in dep.records:
      if record.kind == mrEventLoss:
        return true
    false

  proc withHostPath(path: string; body: proc()) =
    ## The root's PATH resolution (like `posix_spawnp`) and the sandbox's
    ## drop-in population both read the HOST's PATH, so a case about PATH has
    ## to set it here, not only in the child environment.
    let oldPath = getEnv("PATH")
    let oldSandbox = getEnv("CT_SANDBOX_TOOLS_DIR")
    let oldTools = getEnv("STACKABLE_HOOKS_TOOLS_DIR")
    defer:
      putEnv("PATH", oldPath)
      for entry in [("CT_SANDBOX_TOOLS_DIR", oldSandbox),
                    ("STACKABLE_HOOKS_TOOLS_DIR", oldTools)]:
        if entry[1].len > 0: putEnv(entry[0], entry[1])
        else: delEnv(entry[0])
    putEnv("PATH", path)
    delEnv("CT_SANDBOX_TOOLS_DIR")
    delEnv("STACKABLE_HOOKS_TOOLS_DIR")
    body()

  suite "a SIP-protected executable as the monitored root":
    let shim = buildPrivateMacosShim(repoRoot, StackableHooksBuiltToolsDir)
    putEnv("REPRO_MONITOR_SHIM_LIB", shim)
    let protectedHost = sipEnabled()

    test "/bin/sh as the root is captured completely":
      require isSipProtected("/bin/sh")
      let work = createTempDir("io-mon-sip-root-", "")
      defer: removeDir(work)
      writeFile(work / "in.txt", "payload\n")
      createDir(work / "out")
      let res = runMonitored(FsSnoopRequest(
        command: @["/bin/sh", "-c", "cat in.txt > out/o.txt"],
        cwd: work, depFilePath: work / "cap.iomon", streamMode: fsoNone))
      logLosses(res.depFile)
      check res.exitCode == 0
      check readFile(work / "out" / "o.txt") == "payload\n"
      check res.completeness == mcComplete
      check not hasLoss(res.depFile)
      check observed(res.depFile, "/in.txt", {mrFileOpen, mrFileRead})
      check observed(res.depFile, "/out/o.txt", {mrFileOpen, mrFileWrite})

    test "a bare sh resolved to /bin/sh uses the packaged drop-in":
      # Without the packaged bundle nothing could replace /bin/sh here; an
      # empty build-embedded directory would make this case meaningless.
      require StackableHooksBuiltToolsDir.len > 0
      require isValidSipReplacement(
        rewriteSipPath("/bin/sh", StackableHooksBuiltToolsDir))
      let work = createTempDir("io-mon-sip-root-bare-", "")
      defer: removeDir(work)
      writeFile(work / "in.txt", "bare\n")
      withHostPath("/bin:/usr/bin") do ():
        let res = runMonitored(FsSnoopRequest(
          command: @["sh", "-c", "cat in.txt > o.txt"],
          cwd: work, depFilePath: work / "cap.iomon", streamMode: fsoNone,
          env: @[("PATH", "/bin:/usr/bin")]))
        logLosses(res.depFile)
        check res.exitCode == 0
        check readFile(work / "o.txt") == "bare\n"
        check res.completeness == mcComplete
        check not hasLoss(res.depFile)
        check observed(res.depFile, "/in.txt", {mrFileOpen, mrFileRead})

    test "a SIP root with no replacement still fails closed":
      const tool = "/usr/bin/sw_vers"
      require fileExists(tool)
      # The control is only a control while nothing can replace the tool.
      let empty = createTempDir("io-mon-sip-root-none-", "")
      defer: removeDir(empty)
      require resolveSipReplacement(tool, empty) == tool
      withHostPath("/bin:/usr/bin") do ():
        let res = runMonitored(FsSnoopRequest(
          command: @[tool, "-productVersion"],
          cwd: empty, depFilePath: empty / "cap.iomon", streamMode: fsoNone))
        logLosses(res.depFile)
        check res.exitCode == 0
        if protectedHost:
          check res.completeness == mcIncomplete
          var missingRoot = false
          for record in res.depFile.records:
            if record.kind == mrEventLoss and
                "missing process-start" in record.detail:
              missingRoot = true
          check missingRoot
        else:
          # SIP disabled: the native tool really is injected, so calling the
          # capture incomplete would be a false downgrade.
          check res.completeness == mcComplete
else:
  suite "a SIP-protected executable as the monitored root":
    test "macOS-only (no-op on this platform)":
      check true
