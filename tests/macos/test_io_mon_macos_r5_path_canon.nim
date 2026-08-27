## test_io_mon_macos_r5_path_canon — ROUND 5 phase 1: path-fidelity of
## negative-existence dependencies (ENOENT probes / failed opens).
##
## # The break (round-5 pathfidelity corpus)
##
## A file operation targeting a NON-EXISTENT path (ENOENT — a stat/lstat/access of a
## missing file, or a failed open) has NO fd, so the F_GETPATH canonicalisation the
## shim applies to EXISTENT files (recordCanonicalTarget / canonicalPathFor) does not
## run and the shim recorded the RAW caller string while completeness stayed
## mcComplete. These are real negative-existence dependencies (a file absent now whose
## later appearance changes the build — universal in compiler include-path search:
## `-I.`, `-Iinclude`, statting `foo.h` across dirs where most miss). The raw string
## was non-canonical two ways:
##   1. RELATIVE paths were UNANCHORED — `chdir("/build"); stat("nope.h")` recorded a
##      bare `path=nope.h` with NO cwd record anywhere, so no consumer could
##      re-anchor it.
##   2. ABSOLUTE paths were UN-FIRMLINKED — `stat("/tmp/x/nope.h")` recorded `/tmp/...`
##      while io-mon's OWN canonical form for the SAME file once it exists (via
##      F_GETPATH) is `/private/tmp/...`; `./`, `../`, `//` were left verbatim.
## So the same logical file got two different key strings depending on existence → a
## realpath-keying consumer could not match → a false cache hit when the absent file
## appears. See research/adversarial-2026-07-round5/pathfidelity/ (prober.c,
## dualspell.c) and the preserved t_*.iomon repro depfiles.
##
## # The fix
##
## For the ENOENT stat/lstat/access/fstatat probe path and the failed-open path (no
## live fd), the shim now LEXICALLY canonicalises the path before emitting a companion
## record, matching what F_GETPATH yields for the existent file:
##   1. anchor a relative path against the process cwd (getcwd);
##   2. resolve the macOS firmlink prefixes /tmp,/var,/etc -> /private/...;
##   3. collapse "." / ".." / "//" segments.
## This is a purely LEXICAL transform + cwd anchor (NO realpath — it would itself
## ENOENT — and no other filesystem access), tagged `canon=lexical` on the wire. The
## EXISTENT-file path (F_GETPATH) is unchanged, so the two agree (no NEW dual-spelling).
##
## # The CARDINAL-SIN GUARD
##
## A normal build must STAY mcComplete: a real cc compile does hundreds of ENOENT
## include probes, and the new lexical companions must add matchable negative deps
## WITHOUT downgrading or flooding.
##
## See reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org
## (ROUND 5) and reprobuild-specs/io-mon-hardening-protocol.md.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs, times]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  corpus = repoRoot / "research" / "adversarial-2026-07-round5" / "pathfidelity"

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

  type ProbeCapture = object
    dep: MonitorDepFile
    rootPid: uint64

  proc hasRootProcessStart(cap: ProbeCapture): bool =
    ## The launcher's concrete root must have loaded the shim and emitted its own
    ## process-start. A synthetic root-spawn record is not sufficient evidence.
    for rec in cap.dep.records:
      if rec.kind == mrProcessStart and rec.osPid == cap.rootPid:
        return true

  proc runProbe(shim, probe: string; args: seq[string];
      workingDir: string; requireMonitoredRoot = true): ProbeCapture =
    ## Run `probe args` under the shim ("both" backend — interpose + body-patch, the
    ## production default) from `workingDir` and return the merged depfile plus
    ## the concrete root pid. Passing that pid to `mergeFragments` is essential:
    ## without it, a SIP/hardened root can strip DYLD injection, emit an EMPTY
    ## fragment set, and the legacy pid-less merge would falsely report
    ## `mcComplete`.
    let runWork = getTempDir() / ("io-mon-r5pc-run-" & probe.extractFilename() &
      "-" & $getCurrentProcessId() & "-" & $epochTime())
    removeDir(runWork)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, "both")
    let p = startProcess(probe, workingDir = workingDir, args = args, env = env,
      options = {poStdErrToStdOut})
    # Capture the launcher's root pid while the Process handle is live. This is
    # the identity `mergeFragments(expectedRootPid=...)` must prove monitored.
    result.rootPid = uint64(p.processID)
    doAssert result.rootPid != 0, "spawned probe has no root pid: " & probe
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(probe.extractFilename() & " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0,
      "monitored probe failed (" & probe & "): " & stdoutText
    let depfile = runWork / "cap.iomon"
    discard mergeFragments(fragmentDir, depfile,
      expectedRootPid = result.rootPid)
    doAssert fileExists(depfile)
    result.dep = readMonitorDepFile(depfile)
    if requireMonitoredRoot:
      doAssert result.dep.records.len > 0,
        "monitored probe emitted no evidence: " & probe
      doAssert result.hasRootProcessStart,
        "spawned root did not emit process-start (pid=" & $result.rootPid &
        ", probe=" & probe & ")"
    removeDir(runWork)

  proc lexicalAbsentProbe(dep: MonitorDepFile; leaf: string): string =
    ## The path of the ENOENT path-probe COMPANION (prAbsent, detail=canon=lexical)
    ## whose path ends with `leaf`. "" when none — i.e. the raw record only.
    for r in dep.records:
      if r.observationKind == moPathProbe and r.probeResult == prAbsent and
          r.path.endsWith(leaf) and detailToken(r.detail, "canon") == "lexical":
        return r.path

  proc lexicalFailedOpen(dep: MonitorDepFile; leaf: string): string =
    ## The path of the failed-open COMPANION (moFileOpen, result<0,
    ## detail=canon=lexical) whose path ends with `leaf`.
    for r in dep.records:
      if r.observationKind in {moFileOpen, moFileRead, moFileWrite} and
          r.result < 0 and r.path.endsWith(leaf) and
          detailToken(r.detail, "canon") == "lexical":
        return r.path

  proc existentOpenTarget(dep: MonitorDepFile; leaf: string): string =
    ## The path of the F_GETPATH-resolved companion of a SUCCESSFUL open
    ## (detail contains "resolved-target") whose path ends with `leaf`. This is
    ## io-mon's OWN canonical spelling of the file when it EXISTS.
    for r in dep.records:
      if r.kind == mrFileOpen and r.result >= 0 and r.path.endsWith(leaf) and
          r.detail.contains("resolved-target"):
        return r.path

  proc rawAbsentProbe(dep: MonitorDepFile; leaf: string): bool =
    ## The as-passed ENOENT probe record (round-4 caught negative dep) is preserved.
    for r in dep.records:
      if r.observationKind == moPathProbe and r.probeResult == prAbsent and
          r.path.endsWith(leaf):
        return true

  proc tmpStateDir(tag: string): string =
    ## A state dir explicitly under /tmp so the /tmp -> /private/tmp firmlink applies
    ## deterministically (getTempDir may be /var/folders, which also firmlinks, but
    ## /tmp keeps the assertions legible).
    result = "/tmp" / ("io-mon-r5pc-" & tag & "-" & $getCurrentProcessId() &
      "-" & $int(epochTime() * 1000))
    removeDir(result)
    createDir(result)

suite "io-mon macOS R5 P1 path canonicalisation (ENOENT / failed-open, live)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r5pc-bins-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    proc probeBin(name: string): string =
      result = work / name
      ccExe(corpus / (name & ".c"), result)

    let
      prober = probeBin("prober")
      dualspell = probeBin("dualspell")

    # --- (a) relative ENOENT stat is now FULLY ANCHORED -----------------------

    test "(a) ENOENT stat of a relative path after chdir is anchored + firmlinked":
      # `chdir(state); stat("nope.h")` recorded a bare unanchored `path=nope.h`. The
      # lexical companion now anchors it against the cwd AND firmlink-resolves it, to
      # the SAME directory spelling F_GETPATH gives for an EXISTENT sibling opened in
      # the same run (there.txt) — so absent and present key identically.
      let state = tmpStateDir("rel")
      writeFile(state / "there.txt", "present\n")
      let cap = runProbe(shim, prober,
        @["chdir:" & state, "stat:nope.h", "open:there.txt"], "/")
      let dep = cap.dep

      # raw record preserved (round-4 negative dep still caught)
      check rawAbsentProbe(dep, "nope.h")

      let anchored = lexicalAbsentProbe(dep, "nope.h")
      check anchored.len > 0                       # a canonical companion exists
      check anchored.startsWith("/")               # ABSOLUTE, not the bare leaf
      check anchored.startsWith("/private/tmp/")   # firmlink-resolved
      check anchored.endsWith("/nope.h")

      # It anchors to the SAME directory F_GETPATH yields for an existent sibling.
      let existentDir = existentOpenTarget(dep, "there.txt")
      check existentDir.startsWith("/private/tmp/")
      check anchored.parentDir == existentDir.parentDir
      removeDir(state)

    # --- (b) absolute /tmp ENOENT matches the existent-file spelling ----------

    test "(b) ENOENT stat of /tmp/... matches the existent read spelling (dualspell)":
      # dualspell stats a /tmp path while ABSENT, then create+read the SAME path. The
      # absent probe recorded /tmp/... but the existent open/read F_GETPATH-resolved
      # to /private/tmp/... — the dual-spelling. The lexical companion now records
      # /private/tmp/... for the absent probe too, so they MATCH.
      let state = tmpStateDir("dual")
      let target = state / "dual.txt"              # ABSENT at pre-stat time
      let dep = runProbe(shim, dualspell, @[target], "/").dep

      let absent = lexicalAbsentProbe(dep, "dual.txt")
      check absent.len > 0
      check absent.startsWith("/private/tmp/")     # firmlink-resolved absent probe

      let existent = existentOpenTarget(dep, "dual.txt")
      check existent.startsWith("/private/tmp/")   # F_GETPATH spelling of the read
      check absent == existent                     # dual-spelling ELIMINATED
      removeDir(state)

    test "(b') a failed absolute open of /tmp/... gets a firmlinked companion":
      # A failed open (ENOENT) has no fd, so the F_GETPATH companion can't run; the
      # lexical companion now firmlink-resolves it.
      let state = tmpStateDir("openfail")
      let dep = runProbe(shim, prober,
        @["open:" & (state / "missing.h")], "/").dep
      let comp = lexicalFailedOpen(dep, "missing.h")
      check comp.len > 0
      check comp.startsWith("/private/tmp/")
      check comp.endsWith("/missing.h")
      removeDir(state)

    # --- CARDINAL-SIN GUARD ----------------------------------------------------

    test "CARDINAL SIN GUARD: a real cc compile stays mcComplete (no false downgrade)":
      # cc/clang stats+opens hundreds of headers, MOST of them ENOENT (include-search
      # misses). The new lexical companions must add matchable negative deps WITHOUT
      # downgrading a fully-monitored compile or flooding the depfile.
      let state = tmpStateDir("cc")
      let src = state / "hello.c"
      writeFile(src,
        "#include <stdio.h>\nint main(void){printf(\"hi\\n\");return 0;}\n")
      let outBin = state / "hello"
      let ccPath = findExe(getEnv("CC", "cc"))
      doAssert ccPath.len > 0, "could not resolve a C compiler on PATH"
      # Compiler distributions differ in whether their include search performs
      # observable failed opens (some Nix clang wrappers pre-resolve every
      # include directory).  Exercise one exact ENOENT stat in a dedicated
      # monitored run, then run the real compiler under the same production shim.
      # Keeping these as two public monitor runs makes both assertions
      # deterministic: the negative-dependency arm cannot disappear with a
      # compiler upgrade, and an uninjectable compiler wrapper cannot make the
      # lexical-path assertion pass without the real compile guard also passing.
      let missingProbe = state / "missing-include-probe.h"
      let probeCap = runProbe(shim, prober,
        @["stat:" & missingProbe], state)
      let probeDep = probeCap.dep
      check probeDep.completeness == mcComplete
      check probeCap.hasRootProcessStart
      check rawAbsentProbe(probeDep, "missing-include-probe.h")
      let lexicalProbe =
        lexicalAbsentProbe(probeDep, "missing-include-probe.h")
      check lexicalProbe == "/private" & missingProbe

      let compilerCap = runProbe(shim, ccPath,
        @["-arch", "arm64", src, "-o", outBin], state)
      let dep = compilerCap.dep
      # The completeness verdict is backed by evidence from the ACTUAL spawned
      # compiler pid, not merely by an output file and a small/empty depfile.
      check compilerCap.hasRootProcessStart
      check dep.records.len > 0
      check dep.completeness == mcComplete         # NO false downgrade
      check fileExists(outBin)                      # the compile really happened
      # No pathological flood.
      check dep.records.len < 60000
      removeDir(state)

    test "ROOT GUARD: a SIP root with no shim evidence is mcIncomplete":
      # /bin/cat is SIP-protected. Direct DYLD injection is stripped and, because
      # this helper deliberately removes CT_SANDBOX_TOOLS_DIR, no non-SIP
      # replacement is involved. The expected-root synthetic spawn must therefore
      # expose the missing process-start and fail closed instead of accepting an
      # empty depfile as mcComplete.
      let sipCap = runProbe(shim, "/bin/cat", @["/dev/null"], "/",
        requireMonitoredRoot = false)
      check sipCap.rootPid != 0
      check not sipCap.hasRootProcessStart
      check sipCap.dep.completeness == mcIncomplete
      var sawRootSpawn = false
      var sawEventLoss = false
      for rec in sipCap.dep.records:
        if rec.kind == mrProcessSpawn and rec.childOsPid == sipCap.rootPid:
          sawRootSpawn = true
        if rec.kind == mrEventLoss:
          sawEventLoss = true
      check sawRootSpawn
      check sawEventLoss

    removeDir(work)
  else:
    test "R5 P1 path canonicalisation is macOS-only (no-op on this platform)":
      check true
