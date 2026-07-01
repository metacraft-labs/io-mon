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
## dualspell.c) and the preserved t_*.rdep repro depfiles.
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

  proc runProbe(shim, probe: string; args: seq[string];
      workingDir: string): MonitorDepFile =
    ## Run `probe args` under the shim ("both" backend — interpose + body-patch, the
    ## production default) from `workingDir` and return the merged depfile.
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
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(probe.extractFilename() & " exit=" & $code & " out=" & stdoutText)
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    result = readMonitorDepFile(depfile)
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
      let dep = runProbe(shim, prober,
        @["chdir:" & state, "stat:nope.h", "open:there.txt"], "/")

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
      let dep = runProbe(shim, dualspell, @[target], "/")

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
        @["open:" & (state / "missing.h")], "/")
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
      let dep = runProbe(shim, ccPath,
        @["-arch", "arm64", src, "-o", outBin], state)
      check dep.completeness == mcComplete         # NO false downgrade
      check fileExists(outBin)                      # the compile really happened
      # The compile DOES exercise the fix: at least one ENOENT include probe gets a
      # lexical companion. (Belt-and-braces: prove the fix is live in a real build.)
      var sawLexical = false
      for r in dep.records:
        if detailToken(r.detail, "canon") == "lexical":
          sawLexical = true
          break
      check sawLexical
      # No pathological flood.
      check dep.records.len < 60000
      removeDir(state)

    removeDir(work)
  else:
    test "R5 P1 path canonicalisation is macOS-only (no-op on this platform)":
      check true
