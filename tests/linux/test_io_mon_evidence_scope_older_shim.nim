## test_io_mon_evidence_scope_older_shim — DA-1i's HOST-SIDE filter, graded.
##
## THE CONTRACT THIS EXISTS FOR IS A DECLARED ONE AND NOTHING CHECKED IT: "the
## host is the source of truth for what the depfile contains — an OLDER SHIM
## that ignores `REPRO_MONITOR_EVIDENCE` still yields a correctly narrowed
## result." That sentence is why the stamp describes the host's scope rather
## than the shim's, and it is why the filter exists at all.
##
## MEASURED: deleting the host filter's evidence clause left the ENTIRE suite
## green — the portable cases, the shim-gate case, the live CLI case and the
## DA-1j fold case. Not because the filter is wrong, but because on Linux with a
## CURRENT shim it is unreachable: the shim has already dropped everything the
## host would drop. The clause is live on macOS and Windows, whose shims do not
## gate, and there it is the ONLY mechanism — so "unreachable here" would leave
## the only mechanism on two platforms graded by nothing.
##
## HOW AN OLDER SHIM IS OBTAINED, since one cannot be checked out: the test
## copies this repo, DELETES the evidence gate from the copy's
## `linux_preload.nim`, and builds a shim from the copy WITH THE REPO'S OWN
## `scripts/build_shim.sh`. The deletion asserts its anchor occurs EXACTLY ONCE
## and fails the test loudly otherwise — a mutation that silently did not apply
## would make everything below a green that means nothing. The resulting `.so` is
## a faithful stand-in for a shim built before `REPRO_MONITOR_EVIDENCE` existed:
## same sources, same build script, minus the gate.
##
## THE BUILD SCRIPT, NOT A HAND-ROLLED `nim c`, AND THAT IS LOAD-BEARING: a
## hand-written compile of the same file with what look like the same flags
## produced a shim whose every monitored process died with SIGTRAP (exit 133).
## Measured, on the UNMUTATED source too, so it was the build and not the
## deletion. Going through the script removes the whole class — whatever it does
## that a transcription of it misses, it keeps doing.
##
## AND THE STAND-IN IS PROVED NOT TO GATE — WHICH IS A DIFFERENT CLAIM FROM THE
## ONE THIS FILE USED TO MAKE, and the difference was measured. The original
## control ran the stand-in at FULL evidence and required the failed lookups to
## be present (`failedLookups(full) >= 2 * Misses`). THAT CONTROL CANNOT FAIL FOR
## THE REASON IT EXISTS: at `esFull` a GATING shim does not gate either, so it
## proves only that the FIXTURE SEARCHED. Measured by handing this test a
## current, gating shim — by simply NOT deleting the gate from the copy — all
## four arms stayed green and the output was indistinguishable from baseline.
## The entire host-side claim rested on a stand-in nothing checked.
##
## THE DISTINGUISHING FACT IS WHAT THE STAND-IN DOES WHEN IT IS TOLD TO NARROW.
## `t_the_stand_in_shim_ignores_the_evidence_variable_which_is_what_makes_it_older`
## runs it SHIM-ONLY at `reads-only` — `REPRO_MONITOR_FRAGMENT_DIR` set by hand,
## no io-mon host anywhere, and a plain `mergeFragments` with NO scope argument,
## so the host filter is not merely unused but UNREACHABLE from this program
## (nothing here calls `runMonitored` or anything that reaches
## `collectMonitorEvidence`; it IS linked in, since `import io_mon` pulls
## `fs_snoop` — see the note in `test_io_mon_evidence_scope_shim_gate.nim`) —
## and requires the failed lookups to STILL BE THERE. A gating shim writes
## essentially nothing there: MEASURED on this fixture, the stand-in publishes
## 400 failed lookups / 53,476 fragment bytes at `reads-only`, and the same file
## with the gate LEFT IN publishes 0 / 1,876 — while the pre-existing arms below
## stayed green through that very mutation. Only once this case passes does the
## narrowed arm's zero below mean "the HOST narrowed it".
##
## NO MOCKS IN THE MONITORING PATH. The public host API (`runMonitored`) drives a
## real capture of a real C fixture through a real preload shim, and every
## assertion is read back from the canonical `.iomon` bytes. The one thing
## fabricated is the OLDER SHIM itself, which is the subject of the test and
## cannot be obtained any other way — it is built from this repo's own sources by
## this repo's own compiler, differing by one deleted gate.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  workspaceRoot = repoRoot.parentDir()
  fixtureC = repoRoot / "tests" / "fixtures" / "evidence_scope_tool" /
    "evidence_scope_tool.c"
  GateAnchor = """
  if not recordInEvidenceScope(gEvidenceScope, record):
    return
"""
    ## The evidence gate in `emitRecord`, verbatim. If this ever stops matching,
    ## the test FAILS rather than silently building a shim that still gates.
  Misses = 200
    ## Must match `EVIDENCE_SCOPE_MISSES` in the fixture.

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon evidence-scope filter on the host (DA-1i, older shim)":
  when defined(linux):
    let work = getTempDir() / ("io-mon-older-shim-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # ── BUILD AN "OLDER" SHIM: this repo, minus the gate ────────────────────
    let repoCopy = work / "repo"
    createDir(repoCopy)
    for kind, path in walkDir(repoRoot):
      let name = path.extractFilename()
      if name in ["build", ".git", "tests", ".direnv"]: continue
      case kind
      of pcDir: copyDir(path, repoCopy / name)
      of pcFile: copyFile(path, repoCopy / name)
      else: discard

    let preload = repoCopy / "src" / "io_mon" / "shim" / "linux_preload.nim"
    let before = readFile(preload)
    let occurrences = before.count(GateAnchor)
    checkpoint("gate anchor occurrences in the copied shim: " & $occurrences)
    require occurrences == 1
    writeFile(preload, before.replace(GateAnchor,
      "  # OLDER SHIM (test fixture): the DA-1i evidence gate does not exist.\n"))
    require readFile(preload).count(GateAnchor) == 0

    # `IO_MON_SHIM_NIMCACHE_DIR` is set EXPLICITLY, and privately: Nim's object
    # names are project-relative, so this second tree would otherwise share
    # `~/.cache/nim/<project>_d` with the repo's own build and the link can die
    # with `ld: final link failed: bad value`.
    var shimEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): shimEnv[k] = v
    shimEnv["IO_MON_SHIM_NIMCACHE_DIR"] = work / "older-shim-nimcache"
    shimEnv["IO_MON_SHIM_OUT_DIR"] = work / "lib"
    shimEnv["STACKABLE_HOOKS_SRC"] = getEnv("STACKABLE_HOOKS_SRC",
      workspaceRoot / "nim-stackable-hooks" / "src")
    shimEnv["SHM_QUEUE_SRC"] = getEnv("SHM_QUEUE_SRC",
      workspaceRoot / "nim-shm-queue" / "src")
    shimEnv["SHM_GSET_SRC"] = getEnv("SHM_GSET_SRC",
      workspaceRoot / "nim-shm-gset" / "src")
    let shimBuild = run("bash", @[repoCopy / "scripts" / "build_shim.sh"],
      shimEnv)
    checkpoint("older shim build: " & shimBuild.output)
    require shimBuild.code == 0
    let olderShim = work / "lib" / "librepro_monitor_shim.so"
    require fileExists(olderShim)

    let tool = work / "evidence-scope-tool"
    let ccRes = run(getEnv("CC", "cc"), @[fixtureC, "-o", tool])
    checkpoint("cc fixture: " & ccRes.output)
    require ccRes.code == 0

    let inputPath = work / "input.txt"
    writeFile(inputPath, "io-mon older-shim fixture\n")
    let missingDir = work / "missing"
    createDir(missingDir)

    # The public host API resolves the shim through `REPRO_MONITOR_SHIM_LIB`
    # (an operator PIN, checked before any discovery candidate), so pinning it
    # here is how the older shim gets injected — no private surface is touched.
    putEnv(ShimLibOverrideEnv, olderShim)
    require findShimLibrary() == olderShim

    proc capture(tag: string; scope: EvidenceScope): MonitorDepFile =
      let depfile = work / (tag & ".iomon")
      let outputPath = work / (tag & ".out")
      removeFile(depfile)
      removeFile(outputPath)
      let res = runMonitored(FsSnoopRequest(
        command: @[tool, inputPath, outputPath, missingDir],
        depFilePath: depfile,
        evidenceScope: scope))
      checkpoint(tag & ": exit=" & $res.exitCode &
        " records=" & $res.depFile.records.len)
      doAssert res.exitCode == 0, tag & ": the fixture failed"
      doAssert fileExists(outputPath), tag & ": the fixture did not run"
      readMonitorDepFile(depfile)

    proc failedLookups(dep: MonitorDepFile): int =
      for rec in dep.records:
        if recordIsFailedExistenceLookup(rec): inc result

    proc successfulLookups(dep: MonitorDepFile): int =
      for rec in dep.records:
        if rec.kind in {mrFileOpen, mrPathProbe, mrDirectoryEnumerate} and
           not recordIsFailedExistenceLookup(rec):
          inc result

    proc captureThroughOlderShimOnly(tag, evidenceValue: string):
        tuple[dep: MonitorDepFile, fragmentBytes: int64] =
      ## Run the fixture under the OLDER shim with NO io-mon host: the shim
      ## writes `.iomon-frag` files directly and nothing on the host side ever
      ## sees an evidence scope. Returns the merged depfile AND the total
      ## fragment bytes, because "the shim did not gate" is a claim about what
      ## reached the TRANSPORT and the bytes are the only direct evidence of it.
      ##
      ## The merge takes NO `observedEvidenceScope` argument, so the host-side
      ## filter cannot have removed anything: whatever is missing here was never
      ## published.
      let fragmentDir = work / ("frag-" & tag)
      removeDir(fragmentDir)
      createDir(fragmentDir)
      let outputPath = work / (tag & ".out")
      removeFile(outputPath)

      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["LD_PRELOAD"] = olderShim
      env["REPRO_MONITOR_SHIM_LIB"] = olderShim
      env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
      env["REPRO_MONITOR_EVIDENCE"] = evidenceValue
      # No `REPRO_MONITOR_DEP_SHM`: the set transport is host-created, so with no
      # host the shim takes the file path — which is what makes the fragment-byte
      # measurement possible at all.

      let res = run(tool, @[inputPath, outputPath, missingDir], env)
      checkpoint(tag & " fixture (rc=" & $res.code & "): " & res.output)
      doAssert res.code == 0, tag & ": the fixture failed: " & res.output
      doAssert fileExists(outputPath), tag & ": the fixture did not run"

      var bytes = 0'i64
      for kind, path in walkDir(fragmentDir):
        if kind == pcFile: bytes += getFileSize(path)

      let depfile = work / (tag & ".iomon")
      removeFile(depfile)
      discard mergeFragments(fragmentDir, depfile)
      (readMonitorDepFile(depfile), bytes)

    test "t_the_stand_in_shim_ignores_the_evidence_variable_which_is_what_makes_it_older":
      # THE FOUNDATION OF EVERYTHING BELOW, AND IT WAS MISSING. This file builds
      # its "older shim" by deleting the gate from a copy of this repo. Nothing
      # checked that the deletion CHANGED ANYTHING OBSERVABLE: handing the test a
      # current, gating shim (by not deleting the gate) left all four arms green
      # and the output indistinguishable from baseline, because the old control
      # ran at `esFull`, where a gating shim does not gate either.
      #
      # So the control has to ask the one question the two shims answer
      # differently: TELL IT TO NARROW, with the host out of the call path, and
      # see whether it obeys. A shim built before `REPRO_MONITOR_EVIDENCE`
      # existed cannot obey — it has never heard of the variable.
      let standInNarrow = captureThroughOlderShimOnly("standin-narrow",
        "reads-only")
      checkpoint("stand-in shim-only @ reads-only: records=" &
        $standInNarrow.dep.records.len &
        " failed=" & $failedLookups(standInNarrow.dep) &
        " fragmentBytes=" & $standInNarrow.fragmentBytes)

      # THE ASSERTION. A gating shim publishes ZERO failed lookups here — that is
      # exactly what `tests/linux/test_io_mon_evidence_scope_shim_gate.nim`
      # proves about the real one. This shim must publish them all.
      check failedLookups(standInNarrow.dep) >= 2 * Misses

      # …AND AT THE TRANSPORT, which is where a gate actually shows. Same shim,
      # same command, scope NOT narrowed. MEASURED, both ways, on this fixture:
      #
      #   stand-in (gate deleted)     reads-only 53,476 B  vs  full 53,474 B
      #   stand-in mutated to GATE    reads-only  1,876 B  vs  full 53,474 B
      #
      # A shim that ignores the variable writes the SAME bytes either way (here,
      # within 0.004%); a gating one collapses to 3.5% of them. The factor-of-two
      # floor therefore sits ~14x above what a gating shim produces and ~2x below
      # what this one produces — an enormous margin on the side that matters and
      # no sensitivity to how much the dynamic loader happens to do on this host,
      # since both arms carry the same loader traffic.
      let standInFull = captureThroughOlderShimOnly("standin-full", "full")
      checkpoint("stand-in shim-only @ full: records=" &
        $standInFull.dep.records.len &
        " failed=" & $failedLookups(standInFull.dep) &
        " fragmentBytes=" & $standInFull.fragmentBytes)
      check standInFull.fragmentBytes > 0
      check standInNarrow.fragmentBytes * 2 > standInFull.fragmentBytes

      # ANTI-VACUITY: both arms are real captures of a program that really
      # searched, so the comparison is not between two empty fragment dirs.
      check failedLookups(standInFull.dep) >= 2 * Misses
      check successfulLookups(standInNarrow.dep) > 0

    test "t_the_host_narrows_a_capture_an_older_shim_did_not":
      # ── THE FIXTURE REALLY SEARCHED ─────────────────────────────────────
      # At full evidence the failed lookups are there. NOTE WHAT THIS DOES AND
      # DOES NOT PROVE: it proves the FIXTURE searched, and nothing about the
      # stand-in, because at `esFull` a gating shim does not gate either. The
      # claim that the stand-in does not gate is the case above; without it the
      # narrowed arm's zero below could equally well have come from a shim that
      # gates after all.
      let full = capture("older-full", esFull)
      checkpoint("older shim @ full: failed=" & $failedLookups(full))
      check failedLookups(full) >= 2 * Misses

      # ── AND THE HOST STILL NARROWS IT ───────────────────────────────────
      # Same shim, same command, scope narrowed. The shim published every failed
      # lookup; the depfile must contain none. Only the host-side filter can
      # have done that, and deleting its evidence clause reddens here — the one
      # place in the suite it does.
      let narrow = capture("older-narrow", esReadsOnly)
      checkpoint("older shim @ reads-only: records=" & $narrow.records.len &
        " failed=" & $failedLookups(narrow))
      check failedLookups(narrow) == 0
      check narrow.records.len < full.records.len

      # …without losing what found something, and without moving the grade.
      check successfulLookups(narrow) > 0
      check successfulLookups(narrow) == successfulLookups(full)
      check narrow.completeness == full.completeness
      check narrow.summary.eventLossCount == full.summary.eventLossCount

      # The re-summarise must match the records that survived — the host rewrote
      # the file, so a stale summary would describe a capture that no longer
      # exists.
      check narrow.summary.recordCount == uint64(narrow.records.len)

      # THE STAMP SURVIVES THE HOST'S REWRITE. The filter re-writes the depfile
      # from the kept records; the stamp rides on the backend-profile record,
      # which is META and therefore always kept. If it did not survive, a
      # narrowed capture would go out unmarked.
      check narrow.observedEvidenceScopeStated
      check narrow.observedEvidenceScope == esReadsOnly
      check narrow.observedEvidenceScopeToken == "reads-only"
      check not observedEvidenceScopeCovers(narrow, esFull)
      check not full.observedEvidenceScopeStated

    removeDir(work)
