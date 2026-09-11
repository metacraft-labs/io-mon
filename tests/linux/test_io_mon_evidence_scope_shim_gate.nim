## test_io_mon_evidence_scope_shim_gate — DA-1i's gate WHERE IT PAYS, isolated.
##
## THE HOST FILTER ALONE WOULD PASS EVERY OTHER TEST IN THIS MILESTONE. A
## `reads-only` capture that publishes every failed lookup and then deletes them
## at the merge produces byte-identical evidence to one that never published
## them — and saves NOTHING, which is the entire point of a mode that exists to
## measure what records cost. So the shim gate needs a grade that the host filter
## cannot supply, and this file is it.
##
## HOW THE HOST IS TAKEN OUT OF THE PICTURE: the fixture runs under the real
## `LD_PRELOAD` shim with `REPRO_MONITOR_FRAGMENT_DIR` set BY HAND and no io-mon
## host anywhere — the same direct-injection capture path the macOS suite uses.
## The merge is then plain `mergeFragments(dir, out)` with NO scope argument, so
## `collectMonitorEvidence`'s host-side filter is not merely unused, it is
## UNREACHABLE from this program: nothing here calls `runMonitored`,
## `finishMonitor` or anything else that reaches it. Whatever is missing from
## the result was never emitted.
##
## Say UNREACHABLE and not "not compiled in", which an earlier draft of this
## line said and which is FALSE: this file does `import io_mon`, the umbrella
## module re-exports `fs_snoop`, and the object really is in the link —
## measured, 2 of 42 objects in this test's nimcache. (Checking that requires
## knowing Nim ROT13-ENCODES nimcache object names, so `fs_snoop` is on disk as
## `sf_fabbc`; a literal grep for the module name matches nothing in any build
## and so "proves" absence for everything.) Reachability is the property that
## matters here and it is the one that holds.
##
## The two arms differ ONLY in `REPRO_MONITOR_EVIDENCE`, so the difference is
## attributable to the shim's gate and to nothing else — not to the flag parser,
## not to the child-environment composer, not to the merge.
##
## LINUX-ONLY, and not by accident: the gate lives in `linux_preload.nim`'s
## `emitRecord`. The macOS and Windows shims deliberately do NOT gate — they are
## the "older shim that ignores the variable" case the host filter exists to
## cover, and `tests/posix/test_io_mon_cli_evidence_scope.nim` grades the result
## on every POSIX arm.
##
## NO MOCKS. A real shim built from source, a real C fixture performing real
## syscalls with known results, real `.iomon-frag` bytes, and the real merge.

import std/[os, osproc, sequtils, streams, strtabs, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  fixtureC = repoRoot / "tests" / "fixtures" / "evidence_scope_tool" /
    "evidence_scope_tool.c"
  Misses = 200
    ## Must match `EVIDENCE_SCOPE_MISSES` in the fixture. The fixture performs
    ## this many failed opens AND this many failed probes, so the full arm owes
    ## at least `2 * Misses` failed existence lookups — a margin no amount of
    ## loader noise can supply by accident.

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon evidence-scope gate in the shim (DA-1i, Linux)":
  when defined(linux):
    let work = getTempDir() / ("io-mon-evidence-shim-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # ONE shim and ONE fixture binary for both arms: two builds could differ,
    # and then a record-count difference would not be evidence about the flag.
    #
    # `--nimcache` is the shim script's own (`IO_MON_SHIM_NIMCACHE_DIR`), for the
    # reason every build in this repo passes one: Nim's object names are
    # project-relative, so two builds of one project from different directories
    # share `~/.cache/nim/<project>_d` and the second can die with
    # `ld: final link failed: bad value`.
    var shimEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): shimEnv[k] = v
    shimEnv["IO_MON_SHIM_NIMCACHE_DIR"] = work / "shim-nimcache"
    let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"],
      shimEnv)
    checkpoint("build_shim: " & shimBuild.output)
    require shimBuild.code == 0
    let shimLib = findShimLibrary()
    require shimLib.len > 0

    let tool = work / "evidence-scope-tool"
    let ccRes = run(getEnv("CC", "cc"), @[fixtureC, "-o", tool])
    checkpoint("cc fixture: " & ccRes.output)
    require ccRes.code == 0

    let inputPath = work / "input.txt"
    writeFile(inputPath, "io-mon evidence-scope fixture\n")
    let missingDir = work / "missing"
    createDir(missingDir)

    proc captureThroughShimOnly(tag, evidenceValue: string):
        tuple[dep: MonitorDepFile, fragmentBytes: int64] =
      ## Run the fixture under the shim with NO io-mon host: the shim writes
      ## `.iomon-frag` files directly and nothing on the host side ever sees an
      ## evidence scope. Returns the merged depfile AND the total fragment
      ## bytes, because "the record was never published" is a claim about the
      ## TRANSPORT and the bytes are the only direct evidence of it.
      let fragmentDir = work / ("frag-" & tag)
      removeDir(fragmentDir)
      createDir(fragmentDir)
      let outputPath = work / (tag & ".out")
      removeFile(outputPath)

      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["LD_PRELOAD"] = shimLib
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib
      env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
      env["REPRO_MONITOR_EVIDENCE"] = evidenceValue
      # No REPRO_MONITOR_DEP_SHM: the set transport is host-created, so with no
      # host the shim takes the file path. That is what makes the fragment-byte
      # measurement below possible at all.

      let res = run(tool, @[inputPath, outputPath, missingDir], env)
      checkpoint(tag & " fixture (rc=" & $res.code & "): " & res.output)
      doAssert res.code == 0, tag & ": the fixture failed: " & res.output
      doAssert fileExists(outputPath), tag & ": the fixture did not run"

      var bytes = 0'i64
      for kind, path in walkDir(fragmentDir):
        if kind == pcFile: bytes += getFileSize(path)

      let depfile = work / (tag & ".iomon")
      removeFile(depfile)
      # NO `observedEvidenceScope` ARGUMENT. The host-side filter is not in this
      # call path, so nothing here can remove a record the shim published.
      discard mergeFragments(fragmentDir, depfile)
      (readMonitorDepFile(depfile), bytes)

    proc failedLookups(dep: MonitorDepFile): int =
      for rec in dep.records:
        if recordIsFailedExistenceLookup(rec): inc result

    proc successfulLookups(dep: MonitorDepFile): int =
      for rec in dep.records:
        if rec.kind in {mrFileOpen, mrPathProbe, mrDirectoryEnumerate} and
           not recordIsFailedExistenceLookup(rec):
          inc result

    test "t_the_shim_never_publishes_a_failed_lookup_under_reads_only":
      let full = captureThroughShimOnly("full", "full")
      let narrow = captureThroughShimOnly("narrow", "reads-only")

      # ── ANTI-VACUITY ────────────────────────────────────────────────────────
      # Both arms must be real captures of a program that really searched, or
      # the comparison is between two empty files. The fixture returns non-zero
      # if any of its "absent" paths turns out to exist, so a full arm carrying
      # `2 * Misses` failed lookups is the fixture's behaviour, not an artefact.
      checkpoint("full records=" & $full.dep.records.len &
        " failed=" & $failedLookups(full.dep) &
        " fragmentBytes=" & $full.fragmentBytes)
      checkpoint("narrow records=" & $narrow.dep.records.len &
        " failed=" & $failedLookups(narrow.dep) &
        " fragmentBytes=" & $narrow.fragmentBytes)
      check failedLookups(full.dep) >= 2 * Misses

      # ── THE GATE ────────────────────────────────────────────────────────────
      # Not one failed lookup reached the fragments. Deleting the gate in
      # `emitRecord` reddens here and NOWHERE ELSE in the suite, because every
      # other case reads a depfile the host filter has already corrected.
      check failedLookups(narrow.dep) == 0
      check narrow.dep.records.len < full.dep.records.len

      # ── AND THE COST REALLY WAS SAVED ───────────────────────────────────────
      # The bytes, not just the record count. A gate that published and then
      # filtered would leave these two equal — and would make `--evidence`
      # useless for the measurement it exists to perform. THIS IS THE SOLE
      # GRADER OF DA-1i'S CENTRAL CLAIM (that the cost is saved at the
      # TRANSPORT), so it is graded in two independent dimensions rather than
      # with one loose inequality.
      #
      # THE BOUND THAT WAS HERE ADMITTED A FACTOR OF 2 while the measured fact
      # is a factor of 29 on this host (54,678 -> 1,880 fragment bytes; 83,546 ->
      # 2,172 on the reviewer's, the absolute numbers moving with path lengths
      # and loader traffic while the ratio does not). Between 2 and 29 sits every
      # PARTIAL gate — one that stopped gating one of the two failed-lookup kinds
      # — and "the gate degrading" is exactly that shape.
      #
      # TWO BOUNDS, AND THEY CATCH DIFFERENT FAILURES. Stating which is which
      # matters, because neither alone is the claim:
      #
      # (1) THE RATIO — THE DEGRADATION DETECTOR, an ORDER OF MAGNITUDE rather
      # than a factor of two. Both arms carry the SAME successful records, so the
      # ratio is `1 + failedBytes/successfulBytes` and is insensitive to scale.
      # MEASURED: 29.1 here, so the bound has 2.9x of headroom. MEASURED AGAINST
      # A PARTIAL GATE (the shim mutated to gate `mrPathProbe` but publish failed
      # `mrFileOpen`s): 28,280 vs 54,858 — a ratio of 1.94, which this rejects by
      # 14x. The old `div 2` bound rejected that same mutation by **3.1%**
      # (28,280 against a threshold of 27,429), and a slightly hungrier partial
      # gate — probes plus half the failed opens, ~15 KB — would have passed it
      # outright while still failing this one by 10x.
      check narrow.fragmentBytes * 10 < full.fragmentBytes
      # (2) THE ABSOLUTE FLOOR — THE ENVIRONMENT-INDEPENDENCE ANCHOR, so that (1)
      # is not the only thing standing between this milestone and a green on a
      # host whose loader traffic swamps the fixture. The fixture performs
      # `2 * Misses` failed lookups on DISTINCT paths of a KNOWN shape
      # (`<missing-dir>/absent-open-0000.h`), and each such record must occupy at
      # least its PATH in the fragment, before any per-record header. So the
      # saving is bounded below by a quantity THIS TEST OWNS and the dynamic
      # loader cannot touch. MEASURED: 52,798 bytes saved against a floor of
      # 24,000 — conservative by 2.2x precisely because it counts only the path
      # bytes of the records it is entitled to count. It deliberately does NOT
      # catch the partial gate above (26,578 saved still clears 24,000); that is
      # (1)'s job, and this one's job is to hold when (1)'s denominator moves.
      const MissPathSuffixBytes = "/absent-open-0000.h".len
      let droppedPathBytes = int64(2 * Misses) *
        int64(missingDir.len + MissPathSuffixBytes)
      checkpoint("bytes saved=" & $(full.fragmentBytes - narrow.fragmentBytes) &
        " floor from the fixture's own paths=" & $droppedPathBytes)
      check full.fragmentBytes - narrow.fragmentBytes >= droppedPathBytes

      # ── WITHOUT LOSING THE SUCCESSFUL LOOKUPS ───────────────────────────────
      # The fixture opens and stats its input on both arms. If the gate were
      # dropping by KIND rather than by RESULT these would go too — which is
      # exactly what a probes-category gate does (measured: 2,066 successful
      # probes discarded on one `nim c`).
      check successfulLookups(narrow.dep) > 0
      check successfulLookups(narrow.dep) == successfulLookups(full.dep)
      check inputPath in narrow.dep.records.mapIt(it.path)

      # ── AND WITHOUT MOVING THE GRADE ────────────────────────────────────────
      # A narrowing is the operator asking a narrower question. The gate cannot
      # drop a loss marker — `recordIsFailedExistenceLookup` answers false for
      # every META kind by construction — so the two arms must grade alike.
      check narrow.dep.completeness == full.dep.completeness
      check narrow.dep.summary.eventLossCount == full.dep.summary.eventLossCount

      # ── THE ENV CHANNEL'S BACK-COMPAT RULE ──────────────────────────────────
      # A shim told NOTHING writes everything down, exactly as it did before
      # this variable existed. Without this, adding the variable would silently
      # change every capture that predates it.
      let silent = captureThroughShimOnly("silent", "")
      check failedLookups(silent.dep) >= 2 * Misses

      # …and a scope token this shim cannot name also records everything. The
      # host filter is the source of truth for the RESULT, so an older shim
      # meeting a newer host's token must err toward capturing MORE.
      let future = captureThroughShimOnly("future", "writes-only")
      check failedLookups(future.dep) >= 2 * Misses

    removeDir(work)
