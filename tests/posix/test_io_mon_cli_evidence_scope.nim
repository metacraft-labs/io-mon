## test_io_mon_cli_evidence_scope — DA-1i's HEADLINE, graded by a LIVE CAPTURE.
##
## THE REAL CLI RUNS TWICE ON ONE COMMAND — once at full evidence, once with
## `--evidence=reads-only` — and the two depfiles it actually wrote must differ
## in the right direction, state two different scopes each matching what was
## asked for on the command line, and agree exactly about every lookup that
## FOUND something.
##
## That closes the whole chain: `--evidence` → `parseEvidenceScopeFlag` →
## `FsSnoopRequest.evidenceScope` → `REPRO_MONITOR_EVIDENCE` in the child
## environment → the shim's gate in `emitRecord` → the host-side filter in
## `collectMonitorEvidence` → the `evidence=` token on the backend-profile
## record → `readMonitorDepFile` → the consumer's verdict.
##
## WRITTEN BECAUSE DA-1j'S EQUIVALENT WAS MISSING AND THE HOLE WAS REAL, not
## hypothetical: the capture-scope stamp shipped with four read-side cases over
## hand-built records and NOTHING on the write side, and deleting the entire
## stamp write left the portable suite green while the rebuilt CLI reproduced the
## original false complete exactly. A milestone about what the depfile SAYS
## cannot be graded only on the reading of records someone typed out by hand.
##
## WHAT THIS FILE CANNOT GRADE, so that the division is explicit rather than
## assumed: it cannot tell the shim's gate from the host's filter, because either
## one alone produces this result. That is the point of having both — an older
## shim that ignores `REPRO_MONITOR_EVIDENCE` must still yield a correctly
## narrowed depfile — and the shim gate's own grade, which needs the host taken
## out of the picture entirely, is
## `tests/linux/test_io_mon_evidence_scope_shim_gate.nim`.
##
## NO MOCKS. A freshly compiled CLI binary, the real `LD_PRELOAD`/`DYLD` shim
## built from source, a freshly compiled C fixture doing real syscalls with known
## results, and every assertion read back out of the canonical `.iomon` bytes the
## CLI wrote.
##
## POSIX (Linux + macOS): the CLI sets up the platform injection itself, so both
## arms are exercised by the same file. On macOS the shim does not gate and the
## host-side filter produces the whole of the narrowing — which is exactly the
## "older shim" contract, so the assertions below are identical on both.
##
## Assertion helpers are `template`s, never `proc`s: a `check` inside a plain
## `proc` prints "Check failed" and the enclosing test still reports `[OK]`.

import std/[options, os, osproc, sequtils, sets, streams, strtabs, strutils,
            unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  fixtureC = repoRoot / "tests" / "fixtures" / "evidence_scope_tool" /
    "evidence_scope_tool.c"
  Misses = 200
    ## Must match `EVIDENCE_SCOPE_MISSES` in the fixture: that many failed opens
    ## AND that many failed probes, so the full arm owes at least `2 * Misses`
    ## failed existence lookups. A margin this size cannot be supplied by loader
    ## noise, which is what makes the count comparison evidence rather than
    ## coincidence.

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon CLI evidence scope (DA-1i, live)":
  let work = getTempDir() / ("io-mon-cli-evidence-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let snoopBin = work / "io-mon"

  # Built at suite scope so both arms run against ONE binary and ONE shim — two
  # builds could differ, and then a record-count difference would not be
  # evidence about the flag.
  #
  # `--nimcache` is passed EXPLICITLY. Nim's object names are project-relative,
  # so two builds of one project from different drivers share
  # `~/.cache/nim/<project>_d` and the second can die with `ld: final link
  # failed: bad value`. A private cache dir costs a cold build and removes the
  # interaction entirely.
  let cliBuild = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"),
    "--path:" & hooksSrc,
    "--nimcache:" & (work / "nimcache"),
    "--out:" & snoopBin,
    snoopSrc])
  checkpoint("nim c io_mon_snoop: " & cliBuild.output)
  require cliBuild.code == 0
  require fileExists(snoopBin)

  var shimEnv = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): shimEnv[k] = v
  shimEnv["IO_MON_SHIM_NIMCACHE_DIR"] = work / "shim-nimcache"
  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"], shimEnv)
  checkpoint("build_shim: " & shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()
  require shimLib.len > 0

  let userBin = work / "evidence-scope-tool"
  let ccRes = run(getEnv("CC", "cc"), @[fixtureC, "-o", userBin])
  checkpoint("cc fixture: " & ccRes.output)
  require ccRes.code == 0

  let inputPath = work / "input.txt"
  writeFile(inputPath, "io-mon evidence-scope fixture\n")
  let missingDir = work / "missing"
  createDir(missingDir)

  proc capture(tag: string; evidenceFlag: seq[string]): MonitorDepFile =
    ## One live capture of THE SAME command through the real CLI, differing only
    ## in the `--evidence` flag. Returns the depfile as read back from the bytes
    ## the CLI wrote, never the in-process value — a consumer only ever sees the
    ## file.
    let depfile = work / (tag & ".iomon")
    let outputPath = work / (tag & ".out")
    removeFile(depfile)
    removeFile(outputPath)
    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin,
      @["run"] & evidenceFlag & @["--depfile", depfile, "--",
        userBin, inputPath, outputPath, missingDir], childEnv)
    checkpoint(tag & " run (rc=" & $cap.code & "): " & cap.output)
    doAssert cap.code == 0, tag & " capture failed: " & cap.output
    doAssert fileExists(outputPath), tag & ": the monitored command did not run"
    readMonitorDepFile(depfile)

  proc failedLookups(dep: MonitorDepFile): int =
    for rec in dep.records:
      if recordIsFailedExistenceLookup(rec): inc result

  proc successfulLookupKeys(dep: MonitorDepFile): HashSet[string] =
    ## The SET of lookups that found something, keyed by (kind, path). The unit
    ## of the claim "the successful lookups are all still present" — record
    ## counts alone would let a dropped read hide behind an added one.
    for rec in dep.records:
      if rec.kind in {mrFileOpen, mrPathProbe, mrDirectoryEnumerate} and
         not recordIsFailedExistenceLookup(rec):
        result.incl($ord(rec.kind) & "|" & rec.path)

  proc metaCount(dep: MonitorDepFile): int =
    for rec in dep.records:
      if categoryOf(rec.kind).isNone: inc result

  test "t_two_captures_of_one_command_differ_by_exactly_the_failed_lookups":
    let full = capture("full", @[])
    let narrow = capture("narrow", @["--evidence=reads-only"])

    # ── ANTI-VACUITY FIRST ──────────────────────────────────────────────────
    # Both arms have to be real captures of a program that really searched and
    # really read, or everything below is a statement about two empty files.
    # The fixture exits non-zero if any of its "absent" paths turns out to
    # exist, so the full arm's failed lookups are its behaviour, not an
    # accident of the environment.
    template capturedTheInput(dep: MonitorDepFile): bool =
      dep.records.anyIt(it.path.len > 0 and inputPath in it.path and
        (it.observationKind == moFileOpen or it.observationKind == moFileRead))
    checkpoint("full records=" & $full.records.len &
      " failed=" & $failedLookups(full) &
      " | narrow records=" & $narrow.records.len &
      " failed=" & $failedLookups(narrow))
    check capturedTheInput(full)
    check capturedTheInput(narrow)
    check failedLookups(full) >= 2 * Misses

    # ── THE COUNTS, AND THE DIRECTION ───────────────────────────────────────
    # THE HEADLINE. Fewer records under `reads-only`, and not merely fewer:
    # fewer by EXACTLY the failed existence lookups the full arm recorded. An
    # equality rather than an inequality, because an inequality would also hold
    # for a narrowing that threw away something it should have kept.
    check narrow.records.len < full.records.len
    check narrow.records.len == full.records.len - failedLookups(full)
    # …and nothing narrower survives in the narrowed depfile. The filter's own
    # contract, asserted against a real file rather than against its source.
    check failedLookups(narrow) == 0

    # ── THE SUCCESSFUL LOOKUPS ARE ALL STILL PRESENT ────────────────────────
    # THE OTHER HALF OF THE HEADLINE, and the half a category gate fails. Gating
    # a probes CATEGORY discards successful probes along with failed ones —
    # measured, 2,066 of them on one `nim c` — because `EventCategory` gates on
    # KIND and success is not a kind. This gates on the RESULT, so the set of
    # lookups that found something must come through UNCHANGED.
    let fullOk = successfulLookupKeys(full)
    let narrowOk = successfulLookupKeys(narrow)
    checkpoint("successful lookups: full=" & $fullOk.len &
      " narrow=" & $narrowOk.len &
      " missing from narrow=" & $(fullOk - narrowOk).len)
    check fullOk.len > 0
    check fullOk == narrowOk

    # ── META AND LOSS RECORDS SURVIVE ───────────────────────────────────────
    # LF-1 at the file level. `recordIsFailedExistenceLookup` answers false for
    # every META kind by construction, so a narrowing cannot drop an
    # `mrEventLoss` and manufacture a false `mcComplete`. The exhaustive
    # statement of that is in `tests/portable/test_io_mon_evidence_scope.nim`;
    # this is the same claim against two files the CLI really wrote.
    check metaCount(narrow) == metaCount(full)
    check narrow.summary.eventLossCount == full.summary.eventLossCount

    # ── AND THE GRADE DID NOT MOVE ──────────────────────────────────────────
    # ASSERTED, not merely reported — and deliberately UNLIKE the interest-axis
    # case, which reports the two grades without comparing them because gating a
    # category removes the records a loss is derived from. This axis cannot:
    # no completeness-bearing record is an existence lookup, so the grade is
    # invariant under the narrowing, and DA-1i's withdrawn first draft — which
    # forced `mcIncomplete` — would redden here.
    checkpoint("completeness: full=" & $full.completeness &
      " narrow=" & $narrow.completeness)
    check narrow.completeness == full.completeness

    # ── THE STAMPS ──────────────────────────────────────────────────────────
    # The two files are now distinguishable by a consumer. Deleting the stamp
    # write in `mergeFragments`, or the `observedEvidenceScope` argument at any
    # `fs_snoop` call site, leaves both files stating nothing and every check in
    # this block reddens.
    check narrow.observedEvidenceScopeStated
    check narrow.observedEvidenceScope == esReadsOnly
    check narrow.observedEvidenceScopeToken == "reads-only"
    # The full arm states nothing, which IS the claim `esFull`: "not stated" has
    # meant exactly that since before this stamp existed, so a full capture's
    # bytes are unchanged by the feature.
    check not full.observedEvidenceScopeStated
    check effectiveObservedEvidenceScope(full) == esFull
    check effectiveObservedEvidenceScope(narrow) !=
      effectiveObservedEvidenceScope(full)

    # ── THE CONSUMER'S VERDICT, which is why it is stated at all ────────────
    check observedEvidenceScopeCovers(full, esFull)
    check not observedEvidenceScopeCovers(narrow, esFull)
    # …while a consumer that opted into the reduced scope accepts BOTH. Trust
    # here is a partial order, not a partition: full evidence is strictly
    # stronger, so keying the cache on the scope would block this direction and
    # the careful teammate's result would be unusable to the fast one.
    check observedEvidenceScopeCovers(full, esReadsOnly)
    check observedEvidenceScopeCovers(narrow, esReadsOnly)

    # ── AND THE OTHER AXIS IS UNTOUCHED ─────────────────────────────────────
    # Narrowing the evidence must not silently narrow the interest, or a
    # consumer reading one stamp would be answering about the other.
    check narrow.observedInterest == full.observedInterest
    check observedInterestCovers(narrow, FullInterest)

  test "t_an_evidence_scope_the_cli_cannot_name_is_refused_not_widened":
    # Silently widening an unrecognised value to `esFull` would discard the
    # operator's reduction without a word — the exact class of silent discard
    # this flag exists to end — and would make `esUnrecognized` reachable from
    # the request side, which the gate and the stamp both rely on it not being.
    let depfile = work / "bogus.iomon"
    removeFile(depfile)
    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let res = run(snoopBin,
      @["run", "--evidence=writes-only", "--depfile", depfile, "--",
        userBin, inputPath, work / "bogus.out", missingDir], childEnv)
    checkpoint("bogus --evidence (rc=" & $res.code & "): " & res.output)
    check res.code != 0
    # The diagnostic has to NAME what was rejected and what was expected, or an
    # operator cannot tell a typo from an unsupported mode.
    check "writes-only" in res.output
    check "reads-only" in res.output
    # And nothing was captured under a scope the CLI could not evaluate.
    check not fileExists(depfile)

  test "t_an_empty_evidence_value_is_refused_in_the_scope_vocabulary":
    # THE FLAG WRITTEN WITH NO SCOPE, in both spellings. `--evidence=` was
    # refused — correctly — but with the parser's catch-all diagnostic,
    # "unsupported fs-snoop argument: --evidence=", which tells an operator the
    # FLAG does not exist when in fact only its VALUE was missing. It reached
    # the catch-all because the option parser dispatched on `value.len > 0`,
    # which cannot tell "the flag with an empty value" from "not this flag".
    #
    # The absent flag still means `esFull` and is untouched: what is refused is
    # writing the flag and naming nothing. Deliberately the OPPOSITE of
    # `parseEvidenceScopeToken("")`, which widens to `esFull` for the ENV
    # channel, where an unset variable really does mean "nothing was said".
    for form in [@["--evidence="], @["--evidence", ""]]:
      let depfile = work / "empty-evidence.iomon"
      removeFile(depfile)
      var childEnv = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): childEnv[k] = v
      childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let res = run(snoopBin,
        @["run"] & form & @["--depfile", depfile, "--",
          userBin, inputPath, work / "empty-evidence.out", missingDir],
        childEnv)
      checkpoint("empty --evidence " & $form & " (rc=" & $res.code & "): " &
        res.output)
      check res.code != 0
      # IT MUST SPEAK THE SCOPE VOCABULARY, not the parser's. Naming the valid
      # set is the difference between "you mistyped a value" and "that flag does
      # not exist", and only one of those is true.
      check "--evidence" in res.output
      check "reads-only" in res.output
      check "full" in res.output
      check "unsupported fs-snoop argument" notin res.output
      # And nothing was captured under a scope the operator never named.
      check not fileExists(depfile)

    # THE CONTRAST THAT MAKES THIS A DEFECT SHAPE RATHER THAN A TASTE: the flag
    # ABSENT is not an error at all — it is `esFull`, exactly as before the flag
    # existed. Refusing the empty value must not have made the default an error.
    let okDep = work / "absent-evidence.iomon"
    removeFile(okDep)
    var okEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): okEnv[k] = v
    okEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let okRes = run(snoopBin,
      @["run", "--depfile", okDep, "--",
        userBin, inputPath, work / "absent-evidence.out", missingDir], okEnv)
    checkpoint("absent --evidence (rc=" & $okRes.code & "): " & okRes.output)
    check okRes.code == 0
    check fileExists(okDep)
    check not readMonitorDepFile(okDep).observedEvidenceScopeStated

  test "t_the_scope_reaches_the_child_environment_so_the_shim_can_gate":
    # THE ARM THAT WAS MISSING, AND IT WAS FOUND BY MUTATION, NOT BY READING.
    # Deleting `REPRO_MONITOR_EVIDENCE` from `childEnv` — so the shim is never
    # told the scope and therefore never gates — left the WHOLE suite green,
    # including the case above. Nothing was wrong with the evidence: the
    # host-side filter still produced a correctly narrowed depfile, identical
    # records, identical stamp. What silently stopped happening was the SAVING.
    #
    # That is the one failure this milestone cannot tolerate quietly, because
    # `--evidence=reads-only` exists to MEASURE what records cost. A mode that
    # publishes every record and deletes it at the merge has the same evidence
    # and none of the point, and no assertion about the depfile can tell the two
    # apart — the depfiles are equal by construction.
    #
    # So this asserts the CHANNEL instead of the result: the variable the shim
    # reads at init must arrive in the child, carrying the scope the operator
    # asked for. `sh` is the monitored command, so no fixture build is needed
    # and nothing here depends on what the shim chose to do with it.
    proc childScope(evidenceFlag: seq[string]): string =
      let seen = work / ("env-" & $evidenceFlag.len & ".txt")
      removeFile(seen)
      var childEnv = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): childEnv[k] = v
      childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let res = run(snoopBin,
        @["run"] & evidenceFlag & @["--depfile", work / "env-probe.iomon", "--",
          "sh", "-c", "printf %s \"$REPRO_MONITOR_EVIDENCE\" > " & seen],
        childEnv)
      doAssert res.code == 0, "env probe failed: " & res.output
      doAssert fileExists(seen), "the monitored command did not run"
      readFile(seen)

    let narrowScope = childScope(@["--evidence=reads-only"])
    let fullScope = childScope(@[])
    checkpoint("child REPRO_MONITOR_EVIDENCE: narrow='" & narrowScope &
      "' full='" & fullScope & "'")
    check narrowScope == "reads-only"
    # …and the default arrives as an explicit `full` rather than as an absent
    # variable, so the shim can tell "record everything" from "unset" — the same
    # property `interestToTokens` gives the interest channel.
    check fullScope == "full"
    check narrowScope != fullScope
    # Both are tokens THIS BUILD can parse back to the scope that was asked for;
    # a channel that delivered an unrecognised token would make the shim record
    # everything while the operator believed they had narrowed.
    check parseEvidenceScopeToken(narrowScope) == esReadsOnly
    check parseEvidenceScopeToken(fullScope) == esFull

  removeDir(work)
