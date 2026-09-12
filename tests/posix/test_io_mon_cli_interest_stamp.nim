## test_io_mon_cli_interest_stamp — DA-1j's WRITE side, graded by a LIVE CAPTURE.
##
## WHY THIS FILE EXISTS, stated bluntly because it is a verification finding and
## not a design preference: the capture-scope stamp shipped with FOUR read-side
## cases over hand-built records and NOTHING at all on the write side. Deleting
## the entire stamp write — the block in `mergeFragments` plus the three
## `normalizeInterest(request.interest)` call sites in `fs_snoop` — left the
## portable suite fully green while the rebuilt CLI reproduced the original false
## complete exactly: `--interest file,proc,lib` graded `mcComplete`, stated no
## scope, and was accepted by a full-scope consumer. A milestone whose whole
## subject is "the depfile must SAY what it was asked to record" cannot be graded
## only on the reading of records someone typed out by hand.
##
## SO THIS IS THE END-TO-END CASE. The REAL CLI runs TWICE on ONE command — once
## at full interest, once narrowed — and the two depfiles it actually wrote must
## state two different scopes, each matching what was requested on the command
## line. That closes the whole chain: `--interest` -> `parseInterestFlag` ->
## `FsSnoopRequest.interest` -> `normalizeInterest` at the merge -> the
## `interest=` token on the backend-profile record -> `readMonitorDepFile` ->
## the consumer's verdict. Nothing in DA-1j is graded end to end without it.
##
## NO MOCKS. A freshly compiled CLI binary, the real `LD_PRELOAD`/`DYLD` shim
## built from source, a freshly compiled C fixture doing real file I/O, and every
## assertion read back out of the canonical `.iomon` bytes the CLI wrote.
##
## POSIX (Linux + macOS): the CLI sets up the platform injection itself, so both
## shims are exercised by the same file. The parse-side half — that the flag
## reaches the child's `REPRO_MONITOR_INTEREST` — is
## `tests/portable/test_io_mon_cli_interest_flag.nim`; the library-boundary half
## — that a caller stating no scope is left unstamped — is in
## `tests/portable/test_io_mon_observation_identity_fold.nim`. This file is the
## live middle that neither of those can reach.
##
## Assertion helpers are `template`s, never `proc`s: a `check` inside a plain
## `proc` prints "Check failed" and the enclosing test still reports `[OK]`.

import std/[options, os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  fixtureC = repoRoot / "tests" / "fixtures" / "fs_snoop_tool" / "fs_snoop_tool.c"
  NarrowTokens = "file"
    ## The narrowing under test. `ecFileDeps` alone is deliberate: every other
    ## category is then gated, and one of them — `ecProcessTree` — is guaranteed
    ## to be present in ANY successful capture on ANY backend (the monitored root
    ## itself emits `mrProcessStart`). So the record-side half of this case
    ## cannot pass by the narrowing having had nothing to remove, without relying
    ## on which optional hooks a given platform advertises.
  NarrowInterest = {ecFileDeps}

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon CLI capture-scope stamp (DA-1j, live)":
  let work = getTempDir() / ("io-mon-cli-scope-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let snoopBin = work / "io-mon"

  # Built at suite scope so both halves of the comparison run against ONE
  # binary and ONE shim — two builds could differ, and then a stamp difference
  # would not be evidence about the flag.
  #
  # `--nimcache` is passed EXPLICITLY. Nim's object names are project-relative,
  # so two builds of the same project source from different drivers share
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

  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint("build_shim: " & shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()
  require shimLib.len > 0

  let userBin = work / "fs-snoop-tool"
  let ccRes = run(getEnv("CC", "cc"), @[fixtureC, "-o", userBin])
  checkpoint("cc fixture: " & ccRes.output)
  require ccRes.code == 0

  let inputPath = work / "input.txt"
  writeFile(inputPath, "io-mon capture-scope stamp fixture\n")

  proc capture(tag: string; interestFlag: seq[string]): MonitorDepFile =
    ## One live capture of THE SAME command through the real CLI, differing only
    ## in the `--interest` flag. Returns the depfile as read back from the bytes
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
      @["run"] & interestFlag & @["--depfile", depfile, "--",
        userBin, inputPath, outputPath], childEnv)
    checkpoint(tag & " run (rc=" & $cap.code & "): " & cap.output)
    doAssert cap.code == 0, tag & " capture failed: " & cap.output
    doAssert fileExists(outputPath), tag & ": the monitored command did not run"
    readMonitorDepFile(depfile)

  proc categoryCount(dep: MonitorDepFile; category: EventCategory): int =
    for r in dep.records:
      let c = categoryOf(r.kind)
      if c.isSome and c.get == category: inc result

  test "t_two_captures_of_one_command_state_the_two_scopes_they_were_asked_for":
    let full = capture("full", @[])
    let narrow = capture("narrow", @["--interest", NarrowTokens])

    # ── ANTI-VACUITY FIRST ──────────────────────────────────────────────────
    # Both captures have to be real captures, or "the stamps differ" would be a
    # statement about two empty files. The monitored command's input read is the
    # thing this CLI exists to record, and it must be there in BOTH arms —
    # narrowing to `file` removes other categories, never the file dependencies.
    template capturedTheInput(dep: MonitorDepFile): bool =
      dep.records.anyIt(it.path.len > 0 and inputPath in it.path and
        (it.observationKind == moFileOpen or it.observationKind == moFileRead))
    checkpoint("full records=" & $full.records.len &
      " narrow records=" & $narrow.records.len)
    check capturedTheInput(full)
    check capturedTheInput(narrow)

    # ── THE STAMPS ──────────────────────────────────────────────────────────
    # THE HEADLINE. Two runs of one command, two scopes, and the file says which
    # one it was. Deleting the stamp write (in `mergeFragments`, or the
    # `normalizeInterest(request.interest)` argument at any `fs_snoop` call site)
    # leaves both files stating nothing, and every check in this block reddens.
    check full.observedInterestStated
    check narrow.observedInterestStated
    check full.observedInterest != narrow.observedInterest

    # …and each states the scope it was actually asked for. The CLI always
    # states one: an absent `--interest` is `FullInterest`, which is a claim the
    # capture really can make, not a silence.
    check full.observedInterest == FullInterest
    check narrow.observedInterest == NarrowInterest
    check narrow.observedInterestTokens == NarrowTokens

    # ── THE CONSUMER'S VERDICT, which is the point of stating it at all ─────
    # The two files are now distinguishable by a consumer, which they were not
    # before DA-1j: both used to report the scope as absent and both were
    # accepted by a full-scope consumer.
    check observedInterestCovers(full, FullInterest)
    check not observedInterestCovers(narrow, FullInterest)
    # …while a consumer that only needs file dependencies accepts both. Trust
    # here is a partial order, not a partition: full-scope evidence is strictly
    # stronger than narrowed evidence.
    check observedInterestCovers(full, NarrowInterest)
    check observedInterestCovers(narrow, NarrowInterest)

    # ── AND THE NARROWING REALLY HAPPENED ───────────────────────────────────
    # The stamp must describe the RESULT, not merely echo the request. The
    # monitored root emits `mrProcessStart` on every backend, so the full arm has
    # process-tree records to lose and the narrow arm must have lost them.
    let fullProc = categoryCount(full, ecProcessTree)
    let narrowProc = categoryCount(narrow, ecProcessTree)
    checkpoint("process-tree records: full=" & $fullProc &
      " narrow=" & $narrowProc)
    check fullProc > 0
    check narrowProc == 0
    # Nothing outside the requested scope survives in the narrowed depfile, for
    # any category — the host-side filter's own contract, asserted against a real
    # file rather than against the filter's source.
    for category in EventCategory:
      if category notin NarrowInterest:
        check categoryCount(narrow, category) == 0

    # The two GRADES are reported and deliberately NOT asserted against each
    # other. A narrowed capture can honestly grade `mcComplete` where the full
    # capture grades `mcIncomplete` — gating a category removes the records a
    # loss is derived from — and that divergence is exactly the phenomenon DA-1j
    # exists to make visible in the file. Pinning the two equal here would be
    # asserting the absence of the thing this milestone is about, so the grades
    # are evidence in the log and the SCOPE is what is asserted.
    checkpoint("completeness: full=" & $full.completeness &
      " narrow=" & $narrow.completeness)

  removeDir(work)
