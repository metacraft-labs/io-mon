## `mcapObservedEnv` on Windows: an environment read must leave evidence, and
## a variable the program never touched must not.
##
## THIS IS THE ONE WINDOWS CAPABILITY GAP THAT COULD PRODUCE A FALSE
## `mcComplete` OVER AN UNSEEN INPUT. M5 closed three of eight declared gaps
## and left five; four of those five are output-side or identity fidelity, and
## `test_io_mon_windows_backend_profile.nim` pinned in a record that exactly
## one of them -- this one -- was an INPUT channel. A build reads a variable,
## nothing records it, the capture grades complete, and the action cache serves
## a stale result the next time the value changes. Every other Windows gap
## costs detail; this one cost correctness.
##
## WHAT IS MIRRORED FROM POSIX, AND WHY EXACTLY. The record is `mrEnvRead` /
## `moEnvRead` with the variable NAME in `path`, deduped per process, never
## downgrading -- byte-for-byte the contract the macOS and Linux arms already
## implement, because consumers compare captures across platforms and a Windows
## record that meant something subtly different would be worse than the honest
## gap it replaces.
##
## THE TWO DIRECTIONS. For the M5 channels the pair was in-tree/out-of-tree.
## An environment read has no peer and no provenance, so the pair that carries
## the same weight here is READ/NOT-READ:
##
##   * a variable the fixture reads must appear, and the run must stay
##     `mcComplete` (an env read is evidence, not loss);
##   * a variable that is SET in the child's environment and never looked at
##     must NOT appear.
##
## Only one of the two would pass against an implementation that always
## answered the same way, which is the property that makes the pair worth
## having. And the second direction is not cosmetic: recording every variable
## would put the whole environment into every action's cache key, so a change
## to an unrelated variable would re-run the build. That is the cardinal sin
## arriving through the consumer instead of through a missed read.
##
## THE FIXTURE ASSERTS ITS OWN OUTCOME. Every mode returns a distinct non-zero
## code when the lookup did not do what the mode needs, and every case here
## checks `exitCode == 0` BEFORE looking at records. Without that, a fixture
## whose variable was not set would produce a run with no env record and a
## records-only assertion would call it a pass -- the same shape as the
## monitoring failure being tested.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, strutils, tempfiles, times, unittest]

import io_mon
import io_mon/capabilities
import io_mon/fs_snoop
import io_mon/types

import windows_channel_fixture

runChannelFixtureIfRequested()

const
  # Set in the test process and inherited by every monitored fixture child.
  # None of these starts with a denylisted prefix -- `IOMON_` is deliberately
  # NOT `IO_MON_`, which is one of the prefixes the shim refuses to record.
  Base = "IOMON_M10"
  # ONE VARIABLE PER ENTRY POINT. A fixture that read a single variable
  # through a whole API family could not tell the family's members apart: the
  # records are deduped by NAME, so the first entry point to fire produces the
  # only record and deleting the hook on any of the others changes nothing an
  # assertion can see. These suffixes match `envVarFor` in the fixture, and
  # each one is asserted on its own below.
  EntryPointVars = [
    "GEVW",       # kernel32 GetEnvironmentVariableW
    "GEVA",       # kernel32 GetEnvironmentVariableA
    "MGETENV", "MWGETENV", "MGETENVS", "MWGETENVS",     # msvcrt.dll
    "UGETENV", "UWGETENV", "UGETENVS", "UWGETENVS",
    "UDUPENVS", "UWDUPENVS"                             # ucrtbase.dll
  ]
  ObservedVar = Base & "_GEVW"
  UnreadVar = Base & "_UNREAD"
  AbsentVar = Base & "_NEVER_SET_AT_ALL"
  CaseVar = Base & "_CASE"
  LoopVar = Base & "_MGETENV"
  # A variable the shim MUST refuse to record: it is one of the monitor's own
  # per-run control variables, and folding it into a consumer's cache key
  # would change that key on every run.
  DeniedVar = "REPRO_MONITOR_M10_DENIED"

const ManyVarCount = 300
  ## Enough names that two of them share a slot in the shim's 1024-slot
  ## trampoline dedup table with near certainty. See the case that uses it.

proc entryPointVar(suffix: string): string = Base & "_" & suffix

proc manyVar(i: int): string =
  var idx = $i
  while idx.len < 3:
    idx = "0" & idx
  Base & "_K" & idx

proc prepareEnvironment() =
  for suffix in EntryPointVars:
    putEnv(entryPointVar(suffix), "value-for-" & suffix)
  for i in 0 ..< ManyVarCount:
    putEnv(manyVar(i), "v" & $i)
  putEnv(UnreadVar, "never-looked-at")
  putEnv(CaseVar, "case-value")
  putEnv(DeniedVar, "per-run-control-value")
  delEnv(AbsentVar)

prepareEnvironment()

proc runFixture(dir: string; mode: string; arg = ""): MonitorResult =
  var command = @[getAppFilename(), ChannelFixtureFlag, mode]
  if arg.len > 0:
    command.add arg
  var request = FsSnoopRequest(
    command: command,
    depFilePath: dir / (mode & ".rdep"),
    captureChildStdio: true)
  runMonitored(request)

proc envRecords(res: MonitorResult): seq[MonitorRecord] =
  result = @[]
  for r in res.records:
    if r.kind == mrEnvRead:
      result.add r

proc envNames(res: MonitorResult): seq[string] =
  result = @[]
  for r in envRecords(res):
    result.add r.path.toUpperAscii

proc countOf(res: MonitorResult; name: string): int =
  result = 0
  for n in envNames(res):
    if n == name.toUpperAscii:
      inc result

proc withTempDir(body: proc(dir: string)) =
  let dir = createTempDir("io_mon_m10_env_", "")
  try:
    body(dir)
  finally:
    try: removeDir(dir)
    except CatchableError: discard

suite "Windows observed-env: the Win32 surface":

  test "GetEnvironmentVariableW and GetEnvironmentVariableA are each recorded":
    ## Each entry point reads its OWN variable, so the ANSI arm is pinned
    ## independently of the wide one. With a shared variable, deleting the
    ## ANSI arm would change nothing an assertion could see.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-win32", Base)
      check res.exitCode == 0
      let names = envNames(res)
      check entryPointVar("GEVW") in names
      check entryPointVar("GEVA") in names
      for r in envRecords(res):
        if r.path.toUpperAscii == entryPointVar("GEVW"):
          # The shape the POSIX arms produce, because a consumer keys on the
          # observation kind and must not need a Windows special case.
          check r.observationKind == moEnvRead
          check r.detail.startsWith("env-read ")
      # An observed declared input is EVIDENCE, never loss. Downgrading on an
      # environment read would re-run every build that reads PATH, which is
      # every build.
      check res.completeness == mcComplete
      check res.depFile.summary.eventLossCount == 0'u64)

  test "a variable that is SET and never read is NOT recorded":
    ## The other direction, and the one that fails against an implementation
    ## that records the whole environment unconditionally. `IOMON_M10_UNREAD`
    ## is in the child's environment for every case in this file; only a
    ## capture that tracks what the program actually asked for can leave it
    ## out.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-win32", Base)
      check res.exitCode == 0
      check ObservedVar in envNames(res)
      checkpoint("recorded names: " & envNames(res).join(","))
      check UnreadVar notin envNames(res))

  test "a process that looks up nothing does not get the whole block":
    ## The strongest form of the same direction, and the one that would fail if
    ## the CRT's startup block snapshot were expanded into per-variable
    ## records: every C runtime reads the whole block once at startup in EVERY
    ## process, so expanding that would make every action on Windows depend on
    ## its entire environment and nothing would ever hit the cache again.
    ##
    ## The assertion is a RATIO rather than zero, because "reads nothing" is
    ## not quite true of any real binary and pretending otherwise would make
    ## this case a lie that happens to pass. This fixture is a Nim test binary,
    ## and Nim's `unittest` reads `NIMTEST_ABORT_ON_ERROR` at module init --
    ## through `msvcrt!getenv`, before the fixture dispatch runs. That single
    ## record is not noise to be tolerated: it is independent evidence that the
    ## CRT arm of the hook is live in the child, from a call this test did not
    ## arrange. What must not appear is the ~50 other variables in the block.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-none")
      check res.exitCode == 0
      var envSize = 0
      for _, _ in envPairs():
        inc envSize
      checkpoint("environment has " & $envSize & " variables; recorded: " &
        envNames(res).join(","))
      # Only meaningful if the environment is actually large.
      check envSize > 10
      check envNames(res).len < envSize div 4
      # And neither of the variables this file puts in the environment for the
      # other cases -- one read by them, one never read by anything.
      check ObservedVar notin envNames(res)
      check UnreadVar notin envNames(res)
      check res.completeness == mcComplete)

  test "a lookup that found NOTHING is still recorded":
    ## Absence is a dependency. A build that behaves one way with a variable
    ## unset and another way with it set must re-run when somebody sets it, and
    ## it can only do that if the miss is in the capture. The fixture asserts
    ## the miss, so a variable that turned out to be set could not make this
    ## pass for the ordinary reason.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-absent", AbsentVar)
      check res.exitCode == 0
      check AbsentVar in envNames(res)
      check res.completeness == mcComplete)

suite "Windows observed-env: the CRT surfaces":

  test "the legacy CRT's getenv family is recorded":
    ## `msvcrt.dll` is what classic mingw-w64 links -- including these test
    ## binaries, whose own import table names it. Its `getenv` is served from
    ## the CRT's OWN snapshot of the environment, taken once at startup, so it
    ## performs NO Win32 environment call: a shim that hooked only kernel32
    ## would see nothing here at all.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-msvcrt", Base)
      check res.exitCode == 0
      let names = envNames(res)
      for suffix in ["MGETENV", "MWGETENV", "MGETENVS", "MWGETENVS"]:
        checkpoint("msvcrt entry point: " & suffix)
        check entryPointVar(suffix) in names
      check res.completeness == mcComplete)

  test "the UCRT's getenv family is recorded":
    ## The runtime MSVC, clang-cl, mingw-w64 UCRT builds, Node and Python all
    ## use. It is a different module with a different snapshot in the same
    ## process, and it exports two entry points `msvcrt.dll` does not
    ## (`_dupenv_s` / `_wdupenv_s`), which is why both arms exist.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-ucrt", Base)
      check res.exitCode == 0
      let names = envNames(res)
      for suffix in ["UGETENV", "UWGETENV", "UGETENVS", "UWGETENVS",
                     "UDUPENVS", "UWDUPENVS"]:
        checkpoint("ucrtbase entry point: " & suffix)
        check entryPointVar(suffix) in names
      check res.completeness == mcComplete)

suite "Windows observed-env: the whole-block read":

  test "a block read from the PROGRAM's own image records every variable":
    ## A program that takes the entire environment has all of it in hand and
    ## nothing can see which parts of it matter, so every name in the block is
    ## a dependency. Over-approximating an input costs a re-run that was not
    ## needed; under-approximating it serves a stale result, and only one of
    ## those is a correctness bug.
    ##
    ## Recorded as the SAME per-name records a named read produces rather than
    ## as a new whole-environment token: the denylist then applies to them (so
    ## the monitor's own per-run control variables stay out of the cache key)
    ## and a cross-platform consumer needs no Windows-specific case.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-block")
      check res.exitCode == 0
      let names = envNames(res)
      # Both the variable the other cases read and the one they never touch:
      # this is the case where the UNREAD variable SHOULD appear, because the
      # program really did receive it.
      check ObservedVar in names
      check UnreadVar in names
      for r in envRecords(res):
        if r.path.toUpperAscii == UnreadVar:
          # `scope=block` is how a consumer tells "the program asked for this
          # variable" from "the program read the whole block and this was in
          # it". Both are dependencies; only the first is evidence the program
          # cared.
          check r.detail.contains("scope=block")
      check res.completeness == mcComplete)

  test "a block read from a SYSTEM image is NOT expanded":
    ## The other side of the gate, and it exists because mutation testing
    ## proved nothing else could see it: with the gate removed, every case in
    ## this file still passed. Nothing in an ordinary fixture process performs
    ## a block read from a system image -- measured, a monitored `cmd /c ver`
    ## records no environment read at all -- so the branch had no coverage.
    ##
    ## It is not an academic branch. A UCRT-linked program's startup calls
    ## `GetEnvironmentStringsW` from `ucrtbase` in EVERY process, and expanding
    ## that into per-variable records would make every action on Windows depend
    ## on its entire environment: no build would ever hit the cache again.
    ##
    ## The fixture manufactures a system-image caller by running
    ## `GetEnvironmentStringsW` as a THREAD START ROUTINE, so it is entered
    ## from `kernel32!BaseThreadInitThunk`, and it asserts the call returned a
    ## real block -- otherwise "nothing was expanded" would pass because
    ## nothing happened.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-block-system")
      check res.exitCode == 0
      var envSize = 0
      for _, _ in envPairs():
        inc envSize
      checkpoint("environment has " & $envSize & " variables; recorded: " &
        envNames(res).join(","))
      check envSize > 10
      check envNames(res).len < envSize div 4
      check UnreadVar notin envNames(res)
      check res.completeness == mcComplete)

  test "the block expansion still refuses the denylisted control variables":
    ## The block contains `REPRO_MONITOR_*` -- the engine put them there. If
    ## the expansion ignored the denylist, every monitored action would depend
    ## on the monitor's own per-run session id and fragment directory, and no
    ## action would ever hit the cache again.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-block")
      check res.exitCode == 0
      for n in envNames(res):
        checkpoint("recorded name: " & n)
        check not n.startsWith("REPRO_MONITOR_")
        check not n.startsWith("IO_MON_"))

suite "Windows observed-env: what must NOT reach the record":

  test "the monitor's own control variables are never recorded":
    ## Read explicitly, through the same entry point every other case uses, so
    ## this cannot pass merely because nothing looked at it.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-one", DeniedVar)
      check res.exitCode == 0
      checkpoint("recorded names: " & envNames(res).join(","))
      check DeniedVar notin envNames(res)
      check res.completeness == mcComplete)

suite "Windows observed-env: dedup and cost":

  test "two spellings of one variable produce one record":
    ## Windows environment lookup is case-INSENSITIVE: `path` and `PATH` name
    ## one variable with one value. A dedup keyed on the spelling would record
    ## it twice and a consumer would fold the same value into its key under two
    ## names.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-case", CaseVar)
      check res.exitCode == 0
      check countOf(res, CaseVar) == 1)

  test "50000 reads of one variable produce one record":
    ## The single-read case cannot tell "recorded once" from "recorded per
    ## call" -- one call produces one record either way. This is the case that
    ## can. A build re-reads PATH and its toolchain variables thousands of
    ## times per process, and a per-call record would bury the depfile in
    ## duplicates of one fact.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-loop", LoopVar)
      check res.exitCode == 0
      check countOf(res, LoopVar) == 1
      check res.completeness == mcComplete)

  test "300 distinct variables are each recorded exactly once":
    ## The dedup the trampoline consults is a fixed-size open-addressed table,
    ## and a dozen names never make two of them share a slot -- so mutations
    ## that made its lookup match on the slot alone, or drop its length check,
    ## both SURVIVED the rest of this file. Three hundred names in a
    ## 1024-slot table make same-slot pairs a near certainty, and an inexact
    ## lookup then answers "already recorded" for a name it has never seen:
    ## the first read of a real variable vanishes from a capture that still
    ## grades `mcComplete`, which is the exact failure this capability exists
    ## to prevent.
    ##
    ## "Exactly once" carries the other half: the table must not be so eager to
    ## treat names as distinct that a repeat re-records.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "env-many", Base)
      check res.exitCode == 0
      var missing: seq[string] = @[]
      var duplicated: seq[string] = @[]
      for i in 0 ..< ManyVarCount:
        let name = manyVar(i)
        let n = countOf(res, name)
        if n == 0: missing.add name
        elif n > 1: duplicated.add name & "x" & $n
      checkpoint("missing: " & missing.join(",") &
        " duplicated: " & duplicated.join(","))
      check missing.len == 0
      check duplicated.len == 0
      check res.completeness == mcComplete)

  test "50000 reads cost bounded wall time under the monitor":
    ## `getenv` is HOT, and the trampoline here cannot take the entropy and
    ## clock trampolines' fast path AS THEY TAKE IT: theirs is a boolean keyed
    ## on a fixed source, while a variable name is only known once the argument
    ## has been read. Nor may it use a hash filter -- one that answered "seen"
    ## for a name it had not seen would silently drop the first read of a real
    ## variable, a missing input, which is the failure this whole capability
    ## exists to prevent.
    ##
    ## So repeat reads take an EXACT, allocation-free lookup in a fixed-size
    ## table of already-recorded names (`envFastSeen*`), and the FIRST read of
    ## each distinct name still dispatches in full. Both costs have to be
    ## measured numbers rather than assumptions, which is what this case is
    ## for -- and the 300-variable case above is what pins the lookup's
    ## exactness, so the two are read together.
    ##
    ## The bound is deliberately loose: this asserts that the dispatch is not
    ## catastrophic, not a benchmark. The campaign's own 10x-monitoring-
    ## slowdown finding had a per-hook system-wide `CreateToolhelp32Snapshot`
    ## behind it, which is the class of cost this would catch.
    withTempDir(proc(dir: string) =
      let started = epochTime()
      let res = runFixture(dir, "env-loop", LoopVar)
      let elapsed = epochTime() - started
      check res.exitCode == 0
      checkpoint("50000 monitored getenv calls, whole run: " &
        $elapsed & " s")
      check elapsed < 20.0)

suite "Windows observed-env: the capability declaration":

  test "observed-env is advertised and no longer a gap":
    ## The declaration is what a consumer reads to decide what the evidence
    ## covers, and it may only move once records genuinely flow -- which is
    ## what the cases above are for. This pins the move against a silent
    ## revert.
    check mcapObservedEnv in WindowsInterposeSupportedCapabilities
    check mcapObservedEnv notin WindowsInterposeKnownUnsupportedCapabilities
    let profile = defaultHooksMonitorProfile()
    for gap in profile.gaps:
      check gap.capability != mcapObservedEnv

  test "advertising it did not make every Windows capture incomplete":
    ## `mcapObservedEnv` is an input CHANNEL but is not in the completeness
    ## FLOOR, so advertising it must not move the floor either way.
    check mcapObservedEnv in InputChannelCapabilities
    check mcapObservedEnv notin InputEvidenceCapabilities
    let profile = defaultHooksMonitorProfile()
    check profile.evidenceComplete

  test "the surfaces NOT covered are stated in the profile":
    ## The honest half. A CRT snapshot is reachable without any call at all --
    ## `msvcrt`'s `_environ` and the UCRT's `__p__environ` hand a program the
    ## array directly -- and no detour can see a program walking an array. That
    ## limit is stated in the profile rather than papered over, and a future
    ## change that dropped the caveat while leaving coverage unchanged would be
    ## the M4 over-claim in a new place.
    let profile = defaultHooksMonitorProfile()
    var sawLimit = false
    for diag in profile.diagnostics:
      if diag.message.contains("_environ"):
        sawLimit = true
    check sawLimit
