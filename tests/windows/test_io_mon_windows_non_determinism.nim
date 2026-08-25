## `mcapNonDeterminism` on Windows: a randomness or time read must leave
## evidence.
##
## M4's gap line was "entropy and clock sources are not hooked, so a randomness
## or time read leaves no evidence". This is the half of the entropy-blessing
## design (M6) that did not exist on Windows at all: reprobuild is to treat a
## program's randomness as a non-issue when the program is BLESSED in its CLI
## spec, and it cannot do that until io-mon can say which programs consumed
## randomness in the first place.
##
## Two properties are asserted beyond "a record appears", because both are
## needed for the report to mean anything:
##
##   * ATTRIBUTION. An inline detour at the function body sees EVERY caller,
##     including the CRT's and the loader's. A report that said "this program
##     consumed randomness" about a process whose only entropy read was
##     ntdll's would bless nothing and flag everything. The record therefore
##     carries `caller=program` / `caller=system`, decided from the return
##     address against the main image's bounds.
##
##   * COST. These entry points are called at a rate no file API approaches --
##     a build's QueryPerformanceCounter calls outnumber its file opens by
##     orders of magnitude -- so the observation is recorded once per source
##     per caller-origin and every later call takes a fast path that never
##     builds a hook context. The dedup test below is what keeps that true:
##     without it, a change that recorded per call would pass every other
##     assertion here while giving back the monitoring overhead S4 recovered.
##
## Neither kind downgrades completeness, and that is asserted too. io-mon
## OBSERVED the read; whether it invalidates a cached result is the consumer's
## policy. Downgrading here would re-run every build that reads a clock, which
## is every build.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, strutils, tempfiles, unittest]

import io_mon
import io_mon/fs_snoop
import io_mon/types
import io_mon/writer

import windows_channel_fixture

runChannelFixtureIfRequested()

proc runFixture(dir: string; mode: string; arg = ""): MonitorResult =
  var command = @[getAppFilename(), ChannelFixtureFlag, mode]
  if arg.len > 0:
    command.add arg
  var request = FsSnoopRequest(
    command: command,
    depFilePath: dir / (mode & ".rdep"),
    captureChildStdio: true)
  runMonitored(request)

proc recordsOfKind(res: MonitorResult; kind: MonitorRecordKind):
    seq[MonitorRecord] =
  result = @[]
  for r in res.records:
    if r.kind == kind:
      result.add r

proc withTempDir(body: proc(dir: string)) =
  let dir = createTempDir("io_mon_m5_nd_", "")
  try:
    body(dir)
  finally:
    try: removeDir(dir)
    except CatchableError: discard

suite "Windows non-determinism: entropy":

  test "an entropy read is recorded, named, and attributed to the program":
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "entropy")
      check res.exitCode == 0
      let entropy = recordsOfKind(res, mrNonDeterministic)
      check entropy.len > 0
      var sources: seq[string] = @[]
      var sawProgramCaller = false
      for r in entropy:
        check r.observationKind == moNonDeterministic
        check r.path.len > 0
        sources.add r.path
        if r.detail.contains("caller=program"):
          sawProgramCaller = true
      # Both entry points the fixture calls must be named. `RtlGenRandom` is
      # the documented name of the `SystemFunction036` export the CRT's
      # `rand_s` bottoms out in; `BCryptGenRandom` is what modern runtimes
      # call. Naming the source is what lets a consumer decide per-source.
      check "BCryptGenRandom" in sources
      check "RtlGenRandom" in sources
      # The fixture's calls are made from the fixture's own image, so at least
      # one record must say so. If attribution were broken this would still
      # see records -- with `caller=system` on all of them.
      check sawProgramCaller
      # Evidence, not loss.
      check nonDeterminismObservationCount(res.records) > 0
      check res.completeness == mcComplete
      check res.depFile.summary.eventLossCount == 0'u64)

  test "500 entropy calls produce a bounded number of records":
    ## Per-call recording would be both useless and expensive. The evidence M6
    ## needs is "this program consumed randomness"; the count is noise, and at
    ## these call rates it is noise that costs more than every file
    ## observation put together. Two sources, two possible caller origins, so
    ## four records is the ceiling regardless of how many calls are made.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "entropy-loop")
      check res.exitCode == 0
      let entropy = recordsOfKind(res, mrNonDeterministic)
      check entropy.len > 0
      check entropy.len <= 8
      check res.completeness == mcComplete)

suite "Windows non-determinism: clocks":

  test "each clock source is recorded once, and none of them downgrades":
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "time")
      check res.exitCode == 0
      let times = recordsOfKind(res, mrTimeRead)
      check times.len > 0
      var sources: seq[string] = @[]
      for r in times:
        check r.observationKind == moTimeRead
        sources.add r.path
      check "QueryPerformanceCounter" in sources
      check "GetSystemTimeAsFileTime" in sources
      check "GetTickCount64" in sources
      # One per source per process: a program that times a loop must not
      # produce a record per iteration.
      for source in ["QueryPerformanceCounter", "GetSystemTimeAsFileTime",
                     "GetTickCount64"]:
        var n = 0
        for r in times:
          if r.path == source:
            inc n
        check n == 1
      # Almost every program reads a clock. Downgrading on that would re-run
      # everything, which is the cardinal sin in its other direction.
      check res.completeness == mcComplete
      check res.depFile.summary.eventLossCount == 0'u64)

  test "500 clock reads per source still produce one record per source":
    ## The single-call case above cannot tell "recorded once" from "recorded
    ## per call" -- one call produces one record either way. This is the case
    ## that can, and it is the one that matters: a build times things in loops,
    ## and QueryPerformanceCounter is called far more often than any file API.
    ## Recording per call would bury the depfile in markers and would also
    ## defeat the trampoline fast path, giving back monitoring overhead for
    ## evidence nobody wants.
    withTempDir(proc(dir: string) =
      let res = runFixture(dir, "time-loop")
      check res.exitCode == 0
      for source in ["QueryPerformanceCounter", "GetSystemTimeAsFileTime",
                     "GetTickCount64"]:
        var n = 0
        for r in recordsOfKind(res, mrTimeRead):
          if r.path == source:
            inc n
        check n == 1
      check res.completeness == mcComplete)

suite "Windows non-determinism: the stated limit":

  test "a clock served from KUSER_SHARED_DATA without a call is NOT claimed":
    ## `GetTickCount64` and `GetSystemTimeAsFileTime` read the shared user data
    ## page rather than entering the kernel, but they are still exported
    ## FUNCTIONS, so a call through the export is seen -- which is what the
    ## test above proves. What cannot be seen is a program that reads
    ## `0x7FFE0000` itself, or issues `rdtsc`: there is no call to detour.
    ##
    ## That is a real limit and it is stated in the profile rather than papered
    ## over, so this test pins the STATEMENT. A future change that quietly
    ## dropped the caveat while leaving the coverage unchanged would be an
    ## over-claim of exactly the kind M4 exists to prevent.
    let profile = defaultHooksMonitorProfile()
    var sawLimit = false
    for diag in profile.diagnostics:
      if diag.message.contains("KUSER_SHARED_DATA"):
        sawLimit = true
    check sawLimit
