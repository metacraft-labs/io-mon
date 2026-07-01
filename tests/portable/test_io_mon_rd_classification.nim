## test_io_mon_rd_classification — PORTABLE half of ROUND 2 phase R-D (NON-FILE
## DETERMINISM INPUTS). This file holds the platform-INDEPENDENT, merge-side
## three-way classification logic that was previously embedded in
## `test_io_mon_macos_rd.nim`; the macOS LIVE-capture half (the hooks proven
## against the r2_implicit corpus) stays in `tests/macos/test_io_mon_macos_rd.nim`.
##
## Why this lives in `tests/portable/`: non-file observation handling and the R-D
## branch of `mergeFragments` are pure `src/io_mon/writer.nim` logic, identical on
## every OS. Running these assertions on Linux / *BSD / Windows catches a
## regression in the (env / time / randomness) classification — not just on macOS.
## See reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org (R-D).
##
## # The split (the crux — record evidence without confusing caller policy with
## # monitoring completeness):
##
## 1. ENV vars / sysctl / uname → OBSERVED DECLARED INPUTS (record, do NOT
##    downgrade). The CONSUMER folds the queried VALUE into its cache key (BuildXL
##    observed-environment model), so SOURCE_DATE_EPOCH / $CFLAGS / hw.ncpu / uname
##    re-run iff the value changed — PRECISE, NO false downgrade.
## 2. RANDOMNESS (getentropy / arc4random*) → OBSERVED ENTROPY evidence. Callers
##    decide whether their cache policy treats that as invalidating.
## 3. WALL CLOCK (clock_gettime / gettimeofday / time / mach_absolute_time) →
##    OBSERVED TIME evidence. Callers decide whether their cache policy treats
##    that as invalidating.
##
## The CARDINAL-SIN GUARD (the most important correctness property): a normal
## deterministic build that reads PATH (getenv) + calls clock_gettime + reads a
## file MUST stay mcComplete, with all non-file observations preserved. Only
## actual monitoring loss downgrades to mcIncomplete.

import std/[os, sequtils, unittest]
import io_mon

proc start(pid: uint64): MonitorRecord =
  MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart, osPid: pid)

proc envRead(pid: uint64; name: string): MonitorRecord =
  MonitorRecord(kind: mrEnvRead, observationKind: moEnvRead, osPid: pid,
    path: name, detail: "env-read")

proc sysctlRead(pid: uint64; name: string): MonitorRecord =
  MonitorRecord(kind: mrSysctlRead, observationKind: moSysctlRead, osPid: pid,
    path: name, detail: "sysctl-read")

proc timeRead(pid: uint64; source: string): MonitorRecord =
  MonitorRecord(kind: mrTimeRead, observationKind: moTimeRead, osPid: pid,
    path: source, detail: "time-read")

proc nonDet(pid: uint64; source: string): MonitorRecord =
  MonitorRecord(kind: mrNonDeterministic, observationKind: moNonDeterministic,
    osPid: pid, path: source, detail: "non-deterministic entropy source")

proc legacyNonDetLossCount(records: openArray[MonitorRecord]): int =
  {.push warning[Deprecated]: off.}
  result = nonDeterminismLossCount(records)
  {.pop.}

suite "io-mon R-D non-file observation classification":
  test "mrNonDeterministic is an observation, not monitoring loss":
    let records = @[start(1), nonDet(1, "arc4random")]
    check nonDeterminismObservationCount(records) == 1
    check legacyNonDetLossCount(records) == 0

  test "env + sysctl + time reads yield ZERO losses":
    # Non-file observations are evidence. The caller, not io-mon completeness,
    # decides whether their values invalidate a build/cache result.
    let records = @[start(1), envRead(1, "SOURCE_DATE_EPOCH"),
      envRead(1, "CFLAGS"), sysctlRead(1, "hw.ncpu"), sysctlRead(1, "uname"),
      timeRead(1, "clock_gettime"), timeRead(1, "gettimeofday")]
    check legacyNonDetLossCount(records) == 0

  test "distinct entropy sources are counted as observations":
    let records = @[start(1), nonDet(1, "arc4random"), nonDet(1, "getentropy"),
      nonDet(1, "arc4random_buf")]
    check nonDeterminismObservationCount(records) == 3
    check legacyNonDetLossCount(records) == 0

suite "io-mon R-D merge downgrade (mergeFragments)":
  test "an entropy-consuming build stays mcComplete when fully monitored":
    let work = getTempDir() / ("io-mon-rd-nd-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, start(700'u64))
    appendFragmentRecord(frag, nonDet(700'u64, "arc4random"))
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcComplete
    check dep.records.anyIt(it.kind == mrNonDeterministic and
      it.path == "arc4random")
    removeDir(work)

  test "CARDINAL SIN GUARD: env + time reads stay mcComplete (NO downgrade)":
    # The most important property: observed non-file inputs must NEVER downgrade.
    # The caller decides how to fold their values into cache policy.
    let work = getTempDir() / ("io-mon-rd-ok-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, start(700'u64))
    appendFragmentRecord(frag, envRead(700'u64, "SOURCE_DATE_EPOCH"))
    appendFragmentRecord(frag, timeRead(700'u64, "clock_gettime"))
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcComplete
    # The env read is preserved in the depfile so the consumer CAN fold it.
    var sawEnv = false
    for r in dep.records:
      if r.kind == mrEnvRead and r.path == "SOURCE_DATE_EPOCH": sawEnv = true
    check sawEnv
    removeDir(work)
