## test_io_mon_macos_rd — ROUND 2 phase R-D: NON-FILE DETERMINISM INPUTS
## (findings-doc break R10). A build whose output depends on a NON-FILE input that
## changed — producing different output but an IDENTICAL depfile — is a false cache
## hit a file-monitor cannot see. See
## reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org (R-D).
##
## # The THREE-WAY split (the crux — get the classification right or cause the
## # cardinal sin of a false downgrade that re-runs every build):
##
## 1. ENV vars / sysctl / uname → OBSERVED DECLARED INPUTS (record, do NOT
##    downgrade). The shim hooks getenv / sysctlbyname / uname / … and records the
##    NAME queried; the CONSUMER folds the queried VALUE into its cache key (BuildXL
##    observed-environment model), so SOURCE_DATE_EPOCH / $CFLAGS / hw.ncpu / uname
##    re-run iff the value changed — PRECISE, NO false downgrade.
## 2. RANDOMNESS (getentropy / arc4random*) → AUTO-DOWNGRADE (non-deterministic ⇒
##    always re-run), but ONLY when the call's CALLER is the program's OWN main-exe
##    code (caller attribution). The cross-dylib libsystem/libobjc/libswift entropy
##    baseline (present in EVERY real cc/clang/bash run) is excluded — else every
##    build re-runs (the cardinal sin). A /dev/urandom OPEN is NOT flagged (mktemp
##    opens it for a random temp name on essentially every build).
## 3. WALL CLOCK (clock_gettime / gettimeofday / time / mach_absolute_time) → RECORD
##    but do NOT auto-downgrade — almost every program times a loop benignly, so
##    flagging that would re-run EVERYTHING (the cardinal sin).
##
## The CARDINAL-SIN GUARD (the most important correctness property): a normal
## deterministic build that reads PATH (getenv) + calls clock_gettime + reads a
## file MUST stay mcComplete / cacheable, with the env read recorded as an observed
## input and NO non-determinism flag. ONLY randomness auto-downgrades.
##
## The platform-independent suite locks the merge-side three-way classification
## (`nonDeterminismLossCount` + `mergeFragments`); the macOS suite proves the live
## hooks against the round-2 r2_implicit corpus (minicc.c / readfile.c).

import std/[os, sets, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir()
  r2impl = repoRoot / "research" / "adversarial-2026-06-round2" / "r2_implicit"

# ---------------------------------------------------------------------------
# Platform-independent: the merge-side three-way classification.
# ---------------------------------------------------------------------------

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

suite "io-mon R-D non-determinism classification (nonDeterminismLossCount)":
  test "ONLY randomness counts: one mrNonDeterministic yields one loss":
    check nonDeterminismLossCount(@[start(1), nonDet(1, "arc4random")]) == 1

  test "CARDINAL SIN GUARD: env + sysctl + time reads yield ZERO losses":
    # A normal deterministic build that reads env vars, sysctls and clocks must NOT
    # be flagged non-deterministic — else every build re-runs forever.
    let records = @[start(1), envRead(1, "SOURCE_DATE_EPOCH"),
      envRead(1, "CFLAGS"), sysctlRead(1, "hw.ncpu"), sysctlRead(1, "uname"),
      timeRead(1, "clock_gettime"), timeRead(1, "gettimeofday")]
    check nonDeterminismLossCount(records) == 0

  test "distinct entropy sources each count":
    let records = @[start(1), nonDet(1, "arc4random"), nonDet(1, "getentropy"),
      nonDet(1, "arc4random_buf")]
    check nonDeterminismLossCount(records) == 3

suite "io-mon R-D merge downgrade (mergeFragments)":
  test "an entropy-consuming build downgrades to mcIncomplete":
    let work = getTempDir() / ("io-mon-rd-nd-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let frag = work / "frags"
    createDir(frag)
    appendFragmentRecord(frag, start(700'u64))
    appendFragmentRecord(frag, nonDet(700'u64, "arc4random"))
    let dep = mergeFragments(frag, work / "out.rdep")
    check dep.completeness == mcIncomplete
    removeDir(work)

  test "CARDINAL SIN GUARD: env + time reads stay mcComplete (NO downgrade)":
    # The most important property: observed env inputs and benign clock reads must
    # NEVER downgrade. The env read is folded into the consumer's cache key; the
    # time read is recorded-not-downgraded.
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

# ---------------------------------------------------------------------------
# macOS live capture against the r2_implicit corpus.
# ---------------------------------------------------------------------------

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
      extraEnv: seq[(string, string)] = @[]): MonitorDepFile =
    ## Run `probe args` under the shim (direct DYLD injection) and return the
    ## merged depfile (records + completeness). Mirrors the existing macOS tests.
    ## The run/fragment dir lives under a WRITABLE temp dir (NOT next to the probe):
    ## the probe may be a read-only /nix/store binary such as the system `cc`.
    let runWork = getTempDir() / ("io-mon-rd-run-" & probe.extractFilename() &
      "-" & $getCurrentProcessId())
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
    for (k, v) in extraEnv:
      env[k] = v
    applyMacosBackendToggle(env, "both")
    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(probe.extractFilename() & " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe should exit 0 (" & probe & ", out=" &
      stdoutText & ")"
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    readMonitorDepFile(depfile)

  proc hasRecord(dep: MonitorDepFile; kind: MonitorRecordKind;
      path: string): bool =
    for r in dep.records:
      if r.kind == kind and r.path == path:
        return true

  proc hasReadEndingWith(dep: MonitorDepFile; suffix: string): bool =
    for r in dep.records:
      if r.path.endsWith(suffix) and r.observationKind in
          {moFileRead, moFileOpen, moPathProbe}:
        return true

suite "io-mon macOS R-D non-file determinism (live, r2_implicit corpus)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-rd-live-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let srcPath = work / "input.c"
    writeFile(srcPath, "int main(void){return 0;}\n")
    let outPath = work / "out.o"

    let minicc = work / "minicc"
    ccExe(r2impl / "minicc.c", minicc)
    let readfile = work / "readfile"
    ccExe(r2impl / "readfile.c", readfile)

    test "ENV: SOURCE_DATE_EPOCH is an OBSERVED INPUT and stays mcComplete":
      let dep = runProbe(shim, minicc, @[srcPath, "env", outPath],
        @[("SOURCE_DATE_EPOCH", "1700000000")])
      # The env-var NAME is recorded (deduped) so the consumer folds its value…
      check hasRecord(dep, mrEnvRead, "SOURCE_DATE_EPOCH")
      # …and the build is NOT downgraded (no false re-run): an env read is an
      # observed input, not non-determinism.
      check dep.completeness == mcComplete
      # The legitimate source-file dependency is still captured.
      check hasReadEndingWith(dep, "input.c")

    test "CFLAGS: $CFLAGS is recorded as an observed input; mcComplete":
      let dep = runProbe(shim, minicc, @[srcPath, "cflags", outPath],
        @[("CFLAGS", "-O2 -g")])
      check hasRecord(dep, mrEnvRead, "CFLAGS")
      check dep.completeness == mcComplete

    test "SYSCTL: hw.ncpu is recorded as an observed input; mcComplete":
      let dep = runProbe(shim, minicc, @[srcPath, "sysctl", outPath])
      check hasRecord(dep, mrSysctlRead, "hw.ncpu")
      check dep.completeness == mcComplete

    test "UNAME: uname is recorded as an observed input; mcComplete":
      let dep = runProbe(shim, minicc, @[srcPath, "uname", outPath])
      check hasRecord(dep, mrSysctlRead, "uname")
      check dep.completeness == mcComplete

    test "CARDINAL SIN GUARD: a clock_gettime build stays mcComplete (time-read)":
      # A time read whose value reaches the output is the build's responsibility to
      # declare; almost every program reads a clock BENIGNLY, so io-mon records it
      # but does NOT downgrade — else every build re-runs (the cardinal sin).
      let dep = runProbe(shim, minicc, @[srcPath, "time", outPath])
      check hasRecord(dep, mrTimeRead, "clock_gettime")
      check dep.completeness == mcComplete       # NO false downgrade
      check hasReadEndingWith(dep, "input.c")     # the file dep is still captured

    test "RANDOMNESS arc4random: flagged non-deterministic ⇒ mcIncomplete":
      let dep = runProbe(shim, minicc, @[srcPath, "arc4", outPath])
      check hasRecord(dep, mrNonDeterministic, "arc4random")
      check dep.completeness == mcIncomplete     # always re-run

    test "RANDOMNESS getentropy: flagged non-deterministic ⇒ mcIncomplete":
      let dep = runProbe(shim, minicc, @[srcPath, "entropy", outPath])
      check hasRecord(dep, mrNonDeterministic, "getentropy")
      check dep.completeness == mcIncomplete

    test "CARDINAL SIN GUARD: a /dev/urandom OPEN does NOT auto-downgrade":
      # readfile.c reads a regular file (captured) AND opens /dev/urandom. A
      # /dev/urandom open must NOT auto-downgrade: a normal cc/clang compile opens
      # /dev/urandom via `mktemp` to pick a random TEMP-FILE NAME (a build
      # intermediate, not an output), so flagging it would re-run essentially every
      # build that uses a temp file (the cardinal sin). The open/read is STILL
      # captured as a normal file dependency; it just carries no non-determinism
      # flag. A program embedding /dev/urandom bytes in its output is a documented
      # false negative (it should use getentropy/arc4random, which ARE flagged).
      let dep = runProbe(shim, readfile, @[srcPath])
      check not hasRecord(dep, mrNonDeterministic, "/dev/urandom")
      check dep.completeness == mcComplete
      # The /dev/urandom open AND the regular-file dependency are both captured.
      check hasReadEndingWith(dep, "/dev/urandom")
      check hasReadEndingWith(dep, "input.c")

    test "CARDINAL SIN GUARD: a real cc compile emits NO non-determinism flag":
      # The catastrophic case the round-1 implementation missed: cc/clang and their
      # helpers (mktemp) consume entropy via /usr/lib libsystem/libobjc/libswift
      # (arc4random_buf, getentropy) and open /dev/urandom on EVERY compile. With
      # caller-attribution ONLY the program's OWN main-exe entropy downgrades, so a
      # normal compile emits ZERO mrNonDeterministic records — the precise R-D
      # cardinal-sin guard. (Whole-capture completeness can still depend on the
      # UNRELATED subtree-injection machinery when a full link spawns ld, so we
      # assert the R-D-specific property — no false non-determinism flag — rather
      # than the env-dependent mcComplete.)
      let ccBin = findExe(getEnv("CC", "cc"))
      doAssert ccBin.len > 0, "cc not found for the cardinal-sin regression"
      let ccOut = work / "cc_regression.o"
      let dep = runProbe(shim, ccBin,
        @["-arch", "arm64", "-c", srcPath, "-o", ccOut])
      var ndet = 0
      for r in dep.records:
        if r.kind == mrNonDeterministic: inc ndet
      check ndet == 0

    test "STABILITY: a gettimeofday loop does not crash under the shim":
      # Regression for a wall-clock hook that forwarded gettimeofday via the raw
      # SYS_gettimeofday syscall: on macOS arm64 that trap returns the seconds in the
      # result register (a commpage ABI), so the bare syscall mis-signalled and
      # corrupted the CALLER's stack frame — every program calling gettimeofday
      # (e.g. bash's $RANDOM seeder) SIGSEGV'd. The hook now forwards via the genuine
      # libc gettimeofday. runProbe asserts the probe exits 0 (no crash).
      let gtodSrc = work / "gtod.c"
      writeFile(gtodSrc, "#include <sys/time.h>\n#include <stdio.h>\n" &
        "int main(void){struct timeval tv;for(int i=0;i<8;i++)gettimeofday(&tv,0);" &
        "printf(\"%ld\\n\",(long)tv.tv_sec);return 0;}\n")
      let gtodBin = work / "gtod"
      ccExe(gtodSrc, gtodBin)
      let dep = runProbe(shim, gtodBin, @[])
      check dep.completeness == mcComplete
      check hasRecord(dep, mrTimeRead, "gettimeofday")

    removeDir(work)
  else:
    test "R-D non-file determinism hooks are macOS-only (no-op on this platform)":
      check true
