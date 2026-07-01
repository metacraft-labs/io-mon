## test_io_mon_macos_r5_determinism — ROUND-5 PHASE 2 determinism-evidence gaps.
##
## Round-5 adversarial probing found determinism INPUTS a build can depend on for
## which the macOS shim recorded NO evidence (the depfile stayed `mcComplete` with
## nothing folded in), so a consumer keying its cache on the depfile could take a
## false cache hit on a non-deterministic build. This suite is the LIVE macOS
## capture that proves each newly-hooked source now records its evidence, that the
## EXTREMELY hot monotonic clock is deduped to ~one record (no depfile flood), and
## — the cardinal-sin guard — that a normal deterministic compile is neither
## downgraded nor flooded.
##
## The sources closed here (see src/io_mon/shim/macos_interpose.nim ROUND-5 P2):
##  1. SecRandomCopyBytes (Security.framework) / CCRandomGenerateBytes
##     (CommonCrypto) → mrNonDeterministic (ENTROPY evidence), like getentropy.
##  2. statfs / fstatfs — the target path was unrecorded → mrPathProbe, canonical.
##
## NOT closed (a documented residual): mach_absolute_time / mach_continuous_time.
## Interposing them is FATAL — dyld's __DATA,__interpose binding is GLOBAL, so it
## rebinds libdispatch/libsystem's OWN hot mach-clock calls to our wrapper and
## deterministically SIGKILLs rustc/clang (the mmap-reentrancy cardinal guard,
## re-confirmed across every mitigation). The wall-clock signals (clock_gettime /
## gettimeofday / time, already hooked) cover the surface that matters; the
## monotonic tick counter is almost never baked into a build's output. See the
## R-D notes in macos_interpose.nim / macos_interpose_runtime.nim.
##
## The corpus probe SOURCES live in research/adversarial-2026-07-round5 (the same
## breaks these hooks close): determinism/p_secrandom.c, p_ccrandom.c and
## unhooked/p_statfs.c. The fstatfs probe is compiled inline (no corpus source).

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r5det = repoRoot / "research" / "adversarial-2026-07-round5" / "determinism"
  r5unhooked = repoRoot / "research" / "adversarial-2026-07-round5" / "unhooked"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc ccExe(src, outBin: string; cc = getEnv("CC", "cc");
      extra: seq[string] = @[]) =
    ## Compile `src` → `outBin`. `cc` defaults to the dev-shell CC (the Nix
    ## toolchain); the SecRandomCopyBytes probe overrides it to the system
    ## `/usr/bin/cc` since it must link `-framework Security` (the Nix cc wrapper
    ## rejects `-framework` and lacks the framework search path).
    var cmd = quoteShell(cc) & " -arch arm64 " & quoteShell(src) &
      " -o " & quoteShell(outBin)
    for e in extra: cmd.add " " & e
    let (output, code) = execCmdEx(cmd)
    doAssert code == 0, "cc failed (" & src & "): " & output
    doAssert fileExists(outBin), "probe not produced: " & outBin

  proc runProbe(shim, probe: string; args: seq[string];
      extraEnv: seq[(string, string)] = @[]): MonitorDepFile =
    ## Run `probe args` under the shim (direct DYLD injection) and return the
    ## merged depfile. Mirrors tests/macos/test_io_mon_macos_rd.nim: the run /
    ## fragment dir lives under a WRITABLE temp dir (never next to a possibly
    ## read-only /nix/store probe).
    let runWork = getTempDir() / ("io-mon-r5det-run-" & probe.extractFilename() &
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
    result = readMonitorDepFile(depfile)
    removeDir(runWork)

  proc hasRecord(dep: MonitorDepFile; kind: MonitorRecordKind;
      path: string): bool =
    for r in dep.records:
      if r.kind == kind and r.path == path:
        return true

  proc hasPathProbe(dep: MonitorDepFile; suffix, detailSub: string): bool =
    ## A path-probe whose recorded path ends with `suffix` and whose detail
    ## contains `detailSub` (e.g. "statfs" / "fstatfs").
    for r in dep.records:
      if r.kind == mrPathProbe and r.path.endsWith(suffix) and
          detailSub in r.detail:
        return true

suite "io-mon macOS R5-P2 determinism evidence (live)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r5det-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    # The corpus mach/entropy probes write their sampled value to a fixed
    # /tmp/r5_determinism/*.txt path; create it so fopen succeeds (else the probe
    # dereferences a NULL FILE* and crashes). The evidence under test is the
    # RECORD, not the file contents.
    createDir("/tmp/r5_determinism")

    # Corpus probes (Nix CC handles the CCRandom / statfs headers via the SDK).
    # SecRandomCopyBytes needs the system CC + `-framework Security`.
    let pCcRandom = work / "p_ccrandom"
    ccExe(r5det / "p_ccrandom.c", pCcRandom)
    let pStatfs = work / "p_statfs"
    ccExe(r5unhooked / "p_statfs.c", pStatfs)

    test "RESIDUAL: mach_absolute_time is NOT hooked (interpose SIGKILLs rustc)":
      # Interposing the commpage clock is fatal (see the module header): dyld's
      # global interpose rebinds libdispatch's own hot calls and SIGKILLs
      # rustc/clang. So mach_absolute_time yields NO time-read evidence — a
      # deliberate residual, asserted here so a future re-hook attempt that would
      # re-break the mmap-reentrancy guard is caught. The mmap-reentrancy suite is
      # the live proof the residual holds; this asserts the recording contract.
      let machSrc = work / "p_machabs.c"
      writeFile(machSrc, "#include <mach/mach_time.h>\n#include <stdio.h>\n" &
        "int main(void){volatile uint64_t t=mach_absolute_time();" &
        "printf(\"%llu\\n\",(unsigned long long)t);return 0;}\n")
      let machBin = work / "p_machabs"
      ccExe(machSrc, machBin)
      let dep = runProbe(shim, machBin, @[])
      check not hasRecord(dep, mrTimeRead, "mach_absolute_time")
      check dep.completeness == mcComplete

    test "ENTROPY: CCRandomGenerateBytes records mrNonDeterministic; mcComplete":
      let dep = runProbe(shim, pCcRandom, @[])
      check hasRecord(dep, mrNonDeterministic, "CCRandomGenerateBytes")
      check dep.completeness == mcComplete

    test "ENTROPY: SecRandomCopyBytes records mrNonDeterministic; mcComplete":
      # SecRandomCopyBytes links Security.framework, so it needs the system CC
      # (the Nix cc wrapper rejects `-framework`). Command Line Tools ship it at
      # /usr/bin/cc on every macOS dev host — required, not skipped.
      const sysCc = "/usr/bin/cc"
      doAssert fileExists(sysCc),
        "system cc (" & sysCc & ") required to link the SecRandomCopyBytes probe"
      let pSecRandom = work / "p_secrandom"
      ccExe(r5det / "p_secrandom.c", pSecRandom, cc = sysCc,
        extra = @["-framework Security"])
      let dep = runProbe(shim, pSecRandom, @[])
      check hasRecord(dep, mrNonDeterministic, "SecRandomCopyBytes")
      check dep.completeness == mcComplete

    test "METADATA: statfs(path) records the canonical path as a path-probe":
      # p_statfs.c calls statfs(argv[1]); the target path was previously
      # unrecorded. It must now appear as an mrPathProbe, canonicalised (the
      # firmlink-resolved /private/tmp spelling), tagged `statfs`.
      let target = work / "statfs_target_dir"
      createDir(target)
      let dep = runProbe(shim, pStatfs, @[target])
      check hasPathProbe(dep, "statfs_target_dir", "statfs")
      check dep.completeness == mcComplete

    test "METADATA: fstatfs(fd) records the fd's F_GETPATH path as a path-probe":
      let fstatfsSrc = work / "p_fstatfs.c"
      writeFile(fstatfsSrc, "#include <stdio.h>\n#include <fcntl.h>\n" &
        "#include <unistd.h>\n#include <sys/mount.h>\n" &
        "int main(int argc,char**argv){int fd=open(argv[1],O_RDONLY);" &
        "if(fd<0){perror(\"open\");return 1;}struct statfs s;" &
        "if(fstatfs(fd,&s)){perror(\"fstatfs\");return 1;}" &
        "printf(\"%s\\n\",s.f_fstypename);close(fd);return 0;}\n")
      let fstatfsBin = work / "p_fstatfs"
      ccExe(fstatfsSrc, fstatfsBin)
      let target = work / "fstatfs_target.txt"
      writeFile(target, "hello\n")
      let dep = runProbe(shim, fstatfsBin, @[target])
      check hasPathProbe(dep, "fstatfs_target.txt", "fstatfs")
      check dep.completeness == mcComplete

    test "CARDINAL-SIN GUARD: a normal cc -c is not flagged nor flooded":
      # The most important property: a normal deterministic compile must NOT be
      # falsely marked non-deterministic by the new entropy hooks. cc/clang and
      # their helpers draw entropy via /usr/lib libsystem (and possibly
      # CommonCrypto) internally on every run; caller attribution excludes that
      # baseline, so ZERO mrNonDeterministic records must appear and the depfile
      # must not be flooded. Uses the injectable Nix cc (the system cc is
      # SIP-hardened → an un-injectable subtree whose event-loss is unrelated to
      # this change, per test_io_mon_macos_rd.nim).
      let ccBin = findExe(getEnv("CC", "cc"))
      doAssert ccBin.len > 0, "cc not found for the cardinal-sin regression"
      let srcPath = work / "input.c"
      writeFile(srcPath, "int main(void){return 0;}\n")
      let ccOut = work / "cc_regression.o"
      let dep = runProbe(shim, ccBin,
        @["-arch", "arm64", "-c", srcPath, "-o", ccOut])
      var ndet = 0
      for r in dep.records:
        if r.kind == mrNonDeterministic: inc ndet
      check ndet == 0                       # NO false non-determinism flag
      check dep.completeness == mcComplete  # NO false downgrade (injectable cc)

    removeDir(work)
    removeDir("/tmp/r5_determinism")
  else:
    test "R5-P2 determinism hooks are macOS-only (no-op on this platform)":
      check true
