## test_io_mon_macos_readdir_inode64 — round-4 P0 TRANSPARENCY regression for the
## INODE64 `readdir`/`getdirentries64` directory-listing corruption.
##
## # The bug this locks in
##
## On modern macOS (always on arm64, where 64-bit inodes are the unconditional
## default) libsystem's `readdir`/`readdir_r`/`scandir` are the `$INODE64`
## implementations: they refill their internal buffer by calling the PRIVATE
## `__getdirentries64` entry, which traps to the 64-bit-inode `SYS_getdirentries64`
## (#344) and returns the modern self-describing record
## (d_ino,8 · d_seekoff,8 · d_reclen,2 · d_namlen,2 · d_type,1 · d_name[…]).
##
## Under the DEFAULT `both` backend the shim body-patches `__getdirentries64` in
## place. The pre-fix code routed BOTH `getdirentries` (#196, legacy 32-bit-inode)
## AND `__getdirentries64` (#344) through ONE hook that forwarded via the LEGACY
## 32-bit `SYS_getdirentries`. That syscall fills the buffer with the INCOMPATIBLE
## 32-bit-inode record (d_ino,4 · d_reclen,2 · d_type,1 · d_namlen,1 · d_name[…]),
## which `readdir` then parses as the 64-bit layout — so every entry name came
## back shifted (missing its leading byte), `..` was dropped, and large directories
## lost entries. A monitor MUST be transparent; this changed monitored programs'
## observable behavior and broke real tools (CPython failed to import `encodings`,
## GNU `ls` returned garbage).
##
## The fix splits the body-patch into TWO specs so `__getdirentries64` forwards via
## the MATCHING `SYS_getdirentries64` (`repro_hook_getdirentries64`), keeping the
## buffer BYTE-IDENTICAL to an unmonitored call.
##
## # What this test asserts
##
## A probe `opendir()`s a directory of first-byte-significant names (`__init__.py`,
## `.hidden`, …) and a large directory (>500 entries), `readdir()`s every entry,
## and prints the names. Run under the `both` backend:
##   1. the monitored listing is byte-identical to the unmonitored listing —
##      every name correct, BOTH `.` and `..` present, ALL entries returned;
##   2. the directory-enumerate DEPENDENCY is still recorded (the transparency
##      fix must NOT lose monitoring) — a `mrDirectoryEnumerate` record naming the
##      enumerated directory is present in the captured depfile.
##
## As the strongest end-to-end check, when a real `python3` is on PATH it must
## START successfully under the shim (the pre-fix shim aborted it with
## "Failed to import encodings module").
##
## macOS-only; a no-op pass elsewhere.

import std/[algorithm, os, osproc, sequtils, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon  # readMonitorDepFile, mergeFragments, record kinds
  import macos_backend_toggle  # applyMacosBackendToggle (A/B → debug toggles)

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc buildShim(): string =
    ## Build the fat (arm64+arm64e) shim and return its path. Fails loudly.
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(args: string) =
    ## Compile a C artifact for this host's primary arm64 slice. Fails loudly.
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " & args)
    doAssert code == 0, "cc failed (" & args & "): " & output

  type Fixture = object
    work: string
    probe: string
    smallDir: string
    bigDir: string

  const bigDirCount = 600  ## >500, so the listing spans multiple getdirentries64
                           ## refills (the pre-fix code also truncated large dirs).

  proc buildFixture(): Fixture =
    ## Create two directories — one with first-byte-significant names, one large —
    ## and build a probe that opendir()/readdir()s a directory given on argv and
    ## prints one entry name per line. The probe uses its OWN `opendir`/`readdir`
    ## bindings, so the body-patched internal `__getdirentries64` refill is on the
    ## path under the `both` backend (the precise condition the bug needed).
    let work = getTempDir() / ("io-mon-readdir64-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # First-byte-significant names: each leading byte is load-bearing, so the
    # pre-fix off-by-one corruption is unmistakable ("_init__.py" for
    # "__init__.py", and a dropped "..").
    let smallDir = work / "small"
    createDir(smallDir)
    for name in ["__init__.py", "alpha.c", "beta.h", ".hidden", "Zfile"]:
      writeFile(smallDir / name, "x")

    let bigDir = work / "big"
    createDir(bigDir)
    for i in 0 ..< bigDirCount:
      # A leading '_' keeps the first byte significant for every entry.
      writeFile(bigDir / ("_entry" & align($i, 4, '0') & ".dat"), "x")

    let probeSrc = work / "probe.c"
    writeFile(probeSrc, """
#include <stdio.h>
#include <dirent.h>
int main(int argc, char **argv) {
  if (argc < 2) return 64;
  DIR *d = opendir(argv[1]);
  if (!d) { perror("opendir"); return 65; }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    /* Print the name verbatim; the Nim harness compares byte-for-byte. */
    printf("%s\n", e->d_name);
  }
  closedir(d);
  return 0;
}
""")
    let probeBin = work / "probe"
    cc(quoteShell(probeSrc) & " -o " & quoteShell(probeBin))
    Fixture(work: work, probe: probeBin, smallDir: smallDir, bigDir: bigDir)

  proc expectedNames(dir: string): seq[string] =
    ## The names readdir MUST return for `dir`: every child plus `.` and `..`.
    result = @[".", ".."]
    for kind, path in walkDir(dir):
      result.add path.extractFilename
    result.sort()

  type RunResult = object
    names: seq[string]      ## the entry names the probe printed, sorted
    exitCode: int
    dirEnumRecorded: bool   ## a mrDirectoryEnumerate record named `dir`

  var runSeq = 0
  proc runProbe(shim, dir: string; fx: Fixture): RunResult =
    ## Run the probe on `dir` under the shim (`both` backend), capture the printed
    ## names, and inspect the merged depfile for the directory-enumerate record.
    inc runSeq
    let runWork = fx.work / ("run-" & $runSeq)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, "both")

    let p = startProcess(fx.probe, args = @[dir], env = env,
      options = {})
    let stdoutText = p.outputStream.readAll()
    result.exitCode = p.waitForExit()
    p.close()

    # The shim prints a one-line banner to stderr (not stdout); stdout is purely
    # the probe's entry names. Drop blank lines and sort for a stable compare.
    result.names = stdoutText.splitLines().filterIt(it.len > 0)
    result.names.sort()

    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    if fileExists(depfile):
      let dep = readMonitorDepFile(depfile)
      for rec in dep.records:
        if rec.kind == mrDirectoryEnumerate and rec.path == dir:
          result.dirEnumRecorded = true

  proc findRealPython(): string =
    ## Locate a real `python3` interpreter for the end-to-end start check. Returns
    ## "" when none is available (the e2e assertion then no-ops — the byte-identity
    ## assertions above are the primary guard and need no external tool).
    let exe = findExe("python3")
    if exe.len == 0: return ""
    exe

suite "io-mon macOS readdir INODE64 transparency (round-4 P0)":
  when defined(macosx):
    let shim = buildShim()
    let fx = buildFixture()

    test "readdir of first-byte-significant names is BYTE-IDENTICAL under the shim":
      # The core transparency property: monitored names must equal unmonitored
      # names EXACTLY. Pre-fix this failed — each name lost its leading byte and
      # `..` was dropped (e.g. "_init__.py", no "..").
      let want = expectedNames(fx.smallDir)
      let got = runProbe(shim, fx.smallDir, fx)
      checkpoint("expected=" & $want & " got=" & $got.names)
      check got.exitCode == 0
      check got.names == want
      # `.` AND `..` must both survive (the pre-fix bug dropped `..`).
      check "." in got.names
      check ".." in got.names
      # The directory-enumerate dependency must STILL be recorded (transparency
      # fix must not silently disable monitoring).
      check got.dirEnumRecorded

    test "readdir of a >500-entry directory returns ALL entries, correctly":
      # Large dirs span multiple getdirentries64 refills; the pre-fix code both
      # corrupted names and TRUNCATED the listing across refill boundaries.
      let want = expectedNames(fx.bigDir)
      let got = runProbe(shim, fx.bigDir, fx)
      checkpoint("want.len=" & $want.len & " got.len=" & $got.names.len)
      check got.exitCode == 0
      check got.names.len == want.len        # nothing lost
      check got.names == want                # every name byte-correct
      check got.dirEnumRecorded

    test "a real python3 STARTS under the shim (encodings import works)":
      # The strongest end-to-end check: CPython enumerates its stdlib directory via
      # readdir at startup. Pre-fix the corrupted listing made it fail with
      # "Failed to import encodings module". When no python3 is on PATH this
      # no-ops (the byte-identity tests above remain the primary guard).
      let py = findRealPython()
      if py.len == 0:
        skip()
      else:
        var env = newStringTable(modeCaseSensitive)
        for k, v in envPairs(): env[k] = v
        env["DYLD_INSERT_LIBRARIES"] = shim
        env["REPRO_MONITOR_SHIM_LIB"] = shim
        applyMacosBackendToggle(env, "both")
        let p = startProcess(py, args = @["-c", "print('ok')"], env = env,
          options = {poStdErrToStdOut})
        let outText = p.outputStream.readAll()
        let code = p.waitForExit()
        p.close()
        checkpoint("python3=" & py & " exit=" & $code & " out=" & outText)
        check code == 0
        check "ok" in outText
        check "Failed to import encodings" notin outText

    removeDir(fx.work)
  else:
    test "readdir INODE64 transparency regression is macOS-only (no-op here)":
      check true
