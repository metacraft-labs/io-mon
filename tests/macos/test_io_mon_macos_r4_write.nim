## test_io_mon_macos_r4_write — ROUND 4 phase RW1: WRITE-SIDE content APIs.
##
## # The break (round-4 r4_write corpus)
##
## `observationForOpen` classifies a pure `O_RDWR` open (no O_CREAT/O_TRUNC/
## O_APPEND) as an INPUT (`moFileOpen`); a path is upgraded to OUTPUT only when an
## actual WRITE is observed. Round-3 added the READ-side positioned/vectored hooks
## (pread/preadv/readv/sendfile) but NO write-side equivalents, so the only write
## observers were `write(2)` (repro_hook_write) and the MAP_SHARED|PROT_WRITE mmap
## (repro_hook_mmap). Therefore:
##
##   * `O_RDWR` + `pwrite`  → mutates a pre-existing file's content with NO write(2)
##     (the SQLite/LMDB page-write idiom) → recorded as a pure INPUT → empty output
##     set → SKIP candidate on rebuild → stale content / downstream false-skip.
##   * `O_RDWR` + `writev`  → same (linkers/archivers/log writers).
##   * `O_RDWR` + `ftruncate` → the ld64 "open O_RDWR, ftruncate to size, mmap-write"
##     idiom; R9 catches the mmap region but a ftruncate-only shrink/zero-extend
##     escaped.
##   * path-based `truncate(2)` → file shrunk/destroyed with NO record at all.
##
## # The fix (symmetric to the round-3 read hooks)
##
## New interpose hooks pwrite / pwritev / writev / ftruncate / truncate emit an
## `mrFileWrite`/`moFileWrite` on the fd's path (or, for truncate, the canonical
## path argument). This auto-upgrades the `O_RDWR` open INPUT→OUTPUT exactly as
## write(2)/mmap-write already do.
##
## # The CARDINAL-SIN GUARD (the most important correctness property)
##
## A NORMAL build must STAY correct: an `O_RDWR` file that is only READ (round-2 R3
## made a pure O_RDWR open an INPUT) must STAY an input — the new write hooks fire
## ONLY on an actual write/size mutation, never on a read. This file proves both
## the break is CLOSED (each write API now records a write) AND no false
## classification (the read-only O_RDWR probe records NO write).
##
## See reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org
## (ROUND 4, RW1) and research/adversarial-2026-06-round4/r4_write/.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r4write = repoRoot / "research" / "adversarial-2026-06-round4" / "r4_write"

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

  proc runProbe(shim, probe: string; args: seq[string]): MonitorDepFile =
    ## Run `probe args` under the shim (direct DYLD injection, "both" backend — the
    ## production default) and return the merged depfile. The run/fragment dir lives
    ## under a WRITABLE temp dir. Mirrors the existing macOS live tests.
    let runWork = getTempDir() / ("io-mon-r4w-run-" & probe.extractFilename() &
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

  proc hasWriteEndingWith(dep: MonitorDepFile; suffix: string): bool =
    ## A genuine OUTPUT record (moFileWrite) whose path ends with `suffix`. The
    ## recorded path is the F_GETPATH / realpath canonical absolute path (e.g.
    ## /private/var/...), so we match by the unique file basename suffix, which is
    ## /var ↔ /private/var agnostic.
    for r in dep.records:
      if r.observationKind == moFileWrite and r.path.endsWith(suffix):
        return true

  proc hasInputEndingWith(dep: MonitorDepFile; suffix: string): bool =
    ## An INPUT record (the O_RDWR open's moFileOpen, or a read) for `suffix`.
    for r in dep.records:
      if r.path.endsWith(suffix) and
          r.observationKind in {moFileOpen, moFileRead}:
        return true

suite "io-mon macOS RW1 write-side content APIs (live, r4_write corpus)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r4w-live-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    # Compile every corpus probe + the inline cardinal-sin probe ONCE.
    proc probeBin(name: string): string =
      result = work / name
      ccExe(r4write / (name & ".c"), result)

    let
      rdwrPwrite = probeBin("rdwr_pwrite")
      cleanPwrite = probeBin("clean_pwrite")
      rdwrWritev = probeBin("rdwr_writev")
      rdwrFtruncate = probeBin("rdwr_ftruncate")
      cleanFtruncate = probeBin("clean_ftruncate")
      pathTruncate = probeBin("path_truncate")
      cleanTruncate = probeBin("clean_truncate")
      rdwrWrite = probeBin("rdwr_write")          # the CAUGHT baseline (write(2))
      wronlyPwrite = probeBin("wronly_pwrite")    # write recorded AT OPEN

    proc target(tag: string): string =
      ## A fresh, uniquely-named output file per case (so records can't collide).
      work / (tag & "_out.bin")

    # --- BREAK CLOSED: each write API now records a moFileWrite ----------------

    test "O_RDWR + pwrite now carries a moFileWrite (was input-only)":
      let t = target("rdwr_pwrite")
      let dep = runProbe(shim, rdwrPwrite, @[t])
      check hasWriteEndingWith(dep, "rdwr_pwrite_out.bin")

    test "pre-existing file + pwrite (SQLite/LMDB idiom) records a write":
      let t = target("clean_pwrite")
      writeFile(t, "STALE-PREEXISTING-CONTENT\n")   # pre-existing artifact
      let dep = runProbe(shim, cleanPwrite, @[t])
      check hasWriteEndingWith(dep, "clean_pwrite_out.bin")

    test "O_RDWR + writev now carries a moFileWrite":
      let t = target("rdwr_writev")
      let dep = runProbe(shim, rdwrWritev, @[t])
      check hasWriteEndingWith(dep, "rdwr_writev_out.bin")

    test "O_RDWR + ftruncate (ld64 idiom) records a write on the path":
      let t = target("rdwr_ftruncate")
      let dep = runProbe(shim, rdwrFtruncate, @[t])
      check hasWriteEndingWith(dep, "rdwr_ftruncate_out.bin")

    test "pre-existing file + ftruncate shrink records a write":
      let t = target("clean_ftruncate")
      writeFile(t, "FULL-CONTENT-TO-BE-SHRUNK\n")
      let dep = runProbe(shim, cleanFtruncate, @[t])
      check hasWriteEndingWith(dep, "clean_ftruncate_out.bin")

    test "path-based truncate(2) records a write on the canonical path":
      let t = target("path_truncate")
      let dep = runProbe(shim, pathTruncate, @[t])
      check hasWriteEndingWith(dep, "path_truncate_out.bin")

    test "pre-existing file + path truncate(2) records a write":
      let t = target("clean_truncate")
      writeFile(t, "0123456789ABCDEF0123456789\n")
      let dep = runProbe(shim, cleanTruncate, @[t])
      check hasWriteEndingWith(dep, "clean_truncate_out.bin")

    # --- CAUGHT baselines stay caught (no regression) -------------------------

    test "baseline: O_RDWR + write(2) still records a moFileWrite":
      let t = target("rdwr_write")
      let dep = runProbe(shim, rdwrWrite, @[t])
      check hasWriteEndingWith(dep, "rdwr_write_out.bin")

    test "baseline: O_WRONLY|O_CREAT + pwrite records a write (at open)":
      let t = target("wronly_pwrite")
      let dep = runProbe(shim, wronlyPwrite, @[t])
      check hasWriteEndingWith(dep, "wronly_pwrite_out.bin")

    # --- CARDINAL-SIN GUARD: read-only O_RDWR stays an INPUT ------------------

    test "CARDINAL SIN GUARD: O_RDWR-open-then-READ-only stays INPUT (no write)":
      # The new write hooks must fire ONLY on an actual write. A program that opens
      # a file O_RDWR (the defensive lock-then-read idiom; SQLite opens its DB
      # O_RDWR even to read it) and only READS it must NOT be upgraded to an output:
      # a downstream "inputs = read AND NOT written" fold would otherwise DROP a
      # genuine input that changes ⇒ a false cache hit. The file must carry an
      # INPUT record (moFileOpen/moFileRead) and NO moFileWrite.
      let src = work / "rdwr_readonly.c"
      writeFile(src, """
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
  int fd = open(argv[1], O_RDWR);   /* pure O_RDWR -> INPUT (R3) */
  if (fd < 0) { perror("open"); return 1; }
  char buf[64];
  ssize_t n = read(fd, buf, sizeof(buf));   /* READ ONLY -- no write of any kind */
  if (n < 0) { perror("read"); return 1; }
  close(fd);
  return 0;
}
""")
      let bin = work / "rdwr_readonly"
      ccExe(src, bin)
      let t = target("rdwr_readonly")
      writeFile(t, "INPUT-CONTENT-THAT-IS-ONLY-READ\n")
      let dep = runProbe(shim, bin, @[t])
      check hasInputEndingWith(dep, "rdwr_readonly_out.bin")     # stays an input
      check not hasWriteEndingWith(dep, "rdwr_readonly_out.bin") # NOT upgraded

    removeDir(work)
  else:
    test "RW1 write-side content hooks are macOS-only (no-op on this platform)":
      check true
