## test_io_mon_macos_rename — the macOS shim hooks rename(2)/renameat(2) and
## records the atomic-output MOVE as a write on the destination, under BOTH the
## interpose and the body-patch backends.
##
## # Why this matters (the gnulib/autotools atomic-write idiom — §16.7.8)
##
## gnulib/autotools makefiles materialise generated outputs atomically with the
## `chmod a-w $@t; mv $@t $@` idiom: write a temp file, drop its write bit, then
## `mv` (rename(2)) it onto the final path. Two things must hold for a monitored
## build:
##   1. The rename must be RECORDED — it is the output's materialisation, the
##      §16.7.8 coverage-relevant fact. Before this change the shim documented
##      "macOS interpose shim does not hook rename/renameat yet" (capabilities.nim
##      mcapRename was an unsupported gap); now rename/renameat are hooked.
##   2. The rename must still WORK — and not be BROKEN by the body-patch. This is
##      the regression the keystone fix targets: the body-patch backend must not
##      corrupt a build subprocess performing this idiom.
##
## # What this test asserts
##
## A freshly-built probe performs the build-shaped sequence: write a temp file,
## `chmod a-w` it, then rename(2) it onto the destination, then re-create. Run
## under the shim with both mechanisms on (the default, body-patch active):
##   * the sequence COMPLETES (the destination has the moved contents — the
##     body-patch did not break the move), and
##   * a write record (moFileWrite) for the DESTINATION path IS captured (the
##     rename was hooked and classified as an output write).
## The same is asserted with body-patch disabled for diagnosis (the
## interpose-only A/B arm) to lock in that interpose hooks it too.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon  # readMonitorDepFile, mergeFragments, MonitorObservationKind
  import macos_backend_toggle  # applyMacosBackendToggle (A/B → debug toggles)

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(args: string) =
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " & args)
    doAssert code == 0, "cc failed (" & args & "): " & output

  type Fixture = object
    work: string
    probe: string
    tmpPath: string
    dstPath: string

  proc buildFixture(): Fixture =
    ## Build a probe replicating the autotools atomic-output idiom:
    ##   fopen(tmp,"w"); write; chmod(tmp, a-w); rename(tmp, dst); then re-create
    ##   the tmp and rename again (a second move) so the destination is rewritten.
    let work = getTempDir() / ("io-mon-rename-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let tmpPath = work / "out.h-t"
    let dstPath = work / "out.h"

    let probeSrc = work / "probe.c"
    writeFile(probeSrc, """
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
static int gen(const char *tmp, const char *dst, const char *content) {
  FILE *f = fopen(tmp, "w");
  if (!f) return 2;
  fputs(content, f);
  fclose(f);
  /* chmod a-w (the gnulib idiom drops the write bit before the move). */
  chmod(tmp, 0444);
  if (rename(tmp, dst) != 0) return 3;
  return 0;
}
int main(int argc, char **argv) {
  if (argc < 3) return 1;
  /* First materialisation, then a second move over the same destination
     (the build re-generates a header) to exercise the move twice. */
  int rc = gen(argv[1], argv[2], "first\n");
  if (rc) return rc;
  /* The destination is now read-only from the moved temp; the build's next
     run removes+rewrites. Make it writable so the test can re-move onto it. */
  chmod(argv[2], 0644);
  return gen(argv[1], argv[2], "second\n");
}
""")
    let probeBin = work / "probe"
    cc(quoteShell(probeSrc) & " -o " & quoteShell(probeBin))
    Fixture(work: work, probe: probeBin, tmpPath: tmpPath, dstPath: dstPath)

  type Capture = object
    destWrite: bool   ## a write/create record whose path is the destination
    completed: bool   ## the destination ends with the moved ("second") content

  proc runCapture(shim: string; fx: Fixture; backend: string): Capture =
    let runWork = fx.work / ("run-" & backend)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)

    let p = startProcess(fx.probe, args = @[fx.tmpPath, fx.dstPath], env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] probe exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "rename probe under shim should exit 0 (backend=" &
      backend & ", out=" & stdoutText & ")"

    # The move must not have been broken: the destination exists with the moved
    # ("second") contents and the temp is gone (rename removes the source).
    if fileExists(fx.dstPath) and not fileExists(fx.tmpPath):
      result.completed = readFile(fx.dstPath).contains("second")

    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    if not fileExists(depfile):
      return
    let dep = readMonitorDepFile(depfile)
    for rec in dep.records:
      if rec.observationKind == moFileWrite and rec.path == fx.dstPath:
        result.destWrite = true

suite "io-mon macOS rename/renameat hooks (atomic-output move, §16.7.8)":
  when defined(macosx):
    let shim = buildShim()
    let fx = buildFixture()

    test "body-patch ('both') records the rename as a dest write AND the move works":
      # The keystone contract: under the body-patch the build-shaped
      # chmod-a-w + mv idiom COMPLETES (the body-patch did not break it) and the
      # destination materialisation IS recorded.
      let cap = runCapture(shim, fx, "both")
      check cap.completed
      check cap.destWrite

    test "interpose backend also records the rename dest write and completes":
      let cap = runCapture(shim, fx, "interpose")
      check cap.completed
      check cap.destWrite

    removeDir(fx.work)
  else:
    test "rename hooks are macOS-only (no-op on this platform)":
      check true
