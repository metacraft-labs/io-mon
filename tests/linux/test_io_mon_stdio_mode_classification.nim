## Linux: a stdio (`fopen`) open must be recorded on every access side its mode
## actually grants, as a RECORD KIND — not encoded in a free-text `detail`.
##
## The Linux shim hooks `fopen`/`fopen64` by symbol (unlike macOS, which
## body-patches `open` and therefore classifies from the real `O_*` flags). Its
## classification used to be a single either/or —
## `if modeLooksReadable(mode): moFileOpen else: moFileWrite` — and
## `modeLooksReadable` answers true for any mode containing `+`. So `"w+"`,
## which CREATES AND TRUNCATES, took the readable arm and produced no write-side
## record at all: the only surviving trace of the write was the string
## `detail="stdio:w+"`.
##
## That is a classification defect with a consumer consequence, not a cosmetic
## one. reprobuild separates an action's inputs from its outputs by record kind;
## `mrFileOpen` sits on the input side. A gcc-produced object file — `as` opens
## it `"w+"` — was therefore recorded as an input, or as nothing, while
## `mcapFileCreate` and `mcapFileTruncate` were advertised Linux capabilities.
##
## Each mode below is exercised by a REAL C program calling the real `fopen`
## under the real shim. The modes are enumerated one at a time (rather than
## inferred from one compiler run) because a single workload only exercises the
## mode it happens to use: a `"w+"`-only workload leaves the plain `"w"` and
## `"a"` paths unverified, and a mutation there survives silently.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc canonical(path: string): string =
  try: expandFilename(path)
  except OSError, IOError: path

suite "io-mon Linux stdio mode classification":
  let work = getTempDir() / ("io-mon-stdio-mode-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)

  let cc = getEnv("CC", "cc")
  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()

  let snoopBin = work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0

  # One program, one mode, one path — so a captured record is unambiguously
  # attributable to the mode under test.
  const appSource = """
#include <stdio.h>
int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], argv[2]);
  if (f == NULL) { perror("fopen"); return 1; }
  fputs("x", f);
  fclose(f);
  return 0;
}
"""
  let app = work / "stdio_app"
  writeFile(work / "stdio_app.c", appSource)
  let built = run(cc, @[work / "stdio_app.c", "-o", app])
  checkpoint(built.output)
  require built.code == 0

  proc kindsFor(mode, tag: string; preCreate: bool):
      tuple[kinds: seq[MonitorRecordKind]; code: int] =
    let target = work / ("target-" & tag & ".bin")
    removeFile(target)
    if preCreate:
      # `"r+"` requires the file to exist; creating it first keeps the case
      # about classification rather than about a failed open.
      writeFile(target, "seed")
    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / ("stdio-" & tag & ".iomon")
    let res = run(snoopBin,
      @["run", "--depfile", depfile, "--", app, target, mode], childEnv)
    checkpoint("mode " & mode & ": " & res.output)
    require res.code == 0
    require fileExists(depfile)
    let dep = readMonitorDepFile(depfile)
    let want = canonical(target)
    result.kinds = dep.records
      .filterIt(it.path.len > 0 and canonical(it.path) == want)
      .mapIt(it.kind)
      .deduplicate
    result.code = res.code

  test "\"w\" (create+truncate) records a write":
    let got = kindsFor("w", "w", preCreate = false)
    checkpoint($got.kinds)
    check mrFileWrite in got.kinds

  test "\"a\" (create+append) records a write":
    let got = kindsFor("a", "a", preCreate = false)
    checkpoint($got.kinds)
    check mrFileWrite in got.kinds

  test "\"w+\" records BOTH a write and an open — this is the regression":
    # The mode gcc's `as` uses for its object file, and the exact case the old
    # either/or classification got wrong: readable (because of the `+`), so the
    # readable arm won and the create+truncate was never recorded as a write.
    let got = kindsFor("w+", "wplus", preCreate = false)
    checkpoint($got.kinds)
    check mrFileWrite in got.kinds
    check mrFileOpen in got.kinds

  test "\"r+\" (update an existing file) records BOTH":
    let got = kindsFor("r+", "rplus", preCreate = true)
    checkpoint($got.kinds)
    check mrFileWrite in got.kinds
    check mrFileOpen in got.kinds

  test "\"r\" (read-only) records an open and NOT a write":
    # The over-correction guard. Without it, "every mode yields a write" would
    # satisfy every assertion above, and the classification would be just as
    # useless in the other direction.
    let got = kindsFor("r", "r", preCreate = true)
    checkpoint($got.kinds)
    check mrFileOpen in got.kinds
    check mrFileWrite notin got.kinds
