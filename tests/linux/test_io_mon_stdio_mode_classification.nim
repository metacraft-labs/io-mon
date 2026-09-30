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

proc stdioMode(detail: string): string =
  ## A stdio record's `detail` is `stdio:<mode>` plus the per-run scope token
  ## `mergeFragments` needs (`stdio:w run=1789…-757108-1`). Strip the token.
  let cut = detail.find(" run=")
  if cut < 0: detail else: detail[0 ..< cut]

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

  proc recordsFor(bin, mode, tag: string; preCreate: bool):
      tuple[records: seq[MonitorRecord]; code: int] =
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
      @["run", "--depfile", depfile, "--", bin, target, mode], childEnv)
    checkpoint("mode " & mode & ": " & res.output)
    require res.code == 0
    require fileExists(depfile)
    let dep = readMonitorDepFile(depfile)
    let want = canonical(target)
    result.records = dep.records
      .filterIt(it.path.len > 0 and canonical(it.path) == want)
    result.code = res.code

  proc kindsFor(mode, tag: string; preCreate: bool):
      tuple[kinds: seq[MonitorRecordKind]; code: int] =
    let got = recordsFor(app, mode, tag, preCreate)
    (got.records.mapIt(it.kind).deduplicate, got.code)

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

  # -------------------------------------------------------------------------
  # DA-1d — a `FILE*` is not an observation.
  #
  # `recordFopen` used to store `cast[int64](stream)` in `record.result`: the raw
  # stdio handle, a per-process HEAP ADDRESS, in a field that is part of the
  # dependency identity. On `mrFileOpen` (path-scoped) the set encoder happened
  # to reduce `result` to success/failure and the address never reached the key —
  # laundered by an arm written for descriptor numbers. On `mrFileWrite`
  # (process-scoped) nothing normalised it, so the address travelled into the
  # depfile: an ASLR-dependent value in a file that is supposed to be
  # reproducible, and one element per `fopen` call instead of one per fact.
  # -------------------------------------------------------------------------

  test "a stdio record carries a success code, NOT the FILE* address":
    for (mode, tag, preCreate) in [("w", "ptr-w", false), ("r", "ptr-r", true),
                                   ("w+", "ptr-wplus", false)]:
      let got = recordsFor(app, mode, tag, preCreate)
      var stdioRecords = 0
      for r in got.records:
        if r.detail.startsWith("stdio:"):
          inc stdioRecords
          checkpoint("mode " & mode & " kind " & $r.kind &
            " result=" & $r.result)
          # A `FILE*` on x86-64 Linux is a heap address: large and positive. A
          # success code is 0. Anything else here is a pointer that escaped.
          check r.result == 0
      check stdioRecords > 0
    echo "DA-1d: stdio records across 3 modes carry result=0 (no FILE*)"

  test "two fopens of one path publish ONE stdio write, not one per handle":
    # Two handles held open SIMULTANEOUSLY, so glibc cannot hand back the same
    # `FILE*` twice. Before DA-1d the two records differed only in that address
    # and reached the depfile as two elements — deduping nothing while looking as
    # if it had. They are the same fact and must arrive once.
    const twiceSource = """
#include <stdio.h>
int main(int argc, char **argv) {
  FILE *a = fopen(argv[1], argv[2]);
  FILE *b = fopen(argv[1], argv[2]);
  if (a == NULL || b == NULL) { perror("fopen"); return 1; }
  if (a == b) { fprintf(stderr, "same FILE* twice\n"); return 2; }
  fclose(a);
  fclose(b);
  return 0;
}
"""
    let twiceApp = work / "stdio_twice"
    writeFile(work / "stdio_twice.c", twiceSource)
    let builtTwice = run(cc, @[work / "stdio_twice.c", "-o", twiceApp])
    checkpoint(builtTwice.output)
    require builtTwice.code == 0

    let got = recordsFor(twiceApp, "w", "twice", preCreate = false)
    # `detail` carries the per-run scope token (`stdio:w run=<id>`), so match the
    # mode prefix rather than the whole string — an equality test here found
    # ZERO records in both arms and would have reddened for the wrong reason.
    let stdioWrites = got.records.filterIt(
      it.kind == mrFileWrite and stdioMode(it.detail) == "stdio:w")
    checkpoint($stdioWrites)
    echo "DA-1d: two simultaneous fopen(\"w\") handles -> ",
      stdioWrites.len, " stdio write record(s)"
    # POSITIVE CONTROL for the filter: the write side is recorded at all, so a
    # `0` here is a broken filter and not a passing dedup.
    check got.records.anyIt(it.kind == mrFileWrite)
    check stdioWrites.len == 1
