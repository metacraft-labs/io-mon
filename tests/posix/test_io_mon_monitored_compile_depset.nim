## A monitored compile with the REAL host compiler must (a) succeed exactly as
## the unmonitored compile does, and (b) capture a dependency set that contains
## every input the compiler itself declared.
##
## Why this test exists at all: io-mon's whole value proposition is that a build
## system can cache against the captured set. Until now the suite proved the
## transport loses nothing and that individual syscalls are hooked, but the only
## end-to-end "a real compiler compiled a real translation unit under the shim"
## evidence lived in `tests/realbuild/oracle.nim`, which needs cmake+ninja+cargo
## and is NOT part of `nimble test`. So the single most load-bearing scenario —
## the one every consumer actually runs — was not covered by the default suite.
## This test closes that with nothing but `cc`.
##
## NO MOCKS: real `cc`, real headers, the real shim, the real `io-mon run`
## driver. The ground truth is the compiler's OWN `-MD` depfile — evidence
## produced independently of io-mon by the tool being observed, which is the
## same differential the real-build oracle calls battery B.
##
## SCOPE NOTE: the comparison domain is the compiler's declared source/header
## closure — what `cc -MD` reports. It does NOT include the shared libraries the
## compiler process itself loads, because the compiler does not declare those and
## this test's ground truth is the compiler's own dep data.
##
## Those libraries ARE captured now: `tests/linux/test_io_mon_library_load_closure.nim`
## covers them against `strace -f` ground truth. When this note was first written
## they were not, and `mcapLibraryLoad` was a declared-unsupported Linux
## capability whose gap could not affect completeness — so a capture that had
## observed none of the compiler's ten loaded shared objects still read
## `mcComplete`. Keeping the two domains in separate tests keeps each one's
## ground truth independent of io-mon.

import std/[os, osproc, sequtils, sets, streams, strtabs, strutils, unittest]

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

proc parseMakeDepfile(path: string): seq[string] =
  ## Prerequisites of a `cc -MD` depfile: everything after the first ':',
  ## with line continuations joined and escaped spaces unescaped.
  result = @[]
  if not fileExists(path): return
  var text = readFile(path).replace("\\\n", " ").replace("\\\r\n", " ")
  let colon = text.find(':')
  if colon < 0: return
  text = text[colon + 1 .. ^1]
  var current = ""
  var i = 0
  while i < text.len:
    let c = text[i]
    if c == '\\' and i + 1 < text.len and text[i + 1] == ' ':
      current.add ' '
      inc i, 2
      continue
    if c in {' ', '\t', '\n', '\r'}:
      if current.len > 0:
        result.add current
        current = ""
      inc i
      continue
    current.add c
    inc i
  if current.len > 0: result.add current

proc canonical(path: string): string =
  try: expandFilename(path)
  except OSError, IOError: path

suite "io-mon monitored real-compiler compile":
  let work = getTempDir() / ("io-mon-compile-depset-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  createDir(work / "include")

  # A small but genuinely nested include graph: the transitive header is only
  # reachable through the first one, so a capture that only recorded the
  # translation unit's direct opens would miss it.
  writeFile(work / "include" / "deep.h", "#define DEEP_VALUE 17\n")
  writeFile(work / "include" / "top.h", """
#include "deep.h"
#define TOP_VALUE (DEEP_VALUE + 4)
""")
  writeFile(work / "unit.c", """
#include <stdio.h>
#include "top.h"
int main(void) { printf("%d\n", TOP_VALUE); return 0; }
""")

  let cc = getEnv("CC", "cc")
  let snoopBin = work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0

  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()

  proc compileArgs(objName, depName: string): seq[string] =
    @["-I", work / "include", "-MD", "-MF", work / depName,
      "-c", work / "unit.c", "-o", work / objName]

  test "the monitored compile succeeds and matches the unmonitored one":
    let bare = run(cc, compileArgs("bare.o", "bare.d"))
    checkpoint("unmonitored cc: " & bare.output)
    require bare.code == 0
    require fileExists(work / "bare.o")

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib

    let depfile = work / "compile.rdep"
    let monitored = run(snoopBin,
      @["run", "--depfile", depfile, "--", cc] &
        compileArgs("monitored.o", "monitored.d"),
      childEnv)
    checkpoint("monitored cc: " & monitored.output)

    # (a) The monitor did not perturb the compile.
    check monitored.code == bare.code
    check fileExists(work / "monitored.o")
    check readFile(work / "monitored.o") == readFile(work / "bare.o")

    # (b) The capture is honest and usable.
    require fileExists(depfile)
    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete

    # READ-SIDE records only. Deliberately NOT "any record mentioning the path":
    # a header that io-mon merely `stat`ed (an `mrPathProbe`) is not evidence
    # that its CONTENT was consumed, and a consumer keying a cache on probes
    # alone would be keying on the wrong thing. Restricting the domain here is
    # what makes the assertion below a content-dependency claim.
    let captured = dep.records
      .filterIt(it.path.len > 0 and
                it.kind in {mrFileRead, mrFileOpen, mrLibraryLoad})
      .mapIt(canonical(it.path))
      .toHashSet

    # (c) Every input the COMPILER declared was observed. This is the
    # under-capture gate: a build system caching on this set must not be able to
    # miss a header the compiler itself says it read.
    var declared: seq[string] = @[]
    for prereq in parseMakeDepfile(work / "monitored.d"):
      let abs = canonical(if isAbsolute(prereq): prereq else: work / prereq)
      if fileExists(abs): declared.add abs
    checkpoint("tool-declared inputs: " & $declared.len)
    require declared.len >= 3     # unit.c, top.h, deep.h at minimum

    var missing: seq[string] = @[]
    for input in declared:
      if input notin captured: missing.add input
    check missing.len == 0
    if missing.len > 0:
      checkpoint("NOT captured: " & missing.join(", "))

    # (d) The nested header specifically — named, so a regression that lost
    # transitive includes cannot hide behind a large declared set.
    check canonical(work / "include" / "deep.h") in captured
    # (e) The compile's own product is captured on the WRITE side, as an
    # `mrFileWrite` RECORD KIND — not as free text inside a `detail` string.
    #
    # This is the assertion that pins the classification fix. gcc's `as` opens
    # the object file through stdio with mode `"w+"`. The mode is readable (it
    # has a `+`), and the old classification was a single either/or
    # (`if modeLooksReadable: moFileOpen else: moFileWrite`), so the readable
    # arm won and the file that the action CREATED and TRUNCATED produced no
    # write-side record at all — the write-ness survived only in
    # `detail="stdio:w+"`. A consumer that splits inputs from outputs by record
    # kind (which is the only stable way to do it) classified the gcc-produced
    # object as an input, or as neither.
    #
    # Asserting `mrFileWrite` specifically — rather than "any record mentioning
    # the path", or a `detail`-substring match — is what makes this falsifiable:
    # the path was already present in the capture before the fix, so a weaker
    # predicate passed against the defect.
    let objPath = canonical(work / "monitored.o")
    check dep.records.anyIt(canonical(it.path) == objPath and
      it.kind == mrFileWrite)
    # And it is still visible on the read side too, because `"w+"` really is
    # both — the fix must not have replaced one half-truth with the other.
    check dep.records.anyIt(canonical(it.path) == objPath and
      it.kind == mrFileOpen)
