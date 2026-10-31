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

import descendant_guard_expectations
import unmonitored_env
import std/[os, osproc, sequtils, sets, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  # Every child belongs to this fixture, never to an inherited monitor.
  var childEnv = if env == nil: unmonitoredEnv() else: env
  childEnv.del("DYLD_INSERT_LIBRARIES")
  let p = startProcess(cmd, args = args, env = childEnv,
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
  # Use the artifact this fixture just built, even if its parent selected a
  # different shim. Discovery intentionally honors the parent's override.
  let shimLib = repoRoot / "build" / "lib" /
    (when defined(macosx): "librepro_monitor_shim.dylib"
     else: "librepro_monitor_shim.so")
  require fileExists(shimLib)

  # Inspect the live loader, not just environment variables: an outer shim
  # reinjects across exec even when the child environment has been scrubbed.
  let probeSource = work / "shim_probe.c"
  let probe = work / "shim-probe"
  writeFile(probeSource, """
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
  int loaded = dlsym(RTLD_DEFAULT, "repro_monitor_shim_init") != NULL;
  printf("shim-loaded=%d\n", loaded);
  return loaded;
}
""")
  var probeArgs = @[probeSource, "-o", probe]
  when defined(linux): probeArgs.add "-ldl"
  let probeBuild = run(cc, probeArgs)
  checkpoint(probeBuild.output)
  require probeBuild.code == 0

  proc monitoredEnv(): StringTableRef =
    result = unmonitoredEnv()
    result["REPRO_MONITOR_SHIM_LIB"] = shimLib

  # Positive control and load-bearing prerequisite for the transparency
  # comparison. A missing isolation policy must fail before accepting a
  # supposedly bare compiler as our independent baseline.
  let bareProbe = run(probe, @[])
  checkpoint("unmonitored prerequisite: " & bareProbe.output)
  require bareProbe.code == 0
  require bareProbe.output.strip == "shim-loaded=0"

  test "the shim-free prerequisite rejects a deliberately monitored process":
    # Negative control: the exact same probe must detect the real shim under
    # a real consumer. Exit 1 is the probe's refusal of an injected baseline.
    let injected = run(snoopBin,
      @["run", "--depfile", work / "probe.iomon", "--", probe], monitoredEnv())
    checkpoint(injected.output)
    check injected.code == 1
    check "shim-loaded=1" in injected.output

  proc compileArgs(objName, depName: string): seq[string] =
    @["-I", work / "include", "-MD", "-MF", work / depName,
      "-c", work / "unit.c", "-o", work / objName]

  test "the monitored compile succeeds and matches the unmonitored one":
    let bare = run(cc, compileArgs("bare.o", "bare.d"))
    checkpoint("unmonitored cc: " & bare.output)
    require bare.code == 0
    require fileExists(work / "bare.o")

    let childEnv = monitoredEnv()

    let depfile = work / "compile.iomon"
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
    check subsystemEvidence(dep).completeness == mcComplete

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
    # Every compiler must expose its output as a write. Read access is a
    # compiler choice: GCC's assembler uses w+, whereas Clang can use a
    # write-only descriptor. The explicit stdio case below pins both sides
    # of w+ independently of which compiler built this translation unit.
    let objPath = canonical(work / "monitored.o")
    check dep.records.anyIt(canonical(it.path) == objPath and
      it.kind == mrFileWrite)

    # (f) The object path also carries a `prAbsent` probe: `as` stats it before
    # creating it. That record is TRUE — the path really was absent when probed
    # — and it is not removed here.
    #
    # It was, however, a hazard, and the reason is (e). A consumer that reads a
    # `prAbsent` probe as a standing anti-dependency ("this must still be
    # absent for the cached result to hold") needs to net it against the
    # action's own outputs, because "absent before I created it" is trivially
    # true of every output. Before (e) there was no write record on this path to
    # net against, so the probe and the creation were indistinguishable from a
    # genuine "this file must not appear" input — and the action could never
    # cache-hit on a rebuild, because its own previous output now exists.
    #
    # This assertion pins the pair, so the netting stays possible. It is the
    # part io-mon owns; which way a consumer nets is its policy, not ours.
    let probes = dep.records.filterIt(canonical(it.path) == objPath and
      it.kind == mrPathProbe)
    if probes.len > 0:
      checkpoint("probe results on the output path: " &
        probes.mapIt($it.probeResult).join(", "))
      check dep.records.anyIt(canonical(it.path) == objPath and
        it.kind == mrFileWrite)

  test "a real stdio update stream is captured as both readable and writable":
    let source = work / "update.c"
    let binary = work / "update"
    let output = work / "update.txt"
    writeFile(source, """
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *f = fopen(argv[1], "w+");
  if (!f) return 3;
  if (fputs("payload", f) < 0 || fflush(f) != 0) return 4;
  rewind(f);
  if (fgetc(f) != 'p') return 5;
  return fclose(f) == 0 ? 0 : 6;
}
""")
    require run(cc, @[source, "-o", binary]).code == 0
    let childEnv = monitoredEnv()
    let depfile = work / "update.iomon"
    require run(snoopBin, @["run", "--depfile", depfile, "--", binary, output],
      childEnv).code == 0
    check readFile(output) == "payload"
    let dep = readMonitorDepFile(depfile)
    let outputPath = canonical(output)
    check dep.records.anyIt(canonical(it.path) == outputPath and it.kind == mrFileWrite)
    check dep.records.anyIt(canonical(it.path) == outputPath and it.kind == mrFileOpen)

  removeDir(work)
