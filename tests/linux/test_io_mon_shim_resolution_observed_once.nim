## A process records each resolution observation once, and still records
## every change.
##
## WHY. realpath(3) and the readlink family resolve inside libc, so the
## Linux shim replays each resolution and records every directory and link
## on the way (`test_io_mon_shim_realpath_resolution`). A compiler
## canonicalises every header it considers, so one compile walks the same
## include directories again for each header, and the shim used to build,
## encode and publish the same probe of each of those directories every
## time. Measured on a 300-source C library (reprobuild-pm
## `issues/2026-11-16-a-monitored-c-compile-costs-about-75-percent-more-cpu-mostly-recording-each-path-resolution.md`):
## the shim's recording inside `cc1` grew from 4.8 s to 18.3 s of CPU, most
## of it under `repro_linux_observe_resolution`. Every repeat was the SET
## element the transport already held, so the work recorded nothing.
##
## WHAT THIS TEST GRADES. Monitor-Hook-Shim.md §"Resolution evidence",
## "Each observation once per process":
##
## * `t_a_process_records_each_resolution_observation_once`: one process
##   resolves 40 files under the same directories, one of them reached
##   through a link. Under the FILE transport
##   (`REPRO_MONITOR_DEP_SHM_DISABLE=1`), where every publish is a record of
##   its own, each directory and the link are recorded exactly once, and
##   every file's own resolution is still there. Before the change each was
##   recorded 40 times. The same run under the default SET transport yields
##   the same distinct facts.
## * `t_a_component_changed_between_walks_is_recorded_again`: one process
##   resolves a path, replaces a directory on it by a link to a copy, then
##   removes it, resolving the path after each change. Each answer is
##   recorded: the directory, the link with its target, and the absence.
##   A dedup that remembered the name instead of the observation would keep
##   only the first.
## * `t_a_process_past_the_table_bound_still_records_every_observation`:
##   one process resolves more distinct directories than the dedup table
##   holds, twice. Every directory is recorded at least once, and the second
##   pass records again the ones the table could not hold: the bound falls
##   back to emitting, never to skipping.
## * `t_two_observations_whose_fields_join_alike_are_both_recorded`: a
##   directory whose name holds the unit separator and a link whose target
##   does, chosen so that the two observations' fields read the same when
##   joined with that byte. Both are recorded, in either order: the dedup
##   key must be unambiguous, not merely made of the right fields.
##
## Mocks: none. Real program, real shim, real files and links.

import foreign_preload_isolation

import std/[algorithm, os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  headerCount = 40
  # More than the shim's resolution table (`resolutionCap` in
  # linux_pod_tables.nim, 16384), so the bound is reached.
  manyDirs = 20000

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

const manyHeadersHostSource = """
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

/* What a compiler does with its include path: canonicalise every header,
   each under the same directories. */
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  int count = atoi(argv[2]), ok = 0;
  char path[PATH_MAX], out[PATH_MAX];
  for (int i = 0; i < count; i++) {
    snprintf(path, sizeof path, "%s/inc/sys/h%d.h", argv[1], i);
    if (realpath(path, out)) ok++;
    snprintf(path, sizeof path, "%s/lnk/h%d.h", argv[1], i);
    if (realpath(path, out)) ok++;
  }
  printf("resolved %d\n", ok);
  return 0;
}
"""

const changingHostSource = """
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void resolve(const char *root, const char *label) {
  char path[PATH_MAX], out[PATH_MAX];
  snprintf(path, sizeof path, "%s/p/f", root);
  char *r = realpath(path, out);
  printf("%s -> %s\n", label, r ? r : "(null)");
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  char p[PATH_MAX], moved[PATH_MAX];
  snprintf(p, sizeof p, "%s/p", argv[1]);
  snprintf(moved, sizeof moved, "%s/moved", argv[1]);
  resolve(argv[1], "dir");
  resolve(argv[1], "dir again");
  /* Same names, same bytes, a different answer. */
  if (rename(p, moved) != 0) return 3;
  if (symlink("other", p) != 0) return 4;
  resolve(argv[1], "link");
  if (unlink(p) != 0) return 5;
  resolve(argv[1], "gone");
  return 0;
}
"""

const manyDirsHostSource = """
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc < 3) return 2;
  int count = atoi(argv[2]), ok = 0;
  char path[PATH_MAX], out[PATH_MAX];
  for (int pass = 0; pass < 2; pass++)
    for (int i = 0; i < count; i++) {
      snprintf(path, sizeof path, "%s/d%d/f", argv[1], i);
      if (realpath(path, out)) ok++;
    }
  printf("resolved %d\n", ok);
  return 0;
}
"""

const collidingNamesHostSource = """
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* argv[1]: the tree; argv[2]: "dir-first" or "link-first". */
int main(int argc, char **argv) {
  char dir[PATH_MAX], link[PATH_MAX], out[PATH_MAX];
  snprintf(dir, sizeof dir, "%s/a\x1fsymlink target=x/f", argv[1]);
  snprintf(link, sizeof link, "%s/a/g", argv[1]);
  int dirFirst = strcmp(argv[2], "dir-first") == 0;
  const char *first = dirFirst ? dir : link;
  const char *second = dirFirst ? link : dir;
  printf("first %s\n", realpath(first, out) ? out : "(null)");
  printf("second %s\n", realpath(second, out) ? out : "(null)");
  return 0;
}
"""

type Harness = object
  work, snoopBin: string
  env: StringTableRef

proc setUpHarness(tag: string): Harness =
  result.work = expandFilename(getTempDir()) /
    ("io-mon-" & tag & "-" & $getCurrentProcessId())
  removeDir(result.work)
  createDir(result.work)
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(built.output)
  doAssert built.code == 0
  result.snoopBin = result.work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & result.snoopBin, snoopSrc])
  checkpoint(cli.output)
  doAssert cli.code == 0
  result.env = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result.env[k] = v
  result.env.del("LD_PRELOAD")
  result.env.del("REPRO_MONITOR_DEP_SHM_DISABLE")
  result.env["REPRO_MONITOR_SHIM_LIB"] = findShimLibrary()

proc compileHost(h: Harness; name, source: string): string =
  result = h.work / name
  writeFile(result & ".c", source)
  let cc = run(getEnv("CC", "cc"), @[result & ".c", "-o", result])
  checkpoint(cc.output)
  doAssert cc.code == 0

proc capture(h: Harness; depfile: string; args: seq[string];
             fileTransport: bool): tuple[output: string; dep: MonitorDepFile] =
  let env = newStringTable(modeCaseSensitive)
  for k, v in h.env: env[k] = v
  if fileTransport:
    # Every publish is a record of its own here, so the record count is the
    # number of times the shim published an observation.
    env["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"
  let cap = run(h.snoopBin, @["run", "--depfile", depfile, "--"] & args, env)
  checkpoint(cap.output)
  doAssert cap.code == 0
  (cap.output, readMonitorDepFile(depfile))

proc probes(dep: MonitorDepFile; path: string): seq[MonitorRecord] =
  dep.records.filterIt(it.kind == mrPathProbe and it.path == path)

proc shimDetail(r: MonitorRecord): string =
  ## The shim's detail without the writer's own tokens (run=...).
  let cut = r.detail.find(" run=")
  if cut >= 0: r.detail[0 ..< cut]
  elif r.detail.startsWith("run="): ""
  else: r.detail

proc isLink(r: MonitorRecord; target: string): bool =
  r.shimDetail == "symlink target=" & target

proc isPresentNonLink(r: MonitorRecord): bool =
  r.probeResult != prAbsent and not r.shimDetail.startsWith("symlink")

proc distinctProbes(dep: MonitorDepFile; under: string): seq[string] =
  for r in dep.records:
    if r.kind == mrPathProbe and r.path.startsWith(under):
      let fact = r.path & " " & $r.probeResult & " " & r.shimDetail
      if fact notin result:
        result.add fact

suite "io-mon Linux shim: resolution observations are recorded once":
  test "t_a_process_records_each_resolution_observation_once":
    let h = setUpHarness("resolution-once")
    let host = h.compileHost("many_headers", manyHeadersHostSource)
    let tree = h.work / "tree"
    createDir(tree / "inc" / "sys")
    for i in 0 ..< headerCount:
      writeFile(tree / "inc" / "sys" / ("h" & $i & ".h"), "\n")
    createSymlink("inc/sys", tree / "lnk")

    let file = h.capture(h.work / "file.iomon",
      @[host, tree, $headerCount], fileTransport = true)
    check ("resolved " & $(2 * headerCount)) in file.output
    let dirs = [tree / "inc", tree / "inc" / "sys"]
    for dir in dirs:
      let found = probes(file.dep, dir)
      checkpoint(dir & ": " & $found.len & " records")
      # Once per process: before the change, once per header resolved.
      check found.len == 1
      check found.allIt(it.isPresentNonLink)
    let link = probes(file.dep, tree / "lnk")
    checkpoint("lnk: " & $link.len & " records")
    check link.len == 1
    check link.allIt(it.isLink("inc/sys"))
    # Nothing a resolution depends on is lost: every header the walk through
    # the link ends at is still recorded.
    for i in 0 ..< headerCount:
      check probes(file.dep, tree / "inc" / "sys" / ("h" & $i & ".h")).anyIt(
        it.probeResult != prAbsent)

    # The SET transport folds repeats itself; the shim publishing each once
    # must leave it the same facts.
    let setRun = h.capture(h.work / "set.iomon",
      @[host, tree, $headerCount], fileTransport = false)
    check distinctProbes(setRun.dep, tree).sorted ==
      distinctProbes(file.dep, tree).sorted
    removeDir(h.work)

  test "t_a_component_changed_between_walks_is_recorded_again":
    let h = setUpHarness("resolution-changes")
    let host = h.compileHost("changing", changingHostSource)
    let tree = h.work / "tree"
    createDir(tree / "p")
    createDir(tree / "other")
    writeFile(tree / "p" / "f", "same\n")
    writeFile(tree / "other" / "f", "same\n")

    for fileTransport in [true, false]:
      let cap = h.capture(h.work / ("changes-" & $fileTransport & ".iomon"),
        @[host, tree], fileTransport)
      check ("dir -> " & tree / "p" / "f") in cap.output
      check ("link -> " & tree / "other" / "f") in cap.output
      check "gone -> (null)" in cap.output
      let p = probes(cap.dep, tree / "p")
      for r in p:
        checkpoint("p: " & $r.probeResult & " " & r.detail)
      # The directory, the link that replaced it, and its absence: three
      # answers for one name, each recorded.
      check p.anyIt(it.isPresentNonLink)
      check p.anyIt(it.isLink("other"))
      check p.anyIt(it.probeResult == prAbsent)
      if fileTransport:
        # The repeated walk before the change added nothing.
        check p.countIt(it.isPresentNonLink) == 1
      # Rebuild the tree for the next transport.
      removeDir(tree / "moved")
      createDir(tree / "p")
      writeFile(tree / "p" / "f", "same\n")
    removeDir(h.work)

  test "t_a_process_past_the_table_bound_still_records_every_observation":
    let h = setUpHarness("resolution-bound")
    let host = h.compileHost("many_dirs", manyDirsHostSource)
    let tree = h.work / "tree"
    createDir(tree)
    for i in 0 ..< manyDirs:
      createDir(tree / ("d" & $i))
      writeFile(tree / ("d" & $i) / "f", "")

    let cap = h.capture(h.work / "bound.iomon", @[host, tree, $manyDirs],
      fileTransport = true)
    check ("resolved " & $(2 * manyDirs)) in cap.output
    var counts = newSeq[int](manyDirs)
    let prefix = tree & "/d"
    for r in cap.dep.records:
      if r.kind == mrPathProbe and r.path.startsWith(prefix) and
          '/' notin r.path[prefix.len .. ^1]:
        let i = parseInt(r.path[prefix.len .. ^1])
        if r.isPresentNonLink:
          inc counts[i]
    let missing = toSeq(0 ..< manyDirs).filterIt(counts[it] == 0)
    checkpoint("missing: " & $missing.len & ", recorded twice: " &
      $counts.countIt(it >= 2))
    # Never skipped: every directory is there.
    check missing.len == 0
    # The bound was reached, and past it the repeat was published again.
    check counts.countIt(it >= 2) > 0
    check counts.allIt(it <= 2)
    removeDir(h.work)

  test "t_two_observations_whose_fields_join_alike_are_both_recorded":
    # A name may hold any byte but NUL and `/`, a link target any byte but
    # NUL, so the unit separator can sit inside either. The directory
    # `a<US>symlink target=x` (no detail) and the link `a` -> `x<US>`
    # (detail `symlink target=x<US>`) are two observations whose fields,
    # joined with that separator, read the same. Each must be recorded,
    # whichever the process meets first.
    let h = setUpHarness("resolution-colliding-names")
    let host = h.compileHost("colliding", collidingNamesHostSource)
    let tree = h.work / "tree"
    let oddDir = tree / "a\x1fsymlink target=x"
    createDir(oddDir)
    writeFile(oddDir / "f", "")
    createDir(tree / "x\x1f")
    writeFile(tree / "x\x1f" / "g", "")
    createSymlink("x\x1f", tree / "a")
    for order in ["dir-first", "link-first"]:
      for fileTransport in [true, false]:
        let cap = h.capture(
          h.work / (order & "-" & $fileTransport & ".iomon"),
          @[host, tree, order], fileTransport)
        checkpoint(order & " file=" & $fileTransport & ": " & cap.output)
        check ("/a\x1fsymlink target=x/f") in cap.output
        check (tree / "x\x1f" / "g") in cap.output
        check probes(cap.dep, oddDir).anyIt(it.isPresentNonLink)
        check probes(cap.dep, tree / "a").anyIt(it.isLink("x\x1f"))
    removeDir(h.work)
