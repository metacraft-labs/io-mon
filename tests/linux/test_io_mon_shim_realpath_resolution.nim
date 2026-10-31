## realpath records the symbolic links its answer depends on.
##
## WHY. realpath(3) and canonicalize_file_name(3) resolve every component
## inside libc, through calls no LD_PRELOAD interposition sees. Their answer
## depends on every symbolic link followed and on where each one points:
## with a -> b -> c, realpath("a") is c, and retargeting b changes the answer
## while a is untouched. Recording only a probe of the path the caller named
## ("a exists") therefore misses inputs: a cached action that resolved a would
## be replayed after b moved. The readlink family has the same blind spot for
## the directories in front of the link it reads.
##
## WHAT THIS TEST GRADES. `t_realpath_records_every_link_it_follows`: under
## `io-mon run`, a host resolves
##   - `a` (a -> b -> c, c a file) with realpath,
##   - `d/f` (d -> realdir, a directory) with canonicalize_file_name,
##   - `dangling` (dangling -> missing) with realpath, which fails, and
##   - `d/flink` (realdir/flink -> f) with readlink,
##   - `d/nolink`, which does not exist, with readlink, and
##   - the RELATIVE path `deep/../f` (deep -> realdir/sub) with realpath, from
##     inside the tree. The kernel resolves that `..` against where `deep`
##     points, so the answer is realdir/f; collapsing `deep/..` lexically
##     would name tree/f, which does not exist, and lose the link.
## The depfile must hold a probe of each link with its target in the detail
## (`symlink target=...`), a probe of the path each walk ends at (c,
## realdir/f, realdir/flink, realdir/nolink), an ABSENT probe of `missing`
## and of `realdir/nolink`, and no probe claiming either exists.
##
## It must also hold a probe of each DIRECTORY walked through on the way
## (realdir, realdir/sub), and readlink's own link with its target
## (realdir/flink -> f).
##
## `t_resolution_evidence_moves_when_the_answer_does` grades the two
## transitions that evidence exists for. A directory on a resolved path
## replaced by a link to another directory holding the same names leaves
## every name reached through it present, yet realpath answers differently;
## a link retargeted at another file leaves the link present, yet readlink
## answers differently. The first capture must already name the directory
## and the link's target, or a consumer has nothing to re-check, and the
## second capture must record what changed.
##
## Mocks: none. Real program, real shim, real symbolic links.

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

const resolveHostSource = """
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  char path[PATH_MAX], out[PATH_MAX];
  snprintf(path, sizeof path, "%s/a", argv[1]);
  char *r = realpath(path, out);
  printf("a -> %s\n", r ? r : "(null)");
  snprintf(path, sizeof path, "%s/d/f", argv[1]);
  char *c = canonicalize_file_name(path);
  printf("d/f -> %s\n", c ? c : "(null)");
  free(c);
  snprintf(path, sizeof path, "%s/dangling", argv[1]);
  r = realpath(path, out);
  printf("dangling -> %s\n", r ? r : "(null)");
  snprintf(path, sizeof path, "%s/d/flink", argv[1]);
  ssize_t n = readlink(path, out, sizeof out - 1);
  if (n >= 0) out[n] = '\0';
  printf("d/flink -> %s\n", n >= 0 ? out : "(error)");
  snprintf(path, sizeof path, "%s/d/nolink", argv[1]);
  n = readlink(path, out, sizeof out - 1);
  printf("d/nolink -> %s\n", n >= 0 ? "(exists)" : "(error)");
  if (chdir(argv[1]) != 0) return 3;
  r = realpath("deep/../f", out);
  printf("deep/.. -> %s\n", r ? r : "(null)");
  return 0;
}
"""

const answerHostSource = """
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  char path[PATH_MAX], out[PATH_MAX];
  snprintf(path, sizeof path, "%s/plain/f", argv[1]);
  char *r = realpath(path, out);
  printf("plain/f -> %s\n", r ? r : "(null)");
  snprintf(path, sizeof path, "%s/lnk", argv[1]);
  ssize_t n = readlink(path, out, sizeof out - 1);
  if (n >= 0) out[n] = '\0';
  printf("lnk -> %s\n", n >= 0 ? out : "(error)");
  return 0;
}
"""

proc probes(dep: MonitorDepFile; path: string): seq[MonitorRecord] =
  dep.records.filterIt(it.kind == mrPathProbe and it.path == path)

proc linkRecorded(dep: MonitorDepFile; path, target: string): bool =
  # The writer appends its own tokens (run=...) after the shim's detail.
  let detail = "symlink target=" & target
  probes(dep, path).anyIt(
    it.detail == detail or it.detail.startsWith(detail & " "))

proc recordedAsNonLink(dep: MonitorDepFile; path: string): bool =
  let found = probes(dep, path)
  found.len > 0 and found.allIt(it.probeResult != prAbsent and
    not it.detail.startsWith("symlink target="))

type Harness = object
  work, snoopBin: string
  env: StringTableRef

proc setUpHarness(tag: string): Harness =
  result.work = expandFilename(getTempDir()) /
    ("io-mon-" & tag & "-" & $getCurrentProcessId())
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
  result.env["REPRO_MONITOR_SHIM_LIB"] = findShimLibrary()

proc compileHost(h: Harness; name, source: string): string =
  result = h.work / name
  writeFile(result & ".c", source)
  let cc = run(getEnv("CC", "cc"), @[result & ".c", "-o", result])
  checkpoint(cc.output)
  doAssert cc.code == 0

proc capture(h: Harness; depfile: string; args: seq[string]):
    tuple[output: string; dep: MonitorDepFile] =
  let cap = run(h.snoopBin, @["run", "--depfile", depfile, "--"] & args,
    h.env)
  checkpoint(cap.output)
  doAssert cap.code == 0
  (cap.output, readMonitorDepFile(depfile))

suite "io-mon Linux shim: path resolution evidence":
  test "t_realpath_records_every_link_it_follows":
    let work = expandFilename(getTempDir()) /
      ("io-mon-realpath-" & $getCurrentProcessId())
    createDir(work)
    let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(built.output)
    check built.code == 0
    let shimLib = findShimLibrary()
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0
    let host = work / "resolve_host"
    writeFile(host & ".c", resolveHostSource)
    let cc = run(getEnv("CC", "cc"), @[host & ".c", "-o", host])
    checkpoint(cc.output)
    check cc.code == 0

    let tree = work / "tree"
    createDir(tree / "realdir" / "sub")
    writeFile(tree / "c", "c\n")
    writeFile(tree / "realdir" / "f", "f\n")
    createSymlink("c", tree / "b")
    createSymlink("b", tree / "a")
    createSymlink("realdir", tree / "d")
    createSymlink("missing", tree / "dangling")
    createSymlink("f", tree / "realdir" / "flink")
    createSymlink("realdir/sub", tree / "deep")

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env.del("LD_PRELOAD")
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / "resolve.iomon"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host, tree],
      env)
    checkpoint(cap.output)
    check cap.code == 0
    check ("a -> " & tree / "c") in cap.output
    check ("d/f -> " & tree / "realdir" / "f") in cap.output
    check ("deep/.. -> " & tree & "/realdir/f") in cap.output
    check "d/nolink -> (error)" in cap.output
    let dep = readMonitorDepFile(depfile)
    for r in dep.records:
      if r.kind == mrPathProbe and r.path.startsWith(tree):
        checkpoint("probe " & r.path & " " & $r.probeResult & " " & r.detail)

    proc linkRecorded(name, target: string): bool =
      # The writer appends its own tokens (run=...) after the shim's detail.
      let detail = "symlink target=" & target
      probes(dep, tree / name).anyIt(
        it.detail == detail or it.detail.startsWith(detail & " "))
    check linkRecorded("a", "b")
    check linkRecorded("b", "c")
    check linkRecorded("d", "realdir")
    check linkRecorded("dangling", "missing")
    check probes(dep, tree / "c").anyIt(it.probeResult != prAbsent)
    check probes(dep, tree / "realdir" / "f").anyIt(
      it.probeResult != prAbsent)
    check probes(dep, tree / "missing").anyIt(it.probeResult == prAbsent)
    # readlink reads the last link itself; the directory link before it is
    # what it resolved.
    check probes(dep, tree / "realdir" / "flink").anyIt(
      it.probeResult != prAbsent)
    # readlink does not examine its last component on the way, so the shim
    # must look it up rather than report it present.
    check probes(dep, tree / "realdir" / "nolink").len > 0
    check probes(dep, tree / "realdir" / "nolink").allIt(
      it.probeResult == prAbsent)
    # The relative walk follows deep before applying `..`.
    check linkRecorded("deep", "realdir/sub")
    check probes(dep, tree / "realdir" / "f").anyIt(
      it.probeResult != prAbsent)
    # The directories walked through are part of the answer too: had either
    # been a link, realpath would have answered differently.
    check dep.recordedAsNonLink(tree / "realdir")
    check dep.recordedAsNonLink(tree / "realdir" / "sub")
    # readlink's answer is the target of the link it reads.
    check dep.linkRecorded(tree / "realdir" / "flink", "f")
    removeDir(work)

  test "t_resolution_evidence_moves_when_the_answer_does":
    let h = setUpHarness("resolution-moves")
    let host = h.compileHost("answer_host", answerHostSource)
    let tree = h.work / "tree"
    createDir(tree / "plain")
    createDir(tree / "other")
    writeFile(tree / "plain" / "f", "same\n")
    writeFile(tree / "other" / "f", "same\n")
    writeFile(tree / "x", "same\n")
    writeFile(tree / "y", "same\n")
    createSymlink("x", tree / "lnk")

    let first = h.capture(h.work / "first.iomon", @[host, tree])
    check ("plain/f -> " & tree / "plain" / "f") in first.output
    check "lnk -> x" in first.output
    # What a consumer re-checks: the directory itself, and the link's target.
    check first.dep.recordedAsNonLink(tree / "plain")
    check first.dep.linkRecorded(tree / "lnk", "x")

    # Same names, same bytes; different answers.
    removeDir(tree / "plain")
    createSymlink("other", tree / "plain")
    removeFile(tree / "lnk")
    createSymlink("y", tree / "lnk")

    let second = h.capture(h.work / "second.iomon", @[host, tree])
    check ("plain/f -> " & tree / "other" / "f") in second.output
    check "lnk -> y" in second.output
    check second.dep.linkRecorded(tree / "plain", "other")
    check not second.dep.recordedAsNonLink(tree / "plain")
    check second.dep.linkRecorded(tree / "lnk", "y")
    check not second.dep.linkRecorded(tree / "lnk", "x")
    removeDir(h.work)
