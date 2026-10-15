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

proc probes(dep: MonitorDepFile; path: string): seq[MonitorRecord] =
  dep.records.filterIt(it.kind == mrPathProbe and it.path == path)

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
    removeDir(work)
