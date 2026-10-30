## A program built for large files and 64-bit time is observed like any other.
##
## WHY. On ILP32 glibc (32-bit ARM) the `*64` functions are not aliases of
## their plain twins: `stat64`, `readdir64`, `pread64`, `mmap64` take or
## return different structures and offsets. A program built with
## `_FILE_OFFSET_BITS=64` calls those, and one built with `_TIME_BITS=64` --
## all of Debian's armhf userland since trixie: ld, bash, make, gcc's driver
## -- calls `__stat64_time64`, `__lstat64_time64`, `__fstatat64_time64`,
## `__glob64_time64` and `__clock_gettime64` instead. None of those names was
## interposed on ILP32, so the stat probes, directory enumerations and clock
## reads of those programs left no evidence, and `pread64` reached the real
## function with its 64-bit offset passed as a 32-bit one. On LP64 the same
## source compiles to the plain names, which this test then grades the same
## way, so it holds on every architecture the shim is built for.
##
## WHAT THIS TEST GRADES (one program, built with both defines):
##   * `stat`, `lstat` and `fstatat` of an existing and an absent path are
##     recorded as probes with the right outcome;
##   * a `readdir` loop over a directory records its enumeration;
##   * `clock_gettime` records a time read;
##   * `pread` at an offset past 4 GiB in a sparse file returns the bytes
##     written there (the offset reached the kernel intact) and records a read
##     of that file;
##   * the program's own output is what an unmonitored run prints.
##
## Mocks: none. A real program, the real shim, real files.

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

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

# `prober DIR` exercises one call of each family on paths under DIR and
# prints what each returned, so a monitored run can be compared with an
# unmonitored one.
const proberSource = """
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char path[4096];
  struct stat st;
  const char *dir = argv[1];
  snprintf(path, sizeof path, "%s/present.txt", dir);
  printf("stat present=%d\n", stat(path, &st));
  snprintf(path, sizeof path, "%s/absent.txt", dir);
  printf("stat absent=%d\n", stat(path, &st));
  snprintf(path, sizeof path, "%s/link", dir);
  printf("lstat link=%d\n", lstat(path, &st));
  printf("fstatat present=%d\n",
         fstatat(AT_FDCWD, argv[2], &st, 0));
  snprintf(path, sizeof path, "%s/listed", dir);
  DIR *d = opendir(path);
  int entries = 0;
  while (d != NULL && readdir(d) != NULL) entries++;
  if (d != NULL) closedir(d);
  printf("entries=%d\n", entries);
  struct timespec ts;
  printf("clock=%d\n", clock_gettime(CLOCK_REALTIME, &ts));
  snprintf(path, sizeof path, "%s/sparse.bin", dir);
  int fd = open(path, O_RDONLY);
  char buf[8] = {0};
  ssize_t n = pread(fd, buf, 7, (off_t)5 * 1024 * 1024 * 1024);
  printf("pread=%zd %s\n", n, buf);
  close(fd);
  return 0;
}
"""

suite "io-mon Linux shim observes large-file and 64-bit-time programs":
  let work = getTempDir() / ("io-mon-lfs-t64-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let snoopBin = work / "io-mon"
  block:
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    doAssert cli.code == 0, cli.output
  let shimLib = buildPrivateLinuxShim(repoRoot)
  let prober = work / "prober"
  block:
    writeFile(work / "prober.c", proberSource)
    let built = run(getEnv("CC", "cc"), @["-D_FILE_OFFSET_BITS=64",
      "-D_TIME_BITS=64", work / "prober.c", "-o", prober])
    checkpoint("prober cc: " & built.output)
    doAssert built.code == 0, built.output

  let data = work / "data"
  createDir(data / "listed")
  writeFile(data / "present.txt", "x")
  writeFile(data / "listed" / "one", "")
  writeFile(data / "listed" / "two", "")
  createSymlink(data / "present.txt", data / "link")
  # A sparse file whose only data sits past 4 GiB: a pread whose offset lost
  # its high word would read the zeros at offset 1 GiB instead.
  block:
    let f = open(data / "sparse.bin", fmWrite)
    f.setFilePos(5'i64 * 1024 * 1024 * 1024)
    f.write("payload")
    f.close()

  proc probeResults(dep: MonitorDepFile; path: string): seq[ProbeResult] =
    for r in dep.records:
      if r.kind == mrPathProbe and r.path == path:
        result.add r.probeResult

  proc has(dep: MonitorDepFile; kind: MonitorRecordKind; path: string): bool =
    for r in dep.records:
      if r.kind == kind and r.path == path:
        return true

  test "t_large_file_time64_program_is_observed":
    let plain = run(prober, @[data, data / "present.txt"])
    check plain.code == 0
    check plain.output.contains("pread=7 payload")
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / "prober.iomon"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", prober, data,
      data / "present.txt"], env)
    checkpoint("monitored (exit " & $cap.code & "):\n" & cap.output)
    check cap.code == 0
    # The monitored program saw exactly what the unmonitored one saw: in
    # particular pread's 64-bit offset reached the kernel whole.
    check cap.output == plain.output
    let dep = readMonitorDepFile(depfile)
    for r in dep.records:
      if r.path.startsWith(data):
        checkpoint($r.kind & " " & r.path & " probe=" & $r.probeResult & " detail=" & r.detail)
    # A successful probe records that the path exists (not which kind).
    check dep.probeResults(data / "present.txt").len > 0
    check prAbsent notin dep.probeResults(data / "present.txt")
    check prAbsent in dep.probeResults(data / "absent.txt")
    check dep.probeResults(data / "link").len > 0
    check dep.has(mrDirectoryEnumerate, data / "listed")
    check dep.has(mrTimeRead, "clock_gettime:0")
    check dep.has(mrFileRead, data / "sparse.bin")

  removeDir(work)
