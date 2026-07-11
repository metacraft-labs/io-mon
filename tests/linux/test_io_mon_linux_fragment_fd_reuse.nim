import std/[os, osproc, streams, strtabs, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let process = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  result.output = process.outputStream.readAll()
  result.code = process.waitForExit()
  process.close()

proc buildC(work, name, source: string): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let built = run(getEnv("CC", "cc"), @[sourcePath, "-o", result])
  checkpoint(built.output)
  check built.code == 0
  check fileExists(result)

suite "io-mon Linux fragment descriptor reuse":
  let work = getTempDir() / ("io-mon-linux-fragment-fd-" &
    $getCurrentProcessId())
  createDir(work)

  test "replacing a fragment descriptor cannot redirect frames to a pipe":
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

    let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(shimBuild.output)
    require shimBuild.code == 0
    let shimLib = findShimLibrary()

    let probe = buildC(work, "fragment_fd_reuse_probe", """
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_one(const char *path) {
  char byte;
  int fd = open(path, O_RDONLY);
  if (fd < 0) return 10;
  int ok = read(fd, &byte, 1) == 1;
  close(fd);
  return ok ? 0 : 11;
}

static int fragment_fd(void) {
  char link_path[64];
  char target[512];
  for (int fd = 3; fd < 256; ++fd) {
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    ssize_t size = readlink(link_path, target, sizeof(target) - 1);
    if (size <= 0) continue;
    target[size] = '\0';
    if (strstr(target, ".rmdf-frag") != NULL) return fd;
  }
  return -1;
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  if (read_one(argv[1]) != 0) return 3;

  int monitor_fd = fragment_fd();
  if (monitor_fd < 0) return 4;
  int channel[2];
  if (pipe(channel) != 0) return 5;
  /* dup2 closes monitor_fd inside the kernel without calling close(). */
  if (dup2(channel[1], monitor_fd) != monitor_fd) return 6;
  if (channel[1] != monitor_fd) close(channel[1]);
  if (fcntl(channel[0], F_SETFL, O_NONBLOCK) != 0) return 7;
  if (read_one(argv[2]) != 0) return 8;

  struct stat st;
  for (int i = 0; i < 2048; ++i) {
    if (stat(argv[2], &st) != 0) return 9;
  }

  char leaked[16];
  ssize_t count = read(channel[0], leaked, sizeof(leaked));
  if (count > 0) return 10;
  if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 11;
  return 0;
}
""")

    let first = work / "first-marker.txt"
    let second = work / "second-marker.txt"
    writeFile(first, "first\n")
    writeFile(second, "second\n")
    let depfile = work / "fragment-fd-reuse.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for key, value in envPairs():
      childEnv[key] = value
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    childEnv["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"
    let captured = run("timeout", @["--foreground", "15s", snoopBin,
      "run", "--depfile", depfile, "--", probe, first, second], childEnv)
    checkpoint(captured.output)
    check captured.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check dep.records.len > 0

  removeDir(work)
