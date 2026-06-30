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

proc buildC(work, name, source: string): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result])
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc pathExists(path: string): bool =
  try:
    discard getFileInfo(path)
    true
  except OSError:
    false

suite "io-mon Linux LD_PRELOAD live gaps":
  let work = getTempDir() / ("io-mon-linux-live-" & $getCurrentProcessId())
  createDir(work)

  test "stdio fopen/fread captures a file dependency and remains complete":
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    check buildShim.code == 0
    let shimLib = findShimLibrary()

    let reader = buildC(work, "stdio_reader", """
#include <stdio.h>
int main(int argc, char **argv) {
  char buf[64];
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 2;
  size_t n = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  return n > 0 ? 0 : 3;
}
""")
    let marker = work / "marker.txt"
    writeFile(marker, "stdio marker\n")
    let depfile = work / "stdio.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check dep.records.anyIt(it.kind == mrFileRead and marker in it.path)

  test "out-of-tree Unix socket daemon downgrades completeness":
    let snoopBin = work / "io-mon"
    if not fileExists(snoopBin):
      discard run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
    discard run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    let shimLib = findShimLibrary()

    let daemon = buildC(work, "daemon", """
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  unlink(argv[1]);
  int srv = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", argv[1]);
  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 2;
  if (listen(srv, 1) != 0) return 3;
  puts("ready");
  fflush(stdout);
  int c = accept(srv, NULL, NULL);
  char cmd;
  read(c, &cmd, 1);
  int fd = open(argv[2], O_RDONLY);
  char buf[64];
  int ok = fd >= 0 && read(fd, buf, sizeof(buf)) > 0;
  if (fd >= 0) close(fd);
  char reply = ok ? 'Y' : 'N';
  write(c, &reply, 1);
  close(c);
  close(srv);
  return ok ? 0 : 4;
}
""")
    let client = buildC(work, "client", """
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", argv[1]);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 2;
  char cmd = 'R';
  write(fd, &cmd, 1);
  char reply;
  int ok = read(fd, &reply, 1) == 1;
  close(fd);
  return ok ? 0 : 3;
}
""")
    let marker = work / "daemon-marker.txt"
    writeFile(marker, "daemon marker\n")
    let socketPath = work / "daemon.sock"

    let daemonProc = startProcess(daemon, args = @[socketPath, marker],
      options = {poStdErrToStdOut})
    try:
      var ready = false
      for _ in 0 ..< 100:
        if pathExists(socketPath):
          ready = true
          break
        sleep(20)
      checkpoint(if ready: "daemon ready" else: "daemon did not create socket")
      check ready

      var childEnv = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): childEnv[k] = v
      childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let depfile = work / "ipc.rdep"
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", client, socketPath],
        childEnv)
      checkpoint(cap.output)
      check cap.code == 0
      check daemonProc.waitForExit() == 0
      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcIncomplete
      check dep.records.anyIt(it.kind == mrIpcConnect)
    finally:
      if daemonProc.running:
        daemonProc.terminate()
      daemonProc.close()

  test "raw libc syscall openat/read fails closed instead of complete depfile":
    let snoopBin = work / "io-mon"
    if not fileExists(snoopBin):
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      check cli.code == 0
    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    check buildShim.code == 0
    let shimLib = findShimLibrary()

    let reader = buildC(work, "raw_syscall_reader", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  int fd = (int)syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY, 0);
  if (fd < 0) return 2;
  long n = syscall(SYS_read, fd, buf, sizeof(buf));
  syscall(SYS_close, fd);
  return n > 0 ? 0 : 3;
}
""")
    let marker = work / "raw-marker.txt"
    writeFile(marker, "raw marker\n")
    let depfile = work / "raw-syscall.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check dep.records.anyIt(it.kind == mrEventLoss and
      "raw syscall" in it.detail)

  test "inline assembly syscall openat/read fails closed instead of complete depfile":
    let snoopBin = work / "io-mon"
    if not fileExists(snoopBin):
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      check cli.code == 0
    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    check buildShim.code == 0
    let shimLib = findShimLibrary()

    let reader = buildC(work, "inline_syscall_reader", """
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
static long raw6(long nr, long a0, long a1, long a2,
                 long a3, long a4, long a5) {
  register long r10 __asm__("r10") = a3;
  register long r8 __asm__("r8") = a4;
  register long r9 __asm__("r9") = a5;
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(nr), "D"(a0), "S"(a1), "d"(a2),
                     "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}
int main(int argc, char **argv) {
  char buf[64];
  int fd = (int)raw6(SYS_openat, AT_FDCWD, (long)argv[1], O_RDONLY, 0, 0, 0);
  if (fd < 0) return 2;
  long n = raw6(SYS_read, fd, (long)buf, sizeof(buf), 0, 0, 0);
  raw6(SYS_close, fd, 0, 0, 0, 0, 0);
  return n > 0 ? 0 : 3;
}
""")
    let marker = work / "inline-raw-marker.txt"
    writeFile(marker, "inline raw marker\n")
    let depfile = work / "inline-raw-syscall.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check dep.records.anyIt(it.kind == mrEventLoss and
      "inline raw syscall" in it.detail)

  test "unrelated SIGTRAP is not swallowed by inline syscall handler":
    let snoopBin = work / "io-mon"
    if not fileExists(snoopBin):
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      check cli.code == 0
    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    check buildShim.code == 0
    let shimLib = findShimLibrary()

    let trapper = buildC(work, "sigtrap_unrelated", """
#include <signal.h>
int main(void) {
  raise(SIGTRAP);
  return 77;
}
""")
    let depfile = work / "sigtrap-unrelated.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", trapper],
      childEnv)
    checkpoint(cap.output)
    check cap.code != 0
    check cap.code != 77

  removeDir(work)
