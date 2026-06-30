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

proc buildC(work, name, source: string; extraArgs: seq[string] = @[]): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result] & extraArgs)
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc buildSharedC(work, name, source: string): string =
  result = work / ("lib" & name & ".so")
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @["-fPIC", "-shared", sourcePath, "-o", result])
  checkpoint(name & " shared cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc pathExists(path: string): bool =
  try:
    discard getFileInfo(path)
    true
  except OSError:
    false

proc hasRawDependency(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt((it.kind == mrFileOpen or it.kind == mrFileRead) and
    path in it.path)

proc hasPathProbe(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrPathProbe and path in it.path)

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

  test "raw libc syscall openat/read captures dependency":
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
    check dep.completeness == mcComplete
    check hasRawDependency(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "libc raw syscall unsupported" in it.detail)

  test "raw libc syscall openat2/read captures dependency":
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

    let reader = buildC(work, "raw_syscall_openat2_reader", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
int main(int argc, char **argv) {
  char buf[64];
  struct open_how how = {
    .flags = O_RDONLY,
    .mode = 0,
    .resolve = 0,
  };
  int fd = (int)syscall(SYS_openat2, AT_FDCWD, argv[1], &how, sizeof(how));
  if (fd < 0) return 2;
  long n = syscall(SYS_read, fd, buf, sizeof(buf));
  syscall(SYS_close, fd);
  return n > 0 ? 0 : 3;
}
""")
    let marker = work / "raw-openat2-marker.txt"
    writeFile(marker, "raw openat2 marker\n")
    let depfile = work / "raw-openat2.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasRawDependency(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "libc raw syscall unsupported" in it.detail)

  test "inline assembly syscall openat/read captures dependency":
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
    check dep.completeness == mcComplete
    check hasRawDependency(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "inline raw syscall unsupported" in it.detail)

  test "startup shared library inline syscall openat/read captures dependency":
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

    discard buildSharedC(work, "rawdso", """
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
int dso_read_marker(const char *path) {
  char buf[64];
  int fd = (int)raw6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return 2;
  long n = raw6(SYS_read, fd, (long)buf, sizeof(buf), 0, 0, 0);
  raw6(SYS_close, fd, 0, 0, 0, 0, 0);
  return n > 0 ? 0 : 3;
}
""")
    let reader = buildC(work, "inline_dso_reader", """
extern int dso_read_marker(const char *path);
int main(int argc, char **argv) {
  return dso_read_marker(argv[1]);
}
""", @["-L" & work, "-lrawdso", "-Wl,-rpath," & work])
    let marker = work / "inline-dso-marker.txt"
    writeFile(marker, "inline dso marker\n")
    let depfile = work / "inline-dso-syscall.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasRawDependency(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "inline raw syscall unsupported" in it.detail)

  test "late dlopen shared library inline syscall openat/read captures dependency":
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

    let plugin = buildSharedC(work, "rawlate", """
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
int late_read_marker(const char *path) {
  char buf[64];
  int fd = (int)raw6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return 2;
  long n = raw6(SYS_read, fd, (long)buf, sizeof(buf), 0, 0, 0);
  raw6(SYS_close, fd, 0, 0, 0, 0, 0);
  return n > 0 ? 0 : 3;
}
""")
    let loader = buildC(work, "late_dlopen_reader", """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
typedef int (*late_read_marker_fn)(const char *);
int main(int argc, char **argv) {
  void *h = dlopen(argv[1], RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  late_read_marker_fn f = (late_read_marker_fn)dlsym(h, "late_read_marker");
  if (!f) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 3;
  }
  return f(argv[2]);
}
""", @["-ldl"])
    let marker = work / "late-dlopen-marker.txt"
    writeFile(marker, "late dlopen marker\n")
    let depfile = work / "late-dlopen-syscall.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", loader,
      plugin, marker], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasRawDependency(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "inline raw syscall unsupported" in it.detail)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "late inline raw-syscall scanner unavailable" in it.detail)

  test "raw libc statx/access/readlink probes capture path dependencies":
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

    let probe = buildC(work, "raw_syscall_probe", """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_statx
#define SYS_statx 332
#endif
int main(int argc, char **argv) {
  char linkbuf[256];
  struct statx stx;
  long a = syscall(SYS_access, argv[1], R_OK);
  long s = syscall(SYS_statx, AT_FDCWD, argv[1], AT_STATX_SYNC_AS_STAT,
                   STATX_BASIC_STATS, &stx);
  long l = syscall(SYS_readlink, argv[2], linkbuf, sizeof(linkbuf));
  if (a != 0 || l <= 0) return 2;
  if (s != 0 && errno != ENOSYS) return 3;
  return 0;
}
""")
    let marker = work / "raw-probe-marker.txt"
    let linkPath = work / "raw-probe-link.txt"
    writeFile(marker, "raw probe marker\n")
    createSymlink(marker, linkPath)
    let depfile = work / "raw-probe.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe,
      marker, linkPath], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasPathProbe(dep, marker)
    check hasPathProbe(dep, linkPath)

  test "unsupported raw libc syscall still fails closed":
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

    let probe = buildC(work, "raw_unknown_syscall", """
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
  long pid = syscall(SYS_getpid);
  return pid > 0 ? 0 : 2;
}
""")
    let depfile = work / "raw-unknown.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check dep.records.anyIt(it.kind == mrEventLoss and
      "libc raw syscall unsupported" in it.detail)

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
