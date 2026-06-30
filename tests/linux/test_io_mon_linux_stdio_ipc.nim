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

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileRead and path in it.path)

proc hasFileWrite(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileWrite and path in it.path)

proc hasPathProbe(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrPathProbe and path in it.path)

proc hasRecord(dep: MonitorDepFile; kind: MonitorRecordKind; path: string): bool =
  dep.records.anyIt(it.kind == kind and it.path == path)

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

  test "positioned vector and zero-copy libc reads capture source dependency":
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

    let mover = buildC(work, "linux_content_channels", """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <unistd.h>

static ssize_t xsplice(int in, int out) {
  int p[2];
  if (pipe(p) != 0) return -1;
  ssize_t n = splice(in, NULL, p[1], NULL, 4096, 0);
  if (n > 0) {
    ssize_t m = splice(p[0], NULL, out, NULL, (size_t)n, 0);
    if (m < 0) n = -1;
  }
  close(p[0]);
  close(p[1]);
  return n;
}

int main(int argc, char **argv) {
  if (argc != 4) return 2;
  const char *mode = argv[1];
  int in = open(argv[2], O_RDONLY);
  if (in < 0) return 3;
  int out = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) return 4;
  char a[32] = {0};
  char b[32] = {0};
  ssize_t n = -1;
  if (strcmp(mode, "pread") == 0) {
    n = pread(in, a, sizeof(a), 0);
    if (n > 0 && write(out, a, (size_t)n) != n) return 5;
  } else if (strcmp(mode, "readv") == 0) {
    struct iovec iov[2] = {{a, 16}, {b, 16}};
    n = readv(in, iov, 2);
    if (n > 0 && write(out, a, 16) < 0) return 6;
  } else if (strcmp(mode, "preadv") == 0) {
    struct iovec iov[2] = {{a, 16}, {b, 16}};
    n = preadv(in, iov, 2, 0);
    if (n > 0 && write(out, a, 16) < 0) return 7;
  } else if (strcmp(mode, "sendfile") == 0) {
    n = sendfile(out, in, NULL, 4096);
  } else if (strcmp(mode, "copy_file_range") == 0) {
    n = copy_file_range(in, NULL, out, NULL, 4096, 0);
  } else if (strcmp(mode, "splice") == 0) {
    n = xsplice(in, out);
  } else {
    return 8;
  }
  close(out);
  close(in);
  if (n < 0) {
    fprintf(stderr, "%s failed: %s\n", mode, strerror(errno));
    return 9;
  }
  return n > 0 ? 0 : 10;
}
""")
    let source = work / "content-channel-source.txt"
    writeFile(source, "content channel marker bytes for positioned and zero-copy reads\n")

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib

    for mode in ["pread", "readv", "preadv", "sendfile",
                 "copy_file_range", "splice"]:
      let outPath = work / ("content-channel-" & mode & ".out")
      let depfile = work / ("content-channel-" & mode & ".rdep")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", mover,
        mode, source, outPath], childEnv)
      checkpoint(mode & " output: " & cap.output)
      check cap.code == 0
      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcComplete
      check hasFileRead(dep, source)
      check hasFileWrite(dep, outPath)

  test "Linux link and rename mutations preserve source and final-path evidence":
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

    let mutator = buildC(work, "linux_path_mutations", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int read_file(const char *path) {
  char buf[64];
  int fd = open(path, O_RDONLY);
  if (fd < 0) return 20;
  int ok = read(fd, buf, sizeof(buf)) > 0;
  close(fd);
  return ok ? 0 : 21;
}

int main(int argc, char **argv) {
  if (argc != 11) return 2;
  const char *source = argv[1];
  const char *alias = argv[2];
  const char *dir = argv[3];
  const char *alias2_path = argv[4];
  const char *alias2_name = argv[5];
  const char *temp = argv[6];
  const char *final = argv[7];
  const char *final2_path = argv[8];
  const char *final2_name = argv[9];
  const char *missing = argv[10];
  unlink(alias);
  unlink(alias2_path);
  unlink(temp);
  unlink(final);
  unlink(final2_path);
  if (link(source, alias) != 0) return 3;
  int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
  if (dirfd < 0) return 4;
  if (linkat(AT_FDCWD, source, dirfd, alias2_name, 0) != 0) return 5;
  int r = read_file(alias);
  if (r != 0) return r;
  r = read_file(alias2_path);
  if (r != 0) return r;
  int fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) return 6;
  if (write(fd, "renamed\n", 8) != 8) return 7;
  close(fd);
  if (rename(temp, final) != 0) return 8;
  fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) return 9;
  if (write(fd, "renamedat\n", 10) != 10) return 10;
  close(fd);
  if (renameat(AT_FDCWD, temp, dirfd, final2_name) != 0) return 12;
  close(dirfd);
  if (link(missing, "io-mon-failed-link-alias") == 0) return 13;
  if (rename(missing, "io-mon-failed-rename-final") == 0) return 14;
  return 0;
}
""")
    let source = work / "path-mutation-source.txt"
    let alias = work / "path-mutation-alias.txt"
    let alias2 = work / "path-mutation-linkat-alias.txt"
    let alias2Name = "path-mutation-linkat-alias.txt"
    let tempPath = work / "path-mutation.tmp"
    let finalPath = work / "path-mutation.final"
    let final2 = work / "path-mutation-renameat.final"
    let final2Name = "path-mutation-renameat.final"
    let missing = work / "path-mutation-missing.txt"
    writeFile(source, "source identity marker\n")
    let depfile = work / "path-mutation.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", mutator,
      source, alias, work, alias2, alias2Name, tempPath, finalPath, final2,
      final2Name, missing], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasFileRead(dep, source)
    check hasFileRead(dep, alias)
    check hasFileRead(dep, alias2)
    check hasFileWrite(dep, alias)
    check hasFileWrite(dep, alias2)
    check hasFileWrite(dep, finalPath)
    check hasFileWrite(dep, final2)
    check not dep.records.anyIt(it.kind == mrFileWrite and
      "io-mon-failed-link-alias" in it.path)
    check not dep.records.anyIt(it.kind == mrFileWrite and
      "io-mon-failed-rename-final" in it.path)

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

  test "anonymous executable mmap mprotect inline syscall captures dependency":
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

    let jitReader = buildC(work, "jit_mprotect_reader", """
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*jit_read_marker_fn)(const char *);

int main(int argc, char **argv) {
  unsigned char code[] = {
    0x53, 0x41, 0x54, 0x48, 0x83, 0xec, 0x40,
    0x48, 0x89, 0xfe,
    0xb8, 0x01, 0x01, 0x00, 0x00,
    0xbf, 0x9c, 0xff, 0xff, 0xff,
    0x31, 0xd2,
    0x45, 0x31, 0xd2,
    0x0f, 0x05,
    0x48, 0x85, 0xc0,
    0x78, 0x29,
    0x89, 0xc3,
    0x31, 0xc0,
    0x89, 0xdf,
    0x48, 0x89, 0xe6,
    0xba, 0x40, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x49, 0x89, 0xc4,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0x89, 0xdf,
    0x0f, 0x05,
    0x49, 0x83, 0xfc, 0x00,
    0x7f, 0x0e,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0xeb, 0x09,
    0xb8, 0x02, 0x00, 0x00, 0x00,
    0xeb, 0x02,
    0x31, 0xc0,
    0x48, 0x83, 0xc4, 0x40,
    0x41, 0x5c,
    0x5b,
    0xc3
  };
  void *mem = mmap(0, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) return 4;
  memcpy(mem, code, sizeof(code));
  if (mprotect(mem, 4096, PROT_READ | PROT_EXEC) != 0) return 5;
  return ((jit_read_marker_fn)mem)(argv[1]);
}
""")
    let marker = work / "jit-mprotect-marker.txt"
    writeFile(marker, "jit mprotect marker\n")
    let depfile = work / "jit-mprotect-syscall.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", jitReader,
      marker], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasRawDependency(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "inline raw syscall unsupported" in it.detail)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "mprotect-anonymous-exec" in it.detail)

  test "anonymous writable executable mmap fails closed":
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

    let rwxMapper = buildC(work, "rwx_mmap_probe", """
#include <sys/mman.h>
#include <unistd.h>
int main(void) {
  void *mem = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) return 4;
  ((char *)mem)[0] = (char)0xc3;
  return 0;
}
""")
    let depfile = work / "rwx-mmap.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", rwxMapper],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check dep.records.anyIt(it.kind == mrEventLoss and
      "anonymous executable mmap is writable" in it.detail)

  test "anonymous munmap removes stale ownership before address reuse":
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

    let reuseProbe = buildC(work, "jit_munmap_reuse_reader", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef int (*jit_read_marker_fn)(const char *);

int main(int argc, char **argv) {
  unsigned char code[] = {
    0x53, 0x41, 0x54, 0x48, 0x83, 0xec, 0x40,
    0x48, 0x89, 0xfe,
    0xb8, 0x01, 0x01, 0x00, 0x00,
    0xbf, 0x9c, 0xff, 0xff, 0xff,
    0x31, 0xd2,
    0x45, 0x31, 0xd2,
    0x0f, 0x05,
    0x48, 0x85, 0xc0,
    0x78, 0x29,
    0x89, 0xc3,
    0x31, 0xc0,
    0x89, 0xdf,
    0x48, 0x89, 0xe6,
    0xba, 0x40, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x49, 0x89, 0xc4,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0x89, 0xdf,
    0x0f, 0x05,
    0x49, 0x83, 0xfc, 0x00,
    0x7f, 0x0e,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0xeb, 0x09,
    0xb8, 0x02, 0x00, 0x00, 0x00,
    0xeb, 0x02,
    0x31, 0xc0,
    0x48, 0x83, 0xc4, 0x40,
    0x41, 0x5c,
    0x5b,
    0xc3
  };
  void *owned = mmap(0, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (owned == MAP_FAILED) return 4;
  if (munmap(owned, 4096) != 0) return 5;
  void *reused = (void *)syscall(SYS_mmap, owned, 4096,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                 -1, 0);
  if (reused == MAP_FAILED || reused != owned) return 6;
  memcpy(reused, code, sizeof(code));
  if (mprotect(reused, 4096, PROT_READ | PROT_EXEC) != 0) return 7;
  return ((jit_read_marker_fn)reused)(argv[1]);
}
""")
    let marker = work / "jit-munmap-reuse-marker.txt"
    writeFile(marker, "jit munmap reuse marker\n")
    let depfile = work / "jit-munmap-reuse.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reuseProbe,
      marker], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check not hasRawDependency(dep, marker)
    check dep.records.anyIt(it.kind == mrEventLoss and
      "mprotect-anonymous-untracked" in it.detail)

  test "mixed tracked untracked anonymous mprotect fails closed":
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

    let mixedProbe = buildC(work, "jit_mprotect_mixed_reader", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef int (*jit_read_marker_fn)(const char *);

int main(int argc, char **argv) {
  unsigned char code[] = {
    0x53, 0x41, 0x54, 0x48, 0x83, 0xec, 0x40,
    0x48, 0x89, 0xfe,
    0xb8, 0x01, 0x01, 0x00, 0x00,
    0xbf, 0x9c, 0xff, 0xff, 0xff,
    0x31, 0xd2,
    0x45, 0x31, 0xd2,
    0x0f, 0x05,
    0x48, 0x85, 0xc0,
    0x78, 0x29,
    0x89, 0xc3,
    0x31, 0xc0,
    0x89, 0xdf,
    0x48, 0x89, 0xe6,
    0xba, 0x40, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x49, 0x89, 0xc4,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0x89, 0xdf,
    0x0f, 0x05,
    0x49, 0x83, 0xfc, 0x00,
    0x7f, 0x0e,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0xeb, 0x09,
    0xb8, 0x02, 0x00, 0x00, 0x00,
    0xeb, 0x02,
    0x31, 0xc0,
    0x48, 0x83, 0xc4, 0x40,
    0x41, 0x5c,
    0x5b,
    0xc3
  };
  void *reserved = (void *)syscall(SYS_mmap, 0, 8192, PROT_NONE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reserved == MAP_FAILED) return 4;
  void *owned = mmap(reserved, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (owned == MAP_FAILED || owned != reserved) return 5;
  memcpy(owned, code, sizeof(code));
  if (mprotect(reserved, 8192, PROT_READ | PROT_EXEC) != 0) return 6;
  return ((jit_read_marker_fn)owned)(argv[1]);
}
""")
    let marker = work / "jit-mprotect-mixed-marker.txt"
    writeFile(marker, "jit mixed mprotect marker\n")
    let depfile = work / "jit-mprotect-mixed.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", mixedProbe,
      marker], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check dep.records.anyIt(it.kind == mrEventLoss and
      "mprotect-anonymous-untracked" in it.detail)

  test "anonymous mremap preserves ownership before executable scan":
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

    let remapProbe = buildC(work, "jit_mremap_reader", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*jit_read_marker_fn)(const char *);

int main(int argc, char **argv) {
  unsigned char code[] = {
    0x53, 0x41, 0x54, 0x48, 0x83, 0xec, 0x40,
    0x48, 0x89, 0xfe,
    0xb8, 0x01, 0x01, 0x00, 0x00,
    0xbf, 0x9c, 0xff, 0xff, 0xff,
    0x31, 0xd2,
    0x45, 0x31, 0xd2,
    0x0f, 0x05,
    0x48, 0x85, 0xc0,
    0x78, 0x29,
    0x89, 0xc3,
    0x31, 0xc0,
    0x89, 0xdf,
    0x48, 0x89, 0xe6,
    0xba, 0x40, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0x49, 0x89, 0xc4,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0x89, 0xdf,
    0x0f, 0x05,
    0x49, 0x83, 0xfc, 0x00,
    0x7f, 0x0e,
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0xeb, 0x09,
    0xb8, 0x02, 0x00, 0x00, 0x00,
    0xeb, 0x02,
    0x31, 0xc0,
    0x48, 0x83, 0xc4, 0x40,
    0x41, 0x5c,
    0x5b,
    0xc3
  };
  void *mem = mmap(0, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) return 4;
  memcpy(mem, code, sizeof(code));
  void *target = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (target == MAP_FAILED) return 5;
  if (munmap(target, 4096) != 0) return 6;
  void *moved = mremap(mem, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, target);
  if (moved == MAP_FAILED || moved != target) return 7;
  if (mprotect(moved, 4096, PROT_READ | PROT_EXEC) != 0) return 8;
  return ((jit_read_marker_fn)moved)(argv[1]);
}
""")
    let marker = work / "jit-mremap-marker.txt"
    writeFile(marker, "jit mremap marker\n")
    let depfile = work / "jit-mremap.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", remapProbe,
      marker], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasRawDependency(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "mremap-anonymous" in it.detail)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "mprotect-anonymous-untracked" in it.detail)

  test "partial overlap anonymous mremap fails closed":
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

    let partialRemapProbe = buildC(work, "jit_mremap_partial_probe", """
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  void *mem = mmap(0, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) return 4;
  if (munmap(mem, 4096) != 0) return 5;
  void *untracked = (void *)syscall(SYS_mmap, mem, 4096,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                    -1, 0);
  if (untracked == MAP_FAILED || untracked != mem) return 6;
  void *target = mmap(0, 8192, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (target == MAP_FAILED) return 7;
  if (munmap(target, 8192) != 0) return 8;
  void *moved = mremap(mem, 8192, 8192, MREMAP_MAYMOVE | MREMAP_FIXED, target);
  if (moved == MAP_FAILED || moved != target) return 9;
  return 0;
}
""")
    let depfile = work / "jit-mremap-partial.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
      partialRemapProbe], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check dep.records.anyIt(it.kind == mrEventLoss and
      "mremap-anonymous" in it.detail)

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

  test "Linux non-file determinism hooks record observed inputs and entropy":
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

    let probe = buildC(work, "linux_non_file_determinism", """
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

int main(void) {
  const char *v = getenv("IO_MON_ROUND4_ENV_MARKER");
  struct utsname uts;
  struct timespec ts;
  struct timeval tv;
  time_t now;
  unsigned char rnd[8];
  long pagesize = sysconf(_SC_PAGESIZE);
  if (v == NULL || strcmp(v, "present") != 0) return 2;
  if (uname(&uts) != 0) return 3;
  if (pagesize <= 0) return 4;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 5;
  if (gettimeofday(&tv, NULL) != 0) return 6;
  if (time(&now) == (time_t)-1) return 7;
  if (getrandom(rnd, sizeof(rnd), 0) != (ssize_t)sizeof(rnd)) {
    fprintf(stderr, "getrandom failed: %s\n", strerror(errno));
    return 8;
  }
  return rnd[0] == 255 ? 9 : 0;
}
""")
    let depfile = work / "non-file-determinism.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    childEnv["IO_MON_ROUND4_ENV_MARKER"] = "present"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcIncomplete
    check hasRecord(dep, mrEnvRead, "IO_MON_ROUND4_ENV_MARKER")
    check hasRecord(dep, mrSysctlRead, "uname")
    check dep.records.anyIt(it.kind == mrSysctlRead and
      it.path.startsWith("sysconf:"))
    check dep.records.anyIt(it.kind == mrTimeRead and
      it.path.startsWith("clock_gettime:"))
    check hasRecord(dep, mrTimeRead, "gettimeofday")
    check hasRecord(dep, mrTimeRead, "time")
    check hasRecord(dep, mrNonDeterministic, "getrandom")

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
