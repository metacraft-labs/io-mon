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
  dep.records.anyIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

proc hasFileWrite(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileWrite and
    it.observationKind == moFileWrite and path in it.path)

proc hasPathProbe(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrPathProbe and path in it.path)

proc hasRecord(dep: MonitorDepFile; kind: MonitorRecordKind; path: string): bool =
  dep.records.anyIt(it.kind == kind and it.path == path)

proc waitForPath(path: string; timeoutMs = 2000): bool =
  var waited = 0
  while waited <= timeoutMs:
    if fileExists(path):
      return true
    sleep(20)
    waited += 20
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

  test "relative writes follow a process chdir":
    let snoopBin = work / "io-mon"
    if not fileExists(snoopBin):
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      require cli.code == 0

    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    require buildShim.code == 0
    let shimLib = findShimLibrary()

    let writer = buildC(work, "chdir_relative_writer", """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (chdir(argv[1]) != 0) return 2;
  int fd = open("src/result.o", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return 3;
  if (write(fd, "ok", 2) != 2) return 4;
  return close(fd) == 0 ? 0 : 5;
}
""")
    let buildDir = work / "chdir-build"
    createDir(buildDir)
    createDir(buildDir / "src")
    let expected = buildDir / "src" / "result.o"
    let depfile = work / "chdir-relative.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin,
      @["run", "--depfile", depfile, "--", writer, buildDir], childEnv)
    checkpoint(cap.output)
    require cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasRecord(dep, mrFileWrite, expected)
    check not dep.records.anyIt(it.kind == mrFileWrite and
      it.path.endsWith("src/result.o") and it.path != expected)

  test "O_TMPFILE creation preserves its variadic mode":
    let snoopBin = work / "io-mon"
    if not fileExists(snoopBin):
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      require cli.code == 0

    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    require buildShim.code == 0
    let shimLib = findShimLibrary()

    let writer = buildC(work, "otmpfile_mode_writer", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
  mode_t old_umask = umask(0022);
  int fd = open(argv[1], O_RDWR | O_TMPFILE, 0666);
  umask(old_umask);
  if (fd < 0) return 2;
  if (write(fd, "ok", 2) != 2) return 3;
  if (linkat(fd, "", AT_FDCWD, argv[2], AT_EMPTY_PATH) != 0) return 4;
  if (close(fd) != 0) return 5;
  struct stat st;
  if (stat(argv[2], &st) != 0) return 6;
  return (st.st_mode & 0777) == 0644 ? 0 : 7;
}
""")
    let output = work / "otmpfile-mode-output"
    let depfile = work / "otmpfile-mode.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin,
      @["run", "--depfile", depfile, "--", writer, work, output], childEnv)
    checkpoint(cap.output)
    require cap.code == 0

    let permissions = getFilePermissions(output)
    check fpUserRead in permissions
    check fpUserWrite in permissions
    check fpGroupRead in permissions
    check fpOthersRead in permissions

  test "repeated reads emit one dependency record per descriptor":
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

    let reader = buildC(work, "byte_reader", """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char byte;
  long total = 0;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  while (read(fd, &byte, 1) > 0) ++total;
  close(fd);
  return total == 4096 ? 0 : 3;
}
""")
    let marker = work / "byte-reader-marker.txt"
    writeFile(marker, repeat("x", 4096))
    let depfile = work / "byte-reader.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check dep.records.countIt(it.kind == mrFileRead and marker in it.path) == 1

  test "read batch is flushed when a process exits through _exit":
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

    let reader = buildC(work, "direct_exit_reader", """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) _exit(2);
  ssize_t n = read(fd, buf, sizeof(buf));
  _exit(n > 0 ? 0 : 3);
}
""")
    let marker = work / "direct-exit-marker.txt"
    writeFile(marker, "direct exit marker\n")
    let depfile = work / "direct-exit.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasFileRead(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "kill-before-flush" in it.detail)

  test "read batch is flushed before a process execs a new image":
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

    let reader = buildC(work, "read_then_exec", """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  if (n <= 0) return 3;
  execl(argv[2], "true", (char *)0);
  _exit(4);
}
""")
    let trueBin = findExe("true")
    check trueBin.len > 0
    let marker = work / "read-then-exec-marker.txt"
    writeFile(marker, "read then exec marker\n")
    let depfile = work / "read-then-exec.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
      reader, marker, trueBin], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasFileRead(dep, marker)
    check dep.records.anyIt(it.kind == mrProcessExec and it.path == trueBin)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "kill-before-flush" in it.detail)

  test "daemonized injected descendant after root exit is waited or fails closed":
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

    # The injected descendant is a double-forked, setsid'd daemon that is
    # re-parented to init and outlives the monitored root. Two modes, selected
    # by argv[5] (the release-sentinel path):
    #
    #   "-"  legacy quiesce mode: the root exits immediately; the daemon sleeps
    #        argv[3] ms, reads the marker, writes the proof, sleeps argv[4] ms
    #        and exits. Used by the "quiesces inside grace" block, whose
    #        expected result (mcComplete + captured read) is also what a
    #        premature quiescence produces, so it is inherently timing-robust.
    #
    #   path gated "live past grace" mode: the daemon reads the marker, writes
    #        the proof, then SIGNALS the root (via an inherited pipe) that it is
    #        alive, visible in /proc, and past its I/O — only THEN does the root
    #        exit. The daemon subsequently blocks until <path> appears, so it is
    #        GUARANTEED to still be live throughout the monitor's entire grace
    #        window regardless of host load. This removes the historic
    #        /proc-quiescence race: previously the daemon slept a fixed 200 ms
    #        and, under load, a single /proc scan (which reads every process's
    #        environ) could take longer than both the grace window and the
    #        daemon's lifetime, so the first completed scan saw zero live
    #        descendants and the wait declared premature quiescence — flipping
    #        the expected mcIncomplete("still live") to mcComplete. The harness
    #        drops the release file only after `run` returns, then the daemon
    #        exits and is reaped by init.
    let daemonProbe = buildC(work, "daemon_late_reader", """
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void msleep_arg(const char *s) {
  long ms = strtol(s, NULL, 10);
  if (ms > 0) usleep((useconds_t)ms * 1000);
}

int main(int argc, char **argv) {
  if (argc != 6) return 2;
  const char *release = argv[5];
  int gated = strcmp(release, "-") != 0;

  int rp[2];
  if (pipe(rp) != 0) return 8;

  pid_t pid = fork();
  if (pid < 0) return 3;
  if (pid > 0) {
    close(rp[1]);
    char b;
    if (gated) {
      /* Do not exit until the daemon has read the marker, written the proof
         and signalled (one byte) that it is alive and visible in /proc. */
      while (read(rp[0], &b, 1) < 0) { /* retry on EINTR */ }
    } else {
      /* Do not exit until the daemon has fully EXITED (pipe EOF): the
         descendant has already quiesced and flushed before the monitor's
         grace wait begins, so a slow /proc scan under load can no longer race
         the descendant's lifetime and misreport quiescence. */
      while (read(rp[0], &b, 1) > 0) { /* drain until EOF */ }
    }
    close(rp[0]);
    return 0;
  }
  close(rp[0]);
  if (setsid() < 0) _exit(4);
  pid = fork();
  if (pid < 0) _exit(5);
  if (pid > 0) _exit(0);

  if (gated) {
    /* Full daemonization: drop EVERY inherited descriptor except the readiness
       pipe. The monitor launches the tree with parent streams and the shim
       dups the harness's captured stdout pipe (and its own channels) onto high
       fds that we inherit; a daemon that BLOCKS (gated mode) must keep none of
       them, or the harness's readAll() never reaches EOF and `run` hangs.
       Closing them all lets EOF arrive as soon as the short-lived root exits,
       so `run` returns and the harness can drop the release sentinel. (In the
       non-gated quiesce mode the daemon exits promptly, so it simply lets exit
       close its inherited fds — no special handling needed.) */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) maxfd = 4096;
    for (int fd = 0; fd < maxfd; fd++) {
      if (fd != rp[1]) close(fd);
    }
    int dn = open("/dev/null", O_RDWR);
    if (dn == 0) { dup2(dn, 1); dup2(dn, 2); }
  }

  msleep_arg(argv[3]);
  int in = open(argv[1], O_RDONLY);
  if (in < 0) _exit(6);
  char buf[64];
  ssize_t n = read(in, buf, sizeof(buf));
  close(in);
  int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out >= 0) {
    if (n > 0) { if (write(out, "read\n", 5) < 0) {} }
    else { if (write(out, "empty\n", 6) < 0) {} }
    close(out);
  }
  if (gated) {
    char rb = 1;
    if (write(rp[1], &rb, 1) < 0) {}
    close(rp[1]);
    struct stat st;
    while (stat(release, &st) != 0) usleep(2000);
    _exit(n > 0 ? 0 : 7);
  }
  /* Quiesce mode: exit promptly. _exit closes our inherited copy of the
     readiness pipe, which is the root's EOF signal that we have fully gone. */
  msleep_arg(argv[4]);
  _exit(n > 0 ? 0 : 7);
}
""")
    let marker = work / "daemon-late-marker.txt"
    writeFile(marker, "daemon late marker\n")

    block quiescesInsideGrace:
      let depfile = work / "daemon-quiesce.rdep"
      let proof = work / "daemon-quiesce.proof"
      try: removeFile(proof)
      except OSError: discard
      var childEnv = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): childEnv[k] = v
      childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
      childEnv["IO_MON_LINUX_DESCENDANT_GRACE_MS"] = "1000"
      childEnv["IO_MON_LINUX_DESCENDANT_POLL_MS"] = "10"
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
        daemonProbe, marker, proof, "20", "0", "-"], childEnv)
      checkpoint("daemon quiesce output: " & cap.output)
      check cap.code == 0
      check waitForPath(proof)
      check readFile(proof) == "read\n"

      let dep = readMonitorDepFile(depfile)
      check hasFileRead(dep, marker)
      check dep.completeness == mcComplete
      check not dep.records.anyIt(it.kind == mrEventLoss and
        "linux injected descendants still live" in it.detail)

    block livePastGrace:
      let depfile = work / "daemon-live-past-grace.rdep"
      let proof = work / "daemon-live-past-grace.proof"
      # Gated mode: the daemon blocks on this sentinel until we drop it, so it
      # is deterministically still alive across the whole grace window. We
      # remove any stale copy first so the daemon really does block, then drop
      # it the moment `run` returns (before the assertions, so the daemon is
      # released — and reaped by init — even if an assertion below fails).
      let release = work / "daemon-live-past-grace.release"
      try: removeFile(proof)
      except OSError: discard
      try: removeFile(release)
      except OSError: discard
      var childEnv = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): childEnv[k] = v
      childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
      childEnv["IO_MON_LINUX_DESCENDANT_GRACE_MS"] = "100"
      childEnv["IO_MON_LINUX_DESCENDANT_POLL_MS"] = "10"
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
        daemonProbe, marker, proof, "0", "0", release], childEnv)
      writeFile(release, "release\n")
      checkpoint("daemon live output: " & cap.output)
      check cap.code == 0
      check waitForPath(proof)
      check readFile(proof) == "read\n"

      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcIncomplete
      check dep.records.anyIt(it.kind == mrEventLoss and
        ("linux injected descendants still live" in it.detail or
         "linux injected-descendant /proc scan failed" in it.detail))

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

  test "inherited fd 3 regular file resolves through proc fd path":
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

    let reader = buildC(work, "inherited_fd3_reader", """
#include <unistd.h>
int main(void) {
  char buf[128];
  ssize_t n = read(3, buf, sizeof(buf));
  return n > 0 ? 0 : 2;
}
""")
    let launcher = buildC(work, "inherited_file_launcher", """
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 4) return 2;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 3;
  if (fd != 3) {
    if (dup2(fd, 3) != 3) return 4;
    close(fd);
  }
  execv(argv[2], &argv[2]);
  perror("execv");
  return 127;
}
""")
    let marker = work / "inherited-fd3-marker.txt"
    writeFile(marker, "inherited fd marker\n")
    let depfile = work / "inherited-fd3-file.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(launcher, @[marker, snoopBin, "run", "--depfile", depfile,
      "--", reader], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasFileRead(dep, marker)
    check not dep.records.anyIt(it.kind == mrFileRead and it.path.len == 0)
    check dep.records.anyIt(it.kind == mrFileRead and marker in it.path and
      detailToken(it.detail, "run").len > 0)

  test "inherited fd 3 deleted regular file does not become stable proc fd path":
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

    let reader = buildC(work, "inherited_fd3_deleted_reader", """
#include <unistd.h>
int main(void) {
  char buf[128];
  ssize_t n = read(3, buf, sizeof(buf));
  return n > 0 ? 0 : 2;
}
""")
    let launcher = buildC(work, "inherited_fd3_deleted_launcher", """
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 4) return 2;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 3;
  if (fd != 3) {
    if (dup2(fd, 3) != 3) return 4;
    close(fd);
  }
  if (unlink(argv[1]) != 0) return 5;
  execv(argv[2], &argv[2]);
  perror("execv");
  return 127;
}
""")
    let marker = work / "inherited-fd3-deleted-marker.txt"
    writeFile(marker, "deleted inherited fd marker\n")
    let depfile = work / "inherited-fd3-deleted-file.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(launcher, @[marker, snoopBin, "run", "--depfile", depfile,
      "--", reader], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    let deletedFileReads = dep.records.filterIt(it.kind == mrFileRead and
      it.path.endsWith(" (deleted)"))
    check deletedFileReads.len == 0
    check dep.completeness == mcIncomplete or
      dep.records.anyIt(it.kind == mrExternalContent)
    if dep.completeness == mcIncomplete:
      check dep.records.anyIt(it.kind == mrEventLoss and
        "linux inherited regular fd read unnamed key=" in it.detail)

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

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif

static int read_file(const char *path) {
  char buf[64];
  int fd = open(path, O_RDONLY);
  if (fd < 0) return 20;
  int ok = read(fd, buf, sizeof(buf)) > 0;
  close(fd);
  return ok ? 0 : 21;
}

int main(int argc, char **argv) {
  if (argc != 13) return 2;
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
  const char *exchange_left = argv[11];
  const char *exchange_right = argv[12];
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
  if (renameat2(AT_FDCWD, exchange_left, AT_FDCWD, exchange_right,
                RENAME_EXCHANGE) != 0) return 15;
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
    let exchangeLeft = work / "path-mutation-exchange-left.txt"
    let exchangeRight = work / "path-mutation-exchange-right.txt"
    writeFile(source, "source identity marker\n")
    writeFile(exchangeLeft, "exchange left marker\n")
    writeFile(exchangeRight, "exchange right marker\n")
    let depfile = work / "path-mutation.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", mutator,
      source, alias, work, alias2, alias2Name, tempPath, finalPath, final2,
      final2Name, missing, exchangeLeft, exchangeRight], childEnv)
    checkpoint(cap.output)
    check cap.code == 0
    check readFile(exchangeLeft) == "exchange right marker\n"
    check readFile(exchangeRight) == "exchange left marker\n"

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check hasFileRead(dep, source)
    check hasFileRead(dep, alias)
    check hasFileRead(dep, alias2)
    check hasFileWrite(dep, alias)
    check hasFileWrite(dep, alias2)
    check hasFileWrite(dep, finalPath)
    check hasFileWrite(dep, final2)
    check hasFileWrite(dep, exchangeLeft)
    check hasFileWrite(dep, exchangeRight)
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

  test "raw libc zero-copy syscalls capture source and destination evidence":
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

    let mover = buildC(work, "raw_zero_copy_syscalls", """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_copy_file_range
#define SYS_copy_file_range 326
#endif
#ifndef SYS_splice
#define SYS_splice 275
#endif
static long xsplice(int in, int out) {
  int p[2];
  if (pipe(p) != 0) return -1;
  long n = syscall(SYS_splice, in, 0, p[1], 0, 4096, 0);
  if (n > 0) {
    long m = syscall(SYS_splice, p[0], 0, out, 0, (size_t)n, 0);
    if (m < 0) n = -1;
  }
  close(p[0]);
  close(p[1]);
  return n;
}
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  int in = (int)syscall(SYS_openat, AT_FDCWD, argv[2], O_RDONLY, 0);
  if (in < 0) return 3;
  int out = (int)syscall(SYS_openat, AT_FDCWD, argv[3],
                         O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) return 4;
  long n = -1;
  if (strcmp(argv[1], "sendfile") == 0) {
    n = syscall(SYS_sendfile, out, in, 0, 4096);
  } else if (strcmp(argv[1], "copy_file_range") == 0) {
    n = syscall(SYS_copy_file_range, in, 0, out, 0, 4096, 0);
  } else if (strcmp(argv[1], "splice") == 0) {
    n = xsplice(in, out);
  } else {
    return 5;
  }
  syscall(SYS_close, out);
  syscall(SYS_close, in);
  if (n < 0) {
    fprintf(stderr, "%s failed: %s\n", argv[1], strerror(errno));
    return 6;
  }
  return n > 0 ? 0 : 7;
}
""")
    let marker = work / "raw-zero-copy-marker.txt"
    writeFile(marker, "raw zero copy marker\n")

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib

    for mode in ["sendfile", "copy_file_range", "splice"]:
      let outPath = work / ("raw-zero-copy-" & mode & ".out")
      let depfile = work / ("raw-zero-copy-" & mode & ".rdep")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", mover,
        mode, marker, outPath], childEnv)
      checkpoint(mode & ": " & cap.output)
      check cap.code == 0

      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcComplete
      check hasFileRead(dep, marker)
      check hasFileWrite(dep, outPath)
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

  test "late dlopen and base dlmopen capture plugin libc reads; new namespace fails closed":
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

    let plugin = buildSharedC(work, "late", """
#include <stdio.h>
int late_read_marker(const char *path) {
  char buf[64];
  FILE *f = fopen(path, "rb");
  if (!f) return 2;
  size_t n = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  return n > 0 ? 0 : 3;
}
""")
    let loader = buildC(work, "late_dlopen_reader", """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
typedef int (*late_read_marker_fn)(const char *);
int main(int argc, char **argv) {
  void *h = NULL;
  if (argc != 4) return 9;
  if (strcmp(argv[1], "dlopen") == 0) {
    h = dlopen(argv[2], RTLD_NOW);
  } else if (strcmp(argv[1], "dlmopen-base") == 0) {
    h = dlmopen(LM_ID_BASE, argv[2], RTLD_NOW);
  } else if (strcmp(argv[1], "dlmopen-newlm") == 0) {
    h = dlmopen(LM_ID_NEWLM, argv[2], RTLD_NOW);
  } else {
    return 8;
  }
  if (!h) {
    fprintf(stderr, "load: %s\n", dlerror());
    return 2;
  }
  late_read_marker_fn f = (late_read_marker_fn)dlsym(h, "late_read_marker");
  if (!f) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 3;
  }
  return f(argv[3]);
}
""", @["-ldl"])
    let marker = work / "late-load-marker.txt"
    writeFile(marker, "late load marker\n")

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib

    for mode in ["dlopen", "dlmopen-base"]:
      let depfile = work / ("late-load-" & mode & ".rdep")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", loader,
        mode, plugin, marker], childEnv)
      checkpoint(mode & ": " & cap.output)
      check cap.code == 0

      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcComplete
      check hasRawDependency(dep, marker)
      check not dep.records.anyIt(it.kind == mrEventLoss and
        "linux dlmopen non-base namespace unmonitored" in it.detail)
      check not dep.records.anyIt(it.kind == mrEventLoss and
        "late inline raw-syscall scanner unavailable" in it.detail)

    let newlmDepfile = work / "late-load-dlmopen-newlm.rdep"
    let newlm = run(snoopBin, @["run", "--depfile", newlmDepfile, "--",
      loader, "dlmopen-newlm", plugin, marker], childEnv)
    checkpoint("dlmopen-newlm: " & newlm.output)
    check newlm.code == 0

    let newlmDep = readMonitorDepFile(newlmDepfile)
    check newlmDep.completeness == mcIncomplete
    check newlmDep.records.anyIt(it.kind == mrEventLoss and
      "linux dlmopen non-base namespace unmonitored" in it.detail)

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
    check dep.completeness == mcComplete
    check hasRecord(dep, mrEnvRead, "IO_MON_ROUND4_ENV_MARKER")
    check hasRecord(dep, mrSysctlRead, "uname")
    check dep.records.anyIt(it.kind == mrSysctlRead and
      it.path.startsWith("sysconf:"))
    check dep.records.anyIt(it.kind == mrTimeRead and
      it.path.startsWith("clock_gettime:"))
    check hasRecord(dep, mrTimeRead, "gettimeofday")
    check hasRecord(dep, mrTimeRead, "time")
    check hasRecord(dep, mrNonDeterministic, "getrandom")

  test "direct linux vDSO dlsym calls record determinism evidence or fail closed":
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

    let probe = buildC(work, "linux_direct_vdso_dlsym", """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

typedef int (*vdso_clock_gettime_fn)(clockid_t, struct timespec *);
typedef int (*vdso_gettimeofday_fn)(struct timeval *, struct timezone *);
typedef time_t (*vdso_time_fn)(time_t *);
typedef int (*vdso_clock_getres_fn)(clockid_t, struct timespec *);
typedef int (*vdso_getcpu_fn)(unsigned *, unsigned *, void *);
typedef ssize_t (*vdso_getrandom_fn)(void *, size_t, unsigned int, void *, size_t);

static int note(const char *name) {
  printf("called %s\n", name);
  return 1;
}

int main(void) {
  void *h = dlopen("linux-vdso.so.1", RTLD_LAZY | RTLD_LOCAL);
  if (h == NULL) {
    fprintf(stderr, "dlopen linux-vdso.so.1 failed: %s\n", dlerror());
    return 2;
  }
  int called = 0;
  void *sym;
  struct timespec ts;
  struct timeval tv;
  time_t now = 0;

  sym = dlsym(h, "__vdso_clock_gettime");
  if (sym != NULL) {
    if (((vdso_clock_gettime_fn)sym)(CLOCK_REALTIME, &ts) != 0) return 3;
    called += note("__vdso_clock_gettime");
  }

  sym = dlsym(h, "__vdso_gettimeofday");
  if (sym != NULL) {
    if (((vdso_gettimeofday_fn)sym)(&tv, NULL) != 0) return 4;
    called += note("__vdso_gettimeofday");
  }

  sym = dlsym(h, "__vdso_time");
  if (sym != NULL) {
    if (((vdso_time_fn)sym)(&now) == (time_t)-1) return 5;
    called += note("__vdso_time");
  }

  sym = dlsym(h, "__vdso_clock_getres");
  if (sym != NULL) {
    if (((vdso_clock_getres_fn)sym)(CLOCK_REALTIME, &ts) != 0) return 6;
    called += note("__vdso_clock_getres");
  }

  sym = dlsym(h, "__vdso_getcpu");
  if (sym != NULL) {
    unsigned cpu = 0, node = 0;
    if (((vdso_getcpu_fn)sym)(&cpu, &node, NULL) != 0) return 7;
    called += note("__vdso_getcpu");
  }

  sym = dlsym(h, "__vdso_getrandom");
  if (sym != NULL) {
    unsigned char rnd[8];
    ssize_t n = ((vdso_getrandom_fn)sym)(rnd, sizeof(rnd), 0, NULL, 0);
    if (n < 0) {
      fprintf(stderr, "__vdso_getrandom failed: %s\n", strerror(errno));
      return 8;
    }
    called += note("__vdso_getrandom");
  }

  dlclose(h);
  return called > 0 ? 0 : 9;
}
""", @["-ldl"])
    let depfile = work / "direct-vdso-dlsym.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    let eventLoss = dep.records.anyIt(it.kind == mrEventLoss and
      "linux vdso" in it.detail)
    if dep.completeness == mcIncomplete:
      check eventLoss
    else:
      check dep.completeness == mcComplete
      if "called __vdso_clock_gettime" in cap.output:
        check dep.records.anyIt(it.kind == mrTimeRead and
          it.path.startsWith("clock_gettime:"))
      if "called __vdso_gettimeofday" in cap.output:
        check hasRecord(dep, mrTimeRead, "gettimeofday")
      if "called __vdso_time" in cap.output:
        check hasRecord(dep, mrTimeRead, "time")
      if "called __vdso_clock_getres" in cap.output:
        check dep.records.anyIt(it.kind == mrTimeRead and
          it.path.startsWith("clock_getres:"))
      if "called __vdso_getcpu" in cap.output:
        check hasRecord(dep, mrSysctlRead, "getcpu")
      if "called __vdso_getrandom" in cap.output:
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

  test "raw libc SYS_gettid is treated as supported (no event-loss)":
    # Regression pin for M9.R.66.1: meson's Python runtime calls
    # `syscall(SYS_gettid)` (nr=186) per-thread; before this fix the shim's
    # classifier fell through to `unsupported nr=186` event-loss, tripping
    # mesonbin-setup with 2× event-loss per meson invocation. SYS_gettid
    # returns the calling thread's tid with no I/O side effects — classify
    # it as supported and record nothing.
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

    let probe = buildC(work, "raw_gettid", """
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_gettid
#define SYS_gettid 186
#endif
int main(void) {
  long tid = syscall(SYS_gettid);
  return tid > 0 ? 0 : 2;
}
""")
    let depfile = work / "raw-gettid.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check not dep.records.anyIt(it.kind == mrEventLoss and
      ("unsupported nr=186" in it.detail or
       "libc raw syscall unsupported" in it.detail))

  test "raw libc SYS_getrandom is observed, not lost (IoMon-Pipeline-Capture IM-5)":
    # Nim's `std/sysrand` reaches getrandom(2) as `syscall(SYS_getrandom, …)`
    # rather than through the libc symbol, so EVERY Nim binary that touches
    # `std/tempfiles` produced `libc raw syscall unsupported nr=318`. The
    # consumer classifies an unrecognised loss detail as Level 2 (unknown
    # scope), which sets `disableCacheHits` and skips the action-cache
    # publish — so reprobuild's own monitored `nim c` helper edges (interface
    # extraction, provider compile) could never hold a cache entry.
    #
    # This is a CLASSIFICATION gap, not a monitoring gap: the same call is
    # already observed as `mrNonDeterministic` on both other entry points
    # (`repro_hook_getrandom` for the libc symbol, `repro_vdso_getrandom` for
    # the vDSO). The record is deliberately not a completeness downgrade —
    # io-mon SAW the entropy read, so nothing is missing.
    #
    # Both assertions carry weight and fail together under the mutation that
    # removes the classifier arm: the loss reappears (assertion 1, and with
    # it mcComplete) and the observation disappears (assertion 2).
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

    # Deliberately the RAW form. Calling `getrandom()` (the libc symbol)
    # would exercise the already-hooked path and pass with or without the
    # classifier arm — the test would be green both ways.
    let probe = buildC(work, "raw_getrandom", """
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#ifndef SYS_getrandom
#define SYS_getrandom 318
#endif
int main(void) {
  unsigned char buf[16];
  long n = syscall(SYS_getrandom, buf, sizeof(buf), 0);
  return n == (long)sizeof(buf) ? 0 : 2;
}
""")
    let depfile = work / "raw-getrandom.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    # 1. No loss, so the edge stays publishable.
    check not dep.records.anyIt(it.kind == mrEventLoss and
      ("unsupported nr=318" in it.detail or
       "libc raw syscall unsupported" in it.detail))
    check dep.completeness == mcComplete
    # 2. The entropy read is still REPORTED — "supported" must not mean
    #    "invisible". This is the assertion that separates the fix from
    #    silently swallowing the syscall.
    check dep.records.anyIt(it.kind == mrNonDeterministic and
      it.path == "getrandom")

  test "raw libc io_uring_setup probe (failing) is supported (no event-loss)":
    # Regression pin for M9.R.67.2: Python 3.13's stdlib probes for io_uring
    # availability at startup by invoking `syscall(SYS_io_uring_setup)` (nr=425).
    # On kernels without io_uring the probe returns -ENOSYS and Python falls
    # back to poll/epoll. Before M9.R.67.2 the shim's classifier fell through
    # to `unsupported nr=425` event-loss, tripping mesonbin-setup with 47×
    # event-loss on the pixman meson setup (both nr=425 io_uring_setup and
    # nr=426 io_uring_enter — the latter can never actually reach the shim
    # unless setup succeeds first, but was included for symmetry).
    #
    # Policy: classify as supported ONLY when the probe returns a negative
    # error (kernel doesn't support io_uring). A successful setup would mean
    # a live ring where any subsequent io_uring_enter I/O happens invisibly
    # to LD_PRELOAD — that must remain event-loss until io-mon grows real
    # io_uring monitoring.
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

    # The probe attempts io_uring_setup(1, &params). On kernels without
    # io_uring the syscall returns -ENOSYS. If the kernel DOES support
    # io_uring we still want the process to exit cleanly (rc=0) — the
    # classifier's `callResult < 0` gate means we count actual usage as
    # event-loss, but a successful setup + immediate close still requires
    # no observation because our probe never enters the ring.
    let probe = buildC(work, "raw_io_uring_setup", """
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef __NR_close
#define __NR_close 3
#endif
struct io_uring_params_stub {
  uint32_t sq_entries;
  uint32_t cq_entries;
  uint32_t flags;
  uint32_t sq_thread_cpu;
  uint32_t sq_thread_idle;
  uint32_t features;
  uint32_t wq_fd;
  uint32_t resv[3];
  uint32_t sq_off[10];
  uint32_t cq_off[10];
};
int main(void) {
  struct io_uring_params_stub params;
  memset(&params, 0, sizeof(params));
  long fd = syscall(SYS_io_uring_setup, 1, &params);
  if (fd >= 0) {
    /* Kernel supports io_uring — close the ring immediately so the
     * probe never actually enters user-visible io_uring_enter usage. */
    syscall(__NR_close, fd);
  }
  return 0;
}
""")
    let depfile = work / "raw-io-uring-setup.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    # No event-loss for io_uring_setup regardless of whether the kernel
    # supports it (fail → classified supported; success → the ring exists
    # but our probe never issued an I/O op through it, so no io_uring_enter
    # fires).
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "unsupported nr=425" in it.detail)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "unsupported nr=426" in it.detail)

  test "PATH-searching execvp emits exactly one process-exec (M9.R.66.2)":
    # M9.R.66.2 regression pin: M9.R.65.2 added dispatch_execvp / _execvpe /
    # _fexecve interposers that fire the shim's execve hook then hand off to
    # glibc's real_execvp. glibc's real_execvp implements PATH lookup by
    # issuing execve() per candidate directory, and each of those internal
    # execve() calls hit our LD_PRELOAD `execve` interposer — outside a
    # bracket they re-fire the execve hook and emit ANOTHER mrProcessExec
    # per candidate. On a $PATH with N candidates the depfile records
    # execCount(pid) ~= N+1 vs startCount(pid) == 2, tripping T0 signal (b)
    # `execCount(pid) >= startCount(pid)` — one synthetic
    # `unmonitored subtree/peer` event-loss + mcIncomplete.
    #
    # Fix (M9.R.66.2): dispatch_execvp/pe/fexecve bracket the real_exec
    # call with stackable_linux_preload_enter_hook / _exit_hook so the
    # PATH-loop internal execve interposers see CT_BYPASS()==true and
    # delegate straight to real_execve without re-emitting.
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

    # Build a minimal target binary + place it at the END of a $PATH with
    # 3 empty leading directories so real_execvp does 3 failed execve()s
    # + 1 successful one. Build the target from source (rather than
    # copying /bin/true) because NixOS-WSL has no /bin/true and the test
    # must work on both classical distros AND NixOS.
    let targetName = "probe-target-m9r66-2"
    let pathDirs = @[work / "p1", work / "p2", work / "p3", work / "p4"]
    for d in pathDirs:
      createDir(d)
    let targetSrc = work / "probe_target_m9r66_2.c"
    writeFile(targetSrc, "int main(void) { return 0; }\n")
    let targetPath = pathDirs[^1] / targetName
    let cc = getEnv("CC", "cc")
    let ccBuilt = run(cc, @[targetSrc, "-o", targetPath])
    checkpoint("target cc: " & ccBuilt.output)
    check ccBuilt.code == 0
    check fileExists(targetPath)

    let probe = buildC(work, "execvp_path_search_probe", """
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  char *const cargv[] = { argv[1], NULL };
  execvp(argv[1], cargv);
  perror("execvp");
  return 3;
}
""")
    let depfile = work / "execvp-path-search.rdep"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    childEnv["PATH"] = pathDirs.join(":")
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe,
      targetName], childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    check not dep.records.anyIt(it.kind == mrEventLoss and
      ("unmonitored subtree" in it.detail or
       "un-injectable spawn child" in it.detail))

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
