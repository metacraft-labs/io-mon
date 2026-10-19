## test_io_mon_linux_host_entry_points — the Linux shim observes the entry
## points Node 24 and Chromium actually use, and grades them by what they
## mean for dependency evidence (Linux).
##
## WHY. Under monitoring every Node 24 and Chromium run was `mcIncomplete`
## (reprobuild-pm issue 2026-10-02-action-monitor-prevents-declared-browser-
## launch, Grafana addendum), for reasons that were not evidence of anything
## missing — and, once those were gone, some of the runs would have been
## `mcComplete` with dependencies silently missing. Each case below is one
## measured cause, reproduced deterministically in C:
##
##   * raw `syscall()`s the classifier did not know — getpid, capget/capset,
##     eventfd2, memfd_create, pkey_alloc/pkey_free/pkey_mprotect — each
##     made the run incomplete although none reads the filesystem
##     (`t_state_and_anonymous_object_syscalls_are_accepted`);
##   * the eventfd/timerfd creates now recorded for pairing must not pair
##     with a DIFFERENT kind of anonymous-inode object handed in from outside
##     the tree (Linux gives most of them one shared inode), such as an
##     inotify fd (`t_anonymous_inode_creates_pair_only_with_their_own_type`);
##   * raw `getdents64` (Chromium's file enumerator) was a loss even on a
##     directory the shim knew; it must be the same directory enumeration
##     the readdir hook records (`t_raw_getdents64_records_the_enumeration`),
##     including for an fd inherited across exec, attributed through
##     /proc/self/fd as inherited reads are
##     (`t_raw_getdents64_on_an_inherited_fd_is_attributed`);
##   * anything still unclassified must fail closed
##     (`t_unknown_raw_syscall_still_fails_closed`);
##   * V8 reserves its code range with `mmap64`, which the shim did not export,
##     so the range was never in the preload mmap lifecycle and V8's
##     `mprotect(PROT_EXEC)` read as an untracked executable mapping
##     (`t_mmap64_reserved_jit_region_is_tracked_and_scanned`);
##   * a writable+executable transition was scanned once and trusted, though
##     code written into it afterwards is never scanned
##     (`t_writable_executable_mprotect_fails_closed`); `pkey_mprotect`'s
##     executable transitions bypassed the lifecycle check entirely
##     (`t_pkey_mprotect_exec_transition_is_scanned`);
##   * libc entry points Node/libuv and Chromium import but the shim did not
##     export — access, readlink, realpath (and their _FORTIFY_SOURCE
##     `__*_chk` spellings), statx, fstatat, scandir, fdopendir,
##     stat64/lstat64/readdir64 — were invisible: a `readdirSync`
##     or `existsSync` left no record (`t_libc_probe_entry_points_are_recorded`).
##
## The JIT cases execute real machine code (x86_64; the same bytes as
## `test_io_mon_linux_stdio_ipc`'s JIT fixtures), so they run on amd64 only.
##
## Mocks: none. The real shim is built from this checkout, the real
## `io-mon run` CLI injects it into C programs built here, and every
## assertion reads the depfile the real merge wrote.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  # The raw numbers the loss details name (asm-generic on arm64).
  SYS_sched_yield_nr = (when defined(arm64): 124 else: 24)
  SYS_getdents64_nr = (when defined(arm64): 61 else: 217)

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

proc lossDetails(dep: MonitorDepFile): seq[string] =
  for r in dep.records:
    if r.kind == mrEventLoss:
      result.add r.detail

proc hasRecord(dep: MonitorDepFile; kind: MonitorRecordKind; path: string):
    bool =
  dep.records.anyIt(it.kind == kind and it.path == path)

# The JIT body: openat(AT_FDCWD, argv[1]) + read + close as inline `syscall`
# instructions, returning 0 when the read succeeded.
const jitCode = """
static unsigned char code[] = {
  0x53, 0x41, 0x54, 0x48, 0x83, 0xec, 0x40, 0x48, 0x89, 0xfe,
  0xb8, 0x01, 0x01, 0x00, 0x00, 0xbf, 0x9c, 0xff, 0xff, 0xff,
  0x31, 0xd2, 0x45, 0x31, 0xd2, 0x0f, 0x05, 0x48, 0x85, 0xc0,
  0x78, 0x29, 0x89, 0xc3, 0x31, 0xc0, 0x89, 0xdf, 0x48, 0x89,
  0xe6, 0xba, 0x40, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x49, 0x89,
  0xc4, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x89, 0xdf, 0x0f, 0x05,
  0x49, 0x83, 0xfc, 0x00, 0x7f, 0x0e, 0xb8, 0x03, 0x00, 0x00,
  0x00, 0xeb, 0x09, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xeb, 0x02,
  0x31, 0xc0, 0x48, 0x83, 0xc4, 0x40, 0x41, 0x5c, 0x5b, 0xc3
};
typedef int (*jit_read_marker_fn)(const char *);
"""

suite "io-mon Linux shim covers the entry points Node and Chromium use":
  let work = getTempDir() / ("io-mon-host-entry-" & $getCurrentProcessId())
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

  proc monitor(depName: string; args: seq[string]; shellCmd = ""):
      tuple[dep: MonitorDepFile; output: string; code: int] =
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / (depName & ".iomon")
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--"] & args, env)
    checkpoint(depName & " (exit " & $cap.code & "):\n" & cap.output)
    result.output = cap.output
    result.code = cap.code
    if fileExists(depfile):
      result.dep = readMonitorDepFile(depfile)
      checkpoint(depName & ": " & $result.dep.completeness & "; losses: " &
        $lossDetails(result.dep))

  test "t_state_and_anonymous_object_syscalls_are_accepted":
    let marker = work / "state-marker.txt"
    writeFile(marker, "state marker\n")
    let probe = buildC(work, "state_syscalls", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[2];
  if (syscall(SYS_getpid) <= 0) return 2;
  if (syscall(SYS_capget, &hdr, data) != 0) return 3;
  if (syscall(SYS_capset, &hdr, data) != 0) return 4;   /* unchanged sets */
  long efd = syscall(SYS_eventfd2, 0, 0);
  if (efd < 0) return 5;
  close((int)efd);
  long mfd = syscall(SYS_memfd_create, "io-mon-test", 0);
  if (mfd < 0) return 6;
  close((int)mfd);
  /* pkey_alloc fails on CPUs without protection keys; the classification
   * does not depend on the result. */
  long key = syscall(SYS_pkey_alloc, 0, 0);
  if (key >= 0) syscall(SYS_pkey_free, key);
  void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) return 7;
  /* pkey -1 is plain mprotect semantics, with or without PKU. */
  if (syscall(SYS_pkey_mprotect, page, 4096, PROT_READ, -1) != 0) return 8;
  munmap(page, 4096);
  char buf[32];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0 || read(fd, buf, sizeof(buf)) <= 0) return 9;
  close(fd);
  return 0;
}
""")
    let r = monitor("state", @[probe, marker])
    check r.code == 0
    check r.dep.completeness == mcComplete
    check r.dep.records.anyIt(it.kind == mrFileRead and it.path == marker)
    check not r.dep.lossDetails.anyIt("unsupported" in it)

  test "t_anonymous_inode_creates_pair_only_with_their_own_type":
    # eventfd/timerfd creates are recorded as in-tree `localfd role=create` so
    # a child reading an inherited eventfd pairs with its creator. Linux backs
    # most anonymous-inode objects with ONE shared inode, so the pairing key
    # must also carry the object's type: otherwise an in-tree eventfd would
    # pair with an inotify fd handed in from OUTSIDE the tree, whose reads are
    # external input, and grade the run mcComplete.
    let watched = work / "anon-watched"
    createDir(watched)
    let launcher = buildC(work, "anon_launcher", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <unistd.h>
/* Unmonitored: hands an inotify fd with a pending event to the command as
 * fd 9, then execs it. */
int main(int argc, char **argv) {
  if (argc < 3) return 90;
  int fd = inotify_init();             /* no CLOEXEC: inherited */
  if (fd < 0) return 91;
  if (inotify_add_watch(fd, argv[1], IN_CREATE) < 0) return 92;
  char p[4096];
  snprintf(p, sizeof(p), "%s/created", argv[1]);
  int c = open(p, O_CREAT | O_WRONLY, 0644);
  if (c < 0) return 93;
  close(c);
  if (dup2(fd, 9) != 9) return 94;
  if (fd != 9) close(fd);
  execv(argv[2], argv + 2);
  return 95;
}
""")
    let reader = buildC(work, "anon_reader", """
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[4096];
  if (argc < 2) return 2;
  if (strcmp(argv[1], "inotify") == 0) {
    /* An in-tree eventfd, then a read of the OUT-OF-TREE inotify fd 9. */
    if (eventfd(0, 0) < 0) return 3;
    return read(9, buf, sizeof(buf)) > 0 ? 0 : 4;
  }
  if (strcmp(argv[1], "eventfd-parent") == 0) {
    int e = eventfd(1, 0);               /* in-tree, inherited by the child */
    if (e < 0 || dup2(e, 9) != 9) return 5;
    pid_t child = fork();
    if (child < 0) return 6;
    if (child == 0) {
      char *args[] = {argv[0], "eventfd-child", NULL};
      execv(argv[0], args);
      _exit(7);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 8;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 9;
  }
  if (strcmp(argv[1], "eventfd-child") == 0) {
    uint64_t v = 0;
    return read(9, &v, sizeof(v)) == (ssize_t)sizeof(v) && v == 1 ? 0 : 10;
  }
  return 11;
}
""")
    # The launcher runs OUTSIDE the monitor and execs `io-mon run`, so fd 9
    # reaches the monitored root from an out-of-tree creator.
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let innerDep = work / "anon-inotify.iomon"
    let outside = run(launcher, @[watched, snoopBin, "run", "--depfile",
      innerDep, "--", reader, "inotify"], env)
    checkpoint("anon-inotify (exit " & $outside.code & "):\n" &
      outside.output)
    check outside.code == 0
    let inner = readMonitorDepFile(innerDep)
    checkpoint("anon-inotify: " & $inner.completeness & "; losses: " &
      $lossDetails(inner))
    check inner.records.anyIt(it.kind == mrExternalContent and
      "role=read" in it.detail and "anon_inode:inotify" in it.path)
    check inner.records.anyIt(it.kind == mrExternalContent and
      "role=create" in it.detail and "anon_inode:[eventfd]" in it.path)
    check inner.completeness == mcIncomplete

    let paired = monitor("anon-eventfd", @[reader, "eventfd-parent"])
    check paired.code == 0
    check paired.dep.records.anyIt(it.kind == mrExternalContent and
      "role=read" in it.detail and "anon_inode:[eventfd]" in it.path)
    check paired.dep.completeness == mcComplete

  test "t_raw_getdents64_records_the_enumeration":
    let dir = work / "getdents-known"
    createDir(dir)
    writeFile(dir / "entry.txt", "x")
    let probe = buildC(work, "getdents_known", """
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[4096];
  int fd = open(argv[1], O_RDONLY | O_DIRECTORY);
  if (fd < 0) return 2;
  long n;
  while ((n = syscall(SYS_getdents64, fd, buf, sizeof(buf))) > 0) {}
  close(fd);
  return n == 0 ? 0 : 3;
}
""")
    let r = monitor("getdents-known", @[probe, dir])
    check r.code == 0
    check r.dep.completeness == mcComplete
    check r.dep.hasRecord(mrDirectoryEnumerate, dir)
    check r.dep.records.anyIt(it.kind == mrDirectoryEnumerate and
      it.path == dir and it.detail.startsWith("getdents64"))

  test "t_raw_getdents64_on_an_inherited_fd_is_attributed":
    # The fd is inherited across exec, so the shim's fd table (per image) does
    # not know it; the kernel's /proc/self/fd link still names the directory,
    # the same recovery the read path uses for inherited descriptors. (An fd
    # that names no attributable directory stays a loss in the classifier;
    # for a directory that is only reachable when /proc cannot answer, since
    # getdents64 on a removed directory fails rather than enumerating.)
    let dir = work / "getdents-inherited"
    createDir(dir)
    writeFile(dir / "entry.txt", "x")
    let probe = buildC(work, "getdents_fd7", """
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
  char buf[4096];
  long n;
  while ((n = syscall(SYS_getdents64, 7, buf, sizeof(buf))) > 0) {}
  return n == 0 ? 0 : 2;
}
""")
    let script = "exec 7<" & quoteShell(dir) & " && exec " & quoteShell(probe)
    let r = monitor("getdents-inherited", @["bash", "-c", script])
    check r.code == 0
    check r.dep.records.anyIt(it.kind == mrDirectoryEnumerate and
      it.path == dir and it.detail.startsWith("getdents64"))
    check not r.dep.lossDetails.anyIt(
      ("unsupported nr=" & $SYS_getdents64_nr) in it)

  test "t_unknown_raw_syscall_still_fails_closed":
    let probe = buildC(work, "sched_yield_raw", """
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
int main(void) { return syscall(SYS_sched_yield) == 0 ? 0 : 2; }
""")
    let r = monitor("unknown-syscall", @[probe])
    check r.code == 0
    check r.dep.completeness == mcIncomplete
    check r.dep.lossDetails.anyIt(("unsupported nr=" & $SYS_sched_yield_nr) in it)

  when defined(amd64):
    test "t_mmap64_reserved_jit_region_is_tracked_and_scanned":
      # V8's pattern: reserve with mmap64(PROT_NONE, MAP_NORESERVE), commit
      # RW, write code, flip to RX, call it.
      let marker = work / "mmap64-jit-marker.txt"
      writeFile(marker, "mmap64 jit marker\n")
      let probe = buildC(work, "mmap64_jit", """
#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>
""" & jitCode & """
int main(int argc, char **argv) {
  char *range = mmap64(NULL, 1 << 20, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (range == MAP_FAILED) return 4;
  if (mprotect(range, 4096, PROT_READ | PROT_WRITE) != 0) return 5;
  memcpy(range, code, sizeof(code));
  if (mprotect(range, 4096, PROT_READ | PROT_EXEC) != 0) return 6;
  return ((jit_read_marker_fn)(void *)range)(argv[1]);
}
""")
      let r = monitor("mmap64-jit", @[probe, marker])
      check r.code == 0
      check r.dep.completeness == mcComplete
      check r.dep.records.anyIt((it.kind == mrFileOpen or
        it.kind == mrFileRead) and it.path == marker)
      check not r.dep.lossDetails.anyIt("untracked" in it)

    test "t_writable_executable_mprotect_fails_closed":
      let probe = buildC(work, "rwx_mprotect", """
#define _GNU_SOURCE
#include <stddef.h>
#include <sys/mman.h>
int main(void) {
  void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) return 4;
  return mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0 ? 0 : 5;
}
""")
      let r = monitor("rwx-mprotect", @[probe])
      check r.code == 0
      check r.dep.completeness == mcIncomplete
      check r.dep.lossDetails.anyIt("mprotect-anonymous-writable-exec" in it)

    test "t_pkey_mprotect_exec_transition_is_scanned":
      let marker = work / "pkey-jit-marker.txt"
      writeFile(marker, "pkey jit marker\n")
      let probe = buildC(work, "pkey_jit", """
#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>
""" & jitCode & """
int main(int argc, char **argv) {
  void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) return 4;
  memcpy(mem, code, sizeof(code));
  /* pkey -1: no key, mprotect semantics; works with or without PKU. */
  if (pkey_mprotect(mem, 4096, PROT_READ | PROT_EXEC, -1) != 0) return 5;
  return ((jit_read_marker_fn)mem)(argv[1]);
}
""")
      let r = monitor("pkey-jit", @[probe, marker])
      check r.code == 0
      check r.dep.completeness == mcComplete
      check r.dep.records.anyIt((it.kind == mrFileOpen or
        it.kind == mrFileRead) and it.path == marker)

  test "t_libc_probe_entry_points_are_recorded":
    let base = work / "probes"
    createDir(base)
    for name in ["access", "realpath", "statx", "fstatat", "stat64",
                 "lstat64"]:
      writeFile(base / name, name)
    createSymlink(base / "access", base / "link")
    for d in ["scandir-dir", "fdopendir-dir", "readdir64-dir"]:
      createDir(base / d)
      writeFile(base / d / "entry", "x")
    let probe = buildC(work, "libc_probes", """
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
static char p[PATH_MAX];
static const char *at(const char *base, const char *name) {
  snprintf(p, sizeof(p), "%s/%s", base, name);
  return p;
}
int main(int argc, char **argv) {
  const char *b = argv[1];
  char buf[PATH_MAX];
  struct stat st;
  struct stat64 st64;
  struct statx sx;
  struct dirent **list;
  if (access(at(b, "access"), R_OK) != 0) return 2;
  if (readlink(at(b, "link"), buf, sizeof(buf)) <= 0) return 3;
  if (realpath(at(b, "realpath"), buf) == NULL) return 4;
  if (statx(AT_FDCWD, at(b, "statx"), 0, STATX_SIZE, &sx) != 0) return 5;
  if (fstatat(AT_FDCWD, at(b, "fstatat"), &st, 0) != 0) return 6;
  if (stat64(at(b, "stat64"), &st64) != 0) return 7;
  if (lstat64(at(b, "lstat64"), &st64) != 0) return 8;
  if (scandir(at(b, "scandir-dir"), &list, NULL, alphasort) < 0) return 9;
  int fd = open(at(b, "fdopendir-dir"), O_RDONLY | O_DIRECTORY);
  DIR *d = fdopendir(fd);
  if (d == NULL || readdir(d) == NULL) return 10;
  closedir(d);
  DIR *d64 = opendir(at(b, "readdir64-dir"));
  if (d64 == NULL || readdir64(d64) == NULL) return 11;
  closedir(d64);
  return 0;
}
""")
    let r = monitor("libc-probes", @[probe, base])
    check r.code == 0
    for name in ["access", "link", "realpath", "statx", "fstatat", "stat64",
                 "lstat64"]:
      let path = base / name
      if not r.dep.hasRecord(mrPathProbe, path):
        checkpoint("no path probe recorded for " & path)
      check r.dep.hasRecord(mrPathProbe, path)
    for d in ["scandir-dir", "fdopendir-dir", "readdir64-dir"]:
      let path = base / d
      if not r.dep.hasRecord(mrDirectoryEnumerate, path):
        checkpoint("no directory enumeration recorded for " & path)
      check r.dep.hasRecord(mrDirectoryEnumerate, path)
    check r.dep.completeness == mcComplete

  removeDir(work)
