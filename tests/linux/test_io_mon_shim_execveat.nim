## `execveat` and `fexecve` are monitored like `execve`.
##
## WHY. glibc's `execveat` wrapper (2.34+) and its `fexecve` make the system
## call themselves, so an exec through them reached none of the shim's exec
## handling: no exec record, no LD_PRELOAD or exec generation for the new
## image, and no drain of buffered or trapped events before the old image
## was discarded. A caller that passed an environment without LD_PRELOAD
## therefore ran an unmonitored child, and the capture still graded complete.
##
## WHAT THIS TEST GRADES. A host process exec's a child four ways, each with
## its environment stripped of LD_PRELOAD: `execveat` relative to a directory
## descriptor, `execveat` with AT_EMPTY_PATH, `fexecve`, and `execve` as the
## control that has always been hooked. For each, the capture must record:
## the child's read of its input (the child was monitored), one exec record
## from the host naming the child's image, and -- on x86_64, where the host
## opens a file through an inline `syscall` instruction the shim traps just
## before the exec -- that open (the trapped events were classified before
## the image ended). The control passing shows the expectations hold for an
## exec the shim has always handled.
##
## Mocks: none. Real programs, real shim, real files.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

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

const hostSource = """
#define _GNU_SOURCE
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

#ifdef __x86_64__
/* An inline `syscall` instruction the shim patches to trap. */
static long __attribute__((noinline))
raw4(long nr, long a0, long a1, long a2, long a3) {
  register long r10 __asm__("r10") = a3;
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                   : "rcx", "r11", "memory");
  return ret;
}
#endif

int main(int argc, char **argv) {
  if (argc < 4 || chdir(argv[2]) != 0) return 2;
  const char *mode = argv[1];
  const char *child = argv[3];
#ifdef __x86_64__
  if (raw4(SYS_openat, AT_FDCWD, (long)"input-a.txt", O_RDONLY, 0) < 0)
    return 3;
#endif
  /* The environment the host passes, without LD_PRELOAD. */
  size_t n = 0;
  while (environ[n] != NULL) n++;
  char **envp = calloc(n + 1, sizeof(char *));
  size_t k = 0;
  for (size_t i = 0; i < n; i++)
    if (strncmp(environ[i], "LD_PRELOAD=", 11) != 0) envp[k++] = environ[i];
  envp[k] = NULL;
  char *cargv[] = {(char *)child, argv[2], NULL};
  char dir[4096], base[4096];
  strcpy(dir, child);
  strcpy(base, child);
  if (strcmp(mode, "execveat-dirfd") == 0) {
    int dirfd = open(dirname(dir), O_PATH | O_DIRECTORY);
    if (dirfd < 0) return 4;
    execveat(dirfd, basename(base), cargv, envp, 0);
  } else if (strcmp(mode, "execveat-empty-path") == 0) {
    int fd = open(child, O_PATH);
    if (fd < 0) return 4;
    execveat(fd, "", cargv, envp, AT_EMPTY_PATH);
  } else if (strcmp(mode, "fexecve") == 0) {
    int fd = open(child, O_RDONLY);
    if (fd < 0) return 4;
    fexecve(fd, cargv, envp);
  } else if (strcmp(mode, "execve") == 0) {
    execve(child, cargv, envp);
  }
  return 10;
}
"""

const childSource = """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 2 || chdir(argv[1]) != 0) return 20;
  int fd = open("input-b.txt", O_RDONLY);
  if (fd < 0) return 21;
  char buf[16];
  if (read(fd, buf, sizeof(buf)) <= 0) return 22;
  close(fd);
  return 0;
}
"""

suite "io-mon Linux shim: execveat and fexecve":
  test "t_execveat_and_fexecve_run_the_exec_hook":
    let work = expandFilename(getTempDir()) /
      ("io-mon-execveat-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0
    let cc = getEnv("CC", "cc")
    let host = work / "exec-host"
    writeFile(host & ".c", hostSource)
    let hostCc = run(cc, @[host & ".c", "-O0", "-o", host])
    checkpoint(hostCc.output)
    check hostCc.code == 0
    let child = work / "exec-child"
    writeFile(child & ".c", childSource)
    let childCc = run(cc, @[child & ".c", "-o", child])
    checkpoint(childCc.output)
    check childCc.code == 0

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env.del("LD_PRELOAD")
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib

    for mode in ["execve", "execveat-dirfd", "execveat-empty-path",
                 "fexecve"]:
      checkpoint("mode: " & mode)
      let tree = work / ("tree-" & mode)
      createDir(tree)
      writeFile(tree / "input-a.txt", "input a\n")
      writeFile(tree / "input-b.txt", "input b\n")
      let depfile = work / (mode & ".iomon")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
        mode, tree, child], env)
      checkpoint(cap.output)
      check cap.code == 0
      let dep = readMonitorDepFile(depfile)
      for r in dep.records:
        if r.kind in {mrFileOpen, mrEventLoss, mrProcessExec,
                      mrProcessStart}:
          checkpoint($r.kind & " pid=" & $r.osPid & " " & r.path & " " &
            r.detail)
      checkpoint("completeness: " & $dep.completeness)
      # The child ran monitored, so its read is in the capture.
      check dep.records.anyIt(it.kind == mrFileOpen and
        it.path == tree / "input-b.txt")
      # One successful exec, recorded by the host and naming the child.
      let execs = dep.records.filterIt(it.kind == mrProcessExec and
        "execstatus=failed" notin it.detail)
      check execs.len == 1
      if execs.len == 1:
        check execs[0].path == child
      when defined(amd64):
        # The open trapped just before the exec was classified, not lost.
        check dep.records.anyIt(it.kind == mrFileOpen and
          it.path == tree / "input-a.txt")
      check dep.completeness == mcComplete
    removeDir(work)
