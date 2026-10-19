## A trapped inline syscall is classified from what it named WHEN IT RAN.
##
## WHY. The x86_64 inline-syscall backend patches a program's own `syscall`
## instructions to trap, replays each call in the SIGTRAP handler and leaves a
## raw event (number, argument registers, result) to be classified later,
## outside signal context. Those events used to be classified only at process
## exit, from the raw argument registers. By then:
##   - a pathname pointer may name memory the program freed, reused or
##     unmapped: the record names whatever the bytes became, or the shim
##     faults at exit;
##   - a relative pathname was joined onto the working directory AT EXIT, not
##     the one the call used;
##   - a descriptor number may name another file: a read was attributed to
##     whatever the descriptor table held at exit;
##   - an exec, or an exit that bypasses the destructor (an inline
##     `exit_group`), discarded the unclassified events with no record and no
##     loss.
## And because the paths could not be trusted, the path-mutation syscalls
## (mkdir, unlink(at), mkdirat, symlink, creat, truncate) were left
## unclassified on this route: event-loss for every such call.
##
## WHAT THIS TEST GRADES. A host issues each call through ONE inline `syscall`
## instruction (patched by the scanner), from a buffer it overwrites right
## after each call and unmaps before exiting, then moves to `/`. It reads a
## file through a descriptor number it then closes and reuses for another file
## with libc. It ends four ways: by returning from `main`, by a libc `execv`,
## by an inline `exit_group` and by `syscall(SYS_exit_group)`. Each run must record every call on the path
## the call used (absolute, under the host's tree), the symlink's target, the
## read on the file the descriptor named then, nothing under the overwritten
## or post-chdir names, no event-loss, and a complete capture.
##
## x86_64 only: no other architecture has the inline-syscall trap backend.
##
## Mocks: none. Real program, real shim, real files.

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
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The only `syscall` instruction in this program: every raw call below goes
 * through this one patched site. */
static long __attribute__((noinline))
raw6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
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

#define NAME(text) (strcpy(page, (text)), (long)page)
#define SPOIL() memset(page, 'W', 1024)

int main(int argc, char **argv) {
  if (argc < 3 || chdir(argv[1]) != 0) return 2;
  char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) return 3;
  char buf[16];

  if (raw6(SYS_mkdir, NAME("M1"), 0755, 0, 0, 0, 0) != 0) return 10;
  SPOIL();
  strcpy(page + 512, "M1/link");
  if (raw6(SYS_symlink, NAME("target-x"), (long)(page + 512), 0, 0, 0, 0) != 0)
    return 11;
  SPOIL();
  /* A directory fd opened inline: the shim's descriptor table never sees it. */
  long dfd = raw6(SYS_openat, AT_FDCWD, NAME("M1"), O_DIRECTORY | O_RDONLY, 0,
                  0, 0);
  if (dfd < 0) return 12;
  if (raw6(SYS_unlinkat, dfd, NAME("link"), 0, 0, 0, 0) != 0) return 13;
  if (raw6(SYS_mkdirat, dfd, NAME("sub"), 0755, 0, 0, 0) != 0) return 14;
  SPOIL();
  long cfd = raw6(SYS_creat, NAME("M1/created"), 0644, 0, 0, 0, 0);
  if (cfd < 0) return 15;
  raw6(SYS_close, cfd, 0, 0, 0, 0, 0);
  if (raw6(SYS_truncate, NAME("M1/created"), 0, 0, 0, 0, 0) != 0) return 16;
  if (raw6(SYS_unlink, NAME("M1/created"), 0, 0, 0, 0, 0) != 0) return 17;
  if (raw6(SYS_rmdir, NAME("M1/sub"), 0, 0, 0, 0, 0) != 0) return 18;
  SPOIL();
  long afd = raw6(SYS_openat, AT_FDCWD, NAME("input-a.txt"), O_RDONLY, 0, 0, 0);
  if (afd < 0) return 19;
  SPOIL();
  if (raw6(SYS_read, afd, (long)buf, sizeof(buf), 0, 0, 0) <= 0) return 20;
  raw6(SYS_close, afd, 0, 0, 0, 0, 0);
  struct stat st;
  if (raw6(SYS_newfstatat, AT_FDCWD, NAME("input-a.txt"), (long)&st, 0, 0,
           0) != 0)
    return 21;
  SPOIL();
  /* A descriptor libc opened, read inline, then closed and reused by libc
   * for another file that stays open until the end. */
  int cfd2 = open("input-c.txt", O_RDONLY);
  if (cfd2 < 0) return 22;
  if (raw6(SYS_read, cfd2, (long)buf, sizeof(buf), 0, 0, 0) <= 0) return 23;
  close(cfd2);
  int dfd2 = open("input-d.txt", O_RDONLY);
  if (dfd2 != cfd2) { fprintf(stderr, "descriptor not reused\n"); return 24; }

  munmap(page, 4096);      /* every pathname pointer above is now unmapped */
  if (chdir("/") != 0) return 25;

  if (strcmp(argv[2], "exec") == 0) {
    char *args[] = {argv[3], NULL};
    execv(argv[3], args);
    return 26;
  }
  if (strcmp(argv[2], "exit-group") == 0)
    raw6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
  if (strcmp(argv[2], "syscall-exit-group") == 0)
    syscall(SYS_exit_group, 0);
  return 0;
}
"""

suite "io-mon Linux shim: trapped inline syscalls are captured when they trap":
  test "t_inline_trap_events_use_trap_time_paths_and_survive_exit_and_exec":
    when not defined(amd64):
      skip()   # no inline-syscall trap backend on this architecture
    else:
      let work = expandFilename(getTempDir()) /
        ("io-mon-inline-capture-" & $getCurrentProcessId())
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
      let host = work / "inline-host"
      writeFile(host & ".c", hostSource)
      let hostCc = run(cc, @[host & ".c", "-O0", "-o", host])
      checkpoint(hostCc.output)
      check hostCc.code == 0
      let noop = work / "noop"
      writeFile(noop & ".c", "int main(void) { return 0; }\n")
      let noopCc = run(cc, @[noop & ".c", "-o", noop])
      checkpoint(noopCc.output)
      check noopCc.code == 0

      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env.del("LD_PRELOAD")
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib

      for ending in ["return", "exec", "exit-group", "syscall-exit-group"]:
        checkpoint("ending: " & ending)
        let tree = work / ("tree-" & ending)
        createDir(tree)
        for name in ["a", "c", "d"]:
          writeFile(tree / ("input-" & name & ".txt"), "input " & name & "\n")
        let depfile = work / (ending & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
          tree, ending, noop], env)
        checkpoint(cap.output)
        check cap.code == 0
        let dep = readMonitorDepFile(depfile)
        for r in dep.records:
          if r.kind != mrLibraryLoad and r.kind != mrEnvRead:
            checkpoint($r.kind & " " & $r.observationKind & " " & r.path &
              " " & r.detail)

        proc mutated(path, detailPrefix: string): bool =
          dep.records.anyIt(it.kind == mrPathMutation and it.path == path and
            it.detail.startsWith(detailPrefix))

        # Recorded at all only if the scanner patched the site: an unpatched
        # `syscall` instruction reaches the kernel with no record.
        check mutated(tree / "M1", "mkdir")
        check mutated(tree / "M1" / "link", "symlink target=target-x")
        check mutated(tree / "M1" / "link", "unlinkat")
        check mutated(tree / "M1" / "sub", "mkdirat")
        check mutated(tree / "M1" / "sub", "rmdir")
        check mutated(tree / "M1" / "created", "unlink")
        check dep.records.anyIt(it.kind == mrFileOpen and
          it.path == tree / "M1" / "created" and
          it.observationKind == moFileWrite)
        check dep.records.anyIt(it.kind == mrFileWrite and
          it.path == tree / "M1" / "created" and
          it.detail.startsWith("truncate"))
        check dep.records.anyIt(it.kind == mrFileRead and
          it.path == tree / "input-a.txt")
        check dep.records.anyIt(it.kind == mrPathProbe and
          it.path == tree / "input-a.txt")
        # The inline read of the descriptor libc closed and reused: the file
        # it named when it ran, not the one the number names at exit.
        check dep.records.anyIt(it.kind == mrFileRead and
          it.path == tree / "input-c.txt")
        # Nothing under a spoiled buffer or the later working directory.
        check not dep.records.anyIt("WWW" in it.path or
          it.path in ["/M1", "/input-a.txt", "/M1/link", "/M1/created"])
        check dep.records.filterIt(it.kind == mrPathMutation).allIt(
          it.path.startsWith(tree & "/"))
        check not dep.records.anyIt(it.kind == mrEventLoss)
        check dep.completeness == mcComplete
      removeDir(work)
