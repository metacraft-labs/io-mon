## Trapped inline syscalls are never dropped silently when the image ends
## inside a hook.
##
## WHY. The x86_64 inline-syscall backend records each trapped `syscall`
## instruction as a raw event and classifies it later, outside signal
## context. An exit or exec that bypasses the destructor and the exec hooks
## (an inline `exit_group` or `execve`, `syscall(SYS_exit_group)`) drains the
## pending events first -- but only when the thread is not already inside a
## hook, because the classification takes the shim's locks and an
## interrupted hook may hold them. A libc exec made from inside a hook runs
## no hook at all, so no drain either. On those paths the events used to be
## discarded and the capture still graded complete: the shared-memory
## transport has no commit marker for the exit path to withhold.
##
## WHAT THE FIRST TEST GRADES. The host blocks in a hooked `read` on a pipe, so
## its thread is inside a hook, and SIGALRM interrupts it. The handler opens
## a file through the program's one inline `syscall` instruction (patched to
## trap) and then ends the image four ways: an inline `exit_group`,
## `syscall(SYS_exit_group)`, an inline `execve` and a libc `execv`. Each
## capture must either record the open or report event-loss and grade
## incomplete; it must never be complete without the open. A control run
## whose handler only opens the file and returns, letting `main` return,
## must record the open and stay complete, so the four endings are not
## graded on a host whose trap never fired.
##
## THE SECOND TEST grades events trapped after the process's final drain: a
## thread keeps opening files through the inline `syscall` while `main`
## returns, so some of its opens land after the exit destructor drained.
## Every open it made must be in the capture, or the capture must report the
## loss and not be complete; and at least two of up to twenty runs must have
## had such a late open, so the case was exercised at all.
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
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

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

static const char *ending;
static const char *noop;
static volatile sig_atomic_t opened = 0;

static void on_alarm(int signum) {
  (void)signum;
  long fd = raw6(SYS_openat, AT_FDCWD, (long)"input-a.txt", O_RDONLY, 0, 0, 0);
  if (fd < 0) raw6(SYS_exit_group, 40, 0, 0, 0, 0, 0);
  opened = 1;
  char *args[] = {(char *)noop, NULL};
  if (strcmp(ending, "exit-group") == 0)
    raw6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
  if (strcmp(ending, "syscall-exit-group") == 0)
    syscall(SYS_exit_group, 0);
  if (strcmp(ending, "inline-execve") == 0) {
    raw6(SYS_execve, (long)noop, (long)args, (long)environ, 0, 0, 0);
    raw6(SYS_exit_group, 41, 0, 0, 0, 0, 0);
  }
  if (strcmp(ending, "execv") == 0) {
    execv(noop, args);
    raw6(SYS_exit_group, 42, 0, 0, 0, 0, 0);
  }
  /* "control": return; the interrupted read fails with EINTR. */
}

int main(int argc, char **argv) {
  if (argc < 4 || chdir(argv[1]) != 0) return 2;
  ending = argv[2];
  noop = argv[3];
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_alarm;       /* no SA_RESTART: read returns EINTR */
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGALRM, &sa, NULL) != 0) return 3;
  int fds[2];
  if (pipe(fds) != 0) return 4;
  alarm(1);
  char c;
  /* Blocks inside the shim's read hook until SIGALRM arrives. */
  ssize_t n = read(fds[0], &c, 1);
  if (n >= 0 || !opened) return 5;
  return 0;
}
"""

# A thread that keeps opening files through the inline `syscall` while the
# main thread returns from `main`: the shim's exit destructor drains the
# trapped events once, and the thread's later opens land after that drain.
# Each open is followed by printing its index (libc write, not trapped), so
# every index printed was opened before the process died. The thread sleeps
# between opens so the trap buffer cannot overflow (that would report a
# different loss and hide the case).
const lateThreadSource = """
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

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

static volatile int opened = 0;
static int limit;

static void *opener(void *arg) {
  (void)arg;
  for (int i = 0; i < limit; i++) {
    char name[32];
    snprintf(name, sizeof(name), "input-%d.txt", i);
    long fd = raw6(SYS_openat, AT_FDCWD, (long)name, O_RDONLY, 0, 0, 0);
    if (fd < 0) _exit(30);
    close((int)fd);
    char line[16];
    int n = snprintf(line, sizeof(line), "%d\n", i);
    if (write(1, line, (size_t)n) != n) _exit(31);
    __atomic_store_n(&opened, i + 1, __ATOMIC_RELEASE);
    struct timespec pause = {0, 50000};
    nanosleep(&pause, NULL);
  }
  for (;;) pause();
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 3 || chdir(argv[1]) != 0) return 2;
  limit = 0;
  for (const char *p = argv[2]; *p; p++) limit = limit * 10 + (*p - '0');
  pthread_t thread;
  if (pthread_create(&thread, NULL, opener, NULL) != 0) return 3;
  while (__atomic_load_n(&opened, __ATOMIC_ACQUIRE) < 20) {
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
  }
  return 0;
}
"""

suite "io-mon Linux shim: trapped inline syscalls when the image ends inside a hook":
  test "t_unclassified_inline_events_are_recorded_or_reported_as_loss":
    when not defined(amd64):
      skip()   # no inline-syscall trap backend on this architecture
    else:
      let work = expandFilename(getTempDir()) /
        ("io-mon-inline-in-hook-" & $getCurrentProcessId())
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
      let host = work / "in-hook-host"
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

      for ending in ["control", "exit-group", "syscall-exit-group",
                     "inline-execve", "execv"]:
        checkpoint("ending: " & ending)
        let tree = work / ("tree-" & ending)
        createDir(tree)
        writeFile(tree / "input-a.txt", "input a\n")
        let depfile = work / (ending & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
          tree, ending, noop], env)
        checkpoint(cap.output)
        check cap.code == 0
        let dep = readMonitorDepFile(depfile)
        for r in dep.records:
          if r.kind in {mrFileOpen, mrEventLoss, mrProcessExec}:
            checkpoint($r.kind & " " & r.path & " " & r.detail)
        let openRecorded = dep.records.anyIt(it.kind == mrFileOpen and
          it.path == tree / "input-a.txt")
        let lossReported = dep.records.anyIt(it.kind == mrEventLoss)
        checkpoint("open recorded: " & $openRecorded & ", loss reported: " &
          $lossReported & ", completeness: " & $dep.completeness)
        if ending == "control":
          check openRecorded
          check dep.completeness == mcComplete
        else:
          # Never complete without the open it made.
          check openRecorded or
            (lossReported and dep.completeness != mcComplete)
          check not (dep.completeness == mcComplete and not openRecorded)
          if lossReported and not openRecorded:
            check dep.records.anyIt(it.kind == mrEventLoss and
              it.detail.startsWith(
                "inline raw syscall events unclassified at image end"))
      removeDir(work)

  test "t_inline_events_trapped_after_the_final_drain_are_reported":
    ## Every open the thread made is in the capture, or the capture reports
    ## event-loss and is not complete.
    when not defined(amd64):
      skip()   # no inline-syscall trap backend on this architecture
    else:
      let work = expandFilename(getTempDir()) /
        ("io-mon-inline-late-" & $getCurrentProcessId())
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
      let host = work / "late-host"
      writeFile(host & ".c", lateThreadSource)
      let hostCc = run(cc, @[host & ".c", "-O0", "-pthread", "-o", host])
      checkpoint(hostCc.output)
      check hostCc.code == 0
      const limit = 2000
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env.del("LD_PRELOAD")
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib
      var lateOpens = 0
      for attempt in 0 ..< 20:
        if lateOpens >= 2:
          break
        let tree = work / ("tree-" & $attempt)
        createDir(tree)
        for i in 0 ..< limit:
          writeFile(tree / ("input-" & $i & ".txt"), "x\n")
        let depfile = work / ("late-" & $attempt & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
          tree, $limit], env)
        check cap.code == 0
        var printed = 0
        for line in cap.output.splitLines():
          if line.len > 0 and line.allIt(it in {'0' .. '9'}):
            printed = max(printed, parseInt(line) + 1)
        check printed >= 20
        check printed < limit
        let dep = readMonitorDepFile(depfile)
        var missing = 0
        for i in 0 ..< printed:
          let path = tree / ("input-" & $i & ".txt")
          if not dep.records.anyIt(it.kind == mrFileOpen and it.path == path):
            inc missing
        let lossReported = dep.records.anyIt(it.kind == mrEventLoss and
          it.detail.startsWith(
            "inline raw syscall events unclassified at image end"))
        checkpoint("attempt " & $attempt & ": printed " & $printed &
          ", missing " & $missing & ", loss reported: " & $lossReported &
          ", completeness: " & $dep.completeness)
        for r in dep.records:
          if r.kind == mrEventLoss:
            checkpoint("event-loss " & r.detail)
        if missing > 0:
          inc lateOpens
          check lossReported
          check dep.completeness != mcComplete
      # The thread must actually have outlived the drain at least once, or
      # nothing above was graded.
      checkpoint("runs with opens after the final drain: " & $lateOpens)
      check lateOpens >= 2
      removeDir(work)
