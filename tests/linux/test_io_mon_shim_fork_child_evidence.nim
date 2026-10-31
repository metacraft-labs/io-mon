## A fork child of a multi-threaded process never drops evidence silently.
##
## WHY. A thread of a multi-threaded process may hold one of the shim's locks
## at the instant another thread forks. The child inherits that lock held by
## a thread that does not exist in it, so recording anything there could wait
## forever. The shim therefore used to make EVERY child of a multi-threaded
## parent skip monitor bookkeeping until it exec'd -- and a child that read a
## file before its exec (or that never exec'd) left a capture that graded
## complete without that read.
##
## Now the libc fork child samples, in its atfork handler, whether any shim
## lock was held at the fork. When none was (the common case), it records like
## the child of a single-threaded parent. When one was, or when the child was
## made by a raw fork-like system call (`syscall(SYS_clone)`, glibc's
## `clone()` or `_Fork()`, or an inline `syscall` instruction the trap
## replays), which runs
## no atfork reset at all, it still skips bookkeeping, but a hook that would
## have produced evidence reports event-loss.
##
## WHAT IS GRADED. A host starts a second thread, then forks a child that
## opens and reads a file through libc and either execs a no-op program or
## `_exit`s. Each capture must record the child's open, or report the loss and
## not be complete; it must never be complete without the open.
##
## - libc `fork` with an idle second thread: no lock can be held, so the open
##   must be recorded, with no skipped-evidence loss.
## - libc `fork` with a second thread hammering hooked calls: forty forks per
##   run, each child reading its own file; every one is recorded or the
##   capture reports the loss.
## - libc `fork` whose child resets signal state through `syscall(2)` before
##   exec'ing, as Chromium's launcher does: the child records, and the
##   capture stays complete (those calls read nothing).
## - raw clones (`syscall(SYS_clone)`, glibc `clone()`, glibc 2.34's
##   `_Fork()`, and on x86_64 an inline `syscall` instruction), none of which
##   runs atfork handlers: the child skips bookkeeping, so the
##   capture must report the skipped-evidence loss and not be complete.
## - libc `fork` while a second thread holds a shim lock, each lock the
##   atfork child handler checks in turn: the child must skip and report.
##   Contention cannot force that path, so a shim built with the test-only
##   `-d:ioMonShimForkLockTest` exports `repro_test_fork_hold_lock`, which
##   the second thread calls to take the lock and give it back after the
##   child started. A control gives it back before the fork and must record.
##
## Mocks: none. Real programs, real shim, real files. The held-lock case
## adds one test-only export to the shim and nothing else.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import unmonitored_env
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  skippedEvidenceDetail = "linux fork child skipped evidence before exec"

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
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
/* The only `syscall` instruction in this program, patched to trap. */
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
#endif

static const char *noop;
static const char *ending;
static volatile int stop = 0;

/* An idle second thread: it makes the process multi-threaded and is never
 * inside a hook. */
static void *idle_thread(void *arg) {
  (void)arg;
  for (;;) pause();
  return NULL;
}

/* A second thread hammering hooked calls, so a fork can catch it holding a
 * shim lock. */
static void *busy_thread(void *arg) {
  (void)arg;
  struct stat st;
  while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
    int fd = open("busy.txt", O_RDONLY);
    if (fd >= 0) {
      char c;
      (void)read(fd, &c, 1);
      close(fd);
    }
    (void)stat("busy.txt", &st);
  }
  return NULL;
}

/* A second thread holding shim lock `held_lock` at the fork, through the
 * test-only export of a shim built with -d:ioMonShimForkLockTest. It takes
 * the lock, says so, and gives it back only once the child has started:
 * the child's atfork handler ran before that, so the child sees the lock
 * held every time. ("release" mode gives it back before saying so.) */
typedef int (*hold_fn)(int, int);
static hold_fn hold_lock;
static int held_lock;
static int hold_across_fork;
static volatile int lock_state = 0;   /* 1 once the holder is ready */
static volatile int *child_started;   /* shared with the child */

static void *holder_thread(void *arg) {
  (void)arg;
  if (!hold_lock(held_lock, 1)) _exit(30);
  if (!hold_across_fork) hold_lock(held_lock, 0);
  __atomic_store_n(&lock_state, 1, __ATOMIC_RELEASE);
  if (hold_across_fork) {
    while (!__atomic_load_n(child_started, __ATOMIC_ACQUIRE)) {
    }
    hold_lock(held_lock, 0);
  }
  return NULL;
}

/* The child's evidence: a libc open and read, then the chosen ending.
 * "sigreset-exec" first resets signal state through syscall(2), as
 * Chromium's process launcher does between fork and exec. */
static int child_body(void *name) {
  /* A child that waits forever on a shim lock fails the run (the parent's
   * alarm is not inherited). */
  alarm(60);
  if (strcmp(ending, "sigreset-exec") == 0) {
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigset_t none;
    sigemptyset(&none);
    if (syscall(SYS_rt_sigaction, SIGTERM, &dfl, NULL, 8) != 0) _exit(23);
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &none, NULL, 8) != 0)
      _exit(24);
  }
  int fd = open((const char *)name, O_RDONLY);
  if (fd < 0) _exit(20);
  char buf[16];
  if (read(fd, buf, sizeof(buf)) <= 0) _exit(21);
  close(fd);
  if (strcmp(ending, "exec") == 0 || strcmp(ending, "sigreset-exec") == 0) {
    char *args[] = {(char *)noop, NULL};
    execv(noop, args);
    _exit(22);
  }
  _exit(0);
}

static int wait_ok(pid_t pid) {
  int status = 0;
  if (pid < 0) return 0;
  if (waitpid(pid, &status, 0) != pid) return 0;
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static char clone_stack[256 * 1024];

static int fork_one(const char *route, const char *name) {
  pid_t pid;
  if (strcmp(route, "fork") == 0) {
    pid = fork();
    if (pid == 0) {
      if (child_started) __atomic_store_n(child_started, 1, __ATOMIC_RELEASE);
      child_body((void *)name);
    }
  } else if (strcmp(route, "syscall-clone") == 0) {
    pid = (pid_t)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (pid == 0) child_body((void *)name);
#if __GLIBC_PREREQ(2, 34)
  } else if (strcmp(route, "_Fork") == 0) {
    pid = _Fork();
    if (pid == 0) child_body((void *)name);
#endif
  } else if (strcmp(route, "glibc-clone") == 0) {
    pid = clone(child_body, clone_stack + sizeof(clone_stack), SIGCHLD,
                (void *)name);
#if defined(__x86_64__)
  } else if (strcmp(route, "inline-clone") == 0) {
    pid = (pid_t)raw6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (pid == 0) child_body((void *)name);
#endif
  } else {
    return 0;
  }
  return wait_ok(pid);
}

/* argv: tree route thread(none|idle|busy|hold:N|release:N) ending(exec|exit)
 * noop count */
int main(int argc, char **argv) {
  if (argc < 7 || chdir(argv[1]) != 0) return 2;
  const char *route = argv[2];
  const char *thread = argv[3];
  ending = argv[4];
  noop = argv[5];
  int count = atoi(argv[6]);
  /* A shim lock wait that never ends fails the run instead of hanging it. */
  alarm(60);
  pthread_t t;
  void *(*body)(void *) = idle_thread;
  if (strcmp(thread, "busy") == 0) {
    body = busy_thread;
  } else if (strncmp(thread, "hold:", 5) == 0 ||
             strncmp(thread, "release:", 8) == 0) {
    hold_across_fork = thread[0] == 'h';
    held_lock = atoi(strchr(thread, ':') + 1);
    hold_lock = (hold_fn)dlsym(RTLD_DEFAULT, "repro_test_fork_hold_lock");
    if (hold_lock == NULL) return 4;
    child_started = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (child_started == MAP_FAILED) return 5;
    *child_started = 0;
    body = holder_thread;
  }
  /* "none": a single-threaded parent. */
  if (strcmp(thread, "none") != 0 && pthread_create(&t, NULL, body, NULL) != 0)
    return 3;
  if (hold_lock != NULL) {
    while (!__atomic_load_n(&lock_state, __ATOMIC_ACQUIRE)) {
    }
  }
  if (strcmp(thread, "busy") == 0) {
    struct timespec pause = {0, 2000000};
    nanosleep(&pause, NULL);
  }
  for (int i = 0; i < count; i++) {
    char name[32];
    snprintf(name, sizeof(name), "input-%d.txt", i);
    if (!fork_one(route, name)) return 10;
  }
  __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
  if (strcmp(thread, "busy") == 0 || hold_lock != NULL) pthread_join(t, NULL);
  return 0;
}
"""

type Fixture = object
  work, snoopBin, host, noop: string
  env: StringTableRef

proc setUpFixture(tag: string; shimFlags: openArray[string] = []): Fixture =
  result.work = expandFilename(getTempDir()) /
    ("io-mon-fork-child-" & tag & "-" & $getCurrentProcessId())
  removeDir(result.work)
  createDir(result.work)
  let shimLib =
    if shimFlags.len == 0: buildPrivateLinuxShim(repoRoot)
    else: buildPrivateLinuxShimWithFlags(repoRoot, shimFlags)
  result.snoopBin = result.work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & result.snoopBin, snoopSrc])
  checkpoint(cli.output)
  doAssert cli.code == 0, "io-mon CLI build failed"
  let cc = getEnv("CC", "cc")
  result.host = result.work / "fork-host"
  writeFile(result.host & ".c", hostSource)
  let hostCc = run(cc, @[result.host & ".c", "-O0", "-pthread", "-o",
    result.host])
  checkpoint(hostCc.output)
  doAssert hostCc.code == 0, "host build failed"
  result.noop = result.work / "noop"
  writeFile(result.noop & ".c", "int main(void) { return 0; }\n")
  let noopCc = run(cc, @[result.noop & ".c", "-o", result.noop])
  doAssert noopCc.code == 0, "noop build failed"
  result.env = unmonitoredEnv()
  result.env["REPRO_MONITOR_SHIM_LIB"] = shimLib

type Outcome = object
  missing: int
  skippedLoss: bool
  complete: bool

proc capture(f: Fixture; tag, route, thread, ending: string;
             count: int): Outcome =
  let tree = f.work / ("tree-" & tag)
  createDir(tree)
  writeFile(tree / "busy.txt", "b\n")
  for i in 0 ..< count:
    writeFile(tree / ("input-" & $i & ".txt"), "child input\n")
  let depfile = f.work / (tag & ".iomon")
  let cap = run(f.snoopBin, @["run", "--depfile", depfile, "--", f.host,
    tree, route, thread, ending, f.noop, $count], f.env)
  checkpoint(tag & ": " & cap.output)
  doAssert cap.code == 0, tag & ": host failed with " & $cap.code
  let dep = readMonitorDepFile(depfile)
  for i in 0 ..< count:
    let path = tree / ("input-" & $i & ".txt")
    if not dep.records.anyIt(it.kind == mrFileOpen and it.path == path):
      inc result.missing
  result.skippedLoss = dep.records.anyIt(it.kind == mrEventLoss and
    it.detail.startsWith(skippedEvidenceDetail))
  result.complete = dep.completeness == mcComplete
  for r in dep.records:
    if r.kind == mrEventLoss:
      checkpoint(tag & ": event-loss " & r.detail)
  checkpoint(tag & ": missing " & $result.missing & ", skipped-evidence loss: " &
    $result.skippedLoss & ", completeness: " & $dep.completeness)

suite "io-mon Linux shim: fork children of multi-threaded processes":
  test "t_libc_fork_child_records_its_evidence":
    ## No lock can be held by an idle thread, so the child records its open.
    let f = setUpFixture("libc")
    for ending in ["exec", "exit"]:
      let o = capture(f, "fork-idle-" & ending, "fork", "idle", ending, 1)
      check o.missing == 0
      check not o.skippedLoss
    removeDir(f.work)

  test "t_launcher_child_resetting_signals_stays_complete":
    ## rt_sigaction and rt_sigprocmask through syscall(2) read nothing, so a
    ## recording child that makes them adds no loss.
    let f = setUpFixture("sig")
    let o = capture(f, "fork-sigreset", "fork", "idle", "sigreset-exec", 1)
    check o.missing == 0
    check not o.skippedLoss
    check o.complete
    removeDir(f.work)

  test "t_libc_fork_child_under_contention_is_recorded_or_reported":
    ## Every child's open is in the capture, or the capture reports the loss
    ## and is not complete.
    let f = setUpFixture("busy")
    for attempt in 0 ..< 3:
      let o = capture(f, "fork-busy-" & $attempt, "fork", "busy", "exit", 40)
      check o.missing == 0 or (o.skippedLoss and not o.complete)
      check not (o.complete and o.missing > 0)
    removeDir(f.work)

  test "t_raw_clone_child_reports_skipped_evidence":
    ## A raw clone runs no atfork reset, so its child skips bookkeeping; the
    ## open it made is then reported as loss, never silently dropped.
    let f = setUpFixture("raw")
    var routes = @["syscall-clone", "glibc-clone", "_Fork"]
    when defined(amd64):
      routes.add "inline-clone"
    for route in routes:
      for ending in ["exec", "exit"]:
        let o = capture(f, route & "-" & ending, route, "idle", ending, 1)
        # The parent is multi-threaded, so a raw clone's child always skips:
        # its open is missing and the loss is reported.
        check o.missing == 1
        check o.skippedLoss
        check not o.complete
    removeDir(f.work)

  test "t_libc_fork_child_with_a_held_shim_lock_reports_skipped_evidence":
    ## Deterministic: a second thread holds one shim lock across the fork
    ## (through the test-only export of a `-d:ioMonShimForkLockTest` shim)
    ## and gives it back only after the child started. The child must find
    ## it held, skip bookkeeping, and report the open it made as loss. One
    ## case per lock the atfork child handler checks; dropping any of them
    ## from the check records into possibly half-updated state and fails
    ## its case here. The control takes and gives back the same lock before
    ## the fork, and must record.
    let f = setUpFixture("held", ["-d:ioMonShimForkLockTest"])
    for lock in 0 .. 7:
      let held = capture(f, "fork-hold-" & $lock, "fork", "hold:" & $lock,
        "exit", 1)
      check held.missing == 1
      check held.skippedLoss
      check not held.complete
      let control = capture(f, "fork-release-" & $lock, "fork",
        "release:" & $lock, "exit", 1)
      check control.missing == 0
      check not control.skippedLoss
    removeDir(f.work)
