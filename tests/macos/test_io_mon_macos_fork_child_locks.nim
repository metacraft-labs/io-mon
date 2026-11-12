## A fork child of a multi-threaded process never waits on a shim lock, and
## never drops evidence silently (macOS).
##
## WHY. A thread of a multi-threaded process may hold one of the shim's locks
## at the instant another thread forks. The child inherits that lock held by a
## thread that does not exist in it. The macOS shim used to take its locks in
## the child anyway: Rust's `Command::spawn` closes descriptors and Go's
## `syscall.forkExec` `dup2`s them between fork and exec, both calls reached
## the descriptor table under `fdLock`, and a child whose parent had a thread
## inside that table at the fork waited on the lock forever (cargo and
## `go build` under `repro build`; every sample of the hung child sat in
## `__psynch_mutexwait` under `repro_hook_close` / `copyFdPath`).
##
## Now the shim's atfork child handler looks at every lock that guards a shim
## table. When none was held (the common case) the child records like the
## child of a single-threaded parent. When one was, the child forwards every
## hook without touching shim tables until it execs, and a hook that would
## have produced evidence reports event-loss once. The two locks whose state is
## trivial (the record sequence lock and the fragment registry lock) are
## re-initialised instead, so the child still records.
##
## WHAT IS GRADED. A host starts a second thread, then forks children that
## either open and read a file through libc ("read") or only `dup2` and `close`
## descriptors ("fdops", the Rust/Go shape), and then exec a no-op program or
## `_exit`. A child that hangs is killed by its own `alarm`, which fails the
## host, so a regression fails the test instead of stalling it.
##
## - an idle second thread: no lock can be held, so the child's open must be
##   recorded, with no skipped-evidence loss.
## - a second thread hammering the descriptor hooks (open/read/dup2/close/
##   getenv/stat) while the main thread forks hundreds of fdops children: no
##   child may hang. Without the fix this hangs within a few hundred forks.
##   The same with read children: every open is recorded, or the capture
##   reports the loss and is not complete.
## - a second thread holding each shim lock across the fork, deterministically,
##   through the test-only export of a `-d:ioMonShimForkLockTest` shim: the
##   child must not hang. For a table lock it must skip and report its open as
##   loss; an fdops child that execs reports the exec record it skipped. For
##   the two re-initialised locks it must record. A control gives each lock
##   back before the fork and must record.
##
## Mocks: none. Real programs, real shim, real files. The held-lock case adds
## one test-only export to the shim and nothing else.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, unittest]

when defined(macosx):
  import std/[osproc, sequtils, streams, strtabs, strutils, times]
  import io_mon
  import build_test_shim
  import macos_backend_toggle
  import unmonitored_env

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  testRunId = "io-mon-macos-fork-child-locks"
  skippedEvidenceDetail = "macos fork child skipped evidence before exec"
  # Forks per contention run, and contention runs. Measured without the fix
  # on an M1 (macOS 26.5.2), over three runs of this file: 4 of 9 fdops runs
  # and 9 of 9 read runs hung, each within its first 400 forks, so every run
  # of the file failed. With the fix, none of 18 runs of either kind hung
  # (six runs of the file).
  busyForks = 1500
  busyRuns = 3

when defined(macosx):
  const hostSource = """
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *noop;
static const char *ending;   /* exec | exit */
static const char *work;     /* read | fdops */
static volatile int stop = 0;

/* An idle second thread: it makes the process multi-threaded and is never
 * inside a hook. */
static void *idle_thread(void *arg) {
  (void)arg;
  for (;;) pause();
  return NULL;
}

/* A second thread hammering hooked calls, so a fork catches it inside a
 * shim lock: the descriptor table (open, dup2, close), the observed-input
 * set (getenv), the realpath memo (stat). */
static void *busy_thread(void *arg) {
  (void)arg;
  struct stat st;
  while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
    int fd = open("busy.txt", O_RDONLY);
    if (fd >= 0) {
      char c;
      (void)read(fd, &c, 1);
      (void)dup2(fd, 50);
      close(50);
      close(fd);
    }
    (void)getenv("HOME");
    (void)stat("busy.txt", &st);
  }
  return NULL;
}

/* A second thread holding shim lock `held_lock` at the fork, through the
 * test-only export of a shim built with -d:ioMonShimForkLockTest. It takes
 * the lock, says so, and gives it back only once the child has started: the
 * child's atfork handler ran before that, so the child sees the lock held
 * every time. ("release" mode gives it back before saying so.) */
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

static void child_body(const char *name) {
  /* A child that waits forever on a shim lock dies of SIGALRM, which fails
   * the run (the parent's alarm is not inherited by a fork child). */
  alarm(20);
  if (strcmp(work, "read") == 0) {
    int fd = open(name, O_RDONLY);
    if (fd < 0) _exit(20);
    char buf[16];
    if (read(fd, buf, sizeof(buf)) <= 0) _exit(21);
    close(fd);
  } else {
    /* What Rust's and Go's spawn do between fork and exec. */
    if (dup2(2, 60) != 60) _exit(25);
    close(60);
    close(61);
  }
  if (strcmp(ending, "exec") == 0) {
    char *args[] = {(char *)noop, NULL};
    execv(noop, args);
    _exit(22);
  }
  _exit(0);
}

static int fork_one(const char *name, int index) {
  pid_t pid = fork();
  if (pid == 0) {
    if (child_started) __atomic_store_n(child_started, 1, __ATOMIC_RELEASE);
    child_body(name);
  }
  if (pid < 0) return 0;
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 0;
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 1;
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM)
    fprintf(stderr, "fork %d: child %d HUNG (killed by its alarm)\n", index,
            (int)pid);
  else
    fprintf(stderr, "fork %d: child %d failed, status 0x%x\n", index,
            (int)pid, status);
  return 0;
}

/* argv: tree thread(idle|busy|hold:N|release:N) work(read|fdops)
 * ending(exec|exit) noop count */
int main(int argc, char **argv) {
  if (argc < 7 || chdir(argv[1]) != 0) return 2;
  const char *thread = argv[2];
  work = argv[3];
  ending = argv[4];
  noop = argv[5];
  int count = atoi(argv[6]);
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
                         MAP_SHARED | MAP_ANON, -1, 0);
    if (child_started == MAP_FAILED) return 5;
    *child_started = 0;
    body = holder_thread;
  }
  if (pthread_create(&t, NULL, body, NULL) != 0) return 3;
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
    snprintf(name, sizeof(name), "input-%d.txt", i % 8);
    if (!fork_one(name, i)) return 10;
  }
  __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
  if (strcmp(thread, "busy") == 0 || hold_lock != NULL) pthread_join(t, NULL);
  return 0;
}
"""

  type Fixture = object
    work, host, noop, shim: string

  proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
      tuple[output: string; code: int] =
    let p = startProcess(cmd, args = args, env = env,
      options = {poStdErrToStdOut, poUsePath})
    let output = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    (output, code)

  proc cc(src, outBin: string) =
    let built = run(getEnv("CC", "cc"), @["-arch", "arm64", "-O0", src, "-o",
      outBin])
    checkpoint(built.output)
    doAssert built.code == 0, "cc failed: " & src

  proc setUpFixture(tag: string; shimFlags: openArray[string] = []): Fixture =
    result.work = expandFilename(getTempDir()) /
      ("io-mon-macos-fork-locks-" & tag & "-" & $getCurrentProcessId())
    removeDir(result.work)
    createDir(result.work)
    result.shim =
      if shimFlags.len == 0: buildPrivateMacosShim(repoRoot)
      else: buildPrivateMacosShimWithFlags(repoRoot, shimFlags)
    result.host = result.work / "fork-host"
    writeFile(result.host & ".c", hostSource)
    cc(result.host & ".c", result.host)
    result.noop = result.work / "noop"
    writeFile(result.noop & ".c", "int main(void) { return 0; }\n")
    cc(result.noop & ".c", result.noop)

  type Outcome = object
    hostCode: int
    missing: int
    skippedLoss: bool
    complete: bool

  proc capture(f: Fixture; tag, thread, work, ending: string;
               count: int): Outcome =
    let tree = f.work / ("tree-" & tag & "-" & $epochTime())
    createDir(tree)
    writeFile(tree / "busy.txt", "b\n")
    for i in 0 ..< 8:
      writeFile(tree / ("input-" & $i & ".txt"), "child input\n")
    let fragmentDir = tree / "frags"
    createDir(fragmentDir)
    var env = unmonitoredEnv()
    env.del("CT_SANDBOX_TOOLS_DIR")
    env["DYLD_INSERT_LIBRARIES"] = f.shim
    env["REPRO_MONITOR_SHIM_LIB"] = f.shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    env["REPRO_MONITOR_SESSION"] = testRunId
    applyMacosBackendToggle(env, "both")
    let started = epochTime()
    let host = run(f.host, @[tree, thread, work, ending, f.noop, $count], env)
    checkpoint(tag & ": host exit " & $host.code & " after " &
      formatFloat(epochTime() - started, ffDecimal, 1) & " s: " & host.output)
    result.hostCode = host.code
    let depfile = tree / "cap.iomon"
    discard mergeFragments(fragmentDir, depfile, currentRunId = testRunId)
    let dep = readMonitorDepFile(depfile)
    if work == "read":
      for i in 0 ..< min(count, 8):
        let path = tree / ("input-" & $i & ".txt")
        if not dep.records.anyIt(it.kind == mrFileOpen and it.path == path):
          inc result.missing
    result.skippedLoss = dep.records.anyIt(it.kind == mrEventLoss and
      it.detail.startsWith(skippedEvidenceDetail))
    result.complete = dep.completeness == mcComplete
    for r in dep.records:
      if r.kind == mrEventLoss:
        checkpoint(tag & ": event-loss " & r.detail)
    checkpoint(tag & ": missing " & $result.missing &
      ", skipped-evidence loss: " & $result.skippedLoss & ", completeness: " &
      $dep.completeness)
    removeDir(tree)

suite "io-mon macOS shim: fork children of multi-threaded processes":
  when defined(macosx):
    test "t_fork_child_of_idle_threaded_parent_records_its_evidence":
      ## No lock can be held by an idle thread, so the child records its open.
      let f = setUpFixture("idle")
      for ending in ["exec", "exit"]:
        let o = capture(f, "idle-" & ending, "idle", "read", ending, 1)
        check o.hostCode == 0
        check o.missing == 0
        check not o.skippedLoss
      removeDir(f.work)

    test "t_fork_child_never_hangs_on_a_lock_another_thread_held":
      ## The reported hang: a thread inside the descriptor hooks at the fork,
      ## and a child that dup2s and closes before exec. No child may hang.
      let f = setUpFixture("busy")
      for attempt in 0 ..< busyRuns:
        let o = capture(f, "busy-fdops-" & $attempt, "busy", "fdops", "exec",
          busyForks)
        check o.hostCode == 0
      removeDir(f.work)

    test "t_fork_child_under_contention_is_recorded_or_reported":
      ## Every child's open is in the capture, or the capture reports the loss
      ## and is not complete; never complete with an open missing.
      let f = setUpFixture("busyread")
      for attempt in 0 ..< busyRuns:
        let o = capture(f, "busy-read-" & $attempt, "busy", "read", "exit",
          busyForks div 4)
        check o.hostCode == 0
        check o.missing == 0 or (o.skippedLoss and not o.complete)
        check not (o.complete and o.missing > 0)
      removeDir(f.work)

    test "t_fork_child_with_a_held_shim_lock_does_not_hang":
      ## Deterministic: a second thread holds one shim lock across the fork and
      ## gives it back only after the child started. Table locks (0..6): the
      ## child skips, and reports the open it made as loss; an fdops child
      ## that execs reports the exec record it skipped.
      ## Re-initialised locks (7 record, 8 fragment registry): the child
      ## records. Controls give the lock back before the fork and record.
      let f = setUpFixture("held", ["-d:ioMonShimForkLockTest"])
      for lock in 0 .. 8:
        let held = capture(f, "hold-" & $lock, "hold:" & $lock, "read",
          "exit", 1)
        check held.hostCode == 0
        if lock <= 6:
          check held.missing == 1
          check held.skippedLoss
          check not held.complete
        else:
          check held.missing == 0
          check not held.skippedLoss
        let fdops = capture(f, "hold-fdops-" & $lock, "hold:" & $lock,
          "fdops", "exec", 1)
        check fdops.hostCode == 0
        # A table-lock child skips its exec record, which the merge needs to
        # see an exec into an image the shim cannot enter, so it reports.
        check fdops.skippedLoss == (lock <= 6)
        let control = capture(f, "release-" & $lock, "release:" & $lock,
          "read", "exit", 1)
        check control.hostCode == 0
        check control.missing == 0
        check not control.skippedLoss
      removeDir(f.work)
  else:
    test "the macOS fork-child lock test is macOS-only (no-op here)":
      check true
