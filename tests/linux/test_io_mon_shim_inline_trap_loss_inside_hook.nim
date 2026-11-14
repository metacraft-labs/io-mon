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
## returns, and a stdio stream flushed after every library destructor makes
## one more open, so an open lands after the exit destructor drained on every
## run, whatever the scheduler does. Every open must be in the capture, or the
## capture must report the loss and not be complete; the run fails if the
## late open did not happen, so the case cannot go ungraded.
##
## THE THIRD TEST grades a process killed by a signal. A forked child opens
## and reads a file through its own inline `syscall` and then dies of SIGSEGV,
## SIGABRT, SIGTRAP or SIGTERM (which the shim's handlers see), or of SIGKILL,
## SIGUSR1, or a SIGSEGV its own handler re-raises (which they do not); or the
## root crashes itself. The root of the forked variants tolerates the death
## and exits 0. A death ends the image at none of the points that classify
## trapped events, and the capture used to read complete and lack the read.
## Now each capture must record the read, or report the unclassified-events
## loss and not be complete: the loss is armed (an empty file created with no
## descriptor) before a trapped call runs and withdrawn only by a drain. Both
## dependency transports are graded, and so are:
##   - a child at its descriptor limit after its first trap ("segv-nofd") and
##     before it ("nofd-first");
##   - a child whose first trap finds a read-only fragment directory and no
##     descriptor ("rodir-first"), so the loss goes out through the set's
##     no-grow insert or the open fragment, and the same after the root has
##     filled the set's first shard ("nf-rodir"), where it may only bump the
##     growth-failure counter, which the consumer grades incomplete;
##   - a child forked after the root trapped ("rf"), which inherits an armed
##     word naming its parent and must arm for itself;
##   - a child with a thread parked in an inline read while a failed exec's
##     drain withdraws the loss, whose read then returns and is queued before
##     the child is killed ("parked-kill"): the read must arm again.
## The fixture prints how the child ended, and the test checks it died of the
## intended signal, so a child that did not crash is not graded as one that
## did. Four controls must record the read and stay complete with no loss: a
## child that exits normally, one that sends itself a SIGTERM its image
## started with ignored, which it survives, one whose own SIGSEGV handler
## recovers with siglongjmp, and a root that exits with a thread parked in its
## own inline read ("bt"; the parked call never returned, so it is no
## dependency).
##
## THE FOURTH TEST grades an inline `clone(CLONE_VM)` without a child stack:
## both processes then run on one stack and the root dies of SIGSEGV with the
## trapped `clone` never classified. That capture used to read complete with
## no loss; it must now report a loss and not be complete.
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

proc longTempDir(base: string): string =
  ## A directory whose path leaves no room for an armed file's absolute path
  ## in the shim's 512-byte buffer (`CT_INLINE_ARMED_PATH_CAP`), so a
  ## fragment directory under it creates and removes armed files through the
  ## directory-descriptor route.
  result = base / "long"
  while result.len < 560:
    result = result / repeat('d', 60)
  createDir(result)

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

/* The deterministic late open. glibc's exit() runs the atexit handlers, then
 * _dl_fini (every library destructor, the shim's exit destructor and its
 * final drain among them), and only then flushes stdio. A stream made with
 * fopencookie and holding unflushed data is flushed in that last step, so its
 * write callback runs strictly after the final drain, on every run, and the
 * open it makes through the inline `syscall` is trapped after it. */
static ssize_t late_write(void *cookie, const char *buf, size_t size) {
  (void)cookie;
  long fd = raw6(SYS_openat, AT_FDCWD, (long)"input-late.txt", O_RDONLY,
                 0, 0, 0);
  if (fd < 0) _exit(32);
  close((int)fd);
  /* Raw write: the line says the open happened, and must not depend on
   * stdio, which is being flushed. */
  raw6(SYS_write, 1, (long)"late\n", 5, 0, 0, 0);
  return (ssize_t)size;
}

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
  cookie_io_functions_t io = {NULL, late_write, NULL, NULL};
  FILE *late = fopencookie(NULL, "w", io);
  if (late == NULL || fputc('x', late) == EOF) return 4;   /* left unflushed */
  pthread_t thread;
  if (pthread_create(&thread, NULL, opener, NULL) != 0) return 3;
  while (__atomic_load_n(&opened, __ATOMIC_ACQUIRE) < 20) {
    struct timespec pause = {0, 1000000};
    nanosleep(&pause, NULL);
  }
  return 0;
}
"""

# A child (or, in the "root-" modes, the root itself) opens and reads
# `input-a.txt` through the program's one inline `syscall` instruction and
# then ends as `argv[2]` says: "exit" through libc `_exit`, "segv" by a null
# store, "abort" through abort(3), "int3" by a breakpoint trap (SIGTRAP,
# which the shim's inline-syscall trap handler owns), "term" by sending
# itself SIGTERM, "segv-nofd" by a null store after lowering its descriptor
# limit to zero, "term-ignored" by sending itself a SIGTERM its image started
# with ignored, then exiting 0, "kill" by SIGKILL, "usr1" by SIGUSR1 (a
# default-terminating signal the shim does not hook), "uh-die" by a null store
# under its own SIGSEGV handler that restores the default and re-raises, and
# "uh-survive" by a null store its own handler recovers from with siglongjmp,
# then exiting 0. "nofd-first" reads, through its first trapped call, a file
# the root opened, after lowering its descriptor limit to zero, and then
# SIGKILLs itself. The root of the forked modes waits, prints how
# the child ended and exits 0.
const signalDeathSource = """
#define _GNU_SOURCE
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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

static sigjmp_buf recover;

/* A handler the program installs after the shim's, as crash reporters do:
 * it restores the default disposition and re-raises, so the process dies of
 * the signal without the shim's handler ever running. */
static void die_again(int signum) {
  signal(signum, SIG_DFL);
  raise(signum);
}

/* A handler that recovers: the process carries on and exits normally. */
static void jump_back(int signum) {
  (void)signum;
  siglongjmp(recover, 1);
}

static void install(int signum, void (*handler)(int)) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(signum, &sa, NULL) != 0) _exit(23);
}

static int inherited_fd = -1;
static int pipe_fds[2];
static volatile int parked_done = 0;

/* Inline open + read + close of `name`. */
static void read_file(const char *name) {
  char buf[64];
  long fd = raw6(SYS_openat, AT_FDCWD, (long)name, O_RDONLY, 0, 0, 0);
  if (fd < 0) _exit(20);
  if (raw6(SYS_read, fd, (long)buf, sizeof(buf), 0, 0, 0) <= 0) _exit(21);
  raw6(SYS_close, fd, 0, 0, 0, 0, 0);
}

/* A thread parked in an inline read on a pipe nobody writes (yet). */
static void *park(void *arg) {
  (void)arg;
  char c;
  raw6(SYS_read, pipe_fds[0], (long)&c, 1, 0, 0, 0);
  __atomic_store_n(&parked_done, 1, __ATOMIC_RELEASE);
  for (;;) pause();
  return NULL;
}

static void sleep_ms(long ms) {
  struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
  nanosleep(&ts, NULL);
}

/* The fragment directory the monitor named: made read-only so that no armed
 * file can be created in it, and restored by the root. */
static void fragment_dir_mode(mode_t mode) {
  const char *dir = getenv("REPRO_MONITOR_FRAGMENT_DIR");
  if (dir == NULL || chmod(dir, mode) != 0) _exit(26);
}

static void read_then_end(const char *how) {
  char buf[64];
  if (strcmp(how, "rodir-first") == 0 || strcmp(how, "nf-rodir") == 0) {
    /* The first trapped call finds neither a writable directory nor a
     * descriptor to spare: the loss must go out through the set's no-grow
     * insert (set transport) or the open fragment (file transport). */
    struct rlimit none = {0, 0};
    fragment_dir_mode(0500);
    if (setrlimit(RLIMIT_NOFILE, &none) != 0) _exit(24);
    if (raw6(SYS_read, inherited_fd, (long)buf, sizeof(buf), 0, 0, 0) <= 0)
      _exit(25);
    kill(getpid(), SIGKILL);
    for (;;) pause();
  }
  if (strcmp(how, "rf") == 0) {
    /* The root trapped first, so this child inherits an armed word that
     * names its parent; it must arm for itself. */
    read_file("input-b.txt");
    kill(getpid(), SIGKILL);
    for (;;) pause();
  }
  if (strcmp(how, "parked-kill") == 0) {
    /* A read-only call parked in the kernel does not hold back a retraction
     * (the failed exec's drain withdraws the loss), so when it returns it must
     * arm again before its event is queued. */
    pthread_t t;
    if (pipe(pipe_fds) != 0 || pthread_create(&t, NULL, park, NULL) != 0)
      _exit(27);
    sleep_ms(50);
    char *args[] = {"/nonexistent-io-mon-exec", NULL};
    execv(args[0], args);                 /* fails: a drain and a retraction */
    if (write(pipe_fds[1], "x", 1) != 1) _exit(28);
    while (!__atomic_load_n(&parked_done, __ATOMIC_ACQUIRE)) sleep_ms(1);
    kill(getpid(), SIGKILL);
    for (;;) pause();
  }
  if (strcmp(how, "nofd-first") == 0) {
    /* The first trapped call happens with no descriptor to spare, so the
     * loss armed before it cannot be a file of its own. */
    struct rlimit none = {0, 0};
    if (setrlimit(RLIMIT_NOFILE, &none) != 0) _exit(24);
    if (raw6(SYS_read, inherited_fd, (long)buf, sizeof(buf), 0, 0, 0) <= 0)
      _exit(25);
    kill(getpid(), SIGKILL);
    for (;;) pause();
  }
  if (strcmp(how, "uh-die") == 0) install(SIGSEGV, die_again);
  if (strcmp(how, "uh-survive") == 0) {
    install(SIGSEGV, jump_back);
    if (sigsetjmp(recover, 1) != 0) _exit(0);
  }
  long fd = raw6(SYS_openat, AT_FDCWD, (long)"input-a.txt", O_RDONLY, 0, 0, 0);
  if (fd < 0) _exit(20);
  if (raw6(SYS_read, fd, (long)buf, sizeof(buf), 0, 0, 0) <= 0) _exit(21);
  raw6(SYS_close, fd, 0, 0, 0, 0, 0);
  if (strcmp(how, "segv-nofd") == 0) {
    /* No new descriptor can be opened (those already open stay usable), so
     * the loss report cannot create its file of its own: on the fragment
     * transport it must go into the open fragment instead. */
    struct rlimit none = {0, 0};
    if (setrlimit(RLIMIT_NOFILE, &none) != 0) _exit(22);
    *(volatile int *)0 = 0;
  }
  if (strcmp(how, "segv") == 0 || strcmp(how, "uh-die") == 0 ||
      strcmp(how, "uh-survive") == 0)
    *(volatile int *)0 = 0;
  if (strcmp(how, "kill") == 0 || strcmp(how, "usr1") == 0) {
    kill(getpid(), how[0] == 'k' ? SIGKILL : SIGUSR1);
    for (;;) pause();
  }
  if (strcmp(how, "abort") == 0) abort();
  /* A breakpoint at no patched site: the shim's trap handler finds no site
   * and no earlier handler to chain to, and ends the process itself. */
  if (strcmp(how, "int3") == 0) __asm__ volatile("int3");
  if (strcmp(how, "term") == 0) {
    kill(getpid(), SIGTERM);
    for (;;) pause();
  }
  if (strcmp(how, "term-ignored") == 0) {
    /* SIGTERM was ignored when this image started: it survives. */
    kill(getpid(), SIGTERM);
    _exit(0);
  }
  _exit(0);
}

int main(int argc, char **argv) {
  if (argc < 3 || chdir(argv[1]) != 0) return 2;
  const char *mode = argv[2];
  if (strcmp(mode, "term-ignored") == 0 && argc == 3) {
    /* Start a new image with SIGTERM already ignored, so the shim finds it
     * ignored when it installs its handler. */
    char *args[] = {argv[0], argv[1], argv[2], "again", NULL};
    signal(SIGTERM, SIG_IGN);
    execv(argv[0], args);
    return 6;
  }
  if (strncmp(mode, "root-", 5) == 0) {
    read_then_end(mode + 5);
    return 3;
  }
  if (strcmp(mode, "bt") == 0) {
    /* The root reads inline, then leaves a thread parked in its own inline
     * read when it exits normally: the parked call never returned, so the
     * capture is sound and must be complete. */
    pthread_t t;
    read_file("input-a.txt");
    if (pipe(pipe_fds) != 0 || pthread_create(&t, NULL, park, NULL) != 0)
      return 8;
    sleep_ms(20);
    printf("child exited 0\n");
    return 0;
  }
  if (strcmp(mode, "rf") == 0) read_file("input-a.txt");
  if (strcmp(mode, "nf-rodir") == 0) {
    /* Fill the set's first shard with long missing-path probes, so the
     * child's no-grow loss element may not fit and bumps the growth-failure
     * counter instead (which the consumer must grade incomplete). */
    char name[600];
    memset(name, 'y', 200);
    name[200] = '/';
    memset(name + 201, 'x', 200);
    for (int i = 0; i < 1200; ++i) {
      snprintf(name + 401, 16, "-%d", i);
      open(name, O_RDONLY);
    }
  }
  if (strcmp(mode, "nofd-first") == 0 || strcmp(mode, "rodir-first") == 0 ||
      strcmp(mode, "nf-rodir") == 0) {
    /* Opened here, by the root, through libc; the child only reads it. */
    inherited_fd = open("input-a.txt", O_RDONLY);
    if (inherited_fd < 0) return 7;
  }
  pid_t pid = fork();
  if (pid < 0) return 4;
  if (pid == 0) read_then_end(mode);
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 5;
  if (strcmp(mode, "rodir-first") == 0 || strcmp(mode, "nf-rodir") == 0)
    fragment_dir_mode(0700);
  if (WIFSIGNALED(status))
    printf("child killed by signal %d\n", WTERMSIG(status));
  else
    printf("child exited %d\n", WEXITSTATUS(status));
  return 0;
}
"""

# An inline clone(SIGCHLD | CLONE_VM) with no child stack: parent and child
# run on one stack, and the child exits through an inline exit_group. Not a
# usable form (the parent is expected to crash), only a way to end a process
# by a signal right after it trapped a call it cannot classify.
const stacklessVmCloneSource = """
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noreturn, used)) void child_fn(void) {
  __asm__ volatile("mov $231, %%eax\n\tmov $7, %%edi\n\tsyscall" ::: "memory");
  __builtin_unreachable();
}

int main(void) {
  long ret;
  register long r10 __asm__("r10") = 0;
  register long r8 __asm__("r8") = 0;
  __asm__ volatile("syscall\n\ttest %%rax, %%rax\n\tjnz 1f\n\tcall child_fn\n1:"
                   : "=a"(ret)
                   : "a"(56L), "D"((long)(SIGCHLD | CLONE_VM)), "S"(0L),
                     "d"(0L), "r"(r10), "r"(r8)
                   : "rcx", "r11", "memory");
  if (ret < 0) return 1;
  int status = 0;
  if (waitpid((pid_t)ret, &status, 0) < 0) return 1;
  return 0;
}
"""

const unclassifiedLossPrefix =
  "inline raw syscall events unclassified at image end"

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
      # One run is enough: the host makes a late open on every run (see
      # `late_write`), so nothing here depends on the scheduler. The thread's
      # own opens are graded as well; any of them that landed after the drain
      # must be reported the same way.
      let tree = work / "tree"
      createDir(tree)
      for i in 0 ..< limit:
        writeFile(tree / ("input-" & $i & ".txt"), "x\n")
      writeFile(tree / "input-late.txt", "x\n")
      let depfile = work / "late.iomon"
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
        tree, $limit], env)
      check cap.code == 0
      var printed = 0
      var lateRan = false
      for line in cap.output.splitLines():
        if line == "late":
          lateRan = true
        elif line.len > 0 and line.allIt(it in {'0' .. '9'}):
          printed = max(printed, parseInt(line) + 1)
      check printed >= 20
      check printed < limit
      # The open after the final drain happened, so it is graded: it is in the
      # capture, or the capture reports the loss and is not complete.
      check lateRan
      let dep = readMonitorDepFile(depfile)
      var missing = 0
      for i in 0 ..< printed:
        let path = tree / ("input-" & $i & ".txt")
        if not dep.records.anyIt(it.kind == mrFileOpen and it.path == path):
          inc missing
      if not dep.records.anyIt(it.kind == mrFileOpen and
          it.path == tree / "input-late.txt"):
        inc missing
      let lossReported = dep.records.anyIt(it.kind == mrEventLoss and
        it.detail.startsWith(
          "inline raw syscall events unclassified at image end"))
      checkpoint("printed " & $printed & ", missing " & $missing &
        ", loss reported: " & $lossReported & ", completeness: " &
        $dep.completeness)
      for r in dep.records:
        if r.kind == mrEventLoss:
          checkpoint("event-loss " & r.detail)
      if missing > 0:
        check lossReported
        check dep.completeness != mcComplete
      else:
        # Everything was recorded, so the capture may be complete.
        check dep.completeness == mcComplete or lossReported
      removeDir(work)

  test "t_inline_events_of_a_process_killed_by_a_signal_are_reported":
    ## Every capture records the open and the read, or reports the loss and
    ## is not complete; the normally exiting control records both, complete.
    when not defined(amd64):
      skip()   # no inline-syscall trap backend on this architecture
    else:
      let work = expandFilename(getTempDir()) /
        ("io-mon-inline-signal-" & $getCurrentProcessId())
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
      let host = work / "signal-host"
      writeFile(host & ".c", signalDeathSource)
      let hostCc = run(cc, @[host & ".c", "-O0", "-o", host])
      checkpoint(hostCc.output)
      check hostCc.code == 0
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env.del("LD_PRELOAD")
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib

      # Both dependency transports: the shared-memory set (the default) and
      # the fragment files REPRO_MONITOR_DEP_SHM_DISABLE selects. A few modes
      # run again under a TMPDIR too long for the shim's armed-path buffer,
      # so the armed file is created ("kill", "parked-kill") and withdrawn
      # ("exit") through the directory-descriptor route.
      let longTmp = longTempDir(work)
      for (dirKind, tmp) in [("short", ""), ("long", longTmp)]:
        for transport in ["set", "file"]:
          # (mode, signal the process must die of; 0 = exits normally)
          for (mode, signum) in [("exit", 0), ("term-ignored", 0),
                                 ("uh-survive", 0), ("bt", 0), ("segv", 11),
                                 ("abort", 6), ("int3", 5), ("term", 15),
                                 ("kill", 9), ("usr1", 10), ("uh-die", 11),
                                 ("segv-nofd", 11), ("nofd-first", 9),
                                 ("rodir-first", 9), ("nf-rodir", 9),
                                 ("rf", 9), ("parked-kill", 9),
                                 ("root-segv", 11)]:
            if dirKind == "long" and mode notin ["exit", "kill", "parked-kill"]:
              continue
            checkpoint("dir: " & dirKind & ", transport: " & transport &
              ", mode: " & mode)
            var runEnv = newStringTable(modeCaseSensitive)
            for k, v in env: runEnv[k] = v
            if tmp.len > 0:
              runEnv["TMPDIR"] = tmp
            if transport == "file":
              runEnv["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"
            let tree = work / ("tree-" & dirKind & "-" & transport & "-" & mode)
            createDir(tree)
            writeFile(tree / "input-a.txt", "input a\n")
            writeFile(tree / "input-b.txt", "input b\n")
            # "rf": the dependency at stake is the child's read of input-b
            # (the root's read of input-a is drained normally).
            let input = tree / (if mode == "rf": "input-b.txt" else: "input-a.txt")
            let depfile = work / (dirKind & "-" & transport & "-" & mode &
              ".iomon")
            let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
              tree, mode], runEnv)
            checkpoint(cap.output)
            if mode.startsWith("root-"):
              # The CLI reports a signal death as 128 + signal.
              check cap.code == 128 + signum
            else:
              check cap.code == 0
              if signum == 0:
                check "child exited 0" in cap.output
              else:
                check ("child killed by signal " & $signum) in cap.output
            let dep = readMonitorDepFile(depfile)
            for r in dep.records:
              if r.kind in {mrFileOpen, mrFileRead, mrEventLoss}:
                checkpoint($r.kind & " " & r.path & " " & r.detail)
            let openRecorded = dep.records.anyIt(it.kind == mrFileOpen and
              it.path == input)
            let readRecorded = dep.records.anyIt(it.kind == mrFileRead and
              it.path == input)
            let unclassifiedLoss = dep.records.anyIt(it.kind == mrEventLoss and
              it.detail.startsWith(unclassifiedLossPrefix))
            let anyLoss = dep.records.anyIt(it.kind == mrEventLoss)
            checkpoint("open recorded: " & $openRecorded & ", read recorded: " &
              $readRecorded & ", unclassified loss: " & $unclassifiedLoss &
              ", completeness: " & $dep.completeness)
            if signum == 0:
              # The controls: a normal exit, a signal the process survives
              # because it was ignored, and a crash its own handler recovers
              # from. No spurious loss for events it goes on to classify: the
              # loss armed at its first trap is withdrawn by the drain.
              check openRecorded
              check readRecorded
              check dep.completeness == mcComplete
              check not anyLoss
            elif mode in ["nofd-first", "rodir-first", "nf-rodir"]:
              # "nofd-first" arms with no descriptor (mknodat). In the other two
              # no file can be armed at all: the loss goes out through the set's
              # no-grow insert, or the growth-failure counter when shard0 is
              # full, or the open fragment, and is not necessarily the
              # unclassified-events detail.
              check not (dep.completeness == mcComplete and not readRecorded)
              check readRecorded or (anyLoss and dep.completeness != mcComplete)
            else:
              # Never complete without the read the process made.
              check not (dep.completeness == mcComplete and not readRecorded)
              check (openRecorded and readRecorded) or
                (unclassifiedLoss and dep.completeness != mcComplete)
      removeDir(work)

  test "t_stackless_vm_clone_root_killed_by_a_signal_is_not_complete":
    ## The trapped clone is never classified, so the capture reports a loss
    ## and is not complete.
    when not defined(amd64):
      skip()   # no inline-syscall trap backend on this architecture
    else:
      let work = expandFilename(getTempDir()) /
        ("io-mon-inline-vm-nostack-" & $getCurrentProcessId())
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
      let host = work / "vm-nostack"
      writeFile(host & ".c", stacklessVmCloneSource)
      let hostCc = run(cc, @[host & ".c", "-O0", "-o", host])
      checkpoint(hostCc.output)
      check hostCc.code == 0
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env.del("LD_PRELOAD")
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib
      for attempt in 0 ..< 3:
        let depfile = work / ("vm-nostack-" & $attempt & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host],
          env)
        checkpoint("attempt " & $attempt & " exit " & $cap.code & ": " &
          cap.output)
        let dep = readMonitorDepFile(depfile)
        for r in dep.records:
          if r.kind == mrEventLoss:
            checkpoint("event-loss " & r.detail)
        checkpoint("completeness: " & $dep.completeness)
        check dep.records.anyIt(it.kind == mrEventLoss)
        check dep.completeness != mcComplete
      removeDir(work)
