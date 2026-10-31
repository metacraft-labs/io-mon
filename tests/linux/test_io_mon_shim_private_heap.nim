## The shim's private heap stays live in every monitored process.
##
## WHY. The preloaded shim allocates from its own heap
## (`src/io_mon/shim/linux_private_heap.c`), inside hooks, i.e. at whatever
## moment the host made the hooked call. A lock that heap waits on forever
## hangs the host, and a host has three ordinary ways to make one: a signal
## handler that makes a hooked call (open, stat, clock_gettime are
## async-signal-safe) while the interrupted thread is inside the allocator; a
## fork() while another thread holds a class lock; and a raw clone() — which
## runs no atfork handlers — at such a moment. Each is a race the host wins
## only rarely, which is why a deterministic check is needed besides a stress
## run.
##
## WHAT THIS TEST GRADES — on a debug and a release shim:
##   1. `t_private_heap_selftest` — from inside a real host, the heap's own
##      selftest (`repro_linux_private_heap_selftest`): the malloc / calloc /
##      realloc / free contracts (malloc(0), free(NULL), 16-byte alignment,
##      calloc overflow and zeroing, realloc across every class boundary and
##      to and from a block with its own mapping, a failed realloc keeping
##      the block), and, by forging the states the races above produce, that
##      a re-entered call neither waits nor touches the interrupted class,
##      that a lock inherited from a vanished thread is reclaimed by the
##      raw-fork child hook, and that a hold which never ends delays one
##      caller by a bounded time and none after it.
##   2. `t_private_heap_survives_signals_forks_and_raw_clones` — a host whose
##      threads make hooked calls in a loop while a profiling timer runs a
##      signal handler making hooked calls, and other threads create children
##      that make hooked calls, by every route a process can be created
##      without CLONE_VM: fork(), syscall(SYS_clone), an inline `syscall`
##      instruction issuing clone (which the shim reaches only through its
##      inline-syscall trap; x86_64), and glibc's clone(3) wrapper (whose
##      system call is made inside libc). It must finish, preloaded and under
##      `io-mon run`, with every child exiting, within its time limit.
##   3. A mismatched `REPRO_MONITOR_SHIM_LIB` on the preloaded timeout
##      wrapper injects a second distinct shim at exec. Both images must let
##      the stress host's raw-clone children finish. The host reports its
##      actual loaded-image count so this cannot silently become a one-image
##      test. Same-path, unset and nonexistent overrides are controls.
##
## Mocks: none. The hosts are real programs and the shim is the built
## library; the selftest forges lock states because the races it stands in
## for cannot be scheduled from outside.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import unmonitored_env

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  HostTimeoutSeconds = "180"
    ## The stress host runs for a few seconds; a hang is what this catches.

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
  let built = run(getEnv("CC", "cc"), @[sourcePath, "-o", result] & extraArgs)
  checkpoint(name & " cc: " & built.output)
  check built.code == 0

proc baseEnv(): StringTableRef =
  ## The children's base environment: no preload and no inherited
  ## `REPRO_MONITOR_*` setting of an enclosing monitor (see
  ## `unmonitored_env`). Monitored arms set `REPRO_MONITOR_SHIM_LIB` themselves.
  unmonitoredEnv()

proc ensureShim(): string =
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(built.output)
  check built.code == 0
  findShimLibrary()

proc ensureReleaseShim(work: string): string =
  var env = baseEnv()
  env["IO_MON_BUILD_MODE"] = "release"
  env["IO_MON_SHIM_OUT_DIR"] = work / "release-lib"
  env["IO_MON_SHIM_NIMCACHE_DIR"] = work / "release-nimcache"
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"], env)
  checkpoint(built.output)
  check built.code == 0
  result = work / "release-lib" / "librepro_monitor_shim.so"

proc ensureSnoop(work: string): string =
  result = work / "io-mon"
  if not fileExists(result):
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & result, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

const selftestHostSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
  int (*selftest)(void) =
      (int (*)(void))dlsym(RTLD_DEFAULT, "repro_linux_private_heap_selftest");
  if (selftest == NULL) { printf("selftest missing\n"); return 2; }
  int failed = selftest();
  printf("selftest result=%d\n", failed);
  return failed == 0 ? 0 : 1;
}
"""

const stressHostSource = """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *file;
static atomic_int stop, failed;
static atomic_long calls, signals_seen, forks, clones, inline_clones,
    libc_clones;

static int count_shim(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size;
  if (strstr(info->dlpi_name, "librepro_monitor_shim.so") != NULL)
    ++*(int *)data;
  return 0;
}

/* Hooked calls the shim records, and nothing that allocates from the host's
 * allocator: they also run in raw-clone children, where glibc's own malloc
 * may be locked by a thread that does not exist there. */
static void hooked_calls(void) {
  struct stat st;
  stat(file, &st);
  int fd = open(file, O_RDONLY);
  if (fd >= 0) {
    char buf[16];
    if (read(fd, buf, sizeof buf) < 0) atomic_store(&failed, 1);
    close(fd);
  }
  atomic_fetch_add(&calls, 1);
}

static void on_prof(int sig) {
  (void)sig;
  int saved = errno;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int fd = open(file, O_RDONLY);
  if (fd >= 0) close(fd);
  struct stat st;
  stat(file, &st);
  atomic_fetch_add(&signals_seen, 1);
  errno = saved;
}

static void *worker(void *arg) {
  (void)arg;
  while (!atomic_load(&stop)) hooked_calls();
  return NULL;
}

/* Every child must exit 0 within 20 s; a child stuck on a lock is a HANG. */
static void reap(pid_t pid, const char *what) {
  for (int i = 0; i < 2000; ++i) {
    int status;
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == pid) {
      if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "CHILD-FAILED %s status=%d\n", what, status);
        atomic_store(&failed, 1);
      }
      return;
    }
    if (r < 0 && errno != EINTR) { atomic_store(&failed, 1); return; }
    struct timespec ten_ms = {0, 10000000};
    nanosleep(&ten_ms, NULL);
  }
  fprintf(stderr, "HANG %s child %d\n", what, (int)pid);
  atomic_store(&failed, 1);
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
}

static void *forker(void *arg) {
  (void)arg;
  while (!atomic_load(&stop)) {
    pid_t pid = fork();
    if (pid == 0) {
      for (int i = 0; i < 3; ++i) hooked_calls();
      _exit(0);
    }
    if (pid < 0) { atomic_store(&failed, 1); return NULL; }
    reap(pid, "fork");
    atomic_fetch_add(&forks, 1);
  }
  return NULL;
}

static void *cloner(void *arg) {
  (void)arg;
  while (!atomic_load(&stop)) {
    /* No CLONE_VM, no atfork handlers: the child inherits whatever locks
     * other threads held at this instant. */
    long pid = syscall(SYS_clone, (long)SIGCHLD, 0L, 0L, 0L, 0L);
    if (pid == 0) {
      for (int i = 0; i < 3; ++i) hooked_calls();
      syscall(SYS_exit_group, 0);
    }
    if (pid < 0) { atomic_store(&failed, 1); return NULL; }
    reap((pid_t)pid, "raw clone");
    atomic_fetch_add(&clones, 1);
  }
  return NULL;
}

#if defined(__x86_64__)
/* clone(SIGCHLD) issued by a `syscall` instruction in this program, not by
 * libc: the shim sees it only by trapping the instruction. With no new stack
 * the child resumes here on its copy of this stack, like fork(). */
static long inline_clone(void) {
  register long rax __asm__("rax") = SYS_clone;
  register long rdi __asm__("rdi") = SIGCHLD;
  register long rsi __asm__("rsi") = 0;
  register long rdx __asm__("rdx") = 0;
  register long r10 __asm__("r10") = 0;
  register long r8 __asm__("r8") = 0;
  __asm__ volatile("syscall"
                   : "+r"(rax)
                   : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8)
                   : "rcx", "r11", "memory");
  return rax;
}

static void *inline_cloner(void *arg) {
  (void)arg;
  while (!atomic_load(&stop)) {
    long pid = inline_clone();
    if (pid == 0) {
      for (int i = 0; i < 3; ++i) hooked_calls();
      syscall(SYS_exit_group, 0);
    }
    if (pid < 0) { atomic_store(&failed, 1); return NULL; }
    reap((pid_t)pid, "inline clone");
    atomic_fetch_add(&inline_clones, 1);
  }
  return NULL;
}
#endif

/* glibc's clone(3) without CLONE_VM: a process whose clone system call is
 * made inside libc. Each child gets a copy of this stack area to run on. */
static char libc_clone_stack[64 * 1024] __attribute__((aligned(16)));

static int libc_clone_child(void *arg) {
  (void)arg;
  for (int i = 0; i < 3; ++i) hooked_calls();
  return 0;
}

static void *libc_cloner(void *arg) {
  (void)arg;
  while (!atomic_load(&stop)) {
    int pid = clone(libc_clone_child,
                    libc_clone_stack + sizeof(libc_clone_stack), SIGCHLD,
                    NULL);
    if (pid < 0) { atomic_store(&failed, 1); return NULL; }
    reap((pid_t)pid, "libc clone");
    atomic_fetch_add(&libc_clones, 1);
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 3) return 2;
  int shim_images = 0;
  dl_iterate_phdr(count_shim, &shim_images);
  printf("shim_images=%d\n", shim_images);
  fflush(stdout);
  file = argv[1];
  int seconds = atoi(argv[2]);
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_prof;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGPROF, &sa, NULL);
  struct itimerval tv = {{0, 500}, {0, 500}};
  setitimer(ITIMER_PROF, &tv, NULL);

  enum { WORKERS = 6 };
  pthread_t threads[WORKERS + 4];
  int nthreads = 0;
  for (int i = 0; i < WORKERS; ++i)
    pthread_create(&threads[nthreads++], NULL, worker, NULL);
  pthread_create(&threads[nthreads++], NULL, forker, NULL);
  pthread_create(&threads[nthreads++], NULL, cloner, NULL);
#if defined(__x86_64__)
  pthread_create(&threads[nthreads++], NULL, inline_cloner, NULL);
#endif
  pthread_create(&threads[nthreads++], NULL, libc_cloner, NULL);

  struct timespec end, now;
  clock_gettime(CLOCK_MONOTONIC, &end);
  end.tv_sec += seconds;
  do {
    struct timespec tick = {0, 50000000};
    nanosleep(&tick, NULL);
    clock_gettime(CLOCK_MONOTONIC, &now);
  } while (now.tv_sec < end.tv_sec ||
           (now.tv_sec == end.tv_sec && now.tv_nsec < end.tv_nsec));
  atomic_store(&stop, 1);
  for (int i = 0; i < nthreads; ++i) pthread_join(threads[i], NULL);
  struct itimerval off = {{0, 0}, {0, 0}};
  setitimer(ITIMER_PROF, &off, NULL);

  printf("stress done calls=%ld signals=%ld forks=%ld clones=%ld "
         "inline_clones=%ld libc_clones=%ld failed=%d\n",
         atomic_load(&calls), atomic_load(&signals_seen), atomic_load(&forks),
         atomic_load(&clones), atomic_load(&inline_clones),
         atomic_load(&libc_clones), atomic_load(&failed));
  return atomic_load(&failed) ? 1 : 0;
}
"""

proc countAfter(output, key: string): int =
  let at = output.find(key)
  if at < 0: return -1
  var i = at + key.len
  var digits = ""
  while i < output.len and output[i].isDigit:
    digits.add output[i]
    inc i
  if digits.len == 0: -1 else: parseInt(digits)

suite "io-mon shim's private heap stays live":
  let work = getTempDir() / ("io-mon-private-heap-" & $getCurrentProcessId())
  createDir(work)
  let shims = [("debug", ensureShim()), ("release", ensureReleaseShim(work))]
  let selftestHost = buildC(work, "selftest_host", selftestHostSource,
    @["-O1", "-ldl"])
  let stressHost = buildC(work, "stress_host", stressHostSource,
    @["-O1", "-pthread"])
  let marker = work / "marker.txt"
  writeFile(marker, "marker\n")

  proc runHost(args: seq[string]; env: StringTableRef):
      tuple[output: string; code: int] =
    run("timeout", @["-s", "KILL", HostTimeoutSeconds] & args, env)

  test "t_private_heap_selftest":
    for (mode, shimLib) in shims:
      var env = baseEnv()
      env["LD_PRELOAD"] = shimLib
      let r = runHost(@[selftestHost], env)
      checkpoint(mode & " (exit " & $r.code & "):\n" & r.output)
      check "selftest result=0" in r.output
      check r.code == 0

  test "t_raw_clone_children_survive_a_mismatched_shim_override":
    let snoopBin = ensureSnoop(work)
    for i, (mode, shimLib) in shims:
      for overrideKind in ["different", "same", "unset", "missing"]:
        var env = baseEnv()
        env["LD_PRELOAD"] = shimLib
        case overrideKind
        of "different": env["REPRO_MONITOR_SHIM_LIB"] = shims[1 - i][1]
        of "same": env["REPRO_MONITOR_SHIM_LIB"] = shimLib
        of "missing": env["REPRO_MONITOR_SHIM_LIB"] = work / "nonexistent.so"
        else: discard
        # timeout is intentionally injected too: its exec is the boundary
        # that propagates the mismatched override into a second loaded image.
        let r = runHost(@[stressHost, marker, "3"], env)
        checkpoint(mode & ", override=" & overrideKind & " (exit " &
          $r.code & "):\n" & r.output)
        check r.code == 0
        check "HANG" notin r.output
        check "stress done" in r.output
        check countAfter(r.output, "shim_images=") ==
          (if overrideKind == "different": 2 else: 1)
        check countAfter(r.output, "clones=") > 0
        when defined(amd64):
          check countAfter(r.output, "inline_clones=") > 0
      var monitoredEnv = baseEnv()
      monitoredEnv["LD_PRELOAD"] = shimLib
      monitoredEnv["REPRO_MONITOR_SHIM_LIB"] = shims[1 - i][1]
      let depfile = work / ("mismatched-" & mode & ".iomon")
      let captured = runHost(@[snoopBin, "run", "--depfile", depfile, "--",
        stressHost, marker, "3"], monitoredEnv)
      checkpoint(mode & ", monitored mismatch (exit " & $captured.code &
        "):\n" & captured.output)
      check captured.code == 0
      check countAfter(captured.output, "shim_images=") == 2
      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcIncomplete
      check dep.records.anyIt(it.kind == mrEventLoss and
        "distinct loaded shim subscriber" in it.detail and
        "REPRO_MONITOR_SHIM_LIB mismatch" in it.detail)

  test "t_private_heap_survives_signals_forks_and_raw_clones":
    let bare = runHost(@[stressHost, marker, "2"], baseEnv())
    checkpoint("without shim (exit " & $bare.code & "):\n" & bare.output)
    check bare.code == 0
    let snoopBin = ensureSnoop(work)
    for (mode, shimLib) in shims:
      var preloadEnv = baseEnv()
      preloadEnv["LD_PRELOAD"] = shimLib
      let pre = runHost(@[stressHost, marker, "3"], preloadEnv)
      checkpoint(mode & ", LD_PRELOAD only (exit " & $pre.code & "):\n" &
        pre.output)
      check pre.code == 0
      check "stress done" in pre.output
      check "HANG" notin pre.output
      var env = baseEnv()
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let depfile = work / ("stress-" & mode & ".iomon")
      let cap = runHost(@[snoopBin, "run", "--depfile", depfile, "--",
        stressHost, marker, "3"], env)
      checkpoint(mode & ", monitored (exit " & $cap.code & "):\n" &
        cap.output)
      check cap.code == 0
      check "stress done" in cap.output
      check "HANG" notin cap.output
      # The run exercised what it is meant to: signals during hooked calls,
      # forks and raw clones.
      check countAfter(cap.output, "signals=") > 0
      check countAfter(cap.output, "forks=") > 0
      check countAfter(cap.output, " clones=") > 0
      check countAfter(cap.output, "libc_clones=") > 0
      when defined(amd64):
        check countAfter(cap.output, "inline_clones=") > 0
      check fileExists(depfile)

  removeDir(work)
