## test_io_mon_linux_tree_ledger — the Linux §4.1 descendant guard checks the
## tree ledger (`src/io_mon/tree_ledger.nim`,
## `fs_snoop.waitForLinuxInjectedDescendants`).
##
## The Linux guard's needle sweep reads `/proc/<pid>/environ`, which is the
## `env_start..env_end` range of the process's OWN stack, not a copy taken at
## exec. A descendant that overwrites its `REPRO_MONITOR_*` strings in place,
## or reuses the argv+environ area for a process title the way PostgreSQL does
## (`ps_status.c`, `PS_USE_CLOBBER_ARGV`), is invisible to that sweep while it
## keeps running. The shim now writes a tree-ledger entry per process it saw
## come into existence, and the guard checks every entry for liveness.
##
## Every case runs a REAL monitored tree built from one C fixture (the macOS
## tree-lifetime guard test's daemon fixture, reduced to what Linux needs) and
## asserts the grade AND the reason:
##
##  1. a quiesced tree is complete on both launch paths (control: the ledger
##     adds no loss to a healthy capture);
##  2. a detached daemon that keeps its environment and outlives the root is
##     incomplete through the needle sweep (`linux injected descendants still
##     live`), as before;
##  3. a daemon that OVERWRITES its needles in place and outlives the root is
##     incomplete through the ledger (`linux recorded descendants still live`,
##     naming its pid), on both launch paths — and the needle sweep really did
##     not see it (no `injected` loss);
##  4. a PostgreSQL-style process title over the whole argv+environ area: the
##     same, and the process still sees its run through `getenv` and shows the
##     title in `/proc/<pid>/cmdline`;
##  5. the ledger does not depend on the event interest (`{ecFileWrites}`);
##  6. a clobbering daemon that exits inside the window is complete, and its
##     read after the root exited is in the evidence (the guard waited for it,
##     which only the ledger could make it do);
##  7. a tree that runs `unshare --pid --fork` (with and without
##     `--mount-proc`) fails closed AT ONCE, naming the other pid namespace:
##     ledger pids are relative to their writer's namespace, so the new
##     namespace's pid 1 must not be checked against the host's init (which
##     reported a live "descendant" and waited out the whole grace window);
##  8. the ledger entry the PARENT of a hooked fork writes for its child is
##     the only one when the child skips monitor bookkeeping (another thread
##     held a shim lock at the fork; a shim built `-d:ioMonShimForkLockTest`
##     holds one on purpose), and a clobbering child is found through it;
##  9. a clobbering child created by a fork path that never reaches the fork
##     hook — `daemon(3)` (glibc's internal `__fork`), `_Fork(3)`,
##     `syscall(SYS_clone)`, `clone(3)`, and a CLONE_VM process — is found
##     through its ledger entry; `popen(3)` and `system(3)` are controls.
##
## Neuters that turn this file red: `noledgercheck` (the guard
## ignores the ledger) — 3, 4, 5 come back `mcComplete` and 6 loses the
## daemon's read; `noshimmark` (the shim writes no entry) — every case fails
## closed with "the tree ledger has no entry for the root".
import std/[monotimes, os, osproc, posix, sequtils, streams, strutils, tempfiles,
  times, unittest]
import io_mon
import build_test_shim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
const StillLive = "linux injected descendants still live after root exit"
const RecordedLive = "linux recorded descendants still live after root exit"
const OtherPidNs = "linux descendant guard failed: the monitored tree ran " &
  "processes in another pid namespace"

const fixtureSrc = """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>

extern char **environ;
static int g_argc;
static char **g_argv;

static void clobber_needles(void) {
  for (char **e = environ; e && *e; e++)
    if (!strncmp(*e, "REPRO_MONITOR_", 14)) memset(*e, 'x', strlen(*e));
}

/* PostgreSQL's ps_status.c (PS_USE_CLOBBER_ARGV): find the contiguous
   argv+environ area, move the environment to the heap so getenv keeps
   working, then reuse the whole area for the process title. */
static int pg_title(void) {
  char *end = NULL;
  for (int i = 0; i < g_argc; i++)
    if (i == 0 || end + 1 == g_argv[i]) end = g_argv[i] + strlen(g_argv[i]);
  int n = 0;
  for (; environ[n]; n++)
    if (end + 1 == environ[n]) end = environ[n] + strlen(environ[n]);
  char **copy = malloc((size_t)(n + 1) * sizeof(char *));
  if (!copy) return 0;
  for (int i = 0; i < n; i++) copy[i] = strdup(environ[i]);
  copy[n] = NULL;
  environ = copy;
  size_t len = (size_t)(end - g_argv[0]);
  memset(g_argv[0], 0, len);
  snprintf(g_argv[0], len, "postgres: checkpointer");
  return getenv("REPRO_MONITOR_SESSION") != NULL;
}

static int read_input(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return 0;
  char buf[32];
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  return n > 0;
}

static void write_text(const char *path, const char *text) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return;
  if (write(fd, text, strlen(text)) < 0) {}
  close(fd);
}

static int wait_child(pid_t pid) {
  int status;
  pid_t r;
  do { r = waitpid(pid, &status, 0); } while (r < 0 && errno == EINTR);
  return r == pid && WIFEXITED(status) ? WEXITSTATUS(status) : 99;
}

/* Double fork + setsid; see the macOS tree-lifetime guard fixture. */
static int daemonize(const char *in, const char *proof, const char *pidfile,
                     int gated, int exit_ms, int mutate) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (gated && sigprocmask(SIG_BLOCK, &set, NULL) != 0) return 10;
  int p[2];
  if (pipe(p) != 0) return 8;
  pid_t pid = fork();
  if (pid < 0) return 4;
  if (pid > 0) {
    close(p[1]);
    char b;
    if (read(p[0], &b, 1) != 1) return 9;
    close(p[0]);
    return wait_child(pid);
  }
  close(p[0]);
  if (setsid() < 0) _exit(11);
  pid = fork();
  if (pid < 0) _exit(12);
  if (pid > 0) _exit(0);
  if (mutate == 1) clobber_needles();
  if (mutate == 2) {
    int kept = pg_title();
    if (gated) write_text(proof, kept ? "env-kept\n" : "env-lost\n");
  }
  char text[32];
  snprintf(text, sizeof(text), "%ld\n", (long)getpid());
  write_text(pidfile, text);
  if (write(p[1], "r", 1) != 1) _exit(13);
  close(p[1]);
  if (gated) {
    int sig = 0;
    if (sigwait(&set, &sig) != 0) _exit(14);
    _exit(0);
  }
  usleep((useconds_t)exit_ms * 1000);
  write_text(proof, read_input(in) ? "read\n" : "empty\n");
  exit(0);
}

/* lockfork <pidfile>: a second thread holds shim lock 0 (through the
   test-only export of a -d:ioMonShimForkLockTest shim) while the main thread
   forks, so the child skips monitor bookkeeping and writes no ledger entry
   of its own. The child clears its needles, writes its pid and waits for
   SIGUSR1; the parent lets the lock go and exits. */
typedef int (*hold_fn)(int, int);
static hold_fn hold_lock;
static volatile int lock_held = 0, lock_release = 0;

static void *lock_holder(void *arg) {
  (void)arg;
  if (!hold_lock(0, 1)) _exit(30);
  __atomic_store_n(&lock_held, 1, __ATOMIC_RELEASE);
  while (!__atomic_load_n(&lock_release, __ATOMIC_ACQUIRE)) {}
  hold_lock(0, 0);
  return NULL;
}

static int lockfork(const char *pidfile) {
  hold_lock = (hold_fn)dlsym(RTLD_DEFAULT, "repro_test_fork_hold_lock");
  if (hold_lock == NULL) return 40;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) return 41;
  int p[2];
  if (pipe(p) != 0) return 42;
  pthread_t t;
  if (pthread_create(&t, NULL, lock_holder, NULL) != 0) return 43;
  while (!__atomic_load_n(&lock_held, __ATOMIC_ACQUIRE)) {}
  pid_t pid = fork();
  if (pid < 0) return 44;
  if (pid == 0) {
    close(p[0]);
    clobber_needles();
    char text[32];
    snprintf(text, sizeof(text), "%ld\n", (long)getpid());
    write_text(pidfile, text);
    if (write(p[1], "r", 1) != 1) _exit(13);
    close(p[1]);
    int sig = 0;
    if (sigwait(&set, &sig) != 0) _exit(14);
    _exit(0);
  }
  close(p[1]);
  char b;
  if (read(p[0], &b, 1) != 1) return 45;
  __atomic_store_n(&lock_release, 1, __ATOMIC_RELEASE);
  pthread_join(t, NULL);
  return 0;
}

/* Children created by fork paths that never reach the fork hook. Each one
   clears its needles, records its pid and waits for SIGUSR1, outliving the
   root; only its tree-ledger entry can show the guard it is still there. */
static void linger(const char *pidfile) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  sigprocmask(SIG_BLOCK, &set, NULL);
  clobber_needles();
  char text[32];
  snprintf(text, sizeof(text), "%ld\n", (long)getpid());
  write_text(pidfile, text);
  int sig = 0;
  sigwait(&set, &sig);
  _exit(0);
}

static const char *g_pidfile;
static int clone_child(void *arg) {
  (void)arg;
  linger(g_pidfile);
  return 0;
}
static int vm_child(void *arg) {
  (void)arg;
  for (;;) pause();
  return 0;
}
static char g_clone_stack[256 * 1024];

static int internal_fork(const char *how, const char *pidfile, const char *self) {
  g_pidfile = pidfile;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) return 41;
  if (!strcmp(how, "daemon3")) {
    /* glibc's daemon(3) forks through its internal __fork. */
    if (daemon(1, 1) != 0) return 50;
    linger(pidfile);
  }
#if defined(__GLIBC__) && __GLIBC_PREREQ(2, 34)
  if (!strcmp(how, "underscore-fork")) {
    pid_t pid = _Fork();
    if (pid < 0) return 51;
    if (pid == 0) linger(pidfile);
    return 0;
  }
#endif
  if (!strcmp(how, "syscall-fork")) {
    long pid = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (pid < 0) return 52;
    if (pid == 0) linger(pidfile);
    return 0;
  }
  if (!strcmp(how, "glibc-clone")) {
    pid_t pid = clone(clone_child, g_clone_stack + sizeof(g_clone_stack),
                      SIGCHLD, NULL);
    return pid < 0 ? 53 : 0;
  }
  if (!strcmp(how, "vm-clone")) {
    /* A process sharing this memory, neither a thread nor a vfork child.
       The needles are cleared here, in the shared memory, and the child only
       sleeps; its pid comes from clone. */
    clobber_needles();
    pid_t pid = clone(vm_child, g_clone_stack + sizeof(g_clone_stack),
                      CLONE_VM | SIGCHLD, NULL);
    if (pid < 0) return 54;
    char text[32];
    snprintf(text, sizeof(text), "%ld\n", (long)pid);
    write_text(pidfile, text);
    return 0;
  }
  char cmd[8192];
  if (!strcmp(how, "popen")) {
    snprintf(cmd, sizeof(cmd), "exec '%s' linger '%s'", self, pidfile);
    FILE *f = popen(cmd, "r");
    if (f == NULL) return 55;
    /* Not closed: pclose would wait for the child. */
    for (int i = 0; i < 2000 && access(pidfile, F_OK) != 0; i++) usleep(1000);
    return 0;
  }
  if (!strcmp(how, "system")) {
    snprintf(cmd, sizeof(cmd), "'%s' linger '%s' &", self, pidfile);
    return system(cmd) == 0 ? 0 : 56;
  }
  return 57;
}

int main(int argc, char **argv) {
  g_argc = argc;
  g_argv = argv;
  if (argc < 2) return 2;
  const char *mode = argv[1];
  if (!strcmp(mode, "plain") && argc == 3) return read_input(argv[2]) ? 0 : 3;
  if (!strcmp(mode, "lockfork") && argc == 3) return lockfork(argv[2]);
  if (!strcmp(mode, "linger") && argc == 3) linger(argv[2]);
  if (!strcmp(mode, "internal") && argc == 4)
    return internal_fork(argv[2], argv[3], argv[0]);
  if (!strcmp(mode, "daemon") && (argc == 7 || argc == 8))
    return daemonize(strdup(argv[2]), strdup(argv[3]), strdup(argv[4]),
                     !strcmp(argv[5], "gated"),
                     atoi(argv[6]),
                     argc == 8 ? (!strcmp(argv[7], "clobber") ? 1
                                  : !strcmp(argv[7], "pgtitle") ? 2 : 0)
                               : 0);
  return 2;
}
"""

proc run(cmd: string; args: seq[string]): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, options = {poStdErrToStdOut, poUsePath})
  result.output = p.outputStream.readAll()
  result.code = p.waitForExit()
  p.close()

proc capture(request: FsSnoopRequest; hosted: bool): MonitorResult =
  if hosted:
    var handle = startMonitor(request)
    while not pollMonitor(handle): sleep(2)
    finishMonitor(move(handle))
  else:
    runMonitored(request)

proc losses(dep: MonitorDepFile): seq[string] =
  for r in dep.records:
    if r.kind == mrEventLoss: result.add r.detail

proc awaitPidFile(path: string): Pid =
  for _ in 0 ..< 1000:
    if fileExists(path):
      let text = readFile(path)
      if text.endsWith("\n"): return Pid(parseInt(text.strip()))
    sleep(5)
  raise newException(IOError, "no pid file: " & path)

proc alive(pid: Pid): bool =
  ## Alive and not a zombie.
  if posix.kill(pid, 0) != 0: return false
  try:
    let stat = readFile("/proc/" & $pid & "/stat")
    let close = stat.rfind(')')
    close < 0 or close + 2 >= stat.len or stat[close + 2] != 'Z'
  except IOError:
    false

proc reap(pid: Pid) =
  if alive(pid):
    discard posix.kill(pid, SIGUSR1)
    for _ in 0 ..< 400:
      if not alive(pid): return
      sleep(5)
    discard posix.kill(pid, SIGKILL)

putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", "300")
putEnv("IO_MON_LINUX_DESCENDANT_POLL_MS", "10")

suite "Linux descendant guard: the tree ledger":
  let work = expandFilename(createTempDir("io-mon-linux-ledger-", ""))
  let fixture = work / "tree"
  writeFile(work / "tree.c", fixtureSrc)
  let built = run(getEnv("CC", "cc"), @[work / "tree.c", "-pthread", "-o",
    fixture, "-ldl"])
  doAssert built.code == 0, built.output
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  doAssert buildShim.code == 0, buildShim.output
  doAssert findShimLibrary().len > 0
  let input = work / "input"
  writeFile(input, "real dependency")
  var serial = 0
  proc request(args: varargs[string]): FsSnoopRequest =
    inc serial
    FsSnoopRequest(command: @[fixture] & @args,
      depFilePath: work / ("capture-" & $serial & ".iomon"))

  template checkComplete(res: MonitorResult; req: FsSnoopRequest) =
    check res.exitCode == 0
    check res.completeness == mcComplete
    check res.depFile.losses.len == 0
    if res.depFile.losses.len != 0: echo res.depFile.losses
    check readMonitorDepFile(req.depFilePath).completeness == mcComplete

  template clobberedDaemon(name, mutate: string; hosted: bool;
                           wanted: set[EventCategory] = {}) =
    let pidFile = work / (name & "-" & $hosted & ".pid")
    let proof = work / (name & "-" & $hosted & ".proof")
    var req = request("daemon", input, proof, pidFile, "gated", "0", mutate)
    req.interest = wanted
    var daemon = Pid(0)
    try:
      let res = capture(req, hosted)
      daemon = awaitPidFile(pidFile)
      check res.exitCode == 0
      check alive(daemon)
      # The needles really are gone from what the sweep reads.
      let environ = readFile("/proc/" & $daemon & "/environ")
      check "REPRO_MONITOR_SESSION=" notin environ
      if mutate == "pgtitle":
        check readFile(proof) == "env-kept\n"
        check "postgres: checkpointer" in
          readFile("/proc/" & $daemon & "/cmdline")
      check res.completeness == mcIncomplete
      let recorded = res.depFile.losses.filterIt(it.startsWith(RecordedLive))
      check recorded.len == 1
      if recorded.len == 1:
        check ("pids=" & $daemon) in recorded[0]
      check not res.depFile.losses.anyIt(it.startsWith(StillLive))
      if recorded.len != 1: echo res.depFile.losses
      check readMonitorDepFile(req.depFilePath).completeness == mcIncomplete
    finally:
      if daemon == Pid(0) and fileExists(pidFile):
        daemon = awaitPidFile(pidFile)
      if daemon != Pid(0): reap(daemon)

  test "1. a quiesced tree is complete on both launch paths":
    for hosted in [false, true]:
      let req = request("plain", input)
      let res = capture(req, hosted)
      checkComplete(res, req)

  test "2. a daemon that keeps its environment is found by the needle sweep":
    let pidFile = work / "daemon.pid"
    let req = request("daemon", input, work / "unused", pidFile, "gated", "0")
    var daemon = Pid(0)
    try:
      let res = capture(req, false)
      daemon = awaitPidFile(pidFile)
      check alive(daemon)
      check res.completeness == mcIncomplete
      let live = res.depFile.losses.filterIt(it.startsWith(StillLive))
      check live.len == 1
      if live.len == 1:
        check ("pids=" & $daemon) in live[0]
    finally:
      if daemon == Pid(0) and fileExists(pidFile):
        daemon = awaitPidFile(pidFile)
      if daemon != Pid(0): reap(daemon)

  test "3. a daemon that overwrites its needles is still found":
    for hosted in [false, true]:
      clobberedDaemon("clobber", "clobber", hosted)

  test "4. a PostgreSQL-style process title over argv+environ is found":
    clobberedDaemon("pgtitle", "pgtitle", false)

  test "5. the ledger does not depend on the event interest":
    clobberedDaemon("clobber-narrow", "clobber", false, {ecFileWrites})

  test "6. a clobbering daemon that exits inside the window is complete":
    let pidFile = work / "clobber-short.pid"
    let proof = work / "clobber-short.proof"
    let req = request("daemon", input, proof, pidFile, "timed", "120",
      "clobber")
    let res = capture(req, false)
    checkComplete(res, req)
    check fileExists(proof) and readFile(proof) == "read\n"
    let daemon = awaitPidFile(pidFile)
    check not alive(daemon)
    # In daemon mode only the daemon reads `input` (after the root exited),
    # so the read in the evidence is its read. (Linux folds file records
    # across processes: they carry no pid.)
    check res.depFile.records.anyIt(it.kind == mrFileRead and
      it.path == input)

  test "7. a tree that enters another pid namespace fails closed at once":
    let unshare = findExe("unshare")
    let probe =
      if unshare.len == 0: (output: "no unshare on PATH", code: 1)
      else: run(unshare, @["--user", "--map-root-user", "--pid", "--fork",
        "true"])
    if probe.code != 0:
      echo "    SKIP: unprivileged pid namespaces are unavailable: ",
        probe.output
      skip()
    else:
      # A long grace window: a guard that still waited for the namespace's
      # pid 1 to "exit" would take all of it.
      putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", "5000")
      try:
        for mountProc in [false, true]:
          checkpoint("mount-proc=" & $mountProc)
          inc serial
          var args = @[unshare, "--user", "--map-root-user", "--pid",
            "--fork"]
          if mountProc: args.add "--mount-proc"
          args.add @["sh", "-c", "true"]
          let req = FsSnoopRequest(command: args,
            depFilePath: work / ("capture-" & $serial & ".iomon"))
          let t0 = getMonoTime()
          let res = capture(req, false)
          let elapsed = inMilliseconds(getMonoTime() - t0)
          check res.exitCode == 0
          check res.completeness == mcIncomplete
          let ns = res.depFile.losses.filterIt(it.startsWith(OtherPidNs))
          check ns.len == 1
          # The namespace's pid 1 is not reported as a live host process.
          check not res.depFile.losses.anyIt(it.startsWith(RecordedLive) or
            it.startsWith(StillLive))
          if ns.len != 1: echo res.depFile.losses
          check elapsed < 2500
      finally:
        putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", "300")

  test "8. the fork parent's entry finds a child that skipped its own":
    let lockShim = buildPrivateLinuxShimWithFlags(repoRoot,
      ["-d:ioMonShimForkLockTest"])
    let pidFile = work / "lockfork.pid"
    let req = request("lockfork", pidFile)
    var child = Pid(0)
    putEnv("REPRO_MONITOR_SHIM_LIB", lockShim)
    try:
      let res = capture(req, false)
      child = awaitPidFile(pidFile)
      check res.exitCode == 0
      check alive(child)
      check "REPRO_MONITOR_SESSION=" notin
        readFile("/proc/" & $child & "/environ")
      check res.completeness == mcIncomplete
      let recorded = res.depFile.losses.filterIt(it.startsWith(RecordedLive))
      check recorded.len == 1
      if recorded.len == 1:
        check ("pids=" & $child) in recorded[0]
      else:
        echo res.depFile.losses
    finally:
      delEnv("REPRO_MONITOR_SHIM_LIB")
      if child == Pid(0) and fileExists(pidFile):
        child = awaitPidFile(pidFile)
      if child != Pid(0): reap(child)

  test "9. children of forks that never reach the fork hook are found":
    # daemon(3) forks through glibc's internal __fork, _Fork / syscall(2) /
    # clone(3) skip the atfork handlers, and a CLONE_VM process gets no
    # child notification at all: none of them reaches `repro_hook_fork`, so
    # the parent writes no entry for them. Each child clears its needles and
    # outlives the root; only its ledger entry (written by the child itself,
    # or for the CLONE_VM process by its creator) can show it. popen(3) and
    # system(3) are controls: their child execs an image that loads the shim
    # and writes its own entry at init.
    for how in ["daemon3", "underscore-fork", "syscall-fork", "glibc-clone",
                "vm-clone", "popen", "system"]:
      checkpoint(how)
      let pidFile = work / ("internal-" & how & ".pid")
      let req = request("internal", how, pidFile)
      var child = Pid(0)
      try:
        let res = capture(req, false)
        check res.exitCode == 0
        if res.exitCode != 0:
          echo how, ": fixture exit ", res.exitCode
          continue
        child = awaitPidFile(pidFile)
        check alive(child)
        check res.completeness == mcIncomplete
        let recorded = res.depFile.losses.filterIt(it.startsWith(RecordedLive))
        check recorded.len == 1
        if recorded.len == 1:
          check ("pids=" & $child) in recorded[0]
        else:
          echo how, ": ", res.depFile.losses
        check not res.depFile.losses.anyIt(it.startsWith(StillLive))
      finally:
        if child == Pid(0) and fileExists(pidFile):
          child = awaitPidFile(pidFile)
        if child != Pid(0):
          reap(child)

  removeDir(work)
