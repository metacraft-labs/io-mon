## test_io_mon_macos_tree_lifetime_guard — the macOS tree-lifetime guard
## (docs/usage.md, "The macOS tree-lifetime guard (normative)";
## src/io_mon/macos_tree_guard.nim).
##
## Every case runs a REAL monitored tree built from one C fixture, down both
## launch paths where the launch path could matter, and asserts the grade AND
## the reason: no capture may carry the retired "no complete tree-lifetime
## guard" marker, a complete capture carries no loss at all, and an incomplete
## one carries the specific loss its case is about.
##
##  1. quiesced control (both launch paths): complete;
##  2. nested children (root -> child -> grandchild): complete, every level's
##     read and process-start recorded;
##  3. exec chain (execv and posix_spawn+exec alternating): complete;
##  4. fast-exiting children racing root exit (the root does not wait for 40
##     children that read their input only after it has exited): complete,
##     and every child's read is in the evidence;
##  5. a double-forked, setsid daemon grandchild that outlives its parent and
##     the root, held alive past finish (both launch paths): incomplete with
##     `macos descendants still live after root exit` naming its pid;
##  6. a daemon grandchild that exits inside the window after reading: complete,
##     and its post-root read is in the evidence;
##  7. two concurrent monitors: a live descendant of one does not make the
##     other incomplete (the census is scoped by run needle);
##  8. SIP binaries in the tree stay incomplete: a synchronous SIP child, a
##     detached SIP grandchild that outlives the root, and a creator SIGKILLed
##     right after spawning one. The SIP tool is /usr/bin/caffeinate, which
##     has no sandbox-tools drop-in, so it really runs uninjected.
##  9. unrelated process churn outside the monitor does not keep the guard
##     from a conclusive sweep (20 captures under four spawn loops).
## 10. a daemon grandchild that OVERWRITES its argument/environment area in
##     place, so the needle census cannot see it, is still found through the
##     tree ledger (`io_mon/tree_ledger`): (a) one that overwrites its
##     `REPRO_MONITOR_*` strings, on both launch paths; (b) one that reuses the
##     whole argv+environ area for a process title the way PostgreSQL does on
##     Darwin; (c) the same with an event interest that excludes `proc`; (d) a
##     clobbering daemon that exits inside the window is complete; (e) the
##     detached SIP grandchild of 8b is found by the guard itself, through
##     the entry its creator's posix_spawn hook wrote: it never loads the shim
##     (no entry of its own) and the kernel withholds its environment (no
##     needle), so that parent-side entry is the only evidence the guard has.
import std/[os, osproc, posix, sequtils, streams, strutils, tempfiles, unittest]
import io_mon

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
const RetiredMarker = "detached-descendant quiescence cannot be established"
const StillLive = "macos descendants still live after root exit"
const RecordedLive = "macos recorded descendants still live after root exit"

const fixtureSrc = """
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* A SIP-protected platform binary that io-mon has NO drop-in for (the spawn
   hook rewrites /bin/sleep and friends to injectable GNU tools), so dyld strips
   the shim and the kernel withholds its environment. `caffeinate -t N` just
   waits N seconds. */
#define SIP_TOOL "/usr/bin/caffeinate"

extern char **environ;
static const char *self_path;
static int g_argc;
static char **g_argv;

/* Overwrite every REPRO_MONITOR_* environment string in place: the process
   keeps running, and its argument/environment area no longer names the run. */
static void clobber_needles(void) {
  for (char **e = environ; e && *e; e++)
    if (!strncmp(*e, "REPRO_MONITOR_", 14)) memset(*e, 'x', strlen(*e));
}

/* PostgreSQL's ps_status.c on Darwin (PS_USE_CLOBBER_ARGV): find the
   contiguous argv+environ area, move the environment to the heap so getenv
   keeps working, then reuse the whole area for the process title. Returns
   whether getenv still sees the run (it must: only the area was reused). */
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

static int nested(const char *in, int depth) {
  if (!read_input(in)) return 3;
  if (depth == 0) return 0;
  pid_t pid = fork();
  if (pid < 0) return 4;
  if (pid == 0) _exit(nested(in, depth - 1));
  return wait_child(pid);
}

static int exec_chain(const char *in, int n) {
  if (!read_input(in)) return 3;
  if (n == 0) return 0;
  char next[16];
  snprintf(next, sizeof(next), "%d", n - 1);
  char *argv[] = {(char *)self_path, "chain", (char *)in, next, NULL};
  if (n % 2 == 1) {
    execv(self_path, argv);
    return 5;
  }
  pid_t pid;
  if (posix_spawn(&pid, self_path, NULL, NULL, argv, environ) != 0) return 6;
  return wait_child(pid);
}

/* Children read only after the root has exited: the root does not wait.
   They are posix_spawned (each re-execs this fixture in `late-read` mode);
   `fork_burst` below is the fork-only variant. */
/* Like burst, but the children are fork-only (no exec): each inherits the
   root's fragment slot, sleeps, reads `in` and exits. */
static int fork_burst(const char *in, int count, int delay_ms) {
  for (int i = 0; i < count; i++) {
    pid_t pid = fork();
    if (pid < 0) return 4;
    if (pid == 0) {
      usleep((useconds_t)delay_ms * 1000);
      _exit(read_input(in) ? 0 : 3);
    }
  }
  return 0;
}

static int burst(const char *in, int count, int delay_ms) {
  char ms[16];
  snprintf(ms, sizeof(ms), "%d", delay_ms);
  for (int i = 0; i < count; i++) {
    pid_t pid;
    char *argv[] = {(char *)self_path, "late-read", (char *)in, ms, NULL};
    if (posix_spawn(&pid, self_path, NULL, NULL, argv, environ) != 0) return 6;
  }
  return 0;
}

/* Double fork + setsid. The grandchild applies `mutate` (0 nothing, 1
   clobber_needles, 2 pg_title; for 2 a gated grandchild records in `proof`
   whether getenv still sees the run), writes its pid to `pidfile`, signals
   the root through a pipe, then either waits for SIGUSR1 (gated) or sleeps
   `exit_ms`, reads `in`, writes `proof` and exits. */
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

static int spawn_sip(const char *secs, int wait) {
  pid_t pid;
  char *argv[] = {SIP_TOOL, "-t", (char *)secs, NULL};
  if (posix_spawn(&pid, SIP_TOOL, NULL, NULL, argv, environ) != 0) return 6;
  return wait ? wait_child(pid) : 0;
}

static int sip_detached(const char *secs, const char *pidfile) {
  pid_t pid = fork();
  if (pid < 0) return 4;
  if (pid == 0) {
    if (setsid() < 0) _exit(11);
    pid_t sip;
    char *argv[] = {SIP_TOOL, "-t", (char *)secs, NULL};
    if (posix_spawn(&sip, SIP_TOOL, NULL, NULL, argv, environ) != 0) _exit(6);
    char text[32];
    snprintf(text, sizeof(text), "%ld\n", (long)sip);
    write_text(pidfile, text);
    _exit(0);
  }
  return wait_child(pid);
}

/* A creator whose own start is durable spawns a SIP child and is SIGKILLed
   at once, so nothing after the spawn call can flush its records. The creator
   is EXEC'd (a fresh image whose shim knows its main thread): a fork child
   without exec flushes every record at once, which would hide the gap. */
static int killed_creator(const char *secs) {
  int (*flush)(void) = (int (*)(void))dlsym(RTLD_DEFAULT,
                                            "repro_monitor_shim_flush");
  if (!flush) return 20;
  flush();
  spawn_sip(secs, 0);
  kill(getpid(), SIGKILL);
  return 21;
}

static int kill_after_spawn(const char *secs) {
  pid_t pid = fork();
  if (pid < 0) return 4;
  if (pid == 0) {
    char *argv[] = {(char *)self_path, "killed-creator", (char *)secs, NULL};
    execv(self_path, argv);
    _exit(23);
  }
  int status;
  pid_t r;
  do { r = waitpid(pid, &status, 0); } while (r < 0 && errno == EINTR);
  return r == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 22;
}

int main(int argc, char **argv) {
  self_path = argv[0];
  g_argc = argc;
  g_argv = argv;
  if (argc < 2) return 2;
  const char *mode = argv[1];
  if (!strcmp(mode, "plain") && argc == 3) return read_input(argv[2]) ? 0 : 3;
  if (!strcmp(mode, "late-read") && argc == 4) {
    usleep((useconds_t)atoi(argv[3]) * 1000);
    return read_input(argv[2]) ? 0 : 3;
  }
  if (!strcmp(mode, "nested") && argc == 4) return nested(argv[2], atoi(argv[3]));
  if (!strcmp(mode, "chain") && argc == 4) return exec_chain(argv[2], atoi(argv[3]));
  if (!strcmp(mode, "burst") && argc == 5)
    return burst(argv[2], atoi(argv[3]), atoi(argv[4]));
  if (!strcmp(mode, "fork-burst") && argc == 5)
    return fork_burst(argv[2], atoi(argv[3]), atoi(argv[4]));
  /* Copies: pg_title reuses the argv area, as PostgreSQL copies argv first. */
  if (!strcmp(mode, "daemon") && (argc == 7 || argc == 8))
    return daemonize(strdup(argv[2]), strdup(argv[3]), strdup(argv[4]),
                     !strcmp(argv[5], "gated"),
                     atoi(argv[6]),
                     argc == 8 ? (!strcmp(argv[7], "clobber") ? 1
                                  : !strcmp(argv[7], "pgtitle") ? 2 : 0)
                               : 0);
  if (!strcmp(mode, "sip") && argc == 3) return spawn_sip(argv[2], 1);
  if (!strcmp(mode, "sip-detached") && argc == 4)
    return sip_detached(argv[2], argv[3]);
  if (!strcmp(mode, "kill-after-spawn") && argc == 3)
    return kill_after_spawn(argv[2]);
  if (!strcmp(mode, "killed-creator") && argc == 3)
    return killed_creator(argv[2]);
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

proc noRetiredMarker(dep: MonitorDepFile): bool =
  dep.losses.allIt(RetiredMarker notin it)

proc readers(dep: MonitorDepFile; path: string): int =
  ## Distinct pids that read `path`.
  var pids: seq[uint64]
  for r in dep.records:
    if r.kind == mrFileRead and r.path == path and r.osPid notin pids:
      pids.add r.osPid
  pids.len

proc starts(dep: MonitorDepFile): int =
  dep.records.countIt(it.kind == mrProcessStart)

proc awaitPidFile(path: string): Pid =
  for _ in 0 ..< 1000:
    if fileExists(path):
      let text = readFile(path)
      if text.endsWith("\n"): return Pid(parseInt(text.strip()))
    sleep(5)
  raise newException(IOError, "no pid file: " & path)

proc alive(pid: Pid): bool = posix.kill(pid, 0) == 0

proc reap(pid: Pid) =
  ## Release (SIGUSR1) or end a leftover fixture process and wait until it is
  ## gone, so no case leaks a process into the next.
  if alive(pid):
    discard posix.kill(pid, SIGUSR1)
    for _ in 0 ..< 400:
      if not alive(pid): return
      sleep(5)
    discard posix.kill(pid, SIGKILL)

suite "macOS tree-lifetime guard":
  let work = expandFilename(createTempDir("io-mon-tree-guard-", ""))
  let fixture = work / "tree"
  writeFile(work / "tree.c", fixtureSrc)
  let built = run(getEnv("CC", "cc"), @[work / "tree.c", "-o", fixture])
  doAssert built.code == 0, built.output
  putEnv(ShimLibOverrideEnv, repoRoot / "build/lib/librepro_monitor_shim.dylib")
  let input = work / "input"
  writeFile(input, "real dependency")
  var serial = 0
  proc request(args: varargs[string]): FsSnoopRequest =
    inc serial
    FsSnoopRequest(command: @[fixture] & @args,
      depFilePath: work / ("capture-" & $serial & ".iomon"))

  template checkComplete(res: MonitorResult; req: FsSnoopRequest) =
    # A template, not a proc: `check` marks the TEST failed only when it
    # expands inside the test body.
    check res.exitCode == 0
    check res.completeness == mcComplete
    check res.depFile.losses.len == 0
    if res.depFile.losses.len != 0: echo res.depFile.losses
    block:
      let disk = readMonitorDepFile(req.depFilePath)
      check disk.completeness == mcComplete
      check disk.records == res.depFile.records

  test "1. a quiesced tree is complete on both launch paths":
    for hosted in [false, true]:
      let req = request("plain", input)
      let res = capture(req, hosted)
      checkComplete(res, req)
      check res.depFile.readers(input) == 1

  test "2. nested children are complete":
    let req = request("nested", input, "2")
    let res = capture(req, false)
    checkComplete(res, req)
    check res.depFile.readers(input) == 3
    check res.depFile.starts >= 3

  test "3. an exec chain is complete":
    let req = request("chain", input, "4")
    let res = capture(req, false)
    checkComplete(res, req)
    check res.depFile.readers(input) >= 3
    check res.depFile.records.anyIt(it.kind == mrProcessExec)

  test "4. fast-exiting children that outlive the root are waited for":
    for hosted in [false, true]:
      let req = request("burst", input, "40", "120")
      let res = capture(req, hosted)
      checkComplete(res, req)
      check res.depFile.readers(input) == 40

  test "4b. forked children that outlive the root never write its fragment":
    # A fork child inherits the root's open fragment and its in-flight batch.
    # If the child flushed that batch (its first record sees a new pid), the
    # root's frames would land in the root's fragment twice, through the same
    # file offset the root is writing at: duplicated records always, and an
    # interleaved, corrupt fragment when the writes race (io-mon issue
    # 2026-10-29-macos-fork-child-outliving-its-parent-corrupts-the-parent-
    # fragment). Duplicates are deterministic, so count them.
    for round in 0 ..< 3:
      let req = request("fork-burst", input, "40", "120")
      let res = capture(req, round mod 2 == 1)
      checkComplete(res, req)
      check res.depFile.readers(input) == 40
      # The root is the process this test process started.
      let roots = res.depFile.records.filterIt(it.kind == mrProcessStart and
        it.parentOsPid == uint64(getCurrentProcessId()))
      check roots.len == 1
      if roots.len == 1:
        let root = roots[0].osPid
        check res.depFile.records.countIt(it.osPid == root and
          it.kind == mrProcessSpawn) == 40

  test "5. a detached daemon outliving the root is incomplete, named":
    for hosted in [false, true]:
      let pidFile = work / ("daemon-" & $hosted & ".pid")
      let req = request("daemon", input, work / "unused", pidFile, "gated", "0")
      var daemon = Pid(0)
      try:
        let res = capture(req, hosted)
        daemon = awaitPidFile(pidFile)
        check res.exitCode == 0
        check alive(daemon)
        check res.completeness == mcIncomplete
        let live = res.depFile.losses.filterIt(it.startsWith(StillLive))
        check live.len == 1
        if live.len == 1:
          check ("pids=" & $daemon) in live[0]
          check "images=tree" in live[0]
        check res.depFile.noRetiredMarker
        check readMonitorDepFile(req.depFilePath).completeness == mcIncomplete
      finally:
        if daemon == Pid(0) and fileExists(pidFile):
          daemon = awaitPidFile(pidFile)
        if daemon != Pid(0): reap(daemon)

  test "6. a daemon that exits inside the window is complete":
    let pidFile = work / "short-daemon.pid"
    let proof = work / "short-daemon.proof"
    let req = request("daemon", input, proof, pidFile, "timed", "150")
    let res = capture(req, false)
    checkComplete(res, req)
    check readFile(proof) == "read\n"
    let daemon = awaitPidFile(pidFile)
    check not alive(daemon)
    var daemonRead = false
    for r in res.depFile.records:
      if r.kind == mrFileRead and r.path == input and r.osPid == uint64(daemon):
        daemonRead = true
    check daemonRead

  test "7. another run's live descendant does not taint this run":
    # B starts FIRST, so A's daemon is younger than B's root and survives the
    # start-time prune: only the run needle can tell B that it is not B's.
    # B's guard runs at finishMonitor, after A's daemon exists.
    let reqB = request("plain", input)
    var b = startMonitor(reqB)
    let pidFile = work / "other-run.pid"
    let reqA = request("daemon", input, work / "unused", pidFile, "gated", "0")
    var a = startMonitor(reqA)
    var daemon = Pid(0)
    try:
      while not pollMonitor(a): sleep(2)
      daemon = awaitPidFile(pidFile)
      checkpoint("A's daemon=" & $daemon & " A root=" & $a.rootPid &
        " B root=" & $b.rootPid)
      while not pollMonitor(b): sleep(2)
      let resB = finishMonitor(move(b))
      checkComplete(resB, reqB)
      check resB.depFile.readers(input) == 1
      check alive(daemon)
      let resA = finishMonitor(move(a))
      check resA.completeness == mcIncomplete
      check resA.depFile.losses.anyIt(it.startsWith(StillLive) and
        ("pids=" & $daemon) in it)
    finally:
      if daemon == Pid(0) and fileExists(pidFile):
        daemon = awaitPidFile(pidFile)
      if daemon != Pid(0): reap(daemon)

  test "8a. a synchronous SIP child keeps the capture incomplete":
    let req = request("sip", "1")
    let res = capture(req, false)
    check res.exitCode == 0
    check res.completeness == mcIncomplete
    check res.depFile.losses.anyIt("spawn child missing process-start" in it)
    check res.depFile.noRetiredMarker

  test "8b. a detached SIP grandchild outliving the root stays incomplete":
    let pidFile = work / "sip-detached.pid"
    let req = request("sip-detached", "2", pidFile)
    var sip = Pid(0)
    try:
      let res = capture(req, false)
      sip = awaitPidFile(pidFile)
      check res.exitCode == 0
      check alive(sip)
      check res.completeness == mcIncomplete
      check res.depFile.losses.anyIt("spawn child missing process-start" in it)
      check res.depFile.noRetiredMarker
    finally:
      if sip != Pid(0): reap(sip)

  test "8c. a creator killed right after spawning a SIP child cannot hide it":
    let req = request("kill-after-spawn", "1")
    let res = capture(req, false)
    check res.exitCode == 0
    check res.completeness == mcIncomplete
    if res.completeness != mcIncomplete: echo res.depFile.losses
    check res.depFile.noRetiredMarker
    sleep(1100)

  test "9. unrelated process churn does not keep the guard inconclusive":
    # Four loops of short-lived processes OUTSIDE the monitor, started after
    # nothing in particular, so they are young relative to every root below.
    # Processes caught vanishing or mid-exec by a sweep are classified through
    # their (non-member) parent; without that rule a sweep under churn is
    # rarely conclusive and captures time out as unclassified.
    # The loops stop on a stop file (and after 120 s regardless), so a failed
    # or interrupted case cannot leave them running.
    let stop = work / "churn.stop"
    let churn = startProcess("/bin/sh", args = @["-c",
      "end=$(( $(date +%s) + 120 )); for k in 1 2 3 4; do " &
      "(while [ ! -e \"$0\" ] && [ $(date +%s) -lt $end ]; do " &
      "/usr/bin/true; done) & done; wait", stop],
      options = {poParentStreams})
    try:
      sleep(200)
      for i in 0 ..< 20:
        let req = request("plain", input)
        let res = capture(req, i mod 2 == 1)
        checkComplete(res, req)
    finally:
      writeFile(stop, "")
      discard churn.waitForExit()
      churn.close()

  template clobberedDaemon(name, mutate: string; hosted: bool;
                           wanted: set[EventCategory] = {}) =
    ## A gated daemon grandchild that overwrites its argument/environment area
    ## before the root exits, held alive past finish. The needle census cannot
    ## see it; only the tree ledger can. A template, not a proc, so its
    ## `check`s fail the test they expand in (see `checkComplete`).
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
      if mutate == "pgtitle":
        # The title really replaced the area, and the process still knows its
        # run: only the copy the census reads is gone.
        check readFile(proof) == "env-kept\n"
        let ps = execProcess("/bin/ps", args = ["-o", "command=", "-p",
          $daemon], options = {})
        check "postgres: checkpointer" in ps
      check res.completeness == mcIncomplete
      let recorded = res.depFile.losses.filterIt(it.startsWith(RecordedLive))
      check recorded.len == 1
      if recorded.len == 1:
        check ("pids=" & $daemon) in recorded[0]
      # The census itself did not see it: the needles really are gone.
      check not res.depFile.losses.anyIt(it.startsWith(StillLive))
      if recorded.len != 1: echo res.depFile.losses
      check res.depFile.noRetiredMarker
      check readMonitorDepFile(req.depFilePath).completeness == mcIncomplete
    finally:
      if daemon == Pid(0) and fileExists(pidFile):
        daemon = awaitPidFile(pidFile)
      if daemon != Pid(0): reap(daemon)

  test "10a. a daemon that overwrites its needles is still found":
    for hosted in [false, true]:
      clobberedDaemon("clobber", "clobber", hosted)

  test "10b. a PostgreSQL-style process title over argv+environ is found":
    clobberedDaemon("pgtitle", "pgtitle", false)

  test "10c. the ledger does not depend on the event interest":
    clobberedDaemon("clobber-narrow", "clobber", false, {ecFileWrites})

  test "10d. a clobbering daemon that exits inside the window is complete":
    let pidFile = work / "clobber-short.pid"
    let proof = work / "clobber-short.proof"
    let req = request("daemon", input, proof, pidFile, "timed", "150",
      "clobber")
    let res = capture(req, false)
    checkComplete(res, req)
    # The guard waited for it (only the ledger can see it), so its read
    # happened before the capture finished and is in the evidence.
    check fileExists(proof) and readFile(proof) == "read\n"
    let daemon = awaitPidFile(pidFile)
    check not alive(daemon)
    check res.depFile.records.anyIt(it.kind == mrFileRead and
      it.path == input and it.osPid == uint64(daemon))

  test "10e. a SIP grandchild is found through its creator's entry":
    # The SIP grandchild never loads the shim, so it writes no entry of its
    # own, and the kernel withholds its environment, so the census sees no
    # needle. The guard can name it only through the entry the creator's
    # posix_spawn hook wrote before the call returned. (The unmonitored-subtree
    # accounting flags it too, case 8b; this pins the guard's own evidence.)
    let pidFile = work / "sip-ledger.pid"
    let req = request("sip-detached", "3", pidFile)
    var sip = Pid(0)
    try:
      let res = capture(req, false)
      sip = awaitPidFile(pidFile)
      check res.exitCode == 0
      check alive(sip)
      check res.completeness == mcIncomplete
      let recorded = res.depFile.losses.filterIt(it.startsWith(RecordedLive))
      check recorded.len == 1
      if recorded.len == 1:
        check ("pids=" & $sip) in recorded[0]
      else:
        echo res.depFile.losses
      check not res.depFile.losses.anyIt(it.startsWith(StillLive))
      check res.depFile.noRetiredMarker
    finally:
      if sip != Pid(0): reap(sip)

  removeDir(work)
