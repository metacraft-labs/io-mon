## The armed inline-syscall loss holds across the narrow windows of its own
## protocol.
##
## WHY. A process that traps its own inline `syscall` instructions arms an
## event-loss (an empty file in the fragment directory) before a trapped call
## runs, and a drain withdraws it once everything trapped is classified (see
## "AN ARMED LOSS" in `linux_preload_runtime.nim`). Three windows of a few
## microseconds each decide whether a death can still leave a capture that
## reads complete while missing a call. They are too narrow to hit from a
## test, so this file builds the shim with `-d:ioMonInlineWindowTest`, which
## widens exactly those windows with sleeps (never compiled into a production
## build), and kills the process inside them:
##
## - "cd-exit": two concurrent drains. Thread A exits (the exit destructor's
##   drain claims the one queued event, then sleeps 20 ms before it records
##   it); thread B makes a failing libc exec 5 ms later (a second drain, which
##   finds nothing pending and would withdraw the loss); the process is
##   SIGKILLed at 10 ms. The claimed event must still be covered: the open is
##   recorded, or the capture reports the loss and is not complete.
## - "fe-kill": a failed inline exec, killed in the 20 ms after the exec
##   returns and before its epoch loss is armed. The exec-armed file created
##   before the call must cover it: the capture is not complete.
## - "fork-inflight": a libc fork while another thread holds the in-flight
##   count (a marker `close(-4242)` holds it for 100 ms). The child must not
##   inherit that count, or it can never withdraw its loss: a child that reads
##   inline and exits normally gives a complete capture with no loss.
##
## And one case that needs no widening: "exec-ok", a successful inline exec
## into a monitored image. The new image withdraws the exec-armed file at
## init, so the capture is complete with no loss.
##
## Every case runs twice: with a short fragment directory, and with one under
## a `TMPDIR` longer than the shim's armed-path buffer
## (`CT_INLINE_ARMED_PATH_CAP`, 512 bytes). The second creates and removes
## every armed file through the directory-descriptor route instead of an
## absolute path, so a route that failed to create the file ("fe-kill", a
## false complete) or to remove it ("exec-ok", a spurious loss) is caught.
##
## x86_64 only: no other architecture has the inline-syscall trap backend.
##
## Mocks: none. Real program, real shim (built with the test-only define),
## real files.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc longTempDir(base: string): string =
  ## A directory whose path leaves no room for an armed file's absolute path
  ## in the shim's 512-byte buffer, so the fragment directory under it takes
  ## the descriptor route.
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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

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

static void sleep_us(long us) {
  struct timespec ts = {us / 1000000, (us % 1000000) * 1000};
  nanosleep(&ts, NULL);
}

static const char *noop;

static void *exit_now(void *arg) { (void)arg; exit(0); return NULL; }

static void *failing_exec(void *arg) {
  (void)arg;
  char *const av[] = {"/nonexistent-io-mon-window", NULL};
  execve(av[0], av, environ);
  return NULL;
}

static void *kill_soon(void *arg) {
  sleep_us((long)arg);
  kill(getpid(), SIGKILL);
  return NULL;
}

static void *hold_in_flight(void *arg) {
  (void)arg;
  raw6(SYS_close, -4242, 0, 0, 0, 0, 0);   /* held 100 ms in the window build */
  return NULL;
}

static void child(const char *mode) {
  pthread_t a, b, k;
  if (strcmp(mode, "cd-exit") == 0) {
    raw6(SYS_openat, AT_FDCWD, (long)"input-a.txt", O_RDONLY, 0, 0, 0);
    pthread_create(&a, NULL, exit_now, NULL);
    sleep_us(5000);
    pthread_create(&b, NULL, failing_exec, NULL);
    sleep_us(5000);
    kill(getpid(), SIGKILL);
    for (;;) pause();
  }
  if (strcmp(mode, "fe-kill") == 0) {
    char *const av[] = {"/nonexistent-io-mon-window", NULL};
    pthread_create(&k, NULL, kill_soon, (void *)5000L);
    raw6(SYS_execve, (long)av[0], (long)av, (long)environ, 0, 0, 0);
    for (;;) pause();
  }
  if (strcmp(mode, "exec-ok") == 0) {
    char *const av[] = {(char *)noop, NULL};
    raw6(SYS_execve, (long)noop, (long)av, (long)environ, 0, 0, 0);
    _exit(30);
  }
  _exit(31);
}

int main(int argc, char **argv) {
  if (argc < 4 || chdir(argv[1]) != 0) return 2;
  const char *mode = argv[2];
  noop = argv[3];
  pthread_t t;
  if (strcmp(mode, "fork-inflight") == 0) {
    pthread_create(&t, NULL, hold_in_flight, NULL);
    sleep_us(20000);
  }
  pid_t pid = fork();
  if (pid < 0) return 4;
  if (pid == 0) {
    if (strcmp(mode, "fork-inflight") == 0) {
      char buf[64];
      long fd = raw6(SYS_openat, AT_FDCWD, (long)"input-a.txt", O_RDONLY, 0,
                     0, 0);
      if (fd < 0) _exit(20);
      raw6(SYS_read, fd, (long)buf, sizeof(buf), 0, 0, 0);
      raw6(SYS_close, fd, 0, 0, 0, 0, 0);
      _exit(0);
    }
    child(mode);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 5;
  if (strcmp(mode, "fork-inflight") == 0) pthread_join(t, NULL);
  if (WIFSIGNALED(status))
    printf("child killed by signal %d\n", WTERMSIG(status));
  else
    printf("child exited %d\n", WEXITSTATUS(status));
  return 0;
}
"""

suite "io-mon Linux shim: the armed inline loss across its narrow windows":
  test "t_armed_inline_loss_holds_in_widened_windows":
    when not defined(amd64):
      skip()   # no inline-syscall trap backend on this architecture
    else:
      let work = expandFilename(getTempDir()) /
        ("io-mon-inline-windows-" & $getCurrentProcessId())
      removeDir(work)
      createDir(work)
      let snoopBin = work / "io-mon"
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      check cli.code == 0
      # The shim with the widened windows, built by the product's own script
      # into this test's private directory.
      var buildEnv = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): buildEnv[k] = v
      buildEnv["IO_MON_SHIM_OUT_DIR"] = work / "lib"
      buildEnv["IO_MON_SHIM_NIMCACHE_DIR"] = work / "nimcache"
      let shim = run("bash", @[repoRoot / "scripts" / "build_shim.sh",
        "-d:ioMonInlineWindowTest"], buildEnv)
      checkpoint(shim.output)
      check shim.code == 0
      let shimLib = work / "lib" / "librepro_monitor_shim.so"
      check fileExists(shimLib)
      let cc = getEnv("CC", "cc")
      let host = work / "windows-host"
      writeFile(host & ".c", hostSource)
      let hostCc = run(cc, @[host & ".c", "-O0", "-pthread", "-o", host])
      checkpoint(hostCc.output)
      check hostCc.code == 0
      let noop = work / "noop"
      writeFile(noop & ".c", "int main(void) { return 0; }\n")
      check run(cc, @[noop & ".c", "-o", noop]).code == 0

      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env.del("LD_PRELOAD")
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib

      let longTmp = longTempDir(work)
      for (dirKind, tmp) in [("short", ""), ("long", longTmp)]:
        for transport in ["set", "file"]:
          for mode in ["cd-exit", "fe-kill", "fork-inflight", "exec-ok"]:
            for attempt in 0 ..< 2:
              checkpoint("dir: " & dirKind & ", transport: " & transport &
                ", mode: " & mode & ", attempt " & $attempt)
              var runEnv = newStringTable(modeCaseSensitive)
              for k, v in env: runEnv[k] = v
              if tmp.len > 0:
                runEnv["TMPDIR"] = tmp
              if transport == "file":
                runEnv["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"
              let tree = work / ("tree-" & dirKind & "-" & transport & "-" &
                mode & "-" & $attempt)
              createDir(tree)
              let input = tree / "input-a.txt"
              writeFile(input, "input a\n")
              let depfile = work / (dirKind & "-" & transport & "-" & mode &
                "-" & $attempt & ".iomon")
              let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
                tree, mode, noop], runEnv)
              checkpoint(cap.output)
              check cap.code == 0
              let dep = readMonitorDepFile(depfile)
              for r in dep.records:
                if r.kind in {mrFileOpen, mrFileRead, mrEventLoss}:
                  checkpoint($r.kind & " " & r.path & " " & r.detail)
              let openRecorded = dep.records.anyIt(it.kind == mrFileOpen and
                it.path == input)
              let readRecorded = dep.records.anyIt(it.kind == mrFileRead and
                it.path == input)
              let anyLoss = dep.records.anyIt(it.kind == mrEventLoss)
              let unclassifiedLoss = dep.records.anyIt(it.kind == mrEventLoss and
                it.detail.startsWith(
                  "inline raw syscall events unclassified at image end"))
              checkpoint("open: " & $openRecorded & ", read: " & $readRecorded &
                ", unclassified loss: " & $unclassifiedLoss & ", completeness: " &
                $dep.completeness)
              case mode
              of "cd-exit":
                check "child killed by signal 9" in cap.output
                check not (dep.completeness == mcComplete and not openRecorded)
                check openRecorded or
                  (unclassifiedLoss and dep.completeness != mcComplete)
              of "fe-kill":
                check "child killed by signal 9" in cap.output
                check anyLoss
                check dep.completeness != mcComplete
              of "fork-inflight":
                check "child exited 0" in cap.output
                check readRecorded
                check not anyLoss
                check dep.completeness == mcComplete
              of "exec-ok":
                check "child exited 0" in cap.output
                check not anyLoss
                check dep.completeness == mcComplete
              else:
                check false
      removeDir(work)
