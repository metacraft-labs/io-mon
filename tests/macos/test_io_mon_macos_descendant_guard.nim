## Real double-forked, setsid descendant: a blocked release signal holds it alive
## until AFTER finishMonitor, independently of scheduling and host load.
import std/[os, osproc, posix, streams, strutils, tempfiles, unittest]
import io_mon
import descendant_guard_expectations

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc run(cmd: string; args: seq[string]): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, options = {poStdErrToStdOut, poUsePath})
  result.output = p.outputStream.readAll()
  result.code = p.waitForExit()
  p.close()

proc awaitFile(path: string) =
  for attempt in 0 ..< 1000:
    if fileExists(path): return
    sleep(10)
  raise newException(IOError, "descendant did not acknowledge release: " & path)

const detachedDescendantSrc = """
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static _Atomic int *ready = NULL;

static void fail_child(int code) {
  if (ready) atomic_store_explicit(ready, -code, memory_order_release);
  _exit(code);
}

static void msleep_arg(const char *s) {
  long ms = strtol(s, NULL, 10);
  if (ms > 0) usleep((useconds_t)ms * 1000);
}

int main(int argc, char **argv) {
  if (argc != 6) return 2;
  const char *release = argv[5];
  int gated = strcmp(release, "-") != 0;
  sigset_t release_set;
  sigemptyset(&release_set);
  sigaddset(&release_set, SIGUSR1);
  /* Block before forking. A release sent before sigwait is pending rather
     than lost; no filesystem polling runs while finish tears the monitor down. */
  if (gated && sigprocmask(SIG_BLOCK, &release_set, NULL) != 0) return 10;

  if (gated) {
    ready = mmap(NULL, sizeof(*ready), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANON, -1, 0);
    if (ready == MAP_FAILED) return 15;
    atomic_init(ready, 0);
  }
  int rp[2];
  if (pipe(rp) != 0) return 8;

  pid_t pid = fork();
  if (pid < 0) return 3;
  if (pid > 0) {
    close(rp[1]);
    char b;
    if (gated) {
      /* Release/acquire publishes readiness only after every child file and
         descriptor operation has returned through the shim. A pipe byte alone
         can wake the root before the child's write/close hook has finished. */
      int state;
      do {
        state = atomic_load_explicit(ready, memory_order_acquire);
        if (state == 0) usleep(1000);
      } while (state == 0);
      if (state != 1) return 9;
    } else {
      /* Wait until the descendant has fully EXITED (pipe EOF), so the grace
         window opens over a provably quiesced tree. */
      while (read(rp[0], &b, 1) > 0) { /* drain until EOF */ }
    }
    close(rp[0]);
    return 0;
  }
  close(rp[0]);
  if (setsid() < 0) fail_child(4);
  pid = fork();
  if (pid < 0) fail_child(5);
  if (pid > 0) _exit(0);

  if (gated) {
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) maxfd = 4096;
    for (int fd = 0; fd < maxfd; fd++) {
      if (fd != rp[1]) close(fd);
    }
    int dn = open("/dev/null", O_RDWR);
    if (dn == 0) { dup2(dn, 1); dup2(dn, 2); }
  }

  msleep_arg(argv[3]);
  int in = open(argv[1], O_RDONLY);
  if (in < 0) fail_child(6);
  char buf[64];
  ssize_t n = read(in, buf, sizeof(buf));
  close(in);
  int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out >= 0) {
    if (n > 0) { if (write(out, "read\n", 5) < 0) {} }
    else { if (write(out, "empty\n", 6) < 0) {} }
    close(out);
  }
  if (gated) {
    char pid_path[4096];
    snprintf(pid_path, sizeof(pid_path), "%s.pid", release);
    FILE *pid_file = fopen(pid_path, "w");
    if (!pid_file) fail_child(11);
    if (fprintf(pid_file, "%ld\n", (long)getpid()) < 0) fail_child(12);
    if (fclose(pid_file) != 0) fail_child(13);
    close(rp[1]);
    atomic_store_explicit(ready, 1, memory_order_release);
    int received = 0;
    if (sigwait(&release_set, &received) != 0 || received != SIGUSR1) _exit(14);
    /* Acknowledge release before the harness removes the fixture files. */
    char ack[4096];
    snprintf(ack, sizeof(ack), "%s.ack", release);
    int af = open(ack, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (af >= 0) { if (write(af, "gone\n", 5) < 0) {} close(af); }
    _exit(n > 0 ? 0 : 7);
  }
  msleep_arg(argv[4]);
  _exit(n > 0 ? 0 : 7);
}
"""


suite "macOS descendant finish fails closed":
  let work = createTempDir("io-mon-descendant-", "")
  let source = work / "descendant.c"
  let fixture = work / "descendant"
  writeFile(source, detachedDescendantSrc)
  let built = run(getEnv("CC", "cc"), @[source, "-o", fixture])
  doAssert built.code == 0, built.output
  putEnv(ShimLibOverrideEnv, repoRoot / "build/lib/librepro_monitor_shim.dylib")
  writeFile(work / "input", "real dependency")

  for hosted in [false, true]:
    for detached in [true, false]:
      test "hosted=" & $hosted & " detached=" & $detached:
        let stem = work / ($hosted & "-" & $detached)
        let release = stem & ".release"
        let proof = stem & ".proof"
        let request = FsSnoopRequest(
          command: @[fixture, work / "input", proof, "0", "0",
            (if detached: release else: "-")],
          depFilePath: stem & ".iomon")
        var monitored: MonitorResult
        try:
          if hosted:
            var handle = startMonitor(request)
            while not pollMonitor(handle): sleep(5)
            monitored = finishMonitor(move(handle))
          else:
            monitored = runMonitored(request)
          check monitored.exitCode == 0
          if detached:
            let descendant = Pid(parseInt(readFile(release & ".pid").strip()))
            check posix.kill(descendant, 0) == 0
          check fileExists(proof)
          check readFile(proof) == "read\n"
          echo "binary=", getAppFilename(), " hosted=", hosted,
            " detached=", detached, " verdict=", monitored.completeness
          check monitored.completeness == mcIncomplete
          let disk = readMonitorDepFile(request.depFilePath)
          check disk.completeness == mcIncomplete
          var markers = 0
          var inputRead = false
          for record in disk.records:
            if isDescendantLimitation(record): inc markers
            if record.kind == mrFileRead and record.path == expandFilename(work / "input"):
              inputRead = true
          check markers == 1
          check inputRead
          check disk.records == monitored.depFile.records
          check subsystemEvidence(disk).completeness == mcComplete
        finally:
          if detached:
            awaitFile(release & ".pid")
            let descendant = Pid(parseInt(readFile(release & ".pid").strip()))
            doAssert posix.kill(descendant, SIGUSR1) == 0
            awaitFile(release & ".ack")
  test "reduced interest and reads-only scope retain the guard":
    let request = FsSnoopRequest(command: @[fixture, work / "input",
      work / "narrow.proof", "0", "0", "-"],
      depFilePath: work / "narrow.iomon", interest: {ecProcessTree},
      evidenceScope: esReadsOnly)
    let monitored = runMonitored(request)
    check monitored.exitCode == 0
    check monitored.completeness == mcIncomplete
    let disk = readMonitorDepFile(request.depFilePath)
    check disk.completeness == mcIncomplete
    var markers = 0
    for record in disk.records:
      if isDescendantLimitation(record): inc markers
    check markers == 1
    check disk.records == monitored.depFile.records
    check subsystemEvidence(disk).completeness == mcComplete
  removeDir(work)
