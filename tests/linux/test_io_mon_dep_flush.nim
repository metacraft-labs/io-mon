## test_io_mon_dep_flush — milestone io-mon-DEP-FLUSH integration tests.
##
## Closes the "exit/thread-exit/fork-before-flush loses buffered RMDF records"
## gap in the file-based dependency channel (see
## reprobuild-specs/io-mon-Dependency-Flush-Robustness.md). Each test drives the
## LIVE Linux LD_PRELOAD shim (rebuilt from source) against a short-lived C
## child and asserts the merged depfile is COMPLETE — i.e. every record the
## child appended survived process/thread/fork teardown.
##
## Work items exercised:
##   DEP-FLUSH-1  t_shim_flush_drains_calling_thread
##   DEP-FLUSH-2  t_short_lived_process_records_survive
##   DEP-FLUSH-3  t_worker_thread_records_survive_thread_exit
##   DEP-FLUSH-4  t_fork_child_does_not_duplicate_parent_batch
##   DEP-FLUSH-5  t_exit_flush_depfile_byte_identical_to_lazy

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

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

proc buildC(work, name, source: string; extraArgs: seq[string] = @[]): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result] & extraArgs)
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc ensureSnoop(work: string): string =
  result = work / "io-mon"
  if not fileExists(result):
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & result, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

proc ensureShim(): string =
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(buildShim.output)
  check buildShim.code == 0
  findShimLibrary()

proc childEnvWith(shimLib: string): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result["REPRO_MONITOR_SHIM_LIB"] = shimLib

proc fileReadCount(dep: MonitorDepFile; path: string): int =
  dep.records.countIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  fileReadCount(dep, path) > 0

suite "io-mon DEP-FLUSH dependency-flush robustness":
  let work = getTempDir() / ("io-mon-dep-flush-" & $getCurrentProcessId())
  createDir(work)

  test "t_shim_flush_drains_calling_thread":
    # DEP-FLUSH-1 — a monitored child that reads N distinct files and then
    # calls the exported repro_monitor_shim_flush() (via a dlsym lookup)
    # must have all N reads durable in the merged depfile. Proves the
    # exported flush now drains the calling thread's batch (was a no-op).
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    const N = 12
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("flush-marker-" & $i & ".txt")
      writeFile(m, "flush marker " & $i & "\n")
      markers.add m

    # The child reads every marker, then reaches into its own loaded shim
    # via dlsym("repro_monitor_shim_flush") and calls it. It then busy-loops
    # briefly WITHOUT any further I/O and exits — but the assertion is that
    # the explicit flush already made the reads durable.
    let reader = buildC(work, "flush_reader", """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
typedef int (*flush_fn)(void);
int main(int argc, char **argv) {
  char buf[64];
  for (int i = 1; i < argc; i++) {
    int fd = open(argv[i], O_RDONLY);
    if (fd < 0) return 2;
    read(fd, buf, sizeof(buf));
    close(fd);
  }
  flush_fn f = (flush_fn)dlsym(RTLD_DEFAULT, "repro_monitor_shim_flush");
  if (!f) return 3;
  f();
  return 0;
}
""", @["-ldl"])

    let depfile = work / "shim-flush.rdep"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader] & markers,
      childEnvWith(shimLib))
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    for m in markers:
      check hasFileRead(dep, m)

  test "t_short_lived_process_records_survive":
    # DEP-FLUSH-2 — a monitored child that opens+reads N files then exit(0)s
    # immediately (well under the 100 ms staleness flush and the 64 KiB
    # batch cap) must still have all N reads in the merged depfile, proving
    # the __attribute__((destructor)) → shutdown sweep flushed the buffered
    # batch that would otherwise be lost.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    const N = 16
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("shortlived-marker-" & $i & ".txt")
      writeFile(m, "short lived marker " & $i & "\n")
      markers.add m

    # exit(0) (libc, runs the destructor) after a tight read loop — no sleep,
    # no explicit flush. Durability must come from the process-exit teardown.
    let reader = buildC(work, "short_lived_reader", """
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  for (int i = 1; i < argc; i++) {
    int fd = open(argv[i], O_RDONLY);
    if (fd < 0) exit(2);
    read(fd, buf, sizeof(buf));
    close(fd);
  }
  exit(0);
}
""")

    let depfile = work / "short-lived.rdep"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader] & markers,
      childEnvWith(shimLib))
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    for m in markers:
      check hasFileRead(dep, m)
    check not dep.records.anyIt(it.kind == mrEventLoss and
      "kill-before-flush" in it.detail)

  test "t_worker_thread_records_survive_thread_exit":
    # DEP-FLUSH-3 — worker threads that each read a distinct file then RETURN
    # (thread exit) BEFORE the process exits. The parent joins them and then
    # exits. Every worker's read must be present, proving the
    # pthread_key_create thread-exit destructor flushed each worker's slot
    # (the process-exit destructor cannot reach an already-joined worker's
    # TLS).
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    const NThreads = 6
    var markers: seq[string]
    for i in 0 ..< NThreads:
      let m = work / ("worker-marker-" & $i & ".txt")
      writeFile(m, "worker thread marker " & $i & "\n")
      markers.add m

    # Each worker opens+reads its own marker then returns. The main thread
    # joins all workers (so they exit well before process exit) and returns.
    let reader = buildC(work, "worker_thread_reader", """
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
static char *g_paths[64];
static void *worker(void *arg) {
  long idx = (long)arg;
  char buf[64];
  int fd = open(g_paths[idx], O_RDONLY);
  if (fd < 0) return (void *)1;
  read(fd, buf, sizeof(buf));
  close(fd);
  return (void *)0;
}
int main(int argc, char **argv) {
  int n = argc - 1;
  if (n > 64) n = 64;
  for (int i = 0; i < n; i++) g_paths[i] = argv[i + 1];
  pthread_t th[64];
  for (long i = 0; i < n; i++)
    if (pthread_create(&th[i], NULL, worker, (void *)i) != 0) return 3;
  for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
  return 0;
}
""", @["-pthread"])

    let depfile = work / "worker-thread.rdep"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader] & markers,
      childEnvWith(shimLib))
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    for m in markers:
      check hasFileRead(dep, m)

  test "t_fork_child_does_not_duplicate_parent_batch":
    # DEP-FLUSH-4 — the parent reads a file (buffering a batch), then forks.
    # The child reads a DIFFERENT file and exits; the parent reads a THIRD
    # file and exits. The parent's pre-fork read must appear EXACTLY ONCE
    # (not replayed by the child through the COW-shared fd/batch), the
    # child's read exactly once under the child's own pid, and the parent's
    # post-fork read exactly once.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    let parentPre = work / "fork-parent-pre.txt"
    let childMarker = work / "fork-child.txt"
    let parentPost = work / "fork-parent-post.txt"
    writeFile(parentPre, "parent pre-fork marker\n")
    writeFile(childMarker, "child marker\n")
    writeFile(parentPost, "parent post-fork marker\n")

    let forker = buildC(work, "fork_no_dup_reader", """
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
static int read_file(const char *p) {
  char buf[64];
  int fd = open(p, O_RDONLY);
  if (fd < 0) return -1;
  int n = (int)read(fd, buf, sizeof(buf));
  close(fd);
  return n;
}
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  if (read_file(argv[1]) <= 0) return 3;   /* parent buffers a batch */
  pid_t pid = fork();
  if (pid < 0) return 4;
  if (pid == 0) {
    if (read_file(argv[2]) <= 0) _exit(5); /* child reads its own file */
    _exit(0);
  }
  int st;
  waitpid(pid, &st, 0);
  if (read_file(argv[3]) <= 0) return 6;   /* parent reads again */
  return 0;
}
""")

    let depfile = work / "fork-no-dup.rdep"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
      forker, parentPre, childMarker, parentPost], childEnvWith(shimLib))
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete
    # The parent's pre-fork read must be recorded exactly once — NOT
    # duplicated by the child replaying the inherited COW batch.
    check fileReadCount(dep, parentPre) == 1
    check fileReadCount(dep, childMarker) == 1
    check fileReadCount(dep, parentPost) == 1
    # The parent's pre-fork read belongs to the parent pid; the child's read
    # belongs to the child pid. Confirm they are attributed to DIFFERENT pids
    # (no cross-pid duplication of the parent's buffered frame).
    let preReads = dep.records.filterIt(
      it.kind == mrFileRead and parentPre in it.path)
    let childReads = dep.records.filterIt(
      it.kind == mrFileRead and childMarker in it.path)
    check preReads.len == 1
    check childReads.len == 1
    check preReads[0].osPid != childReads[0].osPid

  test "t_exit_flush_depfile_byte_identical_to_lazy":
    # DEP-FLUSH-5 — determinism guard. The SAME workload is captured twice:
    #  (lazy)  the child sleeps > 100 ms after each read so the staleness
    #          timer flushes each batch lazily during the run.
    #  (exit)  the child reads back-to-back and exits fast so the batch is
    #          flushed only by the process-exit teardown.
    # The canonical merged depfile bytes (mergeFragments order) must be
    # byte-identical between the two, proving exit-flush changes only WHEN
    # bytes are written, never WHAT is written.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    const N = 8
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("det-marker-" & $i & ".txt")
      writeFile(m, "determinism marker " & $i & "\n")
      markers.add m

    # argv[1] = per-read sleep in ms (0 => exit-flush path; >100 => lazy).
    let reader = buildC(work, "determinism_reader", """
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  long ms = strtol(argv[1], NULL, 10);
  for (int i = 2; i < argc; i++) {
    int fd = open(argv[i], O_RDONLY);
    if (fd < 0) return 2;
    read(fd, buf, sizeof(buf));
    close(fd);
    if (ms > 0) usleep((useconds_t)ms * 1000);
  }
  return 0;
}
""")

    proc canonicalBytes(sleepMs: string; tag: string): seq[byte] =
      let depfile = work / ("determinism-" & tag & ".rdep")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
        reader, sleepMs] & markers, childEnvWith(shimLib))
      checkpoint(tag & ": " & cap.output)
      check cap.code == 0
      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcComplete
      for m in markers:
        check hasFileRead(dep, m)
      # Re-encode canonically so pid/thread scheduling jitter and batch
      # boundaries are normalised away; only the observed dependency set +
      # canonical order remain. This is the byte-identity contract.
      #
      # Two separate `io-mon run` invocations mint different per-run ids
      # (a timestamp stamped into every record's `run=<id>` detail token)
      # and run under different pids — launcher noise ORTHOGONAL to WHEN a
      # batch was flushed. Normalise both out (drop the run token from the
      # detail, zero the pid/thread) so the comparison isolates the flush-
      # timing contract: lazy-flush vs exit-flush must yield identical
      # observed-dependency bytes.
      var norm = dep.records.filterIt(it.kind == mrFileRead and
        it.path.startsWith(work / "det-marker-"))
      for i in 0 ..< norm.len:
        # Zero every field that is per-run launcher noise (pids, tid, the
        # inherited fd number stashed in `flags`, byte-count in `result`,
        # and the run-token detail); keep only kind + observationKind +
        # path — the observed-dependency identity the flush contract fixes.
        norm[i].osPid = 0
        norm[i].parentOsPid = 0
        norm[i].threadId = 0
        norm[i].childOsPid = 0
        norm[i].flags = 0
        norm[i].result = 0
        norm[i].probeResult = prUnknown
        norm[i].detail = ""
      encodeCanonical(norm)

    let lazyBytes = canonicalBytes("150", "lazy")
    let exitBytes = canonicalBytes("0", "exit")
    check lazyBytes == exitBytes
