## test_io_mon_macos_threaded_write — writes (and reads) issued from a NON-MAIN
## thread are captured as `mrFileWrite` / `mrFileOpen` records, closing the
## tracked threaded-write capture gap.
##
## # The defect this guards against
##
## The fragment writer (io_mon/writer.nim) batches a thread's records into a
## per-thread (threadvar) buffer that is flushed to disk only on overflow
## (64 KiB), a 100 ms staleness age-check (which is LAZY — it fires only on the
## NEXT emit), a fragment-key change, or an explicit flush. The process-exit dyld
## destructor flushes ONLY the main thread's threadvar batch. A WORKER thread
## (`pthread_create`d by the monitored program) that writes a file and then EXITS
## before process teardown left its buffered records unflushed — they were
## silently LOST (no `mrFileWrite` record for the threaded write).
##
## A pthread-key thread-exit destructor cannot fix this: macOS tears down a
## non-Nim thread's Nim-runtime TLS before pthread destructors run, so a Nim
## flush call from there faults. The fix flushes a worker thread's batch
## SYNCHRONOUSLY inside the emit path (while the thread is alive); the main
## thread keeps the batching win.
##
## # What this test asserts
##
## A probe writes a uniquely-tagged file from the MAIN thread and ANOTHER from a
## `pthread_create`d CHILD thread (then joins it). Under each diagnostic A/B arm
## (interpose-only, body-patch-only, and the default both-on)
## the merged depfile must contain an `mrFileWrite` record for BOTH the
## parent-thread file AND the child-thread file, and the two writes must carry
## DIFFERENT thread ids (proving the child-thread record is genuinely captured,
## not the parent's). macOS-only; no-op pass elsewhere.
##
## A second real pthread probe joins 256 short-lived workers under a 128-file
## descriptor limit. Every worker's write must survive, and open descriptors
## must return to their baseline. No process, filesystem or monitor is mocked.

import std/[os, osproc, streams, strtabs, unittest]
from std/strutils import contains

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

when defined(macosx):
  import io_mon  # readMonitorDepFile, mergeFragments, MonitorObservationKind
  import io_mon/writer
  import macos_backend_toggle  # applyMacosBackendToggle (A/B → debug toggles)

  from build_test_shim import buildPrivateMacosShim

  proc buildShim(): string =
    buildPrivateMacosShim(repoRoot)

  proc compileThreadedProbe(work: string): tuple[bin, parentOut, childOut: string] =
    ## Compile a probe that writes a tagged file from the main thread and another
    ## from a pthread_create'd child thread (joined before exit).
    let parentOut = work / "parent_thread.txt"
    let childOut = work / "child_thread.txt"
    let src = work / "threaded_write_probe.c"
    writeFile(src, """
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/resource.h>

static void write_tagged(const char *path, const char *tag) {
  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) { perror("open"); _exit(2); }
  char buf[128]; int n = snprintf(buf, sizeof(buf), "%s-marker\n", tag);
  if (write(fd, buf, (size_t)n) != n) { perror("write"); _exit(3); }
  close(fd);
}

static const char *g_child_path;
static void *child_thread(void *arg) {
  (void)arg;
  /* The crux: this write happens on a NON-MAIN thread that then exits. */
  write_tagged(g_child_path, "child-thread");
  return NULL;
}

static int open_descriptors(void) {
  int count = 0;
  for (int fd = 0; fd < 128; ++fd)
    if (fcntl(fd, F_GETFD) >= 0) ++count;
  return count;
}

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: %s <parent-out> <child-out>\n", argv[0]); return 2; }
  write_tagged(argv[1], "parent-thread");  /* main-thread write */
  if (argc == 4 && strcmp(argv[3], "churn") == 0) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return 10;
    limit.rlim_cur = 128;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return 11;
    int before = open_descriptors();
    for (int i = 0; i < 256; ++i) {
      char path[4096];
      snprintf(path, sizeof(path), "%s-%d", argv[2], i);
      g_child_path = path;
      pthread_t worker;
      if (pthread_create(&worker, NULL, child_thread, NULL) != 0) return 12;
      if (pthread_join(worker, NULL) != 0) return 13;
      int after = open_descriptors();
      if (after > before + 4) {
        fprintf(stderr, "worker %d leaked descriptors: before=%d after=%d\n", i, before, after);
        return 14;
      }
    }
    return 0;
  }
  g_child_path = argv[2];
  pthread_t t;
  if (pthread_create(&t, NULL, child_thread, NULL) != 0) { perror("pthread_create"); return 4; }
  pthread_join(t, NULL);
  return 0;
}
""")
    let bin = work / "threaded_write_probe"
    let cc = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(cc) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(bin))
    doAssert code == 0, "probe compile failed: " & output
    doAssert fileExists(bin)
    (bin, parentOut, childOut)

  type WriteHit = object
    found: bool
    threadId: uint64

  proc findWrite(records: seq[MonitorRecord]; target: string): WriteHit =
    ## Find an mrFileWrite (or write-classified open) record for `target` and
    ## return its thread id, so the caller can assert the parent/child writes
    ## came from DIFFERENT threads.
    for rec in records:
      if rec.path.len > 0 and target in rec.path and
          rec.observationKind == moFileWrite:
        return WriteHit(found: true, threadId: rec.threadId)
    WriteHit(found: false)

  proc captureThreadedWrites(shim, probe, parentOut, childOut, backend: string):
      tuple[parent, child: WriteHit] =
    let work = getTempDir() /
      ("io-mon-tw-" & backend & "-" & $getCurrentProcessId())
    createDir(work)
    defer: removeDir(work)
    let fragmentDir = work / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)

    let p = startProcess(probe, args = @[parentOut, childOut], env = env,
      options = {poStdErrToStdOut})
    let stderrOut = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] probe exit=" & $code & " stderr=" & stderrOut)
    doAssert code == 0, "probe under shim should exit 0"

    let depfile = work / "cap.iomon"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    let dep = readMonitorDepFile(depfile)
    result.parent = findWrite(dep.records, "parent_thread.txt")
    result.child = findWrite(dep.records, "child_thread.txt")

suite "io-mon macOS threaded-write capture (non-main-thread writes)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-tw-probe-" & $getCurrentProcessId())
    createDir(work)
    let (probe, parentOut, childOut) = compileThreadedProbe(work)

    test "body-patch ('both') captures BOTH the main- and child-thread writes":
      let hits = captureThreadedWrites(shim, probe, parentOut, childOut, "both")
      check hits.parent.found
      check hits.child.found  # the regression: the child-thread write was lost
      # The two writes must be from DIFFERENT threads — proving the child-thread
      # record is genuinely captured, not a duplicate of the parent's.
      check hits.parent.threadId != hits.child.threadId

    test "interpose backend also captures the child-thread write":
      let hits = captureThreadedWrites(shim, probe, parentOut, childOut, "interpose")
      check hits.parent.found
      check hits.child.found
      check hits.parent.threadId != hits.child.threadId

    test "bodypatch backend captures the child-thread write":
      let hits = captureThreadedWrites(shim, probe, parentOut, childOut, "bodypatch")
      check hits.parent.found
      check hits.child.found
      check hits.parent.threadId != hits.child.threadId

    test "short-lived workers release descriptors and preserve every write":
      let fragments = work / "churn-fragments"
      createDir(fragments)
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["DYLD_INSERT_LIBRARIES"] = shim
      env["REPRO_MONITOR_FRAGMENT_DIR"] = fragments
      applyMacosBackendToggle(env, "both")
      let p = startProcess(probe, args = @[parentOut, childOut, "churn"],
        env = env, options = {poStdErrToStdOut})
      let output = p.outputStream.readAll()
      let code = p.waitForExit()
      p.close()
      checkpoint(output)
      require code == 0
      let depfile = work / "churn.iomon"
      discard mergeFragments(fragments, depfile)
      let dep = readMonitorDepFile(depfile)
      for i in 0 ..< 256:
        let target = childOut & "-" & $i
        var found = false
        for record in dep.records:
          if record.path == target and record.observationKind == moFileWrite:
            found = true
            break
        check found

    test "releasing worker handles preserves the cumulative fragment cap":
      let fragments = work / "capped-worker"
      createDir(fragments)
      setFragmentByteCap(4096)
      defer:
        closeFragmentSlot()
        setFragmentByteCap(0)
      for i in 0 ..< 200:
        appendFragmentRecord(fragments, MonitorRecord(
          kind: mrFileWrite, observationKind: moFileWrite,
          osPid: 123, threadId: 456, seq: uint64(i),
          path: work / ("capped-output-" & $i)))
        closeFragmentSlot(retainIdentity = true)
        check not sigSafeSlotIsOpen()
        check not fragmentSlotIsRegistered()
      check fragmentSlotIsOverCap()
      let fragment = fragmentPath(fragments, 123, 456)
      # The cap counts payload frames; its loss/commit markers add bytes too.
      check getFileSize(fragment) < 3 * 4096
      let cappedSize = getFileSize(fragment)
      appendFragmentRecord(fragments, MonitorRecord(
        kind: mrFileWrite, observationKind: moFileWrite,
        osPid: 123, threadId: 456, seq: 201, path: work / "after-cap"))
      closeFragmentSlot(retainIdentity = true)
      check getFileSize(fragment) == cappedSize
      let dep = mergeFragments(fragments, work / "capped-worker.iomon")
      check dep.completeness == mcIncomplete

    removeDir(work)
  else:
    test "threaded-write capture is macOS-only (no-op on this platform)":
      check true
