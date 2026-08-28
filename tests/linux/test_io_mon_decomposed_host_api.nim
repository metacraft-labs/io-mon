## test_io_mon_decomposed_host_api — IoMon-Decomposed-Host-API DH-2.
##
## The monitor lifecycle is now three steps a caller can drive —
## `startMonitor` → `pollMonitor` → `finishMonitor` — so a build engine can
## interleave N in-flight monitors in ONE poll loop instead of serialising the
## build behind N blocking `runMonitored` calls. Moving the WAIT out of
## `runMonitored` is exactly what re-opens the LF-2 window it used to close by
## owning the whole lifecycle, so the decomposed form carries its own
## STRUCTURAL guarantee (a non-copyable handle whose destructor reaps the
## monitored root before releasing the consumer). These cases pin that the
## capability is real and that the guarantee is not merely written down.
##
## NO MOCKS. Every monitored program here is a C binary compiled by the host
## toolchain during the test; the rendezvous between the concurrent monitors is
## real files on the real filesystem; the evidence asserted on is what the live
## LD_PRELOAD shim actually captured; and the "was the producer orphaned?"
## question is answered by looking at the real `/proc` entry and the real
## fragment directory under `$TMPDIR`. A faked spawn cannot demonstrate any of
## it — the property under test is precisely what the REAL producer/consumer
## pair does at the moment the handle is dropped.
##
##   t_a_dropped_handle_cannot_orphan_a_producer — the LF-2 case. A handle is
##       taken over a child that is DEMONSTRABLY still running (it has published
##       a ready marker and `pollMonitor` says `false`), and then the scope is
##       left WITHOUT calling `finishMonitor`. The drop must reap the child
##       before releasing the consumer: the leave takes as long as the child's
##       remaining lifetime, the child completes rather than being killed, the
##       fragment directory this run created is gone afterwards (the §4.1
##       incident was a descendant appending to a fragment inside a directory
##       the launcher had already deleted), and the module's live-monitor census
##       returns to zero. Evidence is NOT produced — dropping costs you the
##       depfile, never the safety.
##
##   t_n_monitors_interleave_in_one_poll_loop — the capability HM-4 needs. THREE
##       monitors are started before any of them is waited on, polled in one
##       loop on ONE thread, and finished as they complete. Simultaneity is
##       ENFORCED, not assumed: each child blocks until it has seen every peer's
##       ready marker AND a gate file the host only creates once all three are
##       parked, so a serialised host (start, finish, start, finish) deadlocks
##       its first child against the ceiling and it exits non-zero. The same
##       parked window is what makes the "poll does not block" assertion
##       deterministic.
##
##   t_runMonitored_is_the_decomposed_form — `runMonitored` must not be a second
##       implementation of the lifecycle, because DH-4's premise is that the
##       batch and decomposed paths agree. Pinned twice: at RUNTIME through
##       `monitorLifecycleCounts` (one `runMonitored` call moves the
##       `startMonitor` and `finishMonitor` counters by exactly one each, which
##       a reimplementation would not do), and at SOURCE level by asserting that
##       the body of `runMonitored` is the single expression
##       `finishMonitor(startMonitor(request))` with nothing else in it.
##
## The handle's EXCLUSIVITY (non-copyability, and its transitive propagation
## through `seq`/arrays/wrappers) is a compile-time property and is pinned by
## `tests/portable/test_io_mon_monitor_handle_exclusivity.nim`, which drives the
## real compiler at it.

import std/[monotimes, os, osproc, sequtils, streams, strutils, times, unittest]

import io_mon                            # the PUBLIC host API
import shm_gset                          # shmGSetSupported

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

  ## How long the dropped-handle case's child lingers after the handle is
  ## dropped, and the floor the observed drop cost must clear. The gap between
  ## them absorbs scheduling noise while still being far larger than the ~0ms a
  ## destructor that did NOT wait would take.
  DropLingerMs = 2_000
  DropWaitFloorMs = 1_200

# --------------------------------------------------------------------------
# Helpers.
#
# Every helper that ASSERTS is a `template`: `check` inside a plain `proc`
# prints "Check failed" but leaves the case labelled `[OK]`, so an assertion
# hidden in a proc cannot fail the test it belongs to. Helpers that merely DO
# something are procs and signal failure by RAISING, which unittest reports as
# a genuine `[FAILED]`.
# --------------------------------------------------------------------------

proc run(cmd: string; args: seq[string]): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc buildC(work, name, source: string): string =
  ## Compile `source` to `work/name` with the host toolchain. Raises on failure
  ## — a helper must not swallow a broken fixture into a green test.
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result])
  if built.code != 0 or not fileExists(result):
    raise newException(IOError,
      "failed to compile fixture " & name & " (exit " & $built.code & "): " &
        built.output)

proc ensureShim(): string =
  ## Build the shim the way the rest of the Linux suite does and resolve it with
  ## the same discovery `startMonitor` uses.
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  if buildShim.code != 0:
    raise newException(IOError, "build_shim.sh failed: " & buildShim.output)
  result = findShimLibrary()
  if result.len == 0:
    raise newException(IOError, "findShimLibrary() resolved nothing after build")

proc awaitFile(path: string; ceilingMs = 30_000) =
  ## Block until `path` appears. RAISES on the ceiling, so a rendezvous that
  ## never happens is a `[FAILED]` naming the file rather than a hang.
  let start = getMonoTime()
  while not fileExists(path):
    if inMilliseconds(getMonoTime() - start) >= ceilingMs:
      raise newException(IOError,
        "timed out after " & $ceilingMs & "ms waiting for " & path)
    sleep(10)

proc processIsRunning(pid: uint64): bool =
  ## Is `pid` a live (non-zombie) process? Read straight out of `/proc`, which
  ## is the same place the §4.1 descendant guard looks.
  if pid == 0:
    return false
  let statPath = "/proc" / $pid / "stat"
  var stat = ""
  try:
    stat = readFile(statPath)
  except IOError, OSError:
    return false
  let closeParen = stat.rfind(")")
  if closeParen < 0 or closeParen + 2 >= stat.len:
    return false
  stat[closeParen + 2] != 'Z'

proc fragmentDirsOfThisProcess(): seq[string] =
  ## Every `repro-fs-snoop-fragments-*` scratch directory `createLocalTempDir`
  ## could have made for THIS host process (the name carries our pid). This is
  ## the §4.1 artefact: the incident was a descendant appending to a `.iomon-frag`
  ## inside a directory the launcher had already removed, so "did the drop clean
  ## up" is a question about exactly these directories.
  result = @[]
  let prefix = "repro-fs-snoop-fragments-" & $getCurrentProcessId() & "-"
  try:
    for kind, path in walkDir(getTempDir()):
      if kind == pcDir and path.extractFilename.startsWith(prefix):
        result.add path
  except OSError:
    discard

proc hasFileRead(recs: seq[MonitorRecord]; path: string): bool =
  recs.anyIt(it.kind == mrFileRead and it.observationKind == moFileRead and
    path in it.path)

proc anyPathMentions(recs: seq[MonitorRecord]; needle: string): bool =
  recs.anyIt(needle in it.path)

## The monitored program for the dropped-handle case.
##   argv[1] — ready marker: published as soon as the child is running, so the
##             host can drop the handle while the producer is DEMONSTRABLY live
##   argv[2] — the input file to read (so the run has something to capture)
##   argv[3] — microseconds to linger AFTER the read
##   argv[4] — verdict marker, written LAST. Its CONTENT is the LF-2 question
##             asked from the producer's own side: at the moment this producer
##             finished, was the consumer's fragment directory (the one named to
##             it by `REPRO_MONITOR_FRAGMENT_DIR`) still there?
##                 "present" — the launcher had not torn down under it
##                 "missing" — the §4.1 shape: the fragment directory was
##                             removed while this producer was still running
##                 "unset"   — no injection at all, so the question is moot and
##                             the assertion must not be allowed to pass
##             That the file exists at all is the second signal: it means the
##             child ran to COMPLETION rather than being killed by the teardown.
const lingeringProducerSrc = """
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
static int put(const char *p, const char *text) {
  int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return -1;
  size_t n = strlen(text);
  if (write(fd, text, n) != (ssize_t)n) { close(fd); return -1; }
  close(fd);
  return 0;
}
int main(int argc, char **argv) {
  char buf[64];
  struct stat st;
  if (argc < 5) return 1;
  if (put(argv[1], "x") != 0) return 2;
  int fd = open(argv[2], O_RDONLY);
  if (fd < 0) return 3;
  if (read(fd, buf, sizeof(buf)) < 0) return 4;
  close(fd);
  usleep((useconds_t)atoi(argv[3]));
  const char *fragDir = getenv("REPRO_MONITOR_FRAGMENT_DIR");
  const char *verdict = "unset";
  if (fragDir != NULL && fragDir[0] != '\0') {
    verdict = (stat(fragDir, &st) == 0) ? "present" : "missing";
  }
  if (put(argv[4], verdict) != 0) return 5;
  return 0;
}
"""

## The monitored program for the poll-loop case.
##   argv[1] — my ready marker
##   argv[2] — the gate file; the host creates it only once EVERY monitor is
##             started and parked, so a serialised host never gets here
##   argv[3] — my own input file
##   argv[4] — my done marker
##   argv[5..] — every peer's ready marker; block until all are present
## Exit 3 = the peers never showed up (the runs were serialised).
## Exit 6 = the gate never opened (likewise, from the other direction).
const gatedRendezvousSrc = """
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
static int touch(const char *p) {
  int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return -1;
  if (write(fd, "x", 1) != 1) { close(fd); return -1; }
  close(fd);
  return 0;
}
static int awaitPath(const char *p) {
  struct stat st;
  for (int i = 0; i < 3000; i++) {      /* 30s ceiling */
    if (stat(p, &st) == 0) return 1;
    usleep(10000);
  }
  return 0;
}
int main(int argc, char **argv) {
  char buf[64];
  if (argc < 6) return 1;
  if (touch(argv[1]) != 0) return 2;
  for (int i = 5; i < argc; i++) {
    if (!awaitPath(argv[i])) return 3;  /* the runs were serialised */
  }
  if (!awaitPath(argv[2])) return 6;    /* the gate never opened */
  int fd = open(argv[3], O_RDONLY);
  if (fd < 0) return 4;
  if (read(fd, buf, sizeof(buf)) < 0) return 5;
  close(fd);
  if (touch(argv[4]) != 0) return 7;
  return 0;
}
"""

# --------------------------------------------------------------------------
# Source-level reading of `runMonitored`, for the delegation case.
# --------------------------------------------------------------------------

proc runMonitoredBodyLines(): seq[string] =
  ## The CODE lines of `runMonitored`'s body: everything from its `proc` line to
  ## the next top-level `proc`, minus doc comments and blank lines.
  ##
  ## Deliberately the dumbest parser that can answer the question, because this
  ## campaign's holes have repeatedly been in clever little helper parsers
  ## nobody re-read. It has exactly one job — decide whether the body is one
  ## expression or more — and it fails loudly (RAISES) if it cannot find the
  ## proc at all, so a rename can never make the assertion vacuously true.
  let source = readFile(repoRoot / "src" / "io_mon" / "fs_snoop.nim")
  let lines = source.splitLines()
  var start = -1
  for i, line in lines:
    if line.startsWith("proc runMonitored*("):
      start = i
      break
  if start < 0:
    raise newException(ValueError,
      "could not find `proc runMonitored*(` in src/io_mon/fs_snoop.nim")
  result = @[]
  for i in start + 1 ..< lines.len:
    let line = lines[i]
    if line.startsWith("proc ") or line.startsWith("type ") or
        line.startsWith("# ---"):
      break
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("##"):
      continue
    result.add stripped

suite "io-mon decomposed host API (DH-2)":

  test "t_a_dropped_handle_cannot_orphan_a_producer":
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh2-drop-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let input = work / "dropped-handle-input.txt"
    writeFile(input, "dropped handle marker\n")
    let ready = work / "producer.ready"
    let done = work / "producer.done"
    let depPath = work / "dropped.iomon"
    let producer = buildC(work, "dh2_lingering_producer", lingeringProducerSrc)

    let before = monitorLifecycleCounts()
    let fragmentsBefore = fragmentDirsOfThisProcess().len

    var req: FsSnoopRequest
    req.command = @[producer, ready, input, $(DropLingerMs * 1000), done]
    req.depFilePath = depPath
    req.streamMode = fsoNone

    var childPid = 0'u64
    var fragmentsWhileLive = 0
    var liveWhileLive = 0
    var polledFalse = false

    block dropTheHandle:
      var handle = startMonitor(req)
      childPid = handle.rootPid

      # The producer is DEMONSTRABLY live at the moment of the drop: it has
      # published its ready marker and it is still lingering. Without this the
      # case could pass against a child that had already exited on its own,
      # which proves nothing about ordering.
      awaitFile(ready)
      polledFalse = not pollMonitor(handle)
      fragmentsWhileLive = fragmentDirsOfThisProcess().len
      liveWhileLive = monitorLifecycleCounts().live
      check handle.live
      check childPid != 0
      check processIsRunning(childPid)

      # …and now the handle is simply DROPPED. No `finishMonitor`, no `defer`,
      # no cleanup call of any kind — the scope just ends. (What the drop COSTS
      # is measured by the next case; this one is about what it GUARANTEES.)

    checkpoint("childPid=" & $childPid & " fragmentsBefore=" & $fragmentsBefore &
      " fragmentsWhileLive=" & $fragmentsWhileLive)

    check polledFalse                     # the child really was still running
    check fragmentsWhileLive == fragmentsBefore + 1
    check liveWhileLive == before.live + 1

    let after = monitorLifecycleCounts()
    checkpoint("counts before=" & $before & " after=" & $after)

    # (1) THE ORDERING, asked from the PRODUCER's own side. The consumer is
    #     released only after the monitored root has been reaped, so there is no
    #     window in which a live producer faces a deleted fragment directory —
    #     which is precisely the §4.1 incident (a descendant appending to an
    #     unlinked `.iomon-frag` until it filled the root tmpfs). The child
    #     `stat`s its own `REPRO_MONITOR_FRAGMENT_DIR` as its last act and
    #     reports what it found.
    check fileExists(done)                       # …and it ran to completion
    # Read defensively: when the drop DOES orphan the producer this file has
    # not been written yet, and a raising `readFile` would abort the case
    # before its remaining primary assertions had a chance to report.
    let verdict =
      if fileExists(done): readFile(done).strip() else: "<no verdict written>"
    checkpoint("producer's verdict on its fragment dir: " & verdict)
    check verdict == "present"                   # not "missing", not "unset"
    #     It is also no longer running now that the scope has ended.
    check not processIsRunning(childPid)

    # (2) The scratch state the §4.1 incident grew inside is GONE — released by
    #     the drop, not left for the next reboot.
    check fragmentDirsOfThisProcess().len == fragmentsBefore

    # (3) The module's own census agrees: nothing is outstanding. `released`
    #     advanced without `finished` doing so, which is precisely the shape of
    #     "a handle was dropped rather than finished".
    check after.started == before.started + 1
    check after.released == before.released + 1
    check after.finished == before.finished
    check after.live == before.live

    # (4) Dropping costs the EVIDENCE. A dropped handle never wrote a depfile,
    #     which is what makes (1)–(3) a safety guarantee rather than a silent
    #     second way to finish a monitor.
    check not fileExists(depPath)

    removeDir(work)

  test "t_a_dropped_handle_waits_for_its_producer":
    ## Split out of the case above so the WAIT has its own primary assertion
    ## and its own failure line: (1) there proves the child completed, this
    ## proves the DROP is what waited for it. A destructor that released the
    ## consumer and walked away would satisfy "the child completed eventually"
    ## while still leaving the orphan window open.
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh2-dropwait-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let input = work / "drop-wait-input.txt"
    writeFile(input, "drop wait marker\n")
    let ready = work / "waiter.ready"
    let done = work / "waiter.done"
    let producer = buildC(work, "dh2_lingering_producer2", lingeringProducerSrc)

    var req: FsSnoopRequest
    req.command = @[producer, ready, input, $(DropLingerMs * 1000), done]
    req.depFilePath = work / "drop-wait.iomon"
    req.streamMode = fsoNone

    var dropStart: MonoTime
    var doneExistedBeforeDrop = true
    block:
      var handle = startMonitor(req)
      awaitFile(ready)
      doneExistedBeforeDrop = fileExists(done)
      dropStart = getMonoTime()
      # dropped here
    let elapsedMs = inMilliseconds(getMonoTime() - dropStart)

    checkpoint("drop cost " & $elapsedMs & "ms (floor " & $DropWaitFloorMs &
      "ms, child linger " & $DropLingerMs & "ms)")

    # The child had NOT finished when the handle was dropped …
    check not doneExistedBeforeDrop
    # … so leaving the scope must have cost at least the child's remaining
    # lifetime. A destructor that skipped the wait returns in ~0ms.
    check elapsedMs >= DropWaitFloorMs
    check fileExists(done)

    removeDir(work)

  test "t_n_monitors_interleave_in_one_poll_loop":
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    const n = 3
    let work = getTempDir() / ("io-mon-dh2-poll-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let gate = work / "gate.open"
    let child = buildC(work, "dh2_gated_rendezvous", gatedRendezvousSrc)

    # Disjoint input sets whose basenames are not substrings of one another —
    # the cross-contamination assertions match on substrings.
    var inputs, readys, dones, depPaths: array[n, string]
    for i in 0 ..< n:
      inputs[i] = work / ("input-only-for-job" & $i & ".txt")
      writeFile(inputs[i], "job " & $i & "\n")
      readys[i] = work / ("job" & $i & ".ready")
      dones[i] = work / ("job" & $i & ".done")
      depPaths[i] = work / ("job" & $i & ".iomon")

    let before = monitorLifecycleCounts()

    # ---- start ALL of them before waiting on ANY of them ------------------
    var handles: seq[MonitorHandle] = @[]
    for i in 0 ..< n:
      var req: FsSnoopRequest
      req.command = @[child, readys[i], gate, inputs[i], dones[i]]
      for j in 0 ..< n:
        if j != i:
          req.command.add readys[j]
      req.depFilePath = depPaths[i]
      req.streamMode = fsoNone
      handles.add startMonitor(req)

    let liveAfterStart = monitorLifecycleCounts().live
    checkpoint("live monitors after starting " & $n & ": " & $liveAfterStart)
    # N consumers and N process trees exist AT THE SAME TIME. Under a blocking
    # `runMonitored` this number could never exceed `before.live + 1`.
    check liveAfterStart == before.live + n

    # Every child is now parked on the gate, having already seen its peers —
    # which is only reachable if all three are running simultaneously.
    for i in 0 ..< n:
      awaitFile(readys[i])

    # ---- poll does not block ----------------------------------------------
    # Measured while every child is deterministically parked (the gate is shut),
    # so a `pollMonitor` that waited would have to wait the full 30s ceiling.
    let sweepStart = getMonoTime()
    var falsePolls = 0
    for i in 0 ..< n:
      if not pollMonitor(handles[i]):
        inc falsePolls
    let sweepMs = inMilliseconds(getMonoTime() - sweepStart)
    checkpoint("one poll sweep over " & $n & " parked monitors took " &
      $sweepMs & "ms, " & $falsePolls & " reported still-running")
    check falsePolls == n                # poll tells the truth about running
    check sweepMs < 500                  # …without blocking to find out
    for i in 0 ..< n:
      check not handles[i].hasExited     # and the handle records that answer

    # ---- release them and drive the loop ----------------------------------
    writeFile(gate, "go\n")

    var results: array[n, MonitorResult]
    var finished: array[n, bool]
    var remaining = n
    var loopIterations = 0
    let loopStart = getMonoTime()
    while remaining > 0:
      inc loopIterations
      if inMilliseconds(getMonoTime() - loopStart) > 60_000:
        raise newException(IOError,
          "poll loop ceiling: " & $remaining & " monitor(s) never completed")
      for i in 0 ..< n:
        if finished[i]:
          continue
        if pollMonitor(handles[i]):
          finished[i] = true
          dec remaining
          # `finishMonitor` CONSUMES the handle: the result is obtainable only
          # by giving up the right to poll it again.
          results[i] = finishMonitor(move(handles[i]))
      if remaining > 0:
        sleep(5)

    let after = monitorLifecycleCounts()
    for i in 0 ..< n:
      checkpoint("job " & $i & ": exit=" & $results[i].exitCode &
        " completeness=" & $results[i].completeness &
        " records=" & $results[i].records.len)

    # (1) GENUINELY CONCURRENT. Exit 0 is reachable only through the peer
    #     rendezvous AND the gate; a serialised host's first child exits 3 or 6.
    for i in 0 ..< n:
      check results[i].exitCode == 0
      check fileExists(dones[i])

    # (2) Each edge is honestly complete …
    for i in 0 ..< n:
      check results[i].completeness == mcComplete

    # (3) … carries its OWN input …
    for i in 0 ..< n:
      check hasFileRead(results[i].records, inputs[i])
      check results[i].depFilePath == depPaths[i]
      check fileExists(depPaths[i])

    # (4) … and none of the others'.
    for i in 0 ..< n:
      for j in 0 ..< n:
        if i != j:
          check not anyPathMentions(results[i].records,
            "input-only-for-job" & $j)

    # (5) The census closes: N started, N finished, N released, none live.
    checkpoint("counts before=" & $before & " after=" & $after &
      " loopIterations=" & $loopIterations)
    check after.started == before.started + n
    check after.finished == before.finished + n
    check after.released == before.released + n
    check after.live == before.live

    removeDir(work)

  test "t_runMonitored_is_the_decomposed_form":
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh2-delegate-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let input = work / "delegation-input.txt"
    writeFile(input, "delegation marker\n")
    let ready = work / "delegate.ready"
    let done = work / "delegate.done"
    let producer = buildC(work, "dh2_short_producer", lingeringProducerSrc)

    # ---- (A) RUNTIME: `runMonitored` goes through the decomposed entry points.
    var req: FsSnoopRequest
    req.command = @[producer, ready, input, "0", done]
    req.depFilePath = work / "delegate.iomon"
    req.streamMode = fsoNone

    let before = monitorLifecycleCounts()
    let res = runMonitored(req)
    let after = monitorLifecycleCounts()

    checkpoint("runMonitored: exit=" & $res.exitCode & " completeness=" &
      $res.completeness & " counts before=" & $before & " after=" & $after)
    check res.exitCode == 0
    check res.completeness == mcComplete
    check hasFileRead(res.records, input)

    # One `startMonitor`, one `finishMonitor`, one release, nothing left live.
    # A `runMonitored` that spawned and waited on its own would move none of
    # these.
    check after.started == before.started + 1
    check after.finished == before.finished + 1
    check after.released == before.released + 1
    check after.live == before.live

    # ---- (B) The decomposed path answers the same for the same action.
    # NOTE this is a SHAPE agreement (exit status, completeness, the captured
    # input), not DH-4's byte-identical evidence diff, which is a separate
    # milestone. What it adds here is that the delegation is not merely
    # book-keeping: driving the two halves by hand reproduces the batch result.
    let ready2 = work / "decomposed.ready"
    let done2 = work / "decomposed.done"
    var req2: FsSnoopRequest
    req2.command = @[producer, ready2, input, "0", done2]
    req2.depFilePath = work / "decomposed.iomon"
    req2.streamMode = fsoNone

    var handle = startMonitor(req2)
    while not pollMonitor(handle):
      sleep(5)
    let res2 = finishMonitor(move(handle))

    checkpoint("decomposed: exit=" & $res2.exitCode & " completeness=" &
      $res2.completeness)
    check res2.exitCode == res.exitCode
    check res2.completeness == res.completeness
    check hasFileRead(res2.records, input)

    # The handle was CONSUMED by that `finishMonitor`. Nim will not reliably
    # refuse a use-after-move at compile time — a moved-from value is simply
    # zeroed — so the consumption is enforced where it can be: a spent handle
    # is not live, and both entry points say so loudly instead of quietly
    # operating on nothing (`finishMonitor` would otherwise merge an empty
    # fragment directory and hand back a cheerful, empty `MonitorResult`).
    check not handle.live
    expect ValueError:
      discard finishMonitor(move(handle))
    expect ValueError:
      discard pollMonitor(handle)

    # ---- (C) SOURCE: there is only ONE implementation to agree with.
    let body = runMonitoredBodyLines()
    checkpoint("runMonitored body: " & $body)
    check body == @["finishMonitor(startMonitor(request))"]

    removeDir(work)
