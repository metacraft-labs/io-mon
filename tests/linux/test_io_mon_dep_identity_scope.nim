## test_io_mon_dep_identity_scope — DA-1b (Dependency-Attribution), the
## representation half of the campaign: **stop writing the same fact down once
## per process**, without erasing the process attribution the completeness
## machinery reads.
##
## THE DEFECT, MEASURED. `shm/dep_queue.nim :: encodeDepRecordIdentity` used to
## drop the process-local coordinates for only three record kinds
## (`mrFileOpen` / `mrFileRead` / `mrPathProbe`). Every other kind carried
## `osPid` into the gset element key, so one fact observed by N processes became
## N elements. On a real `nim c` (2,435 processes, 123,837 records) that was
## 33,128 `library-load` records over **26** DSOs, 19,339 `env-read` records
## over 56 names, 3,220 `sysctl-read` over 4 and 1,615 `time-read` over 3.
##
## THE HAZARD THIS FILE EXISTS TO GUARD. Widening the dedup blindly would erase
## the evidence `unmonitoredSubtreeLossDetails` reads to decide whether an IPC
## peer is INSIDE the monitored tree — the peer pid is matched against the set
## of `mrProcessStart` pids — and it would break toward `mcComplete`, which is
## the cardinal sin. So the dedup is per-kind (`depIdentityScope`), and the
## second test here is the assertion that keeps it honest.
##
## NO MOCKS. The shim is the real `LD_PRELOAD` shim built from source, the
## fan-out is real `fork`+`execve`, the shared object is really loaded by the
## dynamic loader, the sockets are real `AF_UNIX` sockets, and every assertion
## reads the canonical depfile io-mon actually wrote.
##
## ── THE THREE CASES ────────────────────────────────────────────────────────
##
##   t_one_fact_observed_by_many_processes_is_one_element
##       The headline, shaped like the measurement: `FanOut` processes across
##       TWO DIFFERENT executables all load ONE shared object and all read ONE
##       environment variable. The depfile must contain exactly ONE
##       `mrLibraryLoad` for that object and exactly ONE `mrEnvRead` for that
##       name — while still showing `FanOut + 1` distinct monitored processes,
##       so it cannot pass by the fan-out having failed to happen.
##
##       Two executables rather than one is deliberate: the element key also
##       carries the caller's per-exec incarnation identity (`setElemImage`),
##       so a fixture with a single image would stay green even if that suffix
##       still split the elements. Mutation-checked both ways — see the
##       milestone report.
##
##   t_completeness_is_unchanged
##       Two opposed runs of the SAME pair of programs. In-tree: a monitored
##       runner spawns both the socket server and its client, and the peer must
##       still be recognised as in-tree — asserted POSITIVELY (the recorded
##       peer pid is one of this run's `mrProcessStart` pids), not merely as
##       the absence of a loss, which would pass vacuously if the connect were
##       never observed at all. Out-of-tree: the identical client connects to a
##       server started OUTSIDE the monitor, and the loss must still be
##       reported and still downgrade to `mcIncomplete`.
##
##   t_evidence_identity_across_launch_paths_holds
##       The dedup happens in the producer, which both launch paths share — but
##       "shared" is a claim about the code, so it is measured: the same
##       fan-out action is captured through `runMonitored` AND through
##       `startMonitor` → `pollMonitor` → `finishMonitor`, and the two must
##       agree on the deduped fact set, on the per-kind record counts, and on
##       completeness. io-mon's full DH-4 comparison
##       (`test_io_mon_evidence_identical_across_launch_paths`) still owns the
##       byte-for-byte version; this case is the DA-1b-specific echo of it, so
##       a regression in the dedup shows up here as well as there.
##
## Assertion helpers are `template`s, never `proc`s: a `check` inside a plain
## `proc` prints "Check failed" and the enclosing test still reports `[OK]`.

import std/[algorithm, os, osproc, sequtils, sets, streams, strtabs, strutils,
            tables, times, unittest]

import io_mon
import io_mon/shm/dep_queue

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  FanOut = 12
    ## Enough processes that "one element" is unmistakably not "one process".
  EnvMarkerName = "IO_MON_DA1B_MARKER"
  IpcLossPrefix = "ipc peer outside monitored tree"
  FactLibName = "da1bfact"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil;
         workDir = ""): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env, workingDir = workDir,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

template buildC(work, name, source: string; extra: seq[string]): string =
  ## Compile `source` to `work/name`. A TEMPLATE so its `check`s belong to the
  ## calling test body.
  let src = work / (name & ".c")
  writeFile(src, source)
  let outPath = work / name
  let built = run(getEnv("CC", "cc"), @[src, "-o", outPath] & extra)
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(outPath)
  outPath

template buildSharedC(work, name, source: string): string =
  let src = work / (name & ".c")
  writeFile(src, source)
  let outPath = work / ("lib" & name & ".so")
  let built = run(getEnv("CC", "cc"), @["-fPIC", "-shared", src, "-o", outPath])
  checkpoint(name & " shared cc: " & built.output)
  check built.code == 0
  check fileExists(outPath)
  outPath

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------

const
  FactLibSrc = """
int da1b_fact(void) { return 42; }
"""

  FactChildSrc = """
/* Loads libda1bfact.so (via DT_NEEDED, so the real loader maps it) and reads
   one environment variable. Both observations are FACT-scoped: what is
   observed does not depend on which process observed it. */
#include <stdlib.h>
extern int da1b_fact(void);
int main(void) {
  const char *marker = getenv("IO_MON_DA1B_MARKER");
  if (marker == 0) return 4;
  return da1b_fact() == 42 ? 0 : 1;
}
"""

  FanOutSrc = """
/* argv[1] argv[2] = two child images; argv[3] = how many children to run.
   Alternates between the two images so the fan-out spans more than one
   executable incarnation. */
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
  if (argc < 4) return 90;
  int n = atoi(argv[3]);
  for (int i = 0; i < n; i++) {
    const char *exe = (i % 2 == 0) ? argv[1] : argv[2];
    pid_t p = fork();
    if (p < 0) return 91;
    if (p == 0) { execl(exe, exe, (char *)0); _exit(127); }
    int st = 0;
    if (waitpid(p, &st, 0) < 0) return 92;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return 93;
  }
  return 0;
}
"""

  SocketServerSrc = """
/* argv[1] = unix socket path, argv[2] = ready-marker path. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc, char **argv) {
  if (argc < 3) return 90;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return 91;
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof addr.sun_path, "%s", argv[1]);
  unlink(argv[1]);
  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) return 92;
  if (listen(fd, 8) != 0) return 93;
  FILE *f = fopen(argv[2], "w");
  if (f == 0) return 94;
  fputs("ready\n", f);
  fclose(f);
  int c = accept(fd, 0, 0);
  if (c < 0) return 95;
  char buf[16];
  ssize_t r = read(c, buf, sizeof buf);
  (void)r;
  close(c);
  close(fd);
  unlink(argv[1]);
  return 0;
}
"""

  SocketClientSrc = """
/* argv[1] = unix socket path. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc, char **argv) {
  if (argc < 2) return 90;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return 91;
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof addr);
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof addr.sun_path, "%s", argv[1]);
  if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) return 92;
  if (write(fd, "hi", 2) != 2) return 93;
  close(fd);
  return 0;
}
"""

  IpcRunnerSrc = """
/* argv[1] = server image, argv[2] = client image, argv[3] = socket path,
   argv[4] = ready marker. Runs BOTH ends inside the monitored tree. */
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
  if (argc < 5) return 90;
  pid_t s = fork();
  if (s < 0) return 91;
  if (s == 0) { execl(argv[1], argv[1], argv[3], argv[4], (char *)0); _exit(127); }
  for (int i = 0; i < 20000; i++) {
    if (access(argv[4], F_OK) == 0) break;
    usleep(1000);
  }
  pid_t c = fork();
  if (c < 0) return 92;
  if (c == 0) { execl(argv[2], argv[2], argv[3], (char *)0); _exit(127); }
  int st = 0;
  if (waitpid(c, &st, 0) < 0) return 93;
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return 94;
  int st2 = 0;
  if (waitpid(s, &st2, 0) < 0) return 95;
  if (!WIFEXITED(st2) || WEXITSTATUS(st2) != 0) return 96;
  return 0;
}
"""

# ---------------------------------------------------------------------------
# Depfile queries.
# ---------------------------------------------------------------------------

proc recordsOfKind(dep: MonitorDepFile; kind: MonitorRecordKind):
    seq[MonitorRecord] =
  dep.records.filterIt(it.kind == kind)

proc libraryLoadsNamed(dep: MonitorDepFile; needle: string): seq[MonitorRecord] =
  dep.records.filterIt(it.kind == mrLibraryLoad and needle in it.path)

proc envReadsNamed(dep: MonitorDepFile; name: string): seq[MonitorRecord] =
  dep.records.filterIt(it.kind == mrEnvRead and it.path == name)

proc ipcLosses(dep: MonitorDepFile): seq[string] =
  unmonitoredSubtreeLossDetails(dep.records).filterIt(
    it.startsWith(IpcLossPrefix))

proc factCensus(dep: MonitorDepFile): CountTable[string] =
  ## Per-kind record counts, keyed by the rendered kind name — the shape the
  ## two launch paths must agree on.
  result = initCountTable[string]()
  for r in dep.records:
    result.inc $r.kind

proc factSet(dep: MonitorDepFile): HashSet[string] =
  ## The deduped FACTS: every record rendered without its process coordinates
  ## and without the per-call run token. Two launch paths must produce the same
  ## set for the same action.
  result = initHashSet[string]()
  for r in dep.records:
    var detail: seq[string]
    for tok in r.detail.splitWhitespace():
      if tok.startsWith("run="): continue
      detail.add tok
    result.incl $r.kind & "|" & $ord(r.observationKind) & "|" &
      r.path & "|" & detail.join(" ")

proc awaitFile(path: string; timeoutMs = 20000) =
  let deadline = epochTime() + float(timeoutMs) / 1000.0
  while epochTime() < deadline:
    if fileExists(path): return
    sleep(5)

# ---------------------------------------------------------------------------

suite "io-mon DA-1b dependency-identity scope":

  let work = getTempDir() / ("io-mon-da1b-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)

  # The shim must be built BEFORE anything runs under it: a cold build/lib
  # otherwise leaves a monitored process reading a half-written shared object.
  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()
  require shimLib.len > 0

  proc requestEnv(extra: openArray[(string, string)] = []): seq[(string, string)] =
    result = @[("REPRO_MONITOR_SHIM_LIB", shimLib)]
    for kv in extra: result.add kv

  test "t_one_fact_observed_by_many_processes_is_one_element":
    discard buildSharedC(work, FactLibName, FactLibSrc)
    let childArgs = @["-L", work, "-l" & FactLibName, "-Wl,-rpath," & work]
    let childA = buildC(work, "da1b_child_a", FactChildSrc, childArgs)
    let childB = buildC(work, "da1b_child_b", FactChildSrc, childArgs)
    let fanOut = buildC(work, "da1b_fanout", FanOutSrc, @[])

    var req: FsSnoopRequest
    req.command = @[fanOut, childA, childB, $FanOut]
    req.depFilePath = work / "fanout.iomon"
    req.streamMode = fsoNone
    req.env = requestEnv({EnvMarkerName: "da1b"})
    let res = runMonitored(req)
    check res.exitCode == 0
    let dep = res.depFile

    # ANTI-VACUITY FIRST: the fan-out must really have happened, on two
    # distinct images, or "one element" would be trivially true.
    var startPids = initHashSet[uint64]()
    for r in recordsOfKind(dep, mrProcessStart):
      check r.osPid != 0
      startPids.incl r.osPid
    checkpoint("monitored processes: " & $startPids.len &
      "  processCount=" & $dep.summary.processCount)
    check startPids.len >= FanOut + 1
    check dep.summary.processCount >= uint64(FanOut + 1)
    var execImages = initHashSet[string]()
    for r in recordsOfKind(dep, mrProcessExec):
      if r.path.len > 0: execImages.incl r.path
    checkpoint("exec images: " & $execImages)
    check toSeq(execImages.items).anyIt("da1b_child_a" in it)
    check toSeq(execImages.items).anyIt("da1b_child_b" in it)

    # THE HEADLINE. One shared object, loaded by `FanOut` processes running two
    # different executables — one element, therefore one record.
    let loads = libraryLoadsNamed(dep, "lib" & FactLibName & ".so")
    checkpoint("library-load records for lib" & FactLibName & ".so: " &
      $loads.len & " (" & loads.mapIt(it.path).deduplicate.join(", ") & ")")
    check loads.len == 1
    check loads[0].osPid == 0
    check loads[0].parentOsPid == 0
    check loads[0].threadId == 0

    # The same claim for the other high-volume fact-scoped kind.
    let envReads = envReadsNamed(dep, EnvMarkerName)
    checkpoint("env-read records for " & EnvMarkerName & ": " & $envReads.len)
    check envReads.len == 1
    check envReads[0].osPid == 0

    # And the fact-scoped kinds as a class: every one of them must be
    # observer-free, and every process-scoped kind that named a process must
    # still name it. This is what stops a future kind being added on the wrong
    # side of the line without anything going red.
    var factScopedWithPid = 0
    var processScopedWithPid = 0
    for r in dep.records:
      case depIdentityScope(r.kind)
      of disFactScoped:
        if r.osPid != 0 or r.parentOsPid != 0 or r.threadId != 0 or
            r.childOsPid != 0:
          inc factScopedWithPid
      of disProcessScoped:
        if r.osPid != 0: inc processScopedWithPid
      of disPathScoped: discard
    check factScopedWithPid == 0
    check processScopedWithPid > 0

  test "t_completeness_is_unchanged":
    let server = buildC(work, "da1b_ipc_server", SocketServerSrc, @[])
    let client = buildC(work, "da1b_ipc_client", SocketClientSrc, @[])
    let runner = buildC(work, "da1b_ipc_runner", IpcRunnerSrc, @[])

    # ── IN-TREE: both ends inside the monitored tree ────────────────────────
    let inSock = work / "in.sock"
    let inReady = work / "in.ready"
    removeFile(inSock)
    removeFile(inReady)
    var inReq: FsSnoopRequest
    inReq.command = @[runner, server, client, inSock, inReady]
    inReq.depFilePath = work / "ipc-in-tree.iomon"
    inReq.streamMode = fsoNone
    inReq.env = requestEnv()
    let inRes = runMonitored(inReq)
    check inRes.exitCode == 0
    let inDep = inRes.depFile

    # POSITIVE, not merely the absence of a loss: the connect WAS observed, it
    # named a peer, and that peer pid is one of THIS run's monitored
    # process-start pids. That is the evidence the in-tree decision reads, and
    # it is exactly what a careless widening of the dedup would erase.
    var inTreeStartPids = initHashSet[uint64]()
    for r in recordsOfKind(inDep, mrProcessStart):
      inTreeStartPids.incl r.osPid
    let inConnects = recordsOfKind(inDep, mrIpcConnect)
    checkpoint("in-tree ipc-connect records: " & $inConnects.len)
    check inConnects.len > 0
    var sawInTreePeer = false
    for r in inConnects:
      checkpoint("  connect osPid=" & $r.osPid & " peer=" & $r.childOsPid &
        " path=" & r.path)
      check r.osPid != 0
      if r.childOsPid != 0 and r.childOsPid in inTreeStartPids:
        sawInTreePeer = true
    check sawInTreePeer
    # …and therefore no downgrade.
    checkpoint("in-tree losses: " & $ipcLosses(inDep))
    check ipcLosses(inDep).len == 0
    check inDep.completeness == mcComplete

    # ── OUT-OF-TREE: the same client, a server started outside the monitor ──
    let outSock = work / "out.sock"
    let outReady = work / "out.ready"
    removeFile(outSock)
    removeFile(outReady)
    let daemon = startProcess(server, args = @[outSock, outReady],
      options = {poStdErrToStdOut})
    awaitFile(outReady)
    check fileExists(outReady)

    var outReq: FsSnoopRequest
    outReq.command = @[client, outSock]
    outReq.depFilePath = work / "ipc-out-of-tree.iomon"
    outReq.streamMode = fsoNone
    outReq.env = requestEnv()
    let outRes = runMonitored(outReq)
    discard daemon.waitForExit()
    daemon.close()
    check outRes.exitCode == 0
    let outDep = outRes.depFile

    let losses = ipcLosses(outDep)
    checkpoint("out-of-tree losses: " & $losses)
    check losses.len >= 1
    check outDep.completeness == mcIncomplete
    # The peer really was named and really was outside the tree — so the
    # downgrade is the guard firing, not a capture failure.
    var outTreeStartPids = initHashSet[uint64]()
    for r in recordsOfKind(outDep, mrProcessStart):
      outTreeStartPids.incl r.osPid
    var sawOutOfTreePeer = false
    for r in recordsOfKind(outDep, mrIpcConnect):
      if r.childOsPid != 0 and r.childOsPid notin outTreeStartPids:
        sawOutOfTreePeer = true
    check sawOutOfTreePeer

  test "t_evidence_identity_across_launch_paths_holds":
    let childArgs = @["-L", work, "-l" & FactLibName, "-Wl,-rpath," & work]
    let childA = buildC(work, "da1b_dh4_a", FactChildSrc, childArgs)
    let childB = buildC(work, "da1b_dh4_b", FactChildSrc, childArgs)
    let fanOut = buildC(work, "da1b_dh4_fanout", FanOutSrc, @[])

    proc requestFor(tag: string): FsSnoopRequest =
      result.command = @[fanOut, childA, childB, $FanOut]
      result.depFilePath = work / ("dh4-" & tag & ".iomon")
      result.streamMode = fsoNone
      result.env = @[("REPRO_MONITOR_SHIM_LIB", shimLib),
                     (EnvMarkerName, "da1b")]

    let batch = runMonitored(requestFor("batch"))
    check batch.exitCode == 0

    var handle = startMonitor(requestFor("polled"))
    while not pollMonitor(handle):
      sleep(5)
    let polled = finishMonitor(move(handle))
    check polled.exitCode == 0

    # The dedup lives in the producer, which both paths share — so the deduped
    # FACT SET, the per-kind census and the verdict must all agree.
    check batch.depFile.completeness == polled.depFile.completeness
    let batchFacts = factSet(batch.depFile)
    let polledFacts = factSet(polled.depFile)
    checkpoint("batch facts=" & $batchFacts.len &
      " polled facts=" & $polledFacts.len)
    check batchFacts == polledFacts

    let batchCensus = factCensus(batch.depFile)
    let polledCensus = factCensus(polled.depFile)
    for kindName, n in batchCensus:
      checkpoint("  " & kindName & ": batch=" & $n & " polled=" &
        $polledCensus.getOrDefault(kindName))
    check toSeq(batchCensus.pairs).sorted == toSeq(polledCensus.pairs).sorted

    # And the dedup itself holds on BOTH paths, so this case cannot go green by
    # the two paths agreeing on un-deduped evidence.
    check libraryLoadsNamed(batch.depFile, "lib" & FactLibName & ".so").len == 1
    check libraryLoadsNamed(polled.depFile, "lib" & FactLibName & ".so").len == 1

  removeDir(work)
