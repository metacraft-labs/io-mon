## test_io_mon_external_host_descendant_guard — IoMon-Decomposed-Host-API DH-3.
##
## §4.1's incident is a monitored tree that leaves a DETACHED DESCENDANT behind:
## the root exits, the launcher tears the edge down, and a process that is still
## reading and writing files carries on outside the evidence. io-mon's answer is
## the descendant guard — `liveInjectedDescendants` walks `/proc/*/environ` for
## this run's `REPRO_MONITOR_SESSION` / `REPRO_MONITOR_FRAGMENT_DIR` needles and,
## past the grace window, `waitForLinuxInjectedDescendants` publishes an
## `mrEventLoss` that `summarizeRecords` counts into `eventLossCount` and that
## downgrades the edge to `mcIncomplete`.
##
## Both procs are PRIVATE, and DH-3 keeps them private ON PURPOSE. The
## alternative the milestone weighed — exporting them so a host can call them —
## hands the host a proc it may forget, which reproduces the false-`mcComplete`
## hazard one level up instead of closing it. Instead the guard is folded into
## the one funnel every `MonitorResult`'s evidence is produced by
## (`collectMonitorEvidence`), and that funnel refuses to merge for a handle the
## guard has not marked.
##
## NO MOCKS. The descendant is a real double-forked, `setsid`'d daemon compiled
## by the host toolchain during the test; it is re-parented to init and really
## does outlive the monitored root; the guard really does read `/proc`; the
## completeness verdict asserted on is decoded from the canonical depfile io-mon
## actually wrote. Nothing here can be demonstrated by a fake: the property under
## test is what the real `/proc` scan sees at the moment the real root exits.
##
##   t_an_external_host_reports_mcIncomplete_for_a_detached_descendant — THE case
##       that makes the milestone worth doing. The same action is run twice, by
##       the two launch paths, and both must grade it the same way:
##       `runMonitored` (the reference) and a host driving
##       `startMonitor` → `pollMonitor` → `finishMonitor` by hand (what HM-4's
##       build engine will do). A CONTROL arm runs the same fixture with the
##       descendant quiescing INSIDE the grace window and demands `mcComplete`,
##       so the headline's `mcIncomplete` cannot pass for some unrelated reason
##       about the fixture.
##
##   t_the_guard_cannot_be_skipped — structural, not documented. Two halves.
##       SOURCE: every route to a `MonitorResult` funnels through the one proc
##       that runs the guard first — every evidence-assembly site in
##       `fs_snoop.nim` lives inside that funnel, the guard call precedes them,
##       a gate on the guard's own flag stands between them, and that flag has
##       exactly one writer. Both halves of that sentence are read by DELIBERATELY
##       DUMB parsers whose failure mode is to RAISE, never to answer short: a
##       producer is found from its FOLDED header (so a wrapped signature or a
##       trailing pragma cannot hide one) and "assembles evidence" means any of
##       the five exported routes to a `MonitorDepFile`, not `mergeFragments`
##       alone. RUNTIME: the lifecycle census shows the guard ran
##       once per finished monitor on BOTH launch paths, and — the deliberate
##       asymmetry DH-2 recorded and nothing read — did NOT run for a handle that
##       was dropped rather than finished.
##
##   t_a_late_orphan_emit_sees_the_consumer_gone — LF-4, recorded by DH-2's
##       verification as pinned by NO test in this suite and assigned to DH-3.
##       It is the other half of the same story: the guard makes a surviving
##       descendant VISIBLE in the evidence, and `markConsumerGone` makes that
##       descendant's later writes fail fast instead of growing a set nobody will
##       ever read. A real producer is attached to the real set while the
##       consumer is alive (positive control: the emit lands), the monitor is
##       then finished, and the same producer emits again.

import std/[os, osproc, sequtils, streams, strutils, unittest]

import io_mon                            # the PUBLIC host API
import shm_gset                          # shmGSetSupported
import shm_gset/transport as gsett       # attachProducer / emit / detach,
                                         # and the `EmitStatus` they answer with

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  fsSnoopPath = repoRoot / "src" / "io_mon" / "fs_snoop.nim"

  ## The §4.1 grace window used by every case here, and the poll inside it.
  ##
  ## Set in THIS process's environment because the guard is a LAUNCHER-side step:
  ## `waitForLinuxInjectedDescendants` reads these from the host that owns the
  ## monitor, which for a decomposed host IS this test process. (The CLI-driven
  ## coverage in `test_io_mon_linux_stdio_ipc.nim` passes them to the `io-mon`
  ## subprocess for exactly the same reason — there the subprocess is the host.)
  GraceMs = 300
  PollMs = 10

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

proc descendantLossDetails(dep: MonitorDepFile): seq[string] =
  ## Every §4.1 launcher-side loss marker in an edge's evidence. Both spellings
  ## the guard can produce count: the grace-window timeout, and the `/proc` scan
  ## having failed outright (which is also an honest "I could not tell").
  result = @[]
  for rec in dep.records:
    if rec.kind == mrEventLoss and
        ("linux injected descendants still live" in rec.detail or
         "linux injected-descendant /proc scan failed" in rec.detail):
      result.add rec.detail

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

## The detached-descendant fixture, adapted from the CLI-driven coverage in
## `tests/linux/test_io_mon_linux_stdio_ipc.nim` (same shape, driven here
## through the LIBRARY host API instead of the `io-mon` CLI).
##
##   argv[1] — the marker file the descendant reads (so the run has a real
##             dependency the descendant, not the root, discovered)
##   argv[2] — the proof file the descendant writes when it has read the marker
##   argv[3] — ms the descendant sleeps before reading
##   argv[4] — ms the descendant sleeps before exiting (quiesce mode only)
##   argv[5] — release sentinel path, or "-" for quiesce mode
##
## Two modes, and the difference is the whole test:
##
##   "-"   QUIESCE (the control). The root does not exit until the descendant has
##         fully exited — it drains an inherited pipe to EOF — so by the time the
##         launcher's grace window opens there is provably nothing left alive.
##         Expected verdict: `mcComplete`.
##
##   path  GATED (the headline). The descendant signals the root (one byte down
##         the pipe) only once it is alive, visible in `/proc` and past its I/O;
##         the root then exits, and the descendant BLOCKS until <path> appears.
##         The harness drops that file only after the monitor has been finished,
##         so the descendant is guaranteed live across the ENTIRE grace window
##         regardless of host load. Expected verdict: `mcIncomplete`.
##
## The gated arm closes every fd but the pipe: the shim dups its own channels
## onto inherited descriptors, and a blocking daemon holding them can keep a
## parent's stream from reaching EOF.
const detachedDescendantSrc = """
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void msleep_arg(const char *s) {
  long ms = strtol(s, NULL, 10);
  if (ms > 0) usleep((useconds_t)ms * 1000);
}

int main(int argc, char **argv) {
  if (argc != 6) return 2;
  const char *release = argv[5];
  int gated = strcmp(release, "-") != 0;

  int rp[2];
  if (pipe(rp) != 0) return 8;

  pid_t pid = fork();
  if (pid < 0) return 3;
  if (pid > 0) {
    close(rp[1]);
    char b;
    if (gated) {
      /* Wait until the descendant is alive, visible in /proc and past its
         I/O — then exit, so the grace window opens over a LIVE descendant. */
      while (read(rp[0], &b, 1) < 0) { /* retry on EINTR */ }
    } else {
      /* Wait until the descendant has fully EXITED (pipe EOF), so the grace
         window opens over a provably quiesced tree. */
      while (read(rp[0], &b, 1) > 0) { /* drain until EOF */ }
    }
    close(rp[0]);
    return 0;
  }
  close(rp[0]);
  if (setsid() < 0) _exit(4);
  pid = fork();
  if (pid < 0) _exit(5);
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
  if (in < 0) _exit(6);
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
    char rb = 1;
    if (write(rp[1], &rb, 1) < 0) {}
    close(rp[1]);
    struct stat st;
    while (stat(release, &st) != 0) usleep(2000);
    _exit(n > 0 ? 0 : 7);
  }
  msleep_arg(argv[4]);
  _exit(n > 0 ? 0 : 7);
}
"""

## Reports the shm-gset shard0 path this monitored process was named
## (`REPRO_MONITOR_DEP_SHM`) into argv[1], so the LF-4 case can attach a real
## producer to the real consumer-owned set the way the shim's producers do.
const depShmReporterSrc = """
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const char *p = getenv("REPRO_MONITOR_DEP_SHM");
  if (p == NULL) p = "";
  int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return 3;
  size_t n = strlen(p);
  if (n > 0 && write(fd, p, n) != (ssize_t)n) { close(fd); return 4; }
  close(fd);
  return 0;
}
"""

# --------------------------------------------------------------------------
# Source-level reading of `fs_snoop.nim`, for the structural case.
#
# Deliberately the dumbest parser that can answer the questions asked of it,
# because this campaign's holes have repeatedly been in clever little helper
# parsers nobody re-read. Every lookup RAISES when it cannot find what it was
# told to find, so a rename can never make an assertion vacuously true.
# --------------------------------------------------------------------------

type
  ProcSpan = object
    name: string
    first: int        ## index of the `proc` header line
    last: int         ## index of the last line belonging to the body

proc isTopLevelBoundary(line: string): bool =
  ## A line at column 0 that ends the previous routine's body. `proc`, `func`
  ## and `template` start the next routine; `type`, `var`, `const` and a banner
  ## comment end the current one just as definitively.
  for prefix in ["proc ", "func ", "template ", "iterator ", "type", "var ",
                 "const ", "# ---"]:
    if line.startsWith(prefix):
      return true
  false

proc fsSnoopLines(): seq[string] =
  readFile(fsSnoopPath).splitLines()

proc spanOf(lines: seq[string]; name: string): ProcSpan =
  ## The line range of the top-level routine `name`, header included.
  var first = -1
  for i, line in lines:
    if line.startsWith("proc " & name & "(") or
        line.startsWith("proc " & name & "*("):
      if first >= 0:
        raise newException(ValueError,
          "src/io_mon/fs_snoop.nim declares `" & name & "` more than once — " &
            "this parser assumes one definition per name")
      first = i
  if first < 0:
    raise newException(ValueError,
      "could not find `proc " & name & "(` in src/io_mon/fs_snoop.nim")
  var last = lines.high
  for i in first + 1 .. lines.high:
    if isTopLevelBoundary(lines[i]):
      last = i - 1
      break
  ProcSpan(name: name, first: first, last: last)

proc codeLinesIn(lines: seq[string]; span: ProcSpan): seq[string] =
  ## The CODE lines of a routine's body: no doc comments, no plain comments, no
  ## blanks. Comments are excluded on purpose — a claim that survives only
  ## because a comment mentions the call is exactly the kind of documented-only
  ## guarantee this milestone exists to replace.
  result = @[]
  for i in span.first + 1 .. span.last:
    let stripped = lines[i].strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    result.add stripped

proc lineIndicesMatching(lines: seq[string]; needle: string): seq[int] =
  ## Every index whose CODE (comments stripped) contains `needle`.
  result = @[]
  for i, line in lines:
    let stripped = line.strip()
    if stripped.startsWith("#"):
      continue
    let code =
      if stripped.startsWith("##"): ""
      else: stripped
    if needle in code:
      result.add i

proc foldedRoutineHeaders(lines: seq[string]):
    seq[tuple[name, header: string; line: int]] =
  ## Every top-level `proc`/`func` in the file, with its signature FOLDED onto
  ## one line — continuation lines joined — so a wrapped signature reads exactly
  ## like a single-line one.
  ##
  ## WHY THIS IS NOT A ONE-LINE `endsWith`, which is what it used to be: this
  ## file's own prevailing style for a long signature is to WRAP it
  ## (`monitorLifecycleCounts*():` with its tuple on the next line, `childEnv`,
  ## `renderStreamToPath`, `=copy`'s multi-line pragma), and a matcher that reads
  ## only the `proc` LINE answers with a SHORT list instead of failing. That is
  ## exactly how "there are exactly two producers" passes while a third exists —
  ## measured, not imagined: a third exported producer spelled
  ## `proc sneakyEvidence*(handle: sink MonitorHandle):` / `    MonitorResult =`
  ## left the old matcher reporting `@["finishMonitor", "runMonitored"]`.
  ##
  ## Folding RAISES rather than guessing: a header whose end cannot be found is
  ## an error, never a routine quietly dropped.
  result = @[]
  var i = 0
  while i <= lines.high:
    if not (lines[i].startsWith("proc ") or lines[i].startsWith("func ")):
      inc i
      continue
    var header = lines[i].strip()
    var j = i
    while not (header.endsWith("=") or header.endsWith(".}")):
      inc j
      if j > lines.high or j - i > 16:
        raise newException(ValueError,
          "could not find the end of the routine header starting at " &
            "src/io_mon/fs_snoop.nim:" & $(i + 1) & " — this folder must never " &
            "silently drop a routine")
      header = header & " " & lines[j].strip()
    var name = header[header.find(' ') + 1 .. ^1]
    let paren = name.find('(')
    if paren >= 0:
      name = name[0 ..< paren]
    if name.endsWith("*"):
      name = name[0 ..< name.high]
    result.add (name: name, header: header, line: i)
    i = j + 1

proc exportedProcsReturning(lines: seq[string]; typeName: string): seq[string] =
  ## Names of top-level routines whose RETURN type is `typeName`, read off the
  ## FOLDED header so that neither a wrapped signature nor a trailing pragma
  ## (`… : MonitorResult {.discardable.} =`) can hide a producer. Requires
  ## `): <typeName>` followed by a NON-identifier character, so a parameter of
  ## that type — of which `fs_snoop.nim` has several — is not mistaken for a
  ## producer of one, and `MonitorResultSomething` is not mistaken for
  ## `MonitorResult`.
  result = @[]
  let needle = "): " & typeName
  for r in foldedRoutineHeaders(lines):
    var at = r.header.find(needle)
    while at >= 0:
      let after = at + needle.len
      if after >= r.header.len or r.header[after] notin IdentChars:
        result.add r.name
        break
      at = r.header.find(needle, at + 1)

# --------------------------------------------------------------------------
# The grace window is a LAUNCHER-side setting and this test process is the
# launcher. Narrowed from the 500ms default so the cases are quick, and paired
# with a descendant that is held alive across the whole window by a sentinel
# rather than by a sleep, so the narrowing buys speed and not flakiness.
# --------------------------------------------------------------------------
putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", $GraceMs)
putEnv("IO_MON_LINUX_DESCENDANT_POLL_MS", $PollMs)

suite "io-mon external host descendant guard (DH-3)":

  test "t_an_external_host_reports_mcIncomplete_for_a_detached_descendant":
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh3-guard-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let probe = buildC(work, "dh3_detached_descendant", detachedDescendantSrc)
    let marker = work / "descendant-marker.txt"
    writeFile(marker, "descendant marker\n")

    # ---- CONTROL: the descendant quiesces INSIDE the grace window ----------
    # Same fixture, same launch path, same guard — and it must NOT downgrade.
    # Without this arm the headline could pass because io-mon reports
    # `mcIncomplete` for this fixture for some reason that has nothing to do
    # with a descendant outliving anything.
    let quietProof = work / "quiesced.proof"
    var quietReq: FsSnoopRequest
    quietReq.command = @[probe, marker, quietProof, "10", "0", "-"]
    quietReq.depFilePath = work / "quiesced.rdep"
    quietReq.streamMode = fsoNone

    var quietHandle = startMonitor(quietReq)
    while not pollMonitor(quietHandle):
      sleep(5)
    let quietRes = finishMonitor(move(quietHandle))

    checkpoint("quiesced: exit=" & $quietRes.exitCode & " completeness=" &
      $quietRes.completeness & " losses=" &
      $descendantLossDetails(quietRes.depFile))
    check quietRes.exitCode == 0
    check fileExists(quietProof)
    check quietRes.completeness == mcComplete
    check descendantLossDetails(quietRes.depFile).len == 0
    # The dependency at stake is REAL and capturable: it was discovered by the
    # DESCENDANT, not by the root. That is what makes the headline arm's
    # downgrade meaningful — the edge whose descendant outlives the window is an
    # edge whose input set was still being written when the launcher gave up.
    check hasFileRead(quietRes.depFile, marker)

    # ---- HEADLINE: the descendant outlives the grace window ---------------
    # Run the SAME action twice, once by each launch path, and demand the same
    # grade. `runMonitored` is the reference DH-4 will diff against; the
    # decomposed host is what HM-4's scheduler will actually be.
    let batchProof = work / "batch.proof"
    let batchRelease = work / "batch.release"
    removeFile(batchRelease)
    var batchReq: FsSnoopRequest
    batchReq.command = @[probe, marker, batchProof, "0", "0", batchRelease]
    batchReq.depFilePath = work / "batch.rdep"
    batchReq.streamMode = fsoNone

    let beforeBatch = monitorLifecycleCounts()
    let batchRes = runMonitored(batchReq)
    # Release the descendant IMMEDIATELY, before any assertion — so it is let go
    # (and reaped by init) even if an assertion below fails.
    writeFile(batchRelease, "release\n")
    let afterBatch = monitorLifecycleCounts()

    let hostProof = work / "host.proof"
    let hostRelease = work / "host.release"
    removeFile(hostRelease)
    var hostReq: FsSnoopRequest
    hostReq.command = @[probe, marker, hostProof, "0", "0", hostRelease]
    hostReq.depFilePath = work / "host.rdep"
    hostReq.streamMode = fsoNone

    let beforeHost = monitorLifecycleCounts()
    var handle = startMonitor(hostReq)
    var polls = 0
    while not pollMonitor(handle):
      inc polls
      sleep(5)
    let hostRes = finishMonitor(move(handle))
    writeFile(hostRelease, "release\n")
    let afterHost = monitorLifecycleCounts()

    checkpoint("runMonitored: exit=" & $batchRes.exitCode & " completeness=" &
      $batchRes.completeness & " losses=" &
      $descendantLossDetails(batchRes.depFile))
    checkpoint("external host (" & $polls & " false polls): exit=" &
      $hostRes.exitCode & " completeness=" & $hostRes.completeness &
      " losses=" & $descendantLossDetails(hostRes.depFile))

    # (1) THE MILESTONE. A host that owns the WAIT gets the same honest
    #     downgrade the batch entry point gives — the guard is not something
    #     `runMonitored` does and a decomposed host misses.
    check hostRes.completeness == mcIncomplete
    check descendantLossDetails(hostRes.depFile).len > 0

    # (2) …and the reference path agrees, on the same fixture, in the same
    #     process. Disagreement here would mean the two paths grade differently,
    #     which is precisely the false-complete hazard DH-3 exists to close.
    check batchRes.completeness == mcIncomplete
    check descendantLossDetails(batchRes.depFile).len > 0
    check hostRes.completeness == batchRes.completeness

    # (3) The monitored ROOT still succeeded. The downgrade is a statement about
    #     the EVIDENCE, not about the action — an `mcIncomplete` that came with a
    #     failed command would prove nothing about the guard.
    check hostRes.exitCode == 0
    check batchRes.exitCode == 0
    check fileExists(hostProof)
    check fileExists(batchProof)

    # (4) NOTE what is deliberately NOT asserted for the gated arm: whether the
    #     descendant's read made it into the evidence. A descendant that is
    #     STILL RUNNING when the launcher snapshots may or may not have
    #     published by then — that uncertainty IS the loss the guard reports, and
    #     demanding a particular answer would be asserting the absence of the
    #     very race the marker exists to declare. The control arm above pins that
    #     the read is capturable when the descendant finishes in time.

    # (5) The guard RAN, once, on each path — the census says so rather than the
    #     docstring. `finished` and `settled` move together.
    checkpoint("batch counts " & $beforeBatch & " -> " & $afterBatch)
    checkpoint("host counts " & $beforeHost & " -> " & $afterHost)
    check afterBatch.settled == beforeBatch.settled + 1
    check afterBatch.finished == beforeBatch.finished + 1
    check afterHost.settled == beforeHost.settled + 1
    check afterHost.finished == beforeHost.finished + 1

    removeDir(work)

  test "t_the_guard_cannot_be_skipped":
    # ---- (A) SOURCE: one funnel, guard first, gated on the guard's own flag.
    let lines = fsSnoopLines()

    # (A1) Only two routines in the module produce a `MonitorResult` at all, and
    #      one of them is `runMonitored`, which produces it by delegating.
    let producers = exportedProcsReturning(lines, "MonitorResult")
    checkpoint("routines returning MonitorResult: " & $producers)
    check producers.len == 2
    check "finishMonitor" in producers
    check "runMonitored" in producers

    let runMonitoredBody = codeLinesIn(lines, spanOf(lines, "runMonitored"))
    checkpoint("runMonitored body: " & $runMonitoredBody)
    check runMonitoredBody.anyIt("finishMonitor(" in it)
    # …and it does not assemble evidence of its own on the side.
    check not runMonitoredBody.anyIt("mergeFragments(" in it)
    check not runMonitoredBody.anyIt("collectMonitorEvidence(" in it)

    # (A2) Every EVIDENCE-ASSEMBLY site in the whole module is inside the
    #      funnel. A second one anywhere else would be a second route around the
    #      guard.
    #
    #      `mergeFragments` is deliberately not the only needle. It is not the
    #      only exported way to obtain a `MonitorDepFile`: `depFileFromRecords`
    #      and `depFileFromOwnedRecords` (writer.nim), `readMonitorDepFile`
    #      (reader.nim) and `finalizeMonitorFragments` (hooks/collector.nim) are
    #      all public and all reachable from `import io_mon`. A producer that
    #      assembles an edge's evidence by ANY of them has skipped the guard just
    #      as thoroughly as one that merges, so watching only `mergeFragments(`
    #      would pin the spelling rather than the property.
    let funnel = spanOf(lines, "collectMonitorEvidence")
    let mergeSites = lineIndicesMatching(lines, "mergeFragments(")
    var assemblySites = mergeSites
    for needle in ["depFileFromRecords(", "depFileFromOwnedRecords(",
                   "readMonitorDepFile(", "finalizeMonitorFragments("]:
      assemblySites.add lineIndicesMatching(lines, needle)
    checkpoint("evidence-assembly call sites at lines " &
      $assemblySites.mapIt(it + 1) & " (of which mergeFragments at " &
      $mergeSites.mapIt(it + 1) & "); collectMonitorEvidence spans " &
      $(funnel.first + 1) & ".." & $(funnel.last + 1))
    check mergeSites.len > 0
    for idx in assemblySites:
      check idx >= funnel.first and idx <= funnel.last

    # (A3) Inside the funnel the guard comes FIRST — before any merge, and
    #      before the Linux snapshot that folds its loss marker into the edge.
    #      Order is not cosmetic here: a settle that ran after the snapshot would
    #      publish a marker nothing ever reads, i.e. a false `mcComplete`.
    let funnelCode = codeLinesIn(lines, funnel)
    check funnelCode.len > 0
    check funnelCode[0] == "settleMonitorDescendants(h)"
    let guardAt = lineIndicesMatching(lines, "settleMonitorDescendants(h)")
      .filterIt(it >= funnel.first and it <= funnel.last)
    let snapshotAt = lineIndicesMatching(lines, "h.depSet.snapshot()")
    check guardAt.len == 1
    for idx in mergeSites:
      check guardAt[0] < idx
    for idx in snapshotAt:
      check guardAt[0] < idx

    # (A4) THE GATE. Between the guard and the merge stands a refusal that reads
    #      the guard's own flag — so deleting or reordering the guard call turns
    #      a silent false `mcComplete` into a loud raise. This is the mechanism;
    #      (A3) is only its placement.
    let gateAt = lineIndicesMatching(lines, "if not h.settled:")
      .filterIt(it >= funnel.first and it <= funnel.last)
    checkpoint("gate at line(s) " & $gateAt.mapIt(it + 1))
    check gateAt.len == 1
    for idx in mergeSites:
      check gateAt[0] < idx
    # …and the gate RAISES rather than warning or repairing.
    var gateRaises = false
    for i in gateAt[0] .. min(gateAt[0] + 8, lines.high):
      if "raise newException" in lines[i]:
        gateRaises = true
        break
    check gateRaises

    # (A5) The flag the gate reads has exactly ONE writer, and it is the guard.
    #      Without this the gate would be satisfiable by anything, and it would
    #      be a restatement of the guard rather than a check on it.
    let flagWrites = lineIndicesMatching(lines, "h.settled = true")
    let guardSpan = spanOf(lines, "settleMonitorDescendants")
    checkpoint("h.settled writers at lines " & $flagWrites.mapIt(it + 1) &
      "; settleMonitorDescendants spans " & $(guardSpan.first + 1) & ".." &
      $(guardSpan.last + 1))
    check flagWrites.len == 1
    check flagWrites[0] >= guardSpan.first and flagWrites[0] <= guardSpan.last

    # (A5b) …and that ONE writer runs on EVERY ARM, not just the one this host
    #       compiles. DH-3 deliberately hoisted the flag write (and the census
    #       counter) OUT of `settleMonitorDescendants`' `when defined(linux)`, so
    #       that an arm which grows a real §4.1 guard later inherits the gate
    #       instead of having to remember to re-add it — and so that the gate is
    #       SATISFIED, not merely present, on macOS and Windows.
    #
    #       Nothing else in this workspace can see that. Pushing the two lines
    #       back inside the `when` would leave every macOS and Windows monitor
    #       raising the gate's `ValueError` — both arms bricked — while the Linux
    #       suite stayed green AND `nim check` stayed rc=0 for all three `--os:`,
    #       because both shapes type-check. Measured: that mutation reddened
    #       nothing at all until this assertion existed.
    #
    #       So it is read off the INDENTATION: a statement at the top level of a
    #       proc body sits at two spaces; one nested in a `when`/`else` branch
    #       sits at four or more.
    let counterWrites = lineIndicesMatching(lines, "monitorsSettledCount.fetchAdd")
    check counterWrites.len == 1
    check counterWrites[0] >= guardSpan.first and
          counterWrites[0] <= guardSpan.last
    for idx in [flagWrites[0], counterWrites[0]]:
      let indent = lines[idx].len - lines[idx].strip(trailing = false).len
      checkpoint("src/io_mon/fs_snoop.nim:" & $(idx + 1) & " indent=" & $indent &
        ": " & lines[idx].strip())
      check indent == 2

    # (A6) …and the only way to get a monitored tree in the first place is
    #      `startMonitor`. "A host that owns its OWN spawn" is not a
    #      configuration the public surface can reach: every spawn site in the
    #      module lives in a PRIVATE proc reachable only through the handle.
    var spawnSites: seq[int] = @[]
    spawnSites.add lineIndicesMatching(lines, "startProcess(")
    spawnSites.add lineIndicesMatching(lines, "runWithMonitorShim(")
    let inner = spanOf(lines, "startMonitorInner")
    let waitRoot = spanOf(lines, "waitForMonitorRoot")
    checkpoint("spawn sites at lines " & $spawnSites.mapIt(it + 1))
    check spawnSites.len > 0
    for idx in spawnSites:
      check (idx >= inner.first and idx <= inner.last) or
            (idx >= waitRoot.first and idx <= waitRoot.last)

    # ---- (B) RUNTIME: the census agrees, on both launch paths and on the drop.
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh3-skip-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let probe = buildC(work, "dh3_skip_descendant", detachedDescendantSrc)
    let marker = work / "skip-marker.txt"
    writeFile(marker, "skip marker\n")

    # (B1) The decomposed path settles exactly once …
    var hostReq: FsSnoopRequest
    hostReq.command = @[probe, marker, work / "skip-host.proof", "0", "0", "-"]
    hostReq.depFilePath = work / "skip-host.rdep"
    hostReq.streamMode = fsoNone

    let beforeHost = monitorLifecycleCounts()
    var handle = startMonitor(hostReq)
    while not pollMonitor(handle):
      sleep(5)
    discard finishMonitor(move(handle))
    let afterHost = monitorLifecycleCounts()
    checkpoint("decomposed: " & $beforeHost & " -> " & $afterHost)
    check afterHost.settled == beforeHost.settled + 1

    # (B2) … and so does the batch path, so neither is privileged.
    var batchReq: FsSnoopRequest
    batchReq.command = @[probe, marker, work / "skip-batch.proof", "0", "0", "-"]
    batchReq.depFilePath = work / "skip-batch.rdep"
    batchReq.streamMode = fsoNone

    let beforeBatch = monitorLifecycleCounts()
    discard runMonitored(batchReq)
    let afterBatch = monitorLifecycleCounts()
    checkpoint("batch: " & $beforeBatch & " -> " & $afterBatch)
    check afterBatch.settled == beforeBatch.settled + 1

    # (B3) A DROPPED handle does NOT settle — the deliberate asymmetry DH-2
    #      recorded and no test read. The guard is an EVIDENCE step and a
    #      dropped handle publishes no edge for a loss marker to downgrade, so
    #      running it there would only cost the drop the grace window. What a
    #      drop still does is RELEASE, which is the safety half.
    var dropReq: FsSnoopRequest
    dropReq.command = @[probe, marker, work / "skip-drop.proof", "0", "0", "-"]
    dropReq.depFilePath = work / "skip-drop.rdep"
    dropReq.streamMode = fsoNone

    let beforeDrop = monitorLifecycleCounts()
    block:
      var dropped = startMonitor(dropReq)
      check dropped.live
      # dropped here — no finishMonitor
    let afterDrop = monitorLifecycleCounts()
    checkpoint("dropped: " & $beforeDrop & " -> " & $afterDrop)
    check afterDrop.released == beforeDrop.released + 1
    check afterDrop.finished == beforeDrop.finished
    check afterDrop.settled == beforeDrop.settled

    removeDir(work)

  test "t_a_late_orphan_emit_sees_the_consumer_gone":
    ## LF-4, the other half of the §4.1 story. The guard makes a surviving
    ## descendant VISIBLE in the evidence; `markConsumerGone` makes that
    ## descendant's later writes fail fast instead of growing a set nobody will
    ## ever read. DH-2's verification found this pinned by NO test in this suite
    ## and assigned it to DH-3.
    ##
    ## A REAL producer is attached to the REAL consumer-owned set — the same
    ## `attachProducer(path0)` the shim's producers use, on the path the
    ## monitored process was actually named — and it emits twice: once while the
    ## consumer is alive (the positive control, without which "the second emit
    ## failed" could mean the producer never worked) and once after the monitor
    ## has been finished.
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh3-lf4-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let reporter = buildC(work, "dh3_depshm_reporter", depShmReporterSrc)
    let shmPathFile = work / "dep-shm-path.txt"

    var req: FsSnoopRequest
    req.command = @[reporter, shmPathFile]
    req.depFilePath = work / "lf4.rdep"
    req.streamMode = fsoNone

    var handle = startMonitor(req)
    while not pollMonitor(handle):
      sleep(5)

    check fileExists(shmPathFile)
    let path0 = readFile(shmPathFile).strip()
    checkpoint("monitored process was named REPRO_MONITOR_DEP_SHM=" & path0)
    check path0.len > 0
    check path0.endsWith(".shard0")

    var prod = gsett.attachProducer(path0)
    check gsett.available(prod)

    # POSITIVE CONTROL — the consumer is still alive, so an emit lands.
    let blob = @[byte 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]
    let whileAlive = gsett.emit(prod, blob)
    checkpoint("emit while the consumer is alive: " & $whileAlive)
    check whileAlive in {gsett.emInserted, gsett.emExists}

    # Finish the monitor: `releaseMonitor` announces the consumer gone
    # (`SetHost.finish` → markConsumerGone) and unmaps. The producer above keeps
    # its OWN mapping, exactly as a detached descendant would.
    discard finishMonitor(move(handle))

    let afterGone = gsett.emit(prod, @[byte 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    checkpoint("emit after the monitor was finished: " & $afterGone)
    # THE ASSERTION: a late orphan learns to stop, instead of growing a set with
    # no reader — the structural replacement for §4.1's 61 GiB fragment file.
    check afterGone == gsett.emConsumerGone

    gsett.detach(prod)
    removeDir(work)
