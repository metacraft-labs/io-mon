## test_io_mon_descendant_scan_start_time_prune — the §4.1 sweep's cost cut,
## and the one thing that cut is not allowed to cost.
##
## The detached-descendant guard is O(processes on the machine): it asks, for
## every pid in `/proc`, whether that process carries this monitor's injection
## markers. Measured on a 900-process host, the exhaustive form cost ~150 ms per
## `finishMonitor` — which is fine when each monitor is its own process and
## irrelevant when it is not, but ruinous for a host that runs N monitors in one
## poll loop, where it serialises into a hard ceiling on monitored-action
## throughput.
##
## The sweep now PRUNES: a process whose start time (field 22 of
## `/proc/<pid>/stat`) is earlier than the monitored ROOT's own start time
## cannot be a descendant of that root, and both injection needles reach a
## process only by inheritance from the root, so such a process cannot be
## carrying them. That is an argument about process creation, not a heuristic —
## but its whole weight rests on the bound being the ROOT's start time and the
## comparison being STRICT, and both of those are one character away from
## silently narrowing the guard into a false `mcComplete`. Which is the cardinal
## sin, so they are pinned here rather than argued in a comment.
##
## NO MOCKS. A real double-forked, `setsid`'d daemon is compiled by the host
## toolchain, really outlives the monitored root, and is really found (or not)
## by the real `/proc` scan; the verdict asserted on is decoded from the
## canonical depfile io-mon actually wrote.
##
##   t_a_descendant_born_in_the_same_clock_tick_as_the_root_is_still_found —
##       THE boundary. `/proc`'s start times are quantised to USER_HZ (10 ms),
##       and a descendant forked immediately by the root normally lands in the
##       SAME tick as it, so `descendantTicks == rootTicks` is the ordinary case
##       rather than an exotic one — and a prune written `<=` instead of `<`
##       drops exactly it. The fixture REPORTS both tick values, the case
##       retries until it has actually observed a same-tick run (and fails
##       loudly if it never does, rather than passing on a case it never
##       exercised), and only then demands the `mcIncomplete` downgrade.
##       A CONTROL arm runs the same fixture with the descendant quiescing
##       inside the grace window and demands `mcComplete`, so the headline
##       cannot pass for some unrelated reason about the fixture.
##
##   t_the_prune_bound_is_the_roots_own_start_time — structural. The soundness
##       argument names one specific quantity; this reads `fs_snoop.nim` and
##       checks the code actually uses it: the handle field has exactly one
##       assignment, it is `procStartTicks(h.rootPid)`, it is written in the
##       spawn path, and it is the only thing the sweep's bound is ever fed
##       from. `reportedTicks` RAISES when it cannot find what it was told to
##       find; the source readers answer SHORT instead, so every claim about
##       them is asserted as an exact COUNT (`== 1`, `== 0`) — a rename makes
##       the count wrong and the case red, never vacuously green. Measured
##       against a SECOND writer spelled `h.rootStartTicks=` with the spaces
##       removed — the shape DH-4 recorded a sibling parser walking straight
##       past: the case still reddens, because a spelling the assignment
##       reader misses is a spelling the reads reader counts.

import std/[os, osproc, sequtils, streams, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  fsSnoopPath = repoRoot / "src" / "io_mon" / "fs_snoop.nim"
  GraceMs = 300
  PollMs = 10
  ## How many times the boundary case may be re-run while waiting to observe a
  ## root and a descendant that really did land in the same clock tick. Each
  ## attempt is one process spawn; the same-tick outcome is the COMMON one (the
  ## descendant is forked within a couple of milliseconds of the root), so this
  ## is generous rather than hopeful.
  SameTickAttempts = 12

# --------------------------------------------------------------------------
# Helpers. Every helper that ASSERTS is a `template`: `check` inside a plain
# `proc` prints "Check failed" and still leaves the case labelled `[OK]`.
# Helpers that merely DO something are procs and signal failure by RAISING.
# --------------------------------------------------------------------------

proc run(cmd: string; args: seq[string]): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc buildC(work, name, source: string): string =
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
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  if buildShim.code != 0:
    raise newException(IOError, "build_shim.sh failed: " & buildShim.output)
  result = findShimLibrary()
  if result.len == 0:
    raise newException(IOError, "findShimLibrary() resolved nothing after build")

proc awaitFile(path: string; timeoutMs: int) =
  var waited = 0
  while not fileExists(path):
    if waited >= timeoutMs:
      raise newException(IOError,
        "timed out after " & $timeoutMs & "ms waiting for " & path)
    sleep(10)
    waited += 10

proc descendantLossDetails(dep: MonitorDepFile): seq[string] =
  result = @[]
  for rec in dep.records:
    if rec.kind == mrEventLoss and
        ("linux injected descendants still live" in rec.detail or
         "linux injected-descendant /proc scan failed" in rec.detail):
      result.add rec.detail

proc reportedTicks(path, key: string): uint64 =
  ## Pull `<key> <ticks>` out of the fixture's report. RAISES when the line is
  ## missing — a boundary case that cannot prove which tick it ran in must not
  ## quietly count as a run of the boundary case.
  for line in readFile(path).splitLines():
    let parts = line.strip().split(' ')
    if parts.len == 2 and parts[0] == key:
      return parseBiggestUInt(parts[1])
  raise newException(ValueError,
    "fixture report " & path & " has no `" & key & " <ticks>` line; got:\n" &
      readFile(path))

## The fixture. Same detached-descendant shape as the DH-3 guard test, plus one
## thing that test has no reason to know: BOTH processes report their own start
## time (field 22 of `/proc/self/stat`, USER_HZ ticks since boot) so the harness
## can tell whether the run it just graded actually exercised the same-tick
## boundary the prune is one character away from getting wrong.
##
##   argv[1] — marker file the DESCENDANT reads (a real dependency the root
##             never touches)
##   argv[2] — proof file the descendant writes once it has read the marker
##   argv[3] — report file both processes append their start tick to
##   argv[4] — release sentinel, or "-" for quiesce (control) mode
const startTickFixtureSrc = """
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Field 22 of /proc/self/stat, read the same way fs_snoop reads field 22 of
   /proc/<pid>/stat: everything after the ')' that closes comm is fixed-width
   whitespace-separated fields, and comm is the only one that can contain a
   space or a paren. */
static unsigned long long self_start_ticks(void) {
  int fd = open("/proc/self/stat", O_RDONLY);
  if (fd < 0) return 0;
  char buf[4096];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) return 0;
  buf[n] = 0;
  char *cp = strrchr(buf, ')');
  if (cp == NULL) return 0;
  char *p = cp + 2;
  for (int field = 3; field < 22; field++) {
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    if (*p == 0) return 0;
  }
  return strtoull(p, NULL, 10);
}

static void report(const char *path, const char *key, unsigned long long v) {
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (fd < 0) return;
  char line[128];
  int n = snprintf(line, sizeof(line), "%s %llu\n", key, v);
  if (n > 0) { if (write(fd, line, (size_t)n) < 0) {} }
  close(fd);
}

int main(int argc, char **argv) {
  if (argc != 5) return 2;
  const char *release = argv[4];
  int gated = strcmp(release, "-") != 0;

  report(argv[3], "root", self_start_ticks());

  int rp[2];
  if (pipe(rp) != 0) return 8;

  pid_t pid = fork();
  if (pid < 0) return 3;
  if (pid > 0) {
    close(rp[1]);
    char b;
    if (gated) {
      while (read(rp[0], &b, 1) < 0) { /* retry on EINTR */ }
    } else {
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

  report(argv[3], "descendant", self_start_ticks());

  if (gated) {
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) maxfd = 4096;
    for (int fd = 0; fd < maxfd; fd++) {
      if (fd != rp[1]) close(fd);
    }
    int dn = open("/dev/null", O_RDWR);
    if (dn == 0) { dup2(dn, 1); dup2(dn, 2); }
  }

  int in = open(argv[1], O_RDONLY);
  if (in < 0) _exit(6);
  char buf[64];
  ssize_t n = read(in, buf, sizeof(buf));
  close(in);
  int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out >= 0) {
    if (n > 0) { if (write(out, "read\n", 5) < 0) {} }
    close(out);
  }
  if (gated) {
    char rb = 1;
    if (write(rp[1], &rb, 1) < 0) {}
    close(rp[1]);
    struct stat st;
    while (stat(release, &st) != 0) usleep(2000);
    /* Acknowledge the release BEFORE exiting so the harness can wait for this
       process to be past its last file operation before removing the work
       directory — without it the sentinel and the `removeDir` are a race the
       descendant loses, and it then polls a vanished path forever. */
    char ack[4096];
    snprintf(ack, sizeof(ack), "%s.ack", release);
    int af = open(ack, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (af >= 0) { if (write(af, "gone\n", 5) < 0) {} close(af); }
    _exit(n > 0 ? 0 : 7);
  }
  _exit(n > 0 ? 0 : 7);
}
"""

# --------------------------------------------------------------------------
# Deliberately dumb source reading for the structural case. Every lookup RAISES
# when it finds nothing, so a rename cannot make an assertion vacuously true.
# --------------------------------------------------------------------------

proc fsSnoopCodeLines(): seq[string] =
  ## Every line of `fs_snoop.nim` with comments and doc comments removed, so a
  ## claim can never be satisfied by prose that merely MENTIONS the call.
  result = @[]
  for line in readFile(fsSnoopPath).splitLines():
    let stripped = line.strip()
    if stripped.startsWith("#"):
      result.add ""
    else:
      result.add stripped

proc linesContaining(lines: seq[string]; needle: string): seq[string] =
  result = @[]
  for line in lines:
    if needle in line:
      result.add line

putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", $GraceMs)
putEnv("IO_MON_LINUX_DESCENDANT_POLL_MS", $PollMs)

suite "io-mon detached-descendant scan start-time prune":

  test "t_a_descendant_born_in_the_same_clock_tick_as_the_root_is_still_found":
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-prune-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let probe = buildC(work, "prune_fixture", startTickFixtureSrc)
    let marker = work / "descendant-marker.txt"
    writeFile(marker, "descendant marker\n")

    # ---- CONTROL: the descendant quiesces INSIDE the grace window ---------
    # Without this arm, a headline that reports `mcIncomplete` proves nothing:
    # a guard that downgraded EVERY edge would pass it.
    let quietReport = work / "quiet.report"
    var quietReq: FsSnoopRequest
    quietReq.command = @[probe, marker, work / "quiet.proof", quietReport, "-"]
    quietReq.depFilePath = work / "quiet.rdep"
    quietReq.streamMode = fsoNone
    let quietRes = runMonitored(quietReq)
    checkpoint("control: exit=" & $quietRes.exitCode & " completeness=" &
      $quietRes.completeness & " losses=" &
      $descendantLossDetails(quietRes.depFile))
    check quietRes.exitCode == 0
    check quietRes.completeness == mcComplete
    check descendantLossDetails(quietRes.depFile).len == 0

    # ---- HEADLINE: a same-tick descendant outlives the grace window -------
    var sameTickSeen = false
    var attempts = 0
    var observed: seq[string] = @[]
    while attempts < SameTickAttempts and not sameTickSeen:
      inc attempts
      let tag = "attempt" & $attempts
      let report = work / (tag & ".report")
      let release = work / (tag & ".release")
      removeFile(report)
      removeFile(release)
      var req: FsSnoopRequest
      req.command = @[probe, marker, work / (tag & ".proof"), report, release]
      req.depFilePath = work / (tag & ".rdep")
      req.streamMode = fsoNone

      var handle = startMonitor(req)
      while not pollMonitor(handle):
        sleep(5)
      let res = finishMonitor(move(handle))
      # Release the descendant IMMEDIATELY, before any assertion, so it is let
      # go (and reaped by init) even if an assertion below fails.
      writeFile(release, "release\n")
      awaitFile(release & ".ack", 20_000)

      let rootTicks = reportedTicks(report, "root")
      let descTicks = reportedTicks(report, "descendant")
      observed.add($rootTicks & "/" & $descTicks & " -> " &
        $res.completeness)
      # A descendant can never predate its own ancestor; if this ever failed,
      # the prune's whole soundness argument would be false.
      check descTicks >= rootTicks
      # EVERY attempt is a real gated run whose descendant is held alive across
      # the whole grace window, so every attempt must downgrade — the same-tick
      # ones are simply the attempts that also exercise the boundary.
      checkpoint("attempt " & $attempts & ": rootTicks=" & $rootTicks &
        " descTicks=" & $descTicks & " completeness=" & $res.completeness &
        " losses=" & $descendantLossDetails(res.depFile))
      check res.exitCode == 0
      check res.completeness == mcIncomplete
      check descendantLossDetails(res.depFile).len > 0
      if descTicks == rootTicks:
        sameTickSeen = true

    checkpoint("attempts: " & observed.join("; "))
    # Never let this case pass without having exercised the boundary it exists
    # for. If the machine is so slow that root and descendant never share a
    # tick, that is a fact worth failing on rather than a green tick.
    check sameTickSeen

    removeDir(work)

  test "t_the_prune_bound_is_the_roots_own_start_time":
    let code = fsSnoopCodeLines()

    # The bound the sweep prunes against is fed from exactly one place, and that
    # place is the monitored root's own start time.
    let assignments = code.linesContaining("h.rootStartTicks =")
    checkpoint("assignments: " & $assignments)
    check assignments.len == 1
    check assignments[0] == "h.rootStartTicks = procStartTicks(h.rootPid)"

    # And the sweep is handed that field and nothing else: the ONE read of it
    # is the argument of the ONE call to the grace wait.
    var readIndices: seq[int] = @[]
    for i, line in code:
      if "h.rootStartTicks" in line and not line.contains("h.rootStartTicks ="):
        readIndices.add i
    checkpoint("reads: " & $readIndices.mapIt(code[it]))
    check readIndices.len == 1
    check readIndices[0] > 0
    let callSite = code[readIndices[0] - 1] & " " & code[readIndices[0]]
    checkpoint("call site: " & callSite)
    check callSite.startsWith("waitForLinuxInjectedDescendants(")

    # The comparison must be STRICT. `<=` would prune a descendant that shares a
    # clock tick with its root, which is the ordinary case, not a corner one.
    let prune = code.linesContaining("startTicks < minStartTicks")
    checkpoint("prune: " & $prune)
    check prune.len == 1
    check code.linesContaining("startTicks <= minStartTicks").len == 0

    # `procStartTicks` must stay private: `io_mon` re-exports all of `fs_snoop`,
    # and a raw `/proc` reader is not part of this package's public surface.
    check code.linesContaining("proc procStartTicks*").len == 0
    check code.linesContaining("proc procStartTicks(").len == 1
