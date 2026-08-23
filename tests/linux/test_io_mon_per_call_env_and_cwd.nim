## test_io_mon_per_call_env_and_cwd — IoMon-Decomposed-Host-API DH-1.
##
## Proves that `runMonitored` publishes its injection variables and its working
## directory PER CALL — through the spawn — instead of mutating the hosting
## process's own environment. Everything here drives the LIVE Linux LD_PRELOAD
## shim against real processes and the real filesystem.
##
## NO MOCKS. There is nothing stubbed, faked or intercepted in this file: the
## monitored programs are C binaries compiled by the host toolchain during the
## test, the rendezvous between the two concurrent monitors is real files on the
## real filesystem, and the evidence asserted on is what the shim actually
## captured. Mocking any of it would dissolve the property under test — a fake
## spawn cannot demonstrate that the REAL spawn stopped depending on
## process-global state.
##
##   t_two_concurrent_monitors_do_not_clobber_each_other — the headline. Two
##       monitored trees run SIMULTANEOUSLY on two threads of this one process
##       over disjoint input sets, and each edge gets its own complete evidence
##       and none of the other's. Simultaneity is not assumed, it is ENFORCED:
##       each monitored program publishes a ready marker and then blocks until
##       it sees the peer's marker, so if the two runs were serialised the first
##       would time out and exit non-zero. Under the pre-DH-1 process-global
##       `putEnv` the two runs shared one `LD_PRELOAD` /
##       `REPRO_MONITOR_FRAGMENT_DIR` / `REPRO_MONITOR_DEP_SHM`, so this shape
##       was not merely unproven, it was impossible.
##
##   t_parent_env_is_unchanged_after_a_monitored_run — every injection variable
##       on every arm (the seven Linux ones plus the two macOS-only ones) is
##       absent from THIS process after a monitored run. The same case also
##       asserts the run was honestly complete and captured its input, so
##       "absent because nothing was ever injected" cannot pass it.
##
##   t_per_action_cwd_is_honoured — a relative path named by the monitored
##       command resolves against `request.cwd`, not against the hosting
##       process's current directory (which is asserted not to contain it).
##
##   t_concurrent_runs_do_not_fabricate_an_event_loss — the run id has to be
##       unique per CALL, not merely per wall-clock instant. It is what
##       `liveInjectedDescendants` (fs_snoop.nim) matches in `/proc/*/environ`
##       (`REPRO_MONITOR_SESSION=<runId>`) to decide which surviving processes
##       are ITS OWN detached descendants, and the scan walks ALL of `/proc`,
##       not a process subtree — so two concurrent monitors sharing a run id
##       cross-attribute, and the one whose root exits first reports the OTHER's
##       still-live child as its own escapee and fabricates an `mrEventLoss`
##       -> a FALSE `mcIncomplete` on an edge that lost nothing. Measured, not
##       theorised: with `newRunId` forced to a constant this case reports
##       `mcIncomplete` with detail "linux injected descendants still live after
##       root exit pids=<the peer's child>". The lingering peer makes it
##       DETERMINISTIC rather than a race: 3s of linger against a 500ms grace.

import std/[os, osproc, sequtils, streams, strutils, unittest]

import io_mon                            # runMonitored / FsSnoopRequest (PUBLIC)
import shm_gset                          # shmGSetSupported

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

  ## Every environment variable `runMonitored` injects, across ALL THREE arms.
  ## Enumerated from the arms in `src/io_mon/fs_snoop.nim` rather than from the
  ## milestone's count: Linux publishes seven (`LD_PRELOAD`,
  ## `REPRO_MONITOR_FRAGMENT_DIR`, `_OUTPUT`, `_SESSION`, `_DEP_SHM`, `_APP_ID`,
  ## `_SHIM_LIB`), macOS publishes six — no `_DEP_SHM`/`_APP_ID`, because the
  ## shm-gset arm is Linux-only, but two the Linux arm has not got
  ## (`DYLD_INSERT_LIBRARIES` in place of `LD_PRELOAD`, and
  ## `CT_SANDBOX_TOOLS_DIR` for the SIP bypass) — and Windows publishes four
  ## (no preload variable at all; it injects with CreateRemoteThread).
  ## The union is asserted on every platform: a variable that a future arm
  ## starts publishing must never start leaking here unnoticed.
  injectionEnvVars = [
    "LD_PRELOAD",                  # Linux
    "DYLD_INSERT_LIBRARIES",       # macOS
    "CT_SANDBOX_TOOLS_DIR",        # macOS
    "REPRO_MONITOR_FRAGMENT_DIR",  # Linux, macOS, Windows
    "REPRO_MONITOR_OUTPUT",        # Linux, macOS, Windows
    "REPRO_MONITOR_SESSION",       # Linux, macOS, Windows
    "REPRO_MONITOR_DEP_SHM",       # Linux
    "REPRO_MONITOR_APP_ID",        # Linux
    "REPRO_MONITOR_SHIM_LIB"       # Linux, macOS, Windows
  ]

# --------------------------------------------------------------------------
# Helpers.
#
# Every helper that ASSERTS is a `template`: `check` inside a plain `proc`
# prints "Check failed" but leaves the case labelled `[OK]`, so an assertion
# hidden in a proc is an assertion that cannot fail the test it belongs to.
# Helpers that merely DO something are procs, and they signal failure by
# RAISING (which unittest reports as a genuine `[FAILED]`), never by `check`.
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
  ## Build the shim the way the rest of the Linux suite does, and resolve it
  ## with the SAME discovery `runMonitored` uses — deliberately WITHOUT pinning
  ## `REPRO_MONITOR_SHIM_LIB` in this process, because this file's whole point
  ## is that the injection variables are absent from this process.
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  if buildShim.code != 0:
    raise newException(IOError, "build_shim.sh failed: " & buildShim.output)
  result = findShimLibrary()
  if result.len == 0:
    raise newException(IOError, "findShimLibrary() resolved nothing after build")

proc hasFileRead(recs: seq[MonitorRecord]; path: string): bool =
  recs.anyIt(it.kind == mrFileRead and it.observationKind == moFileRead and
    path in it.path)

proc eventLossDetails(recs: seq[MonitorRecord]): seq[string] =
  ## The `detail` of every event-loss record, so a failure REPORTS which loss
  ## was invented rather than only that the count was wrong.
  recs.filterIt(it.kind == mrEventLoss).mapIt(it.detail)

proc anyPathMentions(recs: seq[MonitorRecord]; needle: string): bool =
  ## Deliberately WIDER than `hasFileRead`: any record of any kind whose path
  ## mentions the needle. Used for the cross-contamination assertion, where the
  ## honest question is "did this edge see the other action's file AT ALL", not
  ## "did it see it as a read".
  recs.anyIt(needle in it.path)

## The monitored program for the concurrency case.
##   argv[1] — the ready marker THIS process publishes
##   argv[2] — the peer's ready marker; block until it appears
##   argv[3] — this action's own input file, read only AFTER the rendezvous
## Exit 3 means the peer never showed up inside the ceiling, i.e. the two
## monitors did NOT overlap — which is exactly the failure this case exists to
## detect, and is why the concurrency claim is enforced rather than assumed.
const rendezvousReaderSrc = """
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  if (argc < 4) return 1;
  int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return 2;
  if (write(fd, "r", 1) != 1) return 2;
  close(fd);
  struct stat st;
  int seen = 0;
  for (int i = 0; i < 3000; i++) {   /* 30s ceiling */
    if (stat(argv[2], &st) == 0) { seen = 1; break; }
    usleep(10000);
  }
  if (!seen) return 3;               /* the runs were serialised */
  fd = open(argv[3], O_RDONLY);
  if (fd < 0) return 4;
  if (read(fd, buf, sizeof(buf)) < 0) return 5;
  close(fd);
  return 0;
}
"""

## The monitored program for the run-id case. Same rendezvous as above, plus a
## LINGER (argv[4], microseconds) after the read, so one monitor's child is
## still alive — and still carrying `REPRO_MONITOR_SESSION` — well past the
## other monitor's root exit and its 500ms descendant-grace window. That is what
## turns a run-id collision from a narrow race into a deterministic failure.
const lingeringReaderSrc = """
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  if (argc < 5) return 1;
  int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return 2;
  if (write(fd, "r", 1) != 1) return 2;
  close(fd);
  struct stat st;
  int seen = 0;
  for (int i = 0; i < 3000; i++) {   /* 30s ceiling */
    if (stat(argv[2], &st) == 0) { seen = 1; break; }
    usleep(10000);
  }
  if (!seen) return 3;               /* the runs were serialised */
  fd = open(argv[3], O_RDONLY);
  if (fd < 0) return 4;
  if (read(fd, buf, sizeof(buf)) < 0) return 5;
  close(fd);
  usleep((useconds_t)atoi(argv[4]));
  return 0;
}
"""

## The monitored program for the cwd case: opens argv[1] verbatim, so a
## relative path can only succeed if the CHILD's working directory is the
## request's.
const relativeReaderSrc = """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  if (argc < 2) return 1;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  if (read(fd, buf, sizeof(buf)) < 0) return 3;
  close(fd);
  return 0;
}
"""

# --------------------------------------------------------------------------
# Concurrent-run plumbing. Two real OS threads of THIS process, each owning one
# `runMonitored` call — the shape the build engine needs and the shape the
# process-global `putEnv` made unusable.
# --------------------------------------------------------------------------

type
  MonitorJob = object
    req: FsSnoopRequest
    res: MonitorResult
    error: string

var jobs: array[2, MonitorJob]

proc runJob(idx: int) {.thread.} =
  {.cast(gcsafe).}:
    try:
      jobs[idx].res = runMonitored(jobs[idx].req)
    except CatchableError as err:
      jobs[idx].error = err.msg

suite "io-mon per-call injection env and cwd (DH-1)":

  test "t_two_concurrent_monitors_do_not_clobber_each_other":
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh1-concurrent-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # Disjoint input sets. The basenames are chosen so that neither is a
    # substring of the other — the record assertions match on substrings.
    let inputAlpha = work / "alpha-only-input.txt"
    let inputBeta = work / "beta-only-input.txt"
    writeFile(inputAlpha, "alpha\n")
    writeFile(inputBeta, "beta\n")

    let readyAlpha = work / "alpha.ready"
    let readyBeta = work / "beta.ready"
    let reader = buildC(work, "dh1_rendezvous_reader", rendezvousReaderSrc)

    let depAlpha = work / "alpha.rdep"
    let depBeta = work / "beta.rdep"

    jobs[0] = MonitorJob()
    jobs[0].req.command = @[reader, readyAlpha, readyBeta, inputAlpha]
    jobs[0].req.depFilePath = depAlpha
    jobs[0].req.streamMode = fsoNone

    jobs[1] = MonitorJob()
    jobs[1].req.command = @[reader, readyBeta, readyAlpha, inputBeta]
    jobs[1].req.depFilePath = depBeta
    jobs[1].req.streamMode = fsoNone

    var threads: array[2, Thread[int]]
    createThread(threads[0], runJob, 0)
    createThread(threads[1], runJob, 1)
    joinThreads(threads)

    checkpoint("alpha: err=\"" & jobs[0].error & "\" exit=" &
      $jobs[0].res.exitCode & " completeness=" & $jobs[0].res.completeness &
      " records=" & $jobs[0].res.records.len)
    checkpoint("beta:  err=\"" & jobs[1].error & "\" exit=" &
      $jobs[1].res.exitCode & " completeness=" & $jobs[1].res.completeness &
      " records=" & $jobs[1].res.records.len)

    check jobs[0].error.len == 0
    check jobs[1].error.len == 0

    # (1) GENUINELY CONCURRENT. Exit 0 is only reachable through the rendezvous:
    #     each program blocked until it saw the other's marker. Serialised runs
    #     would have exited 3.
    check jobs[0].res.exitCode == 0
    check jobs[1].res.exitCode == 0

    # (2) Each edge's evidence is HONESTLY COMPLETE — not downgraded because the
    #     other run stole its fragment dir / dependency set.
    check jobs[0].res.completeness == mcComplete
    check jobs[1].res.completeness == mcComplete

    # (3) Each edge got ITS OWN complete evidence …
    check hasFileRead(jobs[0].res.records, inputAlpha)
    check hasFileRead(jobs[1].res.records, inputBeta)

    # (4) … and NONE of the other's. This is the clobbering assertion: a shared
    #     process-global injection env routes one tree's observations into the
    #     other's set.
    check not anyPathMentions(jobs[0].res.records, "beta-only-input")
    check not anyPathMentions(jobs[1].res.records, "alpha-only-input")

    # (5) The two canonical depfiles are separate artefacts, each holding its own
    #     evidence on disk.
    check jobs[0].res.depFilePath == depAlpha
    check jobs[1].res.depFilePath == depBeta
    check fileExists(depAlpha)
    check fileExists(depBeta)
    check hasFileRead(readMonitorDepFile(depAlpha).records, inputAlpha)
    check hasFileRead(readMonitorDepFile(depBeta).records, inputBeta)

    removeDir(work)

  test "t_parent_env_is_unchanged_after_a_monitored_run":
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh1-parent-env-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let input = work / "parent-env-input.txt"
    writeFile(input, "parent env marker\n")
    let reader = buildC(work, "dh1_relative_reader", relativeReaderSrc)

    # Establish a KNOWN-ABSENT baseline, rather than snapshotting whatever the
    # ambient shell happens to hold. Two reasons, both learned the hard way:
    #
    #   * a "value is unchanged" assertion is satisfied by a leak that happens to
    #     write the SAME value twice, so it is not a sound primary assertion; and
    #   * an earlier `runMonitored` in THIS binary (the concurrency case above)
    #     would, under a leak, have already polluted the baseline — measured:
    #     the first mutation run recorded `before` as the PREVIOUS run's leaked
    #     session id, which turned the absence assertion into a no-op and left
    #     only the value comparison with any teeth.
    #
    # Deleting them here is safe: nothing in this file depends on an ambient
    # value (`ensureShim` above resolved the shim by DISCOVERY, with no
    # `REPRO_MONITOR_SHIM_LIB` pin), and the originals are restored at the end.
    var before: seq[tuple[value: string; existed: bool]] = @[]
    for name in injectionEnvVars:
      before.add((getEnv(name), existsEnv(name)))
      delEnv(name)
    for name in injectionEnvVars:
      check not existsEnv(name)          # baseline precondition

    var req: FsSnoopRequest
    req.command = @[reader, input]
    req.depFilePath = work / "parent-env.rdep"
    req.streamMode = fsoNone
    let res = runMonitored(req)

    checkpoint("exit=" & $res.exitCode & " completeness=" & $res.completeness &
      " records=" & $res.records.len)

    # The run really did inject — otherwise "no variables leaked" would be
    # trivially true of a monitor that never monitored anything.
    check res.exitCode == 0
    check res.completeness == mcComplete
    check hasFileRead(res.records, input)

    # THE PRIMARY ASSERTION. Not one injection variable, on any arm, survived
    # into this process.
    for name in injectionEnvVars:
      checkpoint("after run: " & name & " existsEnv=" & $existsEnv(name) &
        " value=\"" & getEnv(name) & "\"")
      check not existsEnv(name)
      check getEnv(name) == ""

    # Put back whatever the ambient environment had, so a later case in this
    # binary sees the shell it was started with.
    for i, name in injectionEnvVars:
      if before[i].existed:
        putEnv(name, before[i].value)

    removeDir(work)

  test "t_per_action_cwd_is_honoured":
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh1-cwd-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let actionDir = work / "action-dir"
    createDir(actionDir)

    # Named so that the hosting process's own working directory cannot possibly
    # contain it — asserted, not assumed, just below.
    const relativeName = "dh1-cwd-relative-input.txt"
    writeFile(actionDir / relativeName, "resolved against the request cwd\n")

    let hostCwd = getCurrentDir()
    checkpoint("host cwd=" & hostCwd)
    check not fileExists(hostCwd / relativeName)

    let reader = buildC(work, "dh1_cwd_reader", relativeReaderSrc)

    var req: FsSnoopRequest
    req.command = @[reader, relativeName]   # RELATIVE — resolvable only in `cwd`
    req.cwd = actionDir
    req.depFilePath = work / "cwd.rdep"
    req.streamMode = fsoNone
    let res = runMonitored(req)

    checkpoint("exit=" & $res.exitCode & " completeness=" & $res.completeness &
      " records=" & $res.records.len)

    # THE PRIMARY ASSERTION. The reader exits 2 when `open(argv[1])` fails, so
    # exit 0 means the relative name resolved — and it can only have resolved in
    # `req.cwd`, since the hosting process's directory has no such file.
    check res.exitCode == 0

    # The hosting process's own working directory was not moved to get there.
    check getCurrentDir() == hostCwd

    # The dependency landed in the evidence, under whichever spelling the shim
    # recorded (the verbatim relative name or its resolution in the action dir).
    check res.completeness == mcComplete
    check hasFileRead(res.records, relativeName)

    removeDir(work)

  test "t_concurrent_runs_do_not_fabricate_an_event_loss":
    check shmGSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    let work = getTempDir() / ("io-mon-dh1-runid-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let inputFirst = work / "first-only-input.txt"
    let inputSecond = work / "second-only-input.txt"
    writeFile(inputFirst, "first\n")
    writeFile(inputSecond, "second\n")
    let readyFirst = work / "first.ready"
    let readySecond = work / "second.ready"
    let reader = buildC(work, "dh1_lingering_reader", lingeringReaderSrc)

    # Job 0's child exits the instant the rendezvous completes; job 1's lingers
    # 3s. So job 0's root exits FIRST and runs `waitForLinuxInjectedDescendants`
    # while job 1's child is unambiguously still alive — 3s against a 500ms
    # grace, so the outcome does not depend on scheduling.
    jobs[0] = MonitorJob()
    jobs[0].req.command = @[reader, readyFirst, readySecond, inputFirst, "0"]
    jobs[0].req.depFilePath = work / "first.rdep"
    jobs[0].req.streamMode = fsoNone

    jobs[1] = MonitorJob()
    jobs[1].req.command =
      @[reader, readySecond, readyFirst, inputSecond, "3000000"]
    jobs[1].req.depFilePath = work / "second.rdep"
    jobs[1].req.streamMode = fsoNone

    var threads: array[2, Thread[int]]
    createThread(threads[0], runJob, 0)
    createThread(threads[1], runJob, 1)
    joinThreads(threads)

    for i in 0 .. 1:
      checkpoint("job" & $i & ": err=\"" & jobs[i].error & "\" exit=" &
        $jobs[i].res.exitCode & " completeness=" & $jobs[i].res.completeness &
        " losses=" & $eventLossDetails(jobs[i].res.records))

    check jobs[0].error.len == 0
    check jobs[1].error.len == 0

    # The overlap really happened (exit 3 is the rendezvous timeout) and the
    # linger really outlasted the grace window — otherwise a collision would
    # have nothing to cross-attribute and the case would pass vacuously.
    check jobs[0].res.exitCode == 0
    check jobs[1].res.exitCode == 0

    # THE PRIMARY ASSERTION. Distinct run ids ⇒ job 0's `/proc` scan matches
    # NOTHING, so no launcher-side loss is invented for it. Under a colliding
    # run id this is `mcIncomplete` with one `mrEventLoss` naming job 1's child.
    check eventLossDetails(jobs[0].res.records).len == 0
    check jobs[0].res.completeness == mcComplete

    # The lingering side must stay honest too.
    check eventLossDetails(jobs[1].res.records).len == 0
    check jobs[1].res.completeness == mcComplete

    # And each still captured only its own input, so "no loss" is not "no
    # evidence".
    check hasFileRead(jobs[0].res.records, inputFirst)
    check hasFileRead(jobs[1].res.records, inputSecond)
    check not anyPathMentions(jobs[0].res.records, "second-only-input")
    check not anyPathMentions(jobs[1].res.records, "first-only-input")

    removeDir(work)
