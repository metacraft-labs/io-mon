## A child spawned with an EXPLICIT environment block must still be
## configured, and records made on a thread that has already exited must
## still be durable.
##
## THE TWO HOLES, AND WHY THEY LOOK THE SAME FROM THE OUTSIDE
## ----------------------------------------------------------
## Both end with a process that WAS injected, WAS instrumented, and reported
## nothing at all -- which downstream is indistinguishable from a process the
## shim never reached.
##
## 1. THE CONFIGURATION NEVER ARRIVES. The shim reads where to write its
##    records from the child's Windows environment block
##    (`REPRO_MONITOR_FRAGMENT_DIR`). A child spawned with
##    `lpEnvironment = NULL` inherits ours and has it. A child spawned with an
##    EXPLICIT block has whatever its spawner put there -- and a spawner that
##    builds its own block has never heard of us. The injection then
##    SUCCEEDS: `LoadLibraryW` returns, `repro_runtime_init` runs and returns
##    0, `fragmentDir` comes back empty, and every record the child makes is
##    dropped. The spawn hook reports `ioInjected` and the merge reports
##    "spawn child missing process-start" -- an unknown-scope loss whose
##    stated cause is not what happened.
##
##    This is not a corner case. Every build tool that curates its child's
##    environment (cmake, ninja, a test runner, anything calling
##    `startProcess(env = ...)`) is in it, and so is every MSYS2/Cygwin
##    `exec`: that runtime hands a Cygwin child a MINIMAL Windows block on
##    purpose, because the POSIX environment travels through its own
##    `child_info` block instead.
##
## 2. THE RECORDS NEVER REACH DISK. Records are batched per THREAD, in a
##    threadvar the process-exit handler cannot reach for any thread but its
##    own. A worker thread that records and exits leaves its batch behind;
##    the merge accounts the unretired read-tail marker as a
##    `kill-before-flush` loss, which is honest but empty -- the reads it
##    describes are gone. Linux has flushed every registered slot at shutdown
##    since DEP-FLUSH-1 and flushes a dying thread's slot from a
##    `pthread_key_create` destructor; Windows had neither.
##
## WHY THESE TWO ARE ONE FILE. They are the same failure mode at two
## different points on the same path, and the second is the reason the first
## is worth fixing: configuring a child that then loses everything it
## recorded buys nothing.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, osproc, strtabs, strutils, tempfiles, unittest]

import io_mon
import io_mon/fs_snoop

const
  SpawnerArg = "--io-mon-explicit-env-spawner"
  ReaderArg = "--io-mon-explicit-env-reader"
  ThreadArg = "--io-mon-worker-thread-reader"
  MonitorEnvPrefix = "REPRO_MONITOR_"

proc readMarker(path: string): int =
  ## Open and read one file, through the ordinary CRT path the shim hooks.
  try:
    let content = readFile(path)
    if content.len == 0: 9 else: 0
  except CatchableError:
    8

# ---------------------------------------------------------------------------
# Fixtures. This binary re-invokes itself; the modes must be dispatched
# BEFORE the suites so a monitored invocation does not re-run the whole file.
# ---------------------------------------------------------------------------

proc runSpawner(marker: string): int =
  ## Spawn a child with an environment block WE build, from which every
  ## monitoring variable has been removed -- the shape a build tool produces
  ## when it curates its child's environment.
  let childEnv = newStringTable(modeCaseInsensitive)
  for name, value in envPairs():
    if not name.toUpperAscii.startsWith(MonitorEnvPrefix):
      childEnv[name] = value
  let child = startProcess(getAppFilename(), args = @[ReaderArg, marker],
    env = childEnv, options = {poParentStreams})
  result = waitForExit(child)
  close(child)

var workerMarker: string
var workerResult: int

proc workerBody(ignored: int) {.thread.} =
  ## Record from a thread that then EXITS, before the process does.
  {.gcsafe.}:
    workerResult = readMarker(workerMarker)

proc runThreadReader(marker: string): int =
  ## The read happens on a worker thread which is joined -- and therefore
  ## gone -- well before the process exits.
  workerMarker = marker
  var worker: Thread[int]
  createThread(worker, workerBody, 0)
  joinThread(worker)
  workerResult

if paramCount() == 2:
  case paramStr(1)
  of SpawnerArg: quit(runSpawner(paramStr(2)))
  of ReaderArg: quit(readMarker(paramStr(2)))
  of ThreadArg: quit(runThreadReader(paramStr(2)))
  else: discard

# ---------------------------------------------------------------------------

proc monitor(dir: string; args: seq[string]): MonitorResult =
  var command = @[getAppFilename()]
  command.add args
  runMonitored(FsSnoopRequest(
    command: command,
    depFilePath: dir / "run.iomon",
    passthroughChildStdout: false,
    passthroughChildStderr: false,
    captureChildStdio: true))

proc markerFile(dir: string): string =
  result = dir / "marker.txt"
  writeFile(result, "io-mon marker payload\n")

proc pidsReporting(res: MonitorResult): seq[uint64] =
  result = @[]
  for r in res.records:
    if r.kind == mrProcessStart and r.osPid notin result:
      result.add r.osPid

proc markerObservations(res: MonitorResult; marker: string): int =
  ## How many records name the marker file as something the program touched.
  let want = marker.toLowerAscii
  for r in res.records:
    if r.kind in {mrFileOpen, mrFileRead, mrPathProbe} and
        r.path.toLowerAscii == want:
      inc result

suite "Windows child environment: the configuration must travel":

  test "a child spawned with an explicit environment still reports":
    ## FAILING BEFORE: the grandchild is injected and initialised, finds no
    ## `REPRO_MONITOR_FRAGMENT_DIR` in the block its parent built, and emits
    ## nothing -- so exactly ONE process reports (the root) and the marker it
    ## read is in no record.
    let dir = createTempDir("io_mon_explicit_env_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard
    let marker = markerFile(dir)

    let res = monitor(dir, @[SpawnerArg, marker])
    check res.exitCode == 0

    # The root AND the child it spawned with a curated environment.
    check pidsReporting(res).len >= 2
    check markerObservations(res, marker) >= 1

suite "Windows child environment: the records must reach disk":

  test "records made on a thread that has exited are still durable":
    ## FAILING BEFORE: the worker's batch lives in that thread's threadvar,
    ## the process-exit handler flushes only its OWN slot, and nothing
    ## flushes a dead thread's -- so the marker read is lost and the merge
    ## reports a kill-before-flush loss in its place.
    let dir = createTempDir("io_mon_thread_exit_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard
    let marker = markerFile(dir)

    let res = monitor(dir, @[ThreadArg, marker])
    check res.exitCode == 0
    check markerObservations(res, marker) >= 1
