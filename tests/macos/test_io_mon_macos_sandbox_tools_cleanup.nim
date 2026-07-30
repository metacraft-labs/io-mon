## Regression coverage for the invocation-local macOS sandbox-tools fallback.
##
## `runMonitored` populates a non-SIP tool tree when
## CT_SANDBOX_TOOLS_DIR is unset.  The fallback is owned by exactly that
## invocation and must be removed after success and failure.  In contrast, an
## explicitly configured directory is operator-owned and must survive
## byte-for-byte, including unrelated sentinel content.
##
## The concurrency arm launches independent host processes because
## `runMonitored` temporarily publishes injection state through the process
## environment.  That is the supported concurrency topology and proves unique
## fallback directories do not collide or leak under a shared TMPDIR.

import std/[algorithm, os, osproc, sequtils, streams, strtabs, strutils,
    tempfiles, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  ExitWorkerArg = "--sandbox-cleanup-exit-worker"
  MonitorWorkerArg = "--sandbox-cleanup-monitor-worker"

type
  SavedEnv = object
    present: bool
    value: string

proc saveEnv(name: string): SavedEnv =
  result.present = existsEnv(name)
  if result.present:
    result.value = getEnv(name)

proc restoreEnv(name: string; saved: SavedEnv) =
  if saved.present:
    putEnv(name, saved.value)
  else:
    delEnv(name)

proc sandboxDirsUnder(root: string): seq[string] =
  if not dirExists(root):
    return
  for kind, path in walkDir(root):
    if kind == pcDir and
        path.extractFilename.startsWith("repro-fs-snoop-sandbox-tools-"):
      result.add(path)
  result.sort()

proc fragmentDirsUnder(root: string): seq[string] =
  if not dirExists(root):
    return
  for kind, path in walkDir(root):
    if kind == pcDir and
        path.extractFilename.startsWith("repro-fs-snoop-fragments-"):
      result.add(path)
  result.sort()

proc ensureShim(): string =
  result = findShimLibrary()
  if result.len > 0:
    return
  let process = startProcess("bash",
    args = @[repoRoot / "scripts" / "build_shim.sh"],
    options = {poStdErrToStdOut, poUsePath})
  let output = process.outputStream.readAll()
  let exitCode = process.waitForExit()
  process.close()
  if exitCode != 0:
    raise newException(IOError,
      "failed to build macOS monitor shim (" & $exitCode & "):\n" & output)
  result = findShimLibrary()
  if result.len == 0:
    raise newException(IOError, "built monitor shim was not discoverable")

proc monitoredSelfRequest(scratch, depfile: string;
                          exitCode = 0): FsSnoopRequest =
  result.command = @[getAppFilename(), ExitWorkerArg, $exitCode]
  result.depFilePath = depfile
  result.streamMode = fsoNone

proc configureOwnedRun(scratch, shim: string):
    tuple[tmp, sandbox, shim: SavedEnv] =
  result.tmp = saveEnv("TMPDIR")
  result.sandbox = saveEnv("CT_SANDBOX_TOOLS_DIR")
  result.shim = saveEnv("REPRO_MONITOR_SHIM_LIB")
  putEnv("TMPDIR", scratch)
  delEnv("CT_SANDBOX_TOOLS_DIR")
  putEnv("REPRO_MONITOR_SHIM_LIB", shim)

proc restoreOwnedRun(saved: tuple[tmp, sandbox, shim: SavedEnv]) =
  restoreEnv("REPRO_MONITOR_SHIM_LIB", saved.shim)
  restoreEnv("CT_SANDBOX_TOOLS_DIR", saved.sandbox)
  restoreEnv("TMPDIR", saved.tmp)

proc runMonitorWorker(): int =
  if paramCount() != 4:
    return 90
  let scratch = paramStr(2)
  let shim = paramStr(3)
  let workerId = paramStr(4)
  let saved = configureOwnedRun(scratch, shim)
  defer: restoreOwnedRun(saved)
  try:
    let request = monitoredSelfRequest(
      scratch, scratch / ("concurrent-" & workerId & ".rdep"))
    let monitored = runMonitored(request)
    if monitored.exitCode != 0:
      return 91
    if sandboxDirsUnder(scratch).anyIt(
        it.extractFilename.contains("-" & $getCurrentProcessId() & "-")):
      return 92
    return 0
  except CatchableError:
    return 93

if paramCount() >= 1:
  case paramStr(1)
  of ExitWorkerArg:
    if paramCount() != 2:
      quit(80)
    try:
      quit(parseInt(paramStr(2)))
    except ValueError:
      quit(81)
  of MonitorWorkerArg:
    quit(runMonitorWorker())
  else:
    discard

suite "macOS sandbox-tools fallback cleanup":
  test "invocation-owned fallback is removed after success":
    let work = createTempDir("io-mon-sandbox-cleanup-success-", "")
    defer: removeDir(work)
    let scratch = work / "scratch"
    createDir(scratch)
    let shim = ensureShim()
    let saved = configureOwnedRun(scratch, shim)
    defer: restoreOwnedRun(saved)

    let monitored = runMonitored(
      monitoredSelfRequest(scratch, work / "success.rdep"))
    check monitored.exitCode == 0
    check fileExists(work / "success.rdep")
    check not existsEnv("CT_SANDBOX_TOOLS_DIR")
    check sandboxDirsUnder(scratch).len == 0
    check fragmentDirsUnder(scratch).len == 0

  test "invocation-owned fallback is removed after setup failure":
    let work = createTempDir("io-mon-sandbox-cleanup-failure-", "")
    defer: removeDir(work)
    let scratch = work / "scratch"
    createDir(scratch)
    let shim = ensureShim()
    let saved = configureOwnedRun(scratch, shim)
    defer: restoreOwnedRun(saved)

    var request: FsSnoopRequest
    request.command = @[work / "definitely-missing-command"]
    request.depFilePath = work / "failure.rdep"
    request.streamMode = fsoNone
    expect OSError:
      discard runMonitored(request)
    check not existsEnv("CT_SANDBOX_TOOLS_DIR")
    check sandboxDirsUnder(scratch).len == 0
    check fragmentDirsUnder(scratch).len == 0

  test "invocation-owned fallback is removed after non-zero child exit":
    let work = createTempDir("io-mon-sandbox-cleanup-nonzero-", "")
    defer: removeDir(work)
    let scratch = work / "scratch"
    createDir(scratch)
    let shim = ensureShim()
    let saved = configureOwnedRun(scratch, shim)
    defer: restoreOwnedRun(saved)

    let depfile = work / "nonzero.rdep"
    let monitored = runMonitored(
      monitoredSelfRequest(scratch, depfile, exitCode = 23))
    check monitored.exitCode == 23
    check fileExists(depfile)
    check not existsEnv("CT_SANDBOX_TOOLS_DIR")
    check sandboxDirsUnder(scratch).len == 0
    check fragmentDirsUnder(scratch).len == 0

  test "explicit sandbox directory and sentinel remain operator-owned":
    let work = createTempDir("io-mon-sandbox-cleanup-custom-", "")
    defer: removeDir(work)
    let scratch = work / "scratch"
    let customSandbox = work / "custom-sandbox-tools"
    let sentinel = customSandbox / "operator-sentinel.txt"
    createDir(scratch)
    createDir(customSandbox)
    writeFile(sentinel, "operator-owned\n")

    let shim = ensureShim()
    let oldTmp = saveEnv("TMPDIR")
    let oldSandbox = saveEnv("CT_SANDBOX_TOOLS_DIR")
    let oldShim = saveEnv("REPRO_MONITOR_SHIM_LIB")
    defer:
      restoreEnv("REPRO_MONITOR_SHIM_LIB", oldShim)
      restoreEnv("CT_SANDBOX_TOOLS_DIR", oldSandbox)
      restoreEnv("TMPDIR", oldTmp)
    putEnv("TMPDIR", scratch)
    putEnv("CT_SANDBOX_TOOLS_DIR", customSandbox)
    putEnv("REPRO_MONITOR_SHIM_LIB", shim)

    let monitored = runMonitored(
      monitoredSelfRequest(scratch, work / "custom.rdep"))
    check monitored.exitCode == 0
    check dirExists(customSandbox)
    check fileExists(sentinel)
    check readFile(sentinel) == "operator-owned\n"
    check getEnv("CT_SANDBOX_TOOLS_DIR") == customSandbox
    check sandboxDirsUnder(scratch).len == 0
    check fragmentDirsUnder(scratch).len == 0

  test "concurrent host processes leave no unique fallback residue":
    let work = createTempDir("io-mon-sandbox-cleanup-concurrent-", "")
    defer: removeDir(work)
    let scratch = work / "scratch"
    createDir(scratch)
    let shim = ensureShim()

    const WorkerCount = 8
    var workers: seq[Process]
    for i in 0 ..< WorkerCount:
      workers.add(startProcess(getAppFilename(),
        args = @[MonitorWorkerArg, scratch, shim, $i],
        options = {poParentStreams}))
    for worker in workers.mitems:
      check worker.waitForExit() == 0
      worker.close()

    for i in 0 ..< WorkerCount:
      check fileExists(scratch / ("concurrent-" & $i & ".rdep"))
    check sandboxDirsUnder(scratch).len == 0
    check fragmentDirsUnder(scratch).len == 0
