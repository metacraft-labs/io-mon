## test_io_mon_windows_tree_lifetime_guard — the Windows Job Object guard.
##
## THE CLAIM (reprobuild-pm spec/io-mon-Windows-Tree-Lifetime-Guard.md): a
## Windows capture is `mcComplete` only when the monitored root was assigned,
## while still suspended, to a job that refuses breakaway, AND that job's
## active-process count reached zero after the root exited, within the grace
## window. Every other outcome publishes its own specific `mrEventLoss`.
##
## NO MOCKS. Every process here is real, and every one of them is THIS
## executable re-entered in a fixture mode (`fixtureMain` below), built by the
## same compiler as the test and injected with the real shim from `build/lib`.
## The job, its census and the breakaway refusal are the kernel's, not a model
## of them. The one failure-mode case that is provoked rather than observed
## (F4) is provoked honestly, by nesting a host process 101 jobs deep, which is
## the real limit of the real kernel (measured on Windows 11 26200). F1, F2,
## F3 and F7 have no honest trigger and live in the separately compiled
## `test_io_mon_windows_tree_lifetime_guard_faults.nim`.
##
## Cases, numbered as in the spec's §6:
##   1. a quiesced control (the child exits before the root) is complete, with
##      no loss and with every record present;
##   2. a detached descendant held past the window is incomplete, and the loss
##      names its pid and image;
##   3. a descendant that exits inside the window (the root never waits for
##      it) is complete;
##   4. CREATE_BREAKAWAY_FROM_JOB is refused (error 5) and the capture stays
##      sound;
##   5. F4: a root whose inherited job hierarchy cannot nest further fails
##      closed with its own diagnostic, and the command still runs;
##   6. the batch and decomposed launch paths produce identical evidence, for
##      the control and for the detached case;
##   7. a monitored process that runs its own monitor still gets a complete
##      inner capture, inside the outer job.
##
## Every helper that ASSERTS is a template (a `check` inside a proc does not
## fail the enclosing test); helpers that only DO something raise.

when not defined(windows):
  {.error: "windows-only test".}

import std/[algorithm, os, osproc, sequtils, strutils, tables, tempfiles,
  unittest]

import io_mon

type
  HANDLE = pointer
  DWORD = uint32
  BOOL = int32

  StartupInfoW {.bycopy.} = object
    cb: DWORD
    lpReserved, lpDesktop, lpTitle: pointer
    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars: DWORD
    dwFillAttribute, dwFlags: DWORD
    wShowWindow, cbReserved2: uint16
    lpReserved2: pointer
    hStdInput, hStdOutput, hStdError: HANDLE

  ProcessInformation {.bycopy.} = object
    hProcess, hThread: HANDLE
    dwProcessId, dwThreadId: DWORD

const
  CREATE_BREAKAWAY_FROM_JOB = 0x01000000'u32
  PROCESS_TERMINATE = 0x0001'u32
  PROCESS_QUERY_LIMITED_INFORMATION = 0x1000'u32
  SYNCHRONIZE = 0x00100000'u32
  STILL_ACTIVE = 259'u32

  ## Fixture modes. The test re-enters this executable with one of these.
  QuiescedRootArg = "--guard-quiesced-root"
  DetachedRootArg = "--guard-detached-root"
  BriefRootArg = "--guard-brief-root"
  BreakawayRootArg = "--guard-breakaway-root"
  WriterChildArg = "--guard-writer-child"
  SleeperChildArg = "--guard-sleeper-child"
  BriefChildArg = "--guard-brief-child"
  DeepJobHostArg = "--guard-deep-job-host"
  NestedMonitorRootArg = "--guard-nested-monitor-root"

  ## The grace window set for the cases that hold a descendant alive. Short,
  ## because the sleeper is held by a sentinel and not by timing.
  ShortGraceMs = 300
  ## The window for the brief-descendant case: far longer than its child
  ## lives, so the case is decided by the census and not by a race.
  LongGraceMs = 5000
  BriefChildLifeMs = 400
  ## How long a held sleeper waits for its release sentinel before giving up.
  SleeperMaxMs = 60_000

proc CreateProcessW(app: pointer; cmd: ptr uint16; pa, ta: pointer;
    inherit: BOOL; flags: DWORD; env, cwd: pointer; si: ptr StartupInfoW;
    pi: ptr ProcessInformation): BOOL {.importc, stdcall, dynlib: "kernel32".}
proc CloseHandle(h: HANDLE): BOOL {.importc, stdcall, dynlib: "kernel32".}
proc GetLastError(): DWORD {.importc, stdcall, dynlib: "kernel32".}
proc OpenProcess(access: DWORD; inherit: BOOL; pid: DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc TerminateProcess(h: HANDLE; code: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeProcess(h: HANDLE; code: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc WaitForSingleObject(h: HANDLE; ms: DWORD): DWORD
  {.importc, stdcall, dynlib: "kernel32".}
proc CreateJobObjectW(attrs: pointer; name: pointer): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc AssignProcessToJobObject(job, process: HANDLE): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc IsProcessInJob(process, job: HANDLE; result: ptr BOOL): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc GetCurrentProcess(): HANDLE {.importc, stdcall, dynlib: "kernel32".}
proc CreateEventW(attrs: pointer; manualReset, initialState: BOOL;
    name: ptr uint16): HANDLE {.importc, stdcall, dynlib: "kernel32".}
proc SetEvent(h: HANDLE): BOOL {.importc, stdcall, dynlib: "kernel32".}

proc utf16z(s: string): seq[uint16] =
  ## ASCII-only command lines are all this fixture builds.
  for c in s: result.add uint16(ord(c))
  result.add 0'u16

proc spawnRaw(argv: openArray[string]; flags: DWORD): tuple[pi: ProcessInformation; err: DWORD] =
  ## A bare CreateProcessW, so the fixture can pass creation flags osproc does
  ## not expose. Goes through the shim's hook like any other spawn.
  var cmd = utf16z(argv.mapIt(quoteShell(it)).join(" "))
  var si: StartupInfoW
  si.cb = DWORD(sizeof(si))
  if CreateProcessW(nil, addr cmd[0], nil, nil, 0, flags, nil, nil, addr si,
      addr result.pi) == 0:
    result.err = GetLastError()

proc processAlive(pid: int): bool =
  let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, DWORD(pid))
  if h == nil: return false
  defer: discard CloseHandle(h)
  var code: DWORD
  GetExitCodeProcess(h, addr code) != 0 and code == STILL_ACTIVE

proc dirEvent(dir, purpose: string): HANDLE =
  ## A manual-reset named event tied to `dir`, created or opened. The held
  ## sleeper synchronises through events rather than by polling for files:
  ## polling would emit a timing-dependent number of probe records from a
  ## process that is still alive, which no two launch paths could agree on.
  var name = "Local\\io-mon-guard-" & purpose & "-"
  for c in dir:
    name.add(if c in {'a'..'z', 'A'..'Z', '0'..'9'}: c else: '_')
  var nameW = utf16z(name)
  result = CreateEventW(nil, 1, 0, addr nameW[0])
  if result == nil:
    raise newException(OSError, "CreateEventW(" & name & ") failed err=" &
      $GetLastError())

proc releaseAndReap(dir: string; pid: int) =
  ## Release a held sleeper, wait for it to leave, and terminate it as a last
  ## resort, so no case can leak a process into the next one or the host.
  let release = dirEvent(dir, "release")
  discard SetEvent(release)
  discard CloseHandle(release)
  let h = OpenProcess(SYNCHRONIZE or PROCESS_TERMINATE, 0, DWORD(pid))
  if h == nil: return
  defer: discard CloseHandle(h)
  if WaitForSingleObject(h, 10_000) != 0:
    discard TerminateProcess(h, 99)
    discard WaitForSingleObject(h, 5_000)

# ---------------------------------------------------------------------------
# Fixture modes.
# ---------------------------------------------------------------------------

proc fixtureMain() =
  if paramCount() < 2: return
  let mode = paramStr(1)
  let dir = paramStr(2)
  let self = getAppFilename()
  case mode
  of WriterChildArg:
    writeFile(dir / paramStr(3), "written by " & $getCurrentProcessId())
    quit(0)
  of SleeperChildArg:
    # Announce our pid, then stay alive, BLOCKED, until the harness releases
    # us: a kernel wait emits no records, so the evidence this process
    # contributes does not depend on how long it is held.
    let release = dirEvent(dir, "release")
    let ready = dirEvent(dir, "ready")
    writeFile(dir / "sleeper.pid", $getCurrentProcessId())
    discard SetEvent(ready)
    discard WaitForSingleObject(release, DWORD(SleeperMaxMs))
    quit(0)
  of BriefChildArg:
    sleep(BriefChildLifeMs)
    writeFile(dir / "brief-done", $getCurrentProcessId())
    quit(0)
  of QuiescedRootArg:
    # The child writes and EXITS before the root does: the tree is empty at
    # root exit, so the census reads zero on its first query.
    let child = startProcess(self, args = @[WriterChildArg, dir, "child.txt"],
      options = {poParentStreams})
    let code = waitForExit(child)
    close(child)
    writeFile(dir / "root.txt", "root")
    quit(code)
  of DetachedRootArg:
    # The child outlives the root; it is held by an event the harness sets
    # only after the evidence is collected, so it is alive across EVERY grace
    # window any launch path can open.
    let ready = dirEvent(dir, "ready")
    let child = startProcess(self, args = @[SleeperChildArg, dir],
      options = {poParentStreams})
    close(child)   # closes our handles only; the child keeps running
    if WaitForSingleObject(ready, 10_000) != 0:
      quit(41)
    quit(0)
  of BriefRootArg:
    let child = startProcess(self, args = @[BriefChildArg, dir],
      options = {poParentStreams})
    close(child)
    quit(0)
  of BreakawayRootArg:
    # Ask for a breakaway child first, record what the kernel answered, then
    # do what Cygwin does when breakaway is refused: spawn without the flag.
    let (escaped, err) = spawnRaw([self, WriterChildArg, dir, "escaped.txt"],
      CREATE_BREAKAWAY_FROM_JOB)
    writeFile(dir / "breakaway.err", $err)
    if err == 0:
      discard WaitForSingleObject(escaped.hProcess, 10_000)
      discard CloseHandle(escaped.hThread)
      discard CloseHandle(escaped.hProcess)
    let child = startProcess(self, args = @[WriterChildArg, dir, "child.txt"],
      options = {poParentStreams})
    let code = waitForExit(child)
    close(child)
    quit(code)
  of DeepJobHostArg:
    # Exhaust the job nesting depth of THIS process (the host), so the root it
    # monitors inherits a job chain that cannot take one more level. No seam:
    # this is the kernel's own limit.
    var depth = 0
    while true:
      let job = CreateJobObjectW(nil, nil)
      if job == nil: quit(50)
      if AssignProcessToJobObject(job, GetCurrentProcess()) == 0:
        discard CloseHandle(job)
        break
      inc depth   # the job stays referenced by this process; never closed
    writeFile(dir / "depth.txt", $depth)
    let res = runMonitored(FsSnoopRequest(
      command: @[self, WriterChildArg, dir, "deep.txt"],
      depFilePath: dir / "deep.iomon"))
    var lines = @["exit=" & $res.exitCode, "grade=" & $res.completeness]
    for r in res.records:
      if r.kind == mrEventLoss: lines.add "loss=" & r.detail
    writeFile(dir / "deep-result.txt", lines.join("\n"))
    quit(0)
  of NestedMonitorRootArg:
    # A monitored process that runs a monitor of its own. Its root inherits
    # the OUTER job from this process, so the inner job has to nest.
    var inJob: BOOL = 0
    discard IsProcessInJob(GetCurrentProcess(), nil, addr inJob)
    let inner = dir / "inner"
    createDir(inner)
    let res = runMonitored(FsSnoopRequest(
      command: @[self, QuiescedRootArg, inner],
      depFilePath: dir / "inner.iomon"))
    var lines = @["host-in-job=" & $inJob, "exit=" & $res.exitCode,
      "grade=" & $res.completeness]
    for r in res.records:
      if r.kind == mrEventLoss: lines.add "loss=" & r.detail
    writeFile(dir / "inner-result.txt", lines.join("\n"))
    quit(res.exitCode)
  else:
    discard

fixtureMain()

# ---------------------------------------------------------------------------
# Harness.
# ---------------------------------------------------------------------------

proc newWork(tag: string): string =
  createTempDir("io-mon-tree-guard-" & tag & "-", "")

proc request(dir: string; args: varargs[string]): FsSnoopRequest =
  FsSnoopRequest(command: @[getAppFilename()] & @args,
    depFilePath: dir / "evidence.iomon", captureChildStdio: true,
    captureStdioPath: dir / "stdio.log")

proc losses(dep: MonitorDepFile): seq[string] =
  for r in dep.records:
    if r.kind == mrEventLoss: result.add r.detail

proc runDecomposed(req: FsSnoopRequest; hostDelayMs = 0): MonitorResult =
  var h = startMonitor(req)
  while not pollMonitor(h):
    sleep(5)
  if hostDelayMs > 0: sleep(hostDelayMs)
  finishMonitor(move(h))

template withGrace(ms: int; body: untyped) =
  ## The window is a HOST-side knob, read at settle time in this process.
  let old = getEnv("IO_MON_WINDOWS_DESCENDANT_GRACE_MS")
  putEnv("IO_MON_WINDOWS_DESCENDANT_GRACE_MS", $ms)
  try: body
  finally:
    if old.len == 0: delEnv("IO_MON_WINDOWS_DESCENDANT_GRACE_MS")
    else: putEnv("IO_MON_WINDOWS_DESCENDANT_GRACE_MS", old)

const DetachedPrefix = "windows job descendants still live after root exit "
const GuardPrefix = "windows tree-lifetime guard"

proc detachedLoss(dep: MonitorDepFile): string =
  for d in dep.losses:
    if d.startsWith(DetachedPrefix): return d

# --- DH-4 rendering ----------------------------------------------------------
#
# The Linux DH-4 test names pids by first appearance in the canonical record
# order. That cannot work here: the canonical order sorts by osPid, threadId
# and then `seq`, Windows does not hand out pids (or thread ids) in increasing
# order, so the ORDER of the same records differs between two runs, and with it
# any first-appearance token and the `seq` the merge renumbers in that order.
#
# So processes are named by their ROLE instead, which is what a pid stands for
# in this comparison: `HOST` (this process, which writes the launcher's loss
# records), `ROOT` (named by the launcher's `launcher-expected-root` record),
# and `<parent role>><command line>` for a child, read off its parent's spawn
# record. A pid that no spawn record reaches is refused rather than guessed.
# Threads are named within their process by the content they recorded, which
# is order-free. `seq` (the canonical index) is the one field excluded, and the
# rendered lines are compared as a sorted multiset. Every other field is
# compared verbatim, real paths included (both runs use the same directory).
# That includes a spawn record's `result`, which on Windows is the
# `CreateProcessW` BOOL and not, as on Linux, the child's pid.

proc pidRoles(dep: MonitorDepFile): Table[uint64, string] =
  result[uint64(getCurrentProcessId())] = "HOST"
  for r in dep.records:
    if r.kind == mrProcessSpawn and r.osPid == 0 and
        "launcher-expected-root" in r.detail:
      result[r.childOsPid] = "ROOT"
  var grew = true
  while grew:
    grew = false
    for r in dep.records:
      if r.kind == mrProcessSpawn and r.osPid in result and
          r.childOsPid != 0 and r.childOsPid notin result:
        result[r.childOsPid] = result[r.osPid] & ">" & r.path
        grew = true

proc roleOf(roles: Table[uint64, string]; pid: uint64): string =
  if pid == 0: return "0"   # 0 means "no pid"; never conflate it with one
  if pid notin roles:
    raise newException(ValueError, "pid " & $pid & " is reached by no spawn " &
      "record; refusing to guess its role")
  roles[pid]

proc renderRecord(r: MonitorRecord; roles: Table[uint64, string];
    thread: string): string =
  var fields: seq[string]
  for name, value in fieldPairs(r):
    when name == "seq":
      discard   # the canonical index; see above
    elif name == "threadId":
      fields.add name & "=" & thread
    elif name in ["osPid", "parentOsPid", "childOsPid"]:
      fields.add name & "=" & roles.roleOf(uint64(value))
    elif name == "detail":
      var parts: seq[string]
      for tok in value.split(' '):
        if tok.startsWith("run="): parts.add "run=<RUN>"
        elif tok.startsWith("pids=") and tok != "pids=unavailable" and
            tok != "pids=none-listed":
          parts.add "pids=" & tok[5 .. ^1].split(',').mapIt(
            roles.roleOf(uint64(parseBiggestUInt(it)))).join(",")
        else: parts.add tok
      fields.add name & "=" & parts.join(" ")
    else:
      fields.add name & "=" & $value
  fields.join(" | ")

proc render(dep: MonitorDepFile): string =
  let roles = pidRoles(dep)
  # Thread names: within each process, threads ordered by the sorted content
  # of their own records, rendered with the thread masked.
  var byThread: Table[(uint64, uint64), seq[string]]
  for r in dep.records:
    byThread.mgetOrPut((r.osPid, r.threadId), @[]).add renderRecord(r, roles, "?")
  var signatures: Table[uint64, seq[(string, uint64)]]
  for key, lines in byThread:
    signatures.mgetOrPut(key[0], @[]).add (lines.sorted.join("\n"), key[1])
  var threadName: Table[(uint64, uint64), string]
  for pid, sigs in signatures.mpairs:
    sigs.sort()
    for i, (_, tid) in sigs:
      threadName[(pid, tid)] = if tid == 0: "0" else: "T" & $i
  var lines: seq[string]
  for r in dep.records:
    lines.add renderRecord(r, roles, threadName[(r.osPid, r.threadId)])
  lines.sort()
  lines.add "completeness=" & $dep.completeness
  lines.add "summary=" & $dep.summary
  lines.add "capabilityGaps=" & $dep.capabilityGaps
  lines.join("\n")

suite "Windows tree-lifetime guard (Job Object)":
  test "1. a quiesced tree is complete, with no loss and every record":
    let dir = newWork("quiesced")
    defer: removeDir(dir)
    let res = runMonitored(request(dir, QuiescedRootArg, dir))
    check res.exitCode == 0
    check res.completeness == mcComplete
    check res.depFile.losses.len == 0
    # Every record the tree should have produced: both processes started, the
    # root spawned the child, and each wrote its file.
    var starts, spawns: seq[uint64]
    var writes: seq[string]
    for r in res.records:
      case r.kind
      of mrProcessStart: starts.add r.osPid
      of mrProcessSpawn:
        # osPid 0 is the launcher's own `launcher-expected-root` record.
        if r.osPid != 0: spawns.add r.childOsPid
      of mrFileWrite: writes.add extractFilename(r.path)
      else: discard
    check starts.len == 2                     # the root and its child
    check spawns.len == 1 and spawns[0] in starts
    check "child.txt" in writes
    check "root.txt" in writes

  test "2. a detached descendant past the window is incomplete and named":
    let dir = newWork("detached")
    var sleeperPid = 0
    defer:
      if sleeperPid != 0: releaseAndReap(dir, sleeperPid)
      removeDir(dir)
    var res: MonitorResult
    withGrace(ShortGraceMs):
      res = runMonitored(request(dir, DetachedRootArg, dir))
    require fileExists(dir / "sleeper.pid")
    sleeperPid = parseInt(readFile(dir / "sleeper.pid"))
    check res.exitCode == 0
    check res.completeness == mcIncomplete
    let loss = res.depFile.detachedLoss
    checkpoint "losses: " & $res.depFile.losses
    check loss.len > 0
    # The loss NAMES the survivor: its pid, and its image, in the same order.
    check ("pids=" & $sleeperPid) in loss
    check ("images=" & extractFilename(getAppFilename())) in loss
    check "active=1 " in loss
    # The guard reports; it does not kill (WG-8).
    check processAlive(sleeperPid)
    # Exactly one guard loss. The only other loss allowed is the survivor's
    # own still-open fragment batch, which is a second, true consequence of
    # the same live process (it has not exited, so it has not flushed).
    check res.depFile.losses.filterIt(it.startsWith(DetachedPrefix)).len == 1
    for other in res.depFile.losses:
      if not other.startsWith(DetachedPrefix):
        check other.startsWith("process killed with an un-flushed read batch")

  test "3. a descendant that exits inside the window is complete":
    let dir = newWork("brief")
    defer: removeDir(dir)
    var res: MonitorResult
    withGrace(LongGraceMs):
      res = runMonitored(request(dir, BriefRootArg, dir))
    check res.exitCode == 0
    # The child finished its work although the root never waited for it.
    check fileExists(dir / "brief-done")
    # The grade is what discriminates. With the census skipped (mutation (c)
    # in the review notes) this run is incomplete: the merge then reads a
    # still-running child's unflushed batch. That the marker file exists is NOT
    # evidence of the wait on its own, because releasing the fragment
    # directory also waits for the child to close its fragment file.
    check res.completeness == mcComplete
    check res.depFile.losses.len == 0

  test "4. CREATE_BREAKAWAY_FROM_JOB is refused and the capture stays sound":
    let dir = newWork("breakaway")
    defer: removeDir(dir)
    let res = runMonitored(request(dir, BreakawayRootArg, dir))
    check res.exitCode == 0
    require fileExists(dir / "breakaway.err")
    check readFile(dir / "breakaway.err") == "5"   # ERROR_ACCESS_DENIED
    check not fileExists(dir / "escaped.txt")       # the escapee never ran
    check fileExists(dir / "child.txt")             # the in-job retry did
    check res.completeness == mcComplete
    check res.depFile.losses.len == 0

  test "5. F4: an inherited job that cannot nest fails closed, named":
    let dir = newWork("deep")
    defer: removeDir(dir)
    let host = startProcess(getAppFilename(), args = @[DeepJobHostArg, dir],
      options = {poParentStreams})
    let hostExit = waitForExit(host)
    close(host)
    check hostExit == 0
    require fileExists(dir / "deep-result.txt")
    let report = readFile(dir / "deep-result.txt").splitLines()
    checkpoint "depth " & readFile(dir / "depth.txt") & ": " & $report
    check "exit=0" in report                  # the command still ran
    check fileExists(dir / "deep.txt")
    check "grade=mcIncomplete" in report
    let guardLosses = report.filterIt(it.startsWith("loss=" & GuardPrefix))
    check guardLosses.len == 1
    if guardLosses.len == 1:
      check guardLosses[0].startsWith("loss=windows tree-lifetime guard " &
        "unavailable: the root already belongs to a job that refused " &
        "nesting (AssignProcessToJobObject err=50) run=")

  test "6. batch and decomposed launch paths give identical evidence":
    # The control, then the detached case with the polled host dawdling three
    # windows between root exit and finish: the sleeper is held across every
    # window either path can open, so agreement is deterministic.
    var detachedEvidence: MonitorDepFile
    for (mode, held) in [(QuiescedRootArg, false), (DetachedRootArg, true)]:
      var renders: seq[string]
      for decomposed in [false, true]:
        # The SAME directory for both runs, so real paths match exactly.
        let dir = getTempDir() / "io-mon-tree-guard-dh4"
        removeDir(dir)
        createDir(dir)
        var sleeperPid = 0
        try:
          var res: MonitorResult
          withGrace(ShortGraceMs):
            res =
              if decomposed: runDecomposed(request(dir, mode, dir),
                hostDelayMs = 3 * ShortGraceMs)
              else: runMonitored(request(dir, mode, dir))
          if held:
            sleeperPid = parseInt(readFile(dir / "sleeper.pid"))
            check res.completeness == mcIncomplete
            check res.depFile.detachedLoss.len > 0
            detachedEvidence = res.depFile
          else:
            check res.completeness == mcComplete
          renders.add render(res.depFile)
        finally:
          if sleeperPid != 0: releaseAndReap(dir, sleeperPid)
          removeDir(dir)
      check renders.len == 2
      if renders.len == 2 and renders[0] != renders[1]:
        let a = renders[0].splitLines()
        let b = renders[1].splitLines()
        checkpoint mode & ": batch-only " & $a.filterIt(it notin b) &
          " decomposed-only " & $b.filterIt(it notin a)
      check renders[0] == renders[1]

    # THE COMPARISON CANNOT PASS VACUOUSLY. Each perturbation a regression
    # could produce must change the rendering of the REAL detached evidence;
    # the role naming, the thread naming and the dropped `seq` must not erase
    # any of them.
    let base = detachedEvidence
    require base.records.len > 2
    let baseRender = render(base)
    var lossAt = -1
    var rootSpawnAt = -1
    for i, r in base.records:
      if r.kind == mrEventLoss and r.detail.startsWith(DetachedPrefix):
        lossAt = i
      if r.kind == mrProcessSpawn and r.osPid != 0:
        rootSpawnAt = i
    require lossAt >= 0 and rootSpawnAt >= 0
    var perturbed: seq[(string, MonitorDepFile)]
    block:
      var d = base
      d.records.delete(0)
      perturbed.add ("a dropped record", d)
    block:
      var d = base
      d.records.add d.records[^1]
      perturbed.add ("a duplicated record", d)
    block:
      var d = base
      d.completeness = mcComplete
      perturbed.add ("a flipped verdict", d)
    block:
      var d = base
      d.records.delete(lossAt)
      perturbed.add ("a deleted guard loss", d)
    block:
      var d = base
      d.records[lossAt].detail = d.records[lossAt].detail.replace(
        "images=", "images=x")
      perturbed.add ("a changed image name", d)
    block:
      # The survivor named as the ROOT instead of as the root's child.
      var d = base
      let root = d.records[rootSpawnAt].osPid
      let child = d.records[rootSpawnAt].childOsPid
      d.records[lossAt].detail = d.records[lossAt].detail.replace(
        "pids=" & $child, "pids=" & $root)
      perturbed.add ("a re-attributed survivor", d)
    block:
      var d = base
      for r in d.records.mitems:
        if r.path.len > 0:
          r.path.add "x"
          break
      perturbed.add ("a one-character path change", d)
    for (what, d) in perturbed:
      checkpoint what
      # A rendering that REFUSES (a pid no spawn record reaches) is a detected
      # difference too, so it counts as changed.
      let changed =
        try: render(d) != baseRender
        except ValueError: true
      check changed

  test "7. a nested monitor nests its job inside the outer one":
    let dir = newWork("nested")
    defer: removeDir(dir)
    let res = runMonitored(request(dir, NestedMonitorRootArg, dir))
    require fileExists(dir / "inner-result.txt")
    let inner = readFile(dir / "inner-result.txt").splitLines()
    checkpoint "inner: " & $inner & " outer losses: " & $res.depFile.losses
    check "host-in-job=1" in inner          # the inner host IS in the outer job
    check "exit=0" in inner
    check "grade=mcComplete" in inner       # so the inner job really nested
    check inner.filterIt(it.startsWith("loss=")).len == 0
    check fileExists(dir / "inner" / "child.txt")
    check res.exitCode == 0
    # The outer guard waited for the whole tree, the inner host's included.
    check res.depFile.losses.filterIt(it.startsWith(GuardPrefix) or
      it.startsWith(DetachedPrefix)).len == 0
