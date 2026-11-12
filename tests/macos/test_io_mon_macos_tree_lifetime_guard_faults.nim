## test_io_mon_macos_tree_lifetime_guard_faults — the macOS tree-lifetime
## guard's census failure, which has no honest trigger on a healthy host.
##
## docs/usage.md, "The macOS tree-lifetime guard (normative)", requires a failed
## census to FAIL CLOSED with its own diagnostic: never silently complete, and
## never the retired blanket marker. A healthy macOS host does not fail
## `sysctl(KERN_PROC_ALL)` for an unprivileged caller, so there is no outside
## lever. This file is compiled with `-d:ioMonMacosTreeGuardFaultTest` (the
## sibling `.nims` sets it, for this binary only), which compiles a seam into
## `io_mon/macos_tree_guard` that reads `IO_MON_TEST_MACOS_TREE_GUARD_FAULT`.
## The seam does not fabricate a result: it hands the REAL sysctl a real bad
## selector, so the diagnostic carries the errno macOS actually returned. It
## can only make the guard fail, never succeed.
##
## The case runs a real monitored root that writes a real file and asserts:
## the command ran (exit 0, file present), the capture is `mcIncomplete`, and
## the ONLY loss is the census-failure diagnostic. A control with the seam
## disarmed is complete, so the seam itself is not what grades it.
##
## The `vanish` seam (IO_MON_TEST_MACOS_TREE_GUARD_VANISH_PID) pins the two
## sweep rules that real timing exercises only by chance. Between the first
## sweep's snapshot and its strings reads it releases a REAL process, which
## forks and exits, and it records how the census classified that process:
##  * a member that vanishes leaving a child the snapshot does not list must
##    not be trusted (verdict `vanished`; the next sweep finds the child, and
##    the capture names it as still live);
##  * an unrelated process that vanishes is classified through its snapshot
##    parent (verdict `nonmember`; the capture stays complete).
##
## The `slow` seam (IO_MON_TEST_MACOS_TREE_GUARD_SLOW_COMM / _SLOW_MS) has
## the census refuse the strings of every process with a given name for a
## while after it starts, which is what a starved host does to young
## processes (a process still between fork and exec, or not yet scheduled, is
## alive, same-user and unreadable). With it, the load case is deterministic:
##  * a churn of unrelated orphans that stay unclassifiable past the grace
##    window no longer makes a quiesced capture incomplete: the window
##    stretches while that set keeps changing, and the capture completes once
##    the churn stops;
##  * a surviving descendant that is unclassifiable the same way is still
##    caught, at the plain grace window, by the tree ledger;
##  * a set that stops changing ends the stretch long before the ceiling,
##    and the loss names the time spent.
## The `exiting` seam (IO_MON_TEST_MACOS_TREE_GUARD_EXITING_PID) has the
## census classify a non-member as exiting, the state of a parent caught in
## exit, which real timing hits only by chance. An unclassifiable child of an
## exiting parent is then classified through the parent's own parent, but
## never through the monitor's process, which is where the needles start.
## The `nocreator` seam (IO_MON_TEST_MACOS_TREE_GUARD_NO_CREATOR_RULE=1)
## switches off the creator-id rule, as the control for the cases only that
## rule classifies: an orphan of a creator older than the root is classified,
## while an orphan of a younger, gone creator, and a launchd job, are not.
##
## The `wallstep` seam (IO_MON_TEST_MACOS_TREE_GUARD_FAULT=wallstep) makes the
## census read every process's wall-clock start time an hour earlier, which is
## what a wall clock stepped backwards after the root started does to every
## process created after the step. The start-time prune must not trust it: a
## live member must still be found BY THE CENSUS (not only by the tree
## ledger, which would hide a broken prune).

when not defined(macosx):
  {.error: "macos-only test".}
when not defined(ioMonMacosTreeGuardFaultTest):
  {.error: "compile with -d:ioMonMacosTreeGuardFaultTest (the sibling .nims)".}

import std/[monotimes, os, osproc, posix, sequtils, strutils, tempfiles, times, unittest]
import io_mon
import io_mon/macos_tree_guard

const
  WriterArg = "--guard-fault-writer"
  VanishRootArg = "--guard-vanish-root"
  VanishMemberArg = "--guard-vanish-member"
  ChurnArg = "--guard-churn"
  SleepArg = "--guard-sleep"
  ForkSlowArg = "--guard-fork-slow"
  SlowRootArg = "--guard-slow-root"
  CreatorArg = "--guard-creator"
  HoldArg = "--guard-hold"
  NoCreatorVar = "IO_MON_TEST_MACOS_TREE_GUARD_NO_CREATOR_RULE"
  CeilingVar = "IO_MON_MACOS_DESCENDANT_GRACE_CEILING_MS"
  LineageArg = "--guard-lineage"
  SlowCommVar = "IO_MON_TEST_MACOS_TREE_GUARD_SLOW_COMM"
  SlowMsVar = "IO_MON_TEST_MACOS_TREE_GUARD_SLOW_MS"
  ExitingVar = "IO_MON_TEST_MACOS_TREE_GUARD_EXITING_PID"
  Unclassified = "macos tree-lifetime guard could not classify young processes"
  RecordedLive = "macos recorded descendants still live after root exit"
  SlowName = "tgslow"
  FaultVar = "IO_MON_TEST_MACOS_TREE_GUARD_FAULT"
  VanishVar = "IO_MON_TEST_MACOS_TREE_GUARD_VANISH_PID"
  StillLive = "macos descendants still live after root exit"
  # OS-shipped tools are named by absolute path, as the sibling guard test
  # does for /bin/ps: under `repro test` the action's PATH holds only the
  # tools repro.nim declares, so a bare `launchctl` is not found there (the
  # shell exits 127), and neither tool is anything but the OS's own.
  LaunchctlExe = "/bin/launchctl"
  PsExe = "/bin/ps"
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc readPidFile(path: string): Pid =
  for _ in 0 ..< 1000:
    if fileExists(path):
      let text = readFile(path)
      if text.endsWith("\n"): return Pid(parseInt(text.strip()))
    sleep(5)
  Pid(0)

if paramCount() == 2 and paramStr(1) == WriterArg:
  writeFile(paramStr(2), "written")
  quit(0)

if paramCount() == 3 and paramStr(1) == VanishRootArg:
  # The monitored root: spawn the member and exit once it is ready.
  discard startProcess(getAppFilename(),
    args = @[VanishMemberArg, paramStr(2), paramStr(3)],
    options = {poParentStreams})
  quit(if readPidFile(paramStr(2)) == Pid(0): 1 else: 0)

if paramCount() == 3 and paramStr(1) == VanishMemberArg:
  # A member that outlives the root. On SIGUSR1 (sent by the `vanish` seam
  # right after the census snapshot) it forks a child that holds, then exits:
  # the snapshot lists the member, which has vanished by its read, and not
  # the child, which carries the run's needles and outlives everything.
  var usr1: Sigset
  discard sigemptyset(usr1)
  discard sigaddset(usr1, SIGUSR1)
  var oldMask: Sigset
  discard sigprocmask(SIG_BLOCK, usr1, oldMask)
  writeFile(paramStr(2), $getpid() & "\n")
  var sig: cint
  discard sigwait(usr1, sig)
  let child = fork()
  if child == 0:
    writeFile(paramStr(3), $getpid() & "\n")
    while true: discard sigwait(usr1, sig)
  exitnow(0)

if paramCount() == 2 and paramStr(1) == SleepArg:
  sleep(parseInt(paramStr(2)))
  quit(0)

if paramCount() == 5 and paramStr(1) == ChurnArg:
  # Run as a copy named `tgslow`. Every <interval> ms, create an ORPHAN: fork
  # a child that forks the orphan and exits at once, so the orphan's parent
  # is launchd and the census's parent rule cannot classify it. Fork keeps the
  # name, so every orphan is a `tgslow` too. Writes <ready> after the third
  # orphan, so orphans are alive when the caller goes on, and keeps creating
  # them for <duration> ms after that.
  #
  # The cases grade how the guard's window ends against this churn, so the
  # churn must hold its shape on a host of any speed, not only on an idle one:
  #  * <duration> is wall-clock time (a monotonic deadline). Counting it in
  #    intervals let a slow fork or an oversleep stretch a 2 s churn past the
  #    5 s ceiling (CI: the capture completed after 5059 ms).
  #  * An orphan lives at least <life> ms AND until the next orphan exists,
  #    so some orphan is alive at every instant until the churn stops. With a
  #    fixed life only, a churner descheduled for longer than <life> left an
  #    instant with no orphan; a sweep there was conclusive and empty, and a
  #    churn meant to outlast the ceiling graded the capture complete (CI).
  # Orphan k waits, after its <life>, for EOF on pipe k. The churner holds the
  # only write end of pipe k and closes it once orphan k+1 exists (its creator
  # forked it before exiting, and a fork lists the child before it returns);
  # a SIGKILLed churner closes it too, so no orphan outlives the churn by
  # more than <life>. Any failed fork or pipe ends the churner with an error
  # rather than leaving a gap.
  let duration = parseInt(paramStr(2))
  let life = parseInt(paramStr(3))
  let interval = parseInt(paramStr(4))
  var prevWrite: cint = -1
  var made = 0
  var deadline: MonoTime
  while made < 3 or getMonoTime() < deadline:
    var fds: array[2, cint]
    if pipe(fds) != 0: quit(2)
    let child = fork()
    if child < 0: quit(3)
    if child == 0:
      # The intermediate: the orphan keeps only the new pipe's read end, so
      # the churner's close is the last close of its write end.
      if prevWrite >= 0: discard close(prevWrite)
      discard close(fds[1])
      let orphan = fork()
      if orphan == 0:
        discard usleep(Useconds(life * 1000))
        var b: char
        while true:
          let n = read(fds[0], addr b, 1)
          if n == 0 or (n < 0 and errno != EINTR): break
        exitnow(0)
      exitnow(if orphan > 0: cint(0) else: cint(4))
    discard close(fds[0])
    var st: cint
    if waitpid(child, st, 0) != child or not WIFEXITED(st) or
        WEXITSTATUS(st) != 0:
      quit(4)
    # The new orphan exists, so the previous one may end.
    if prevWrite >= 0: discard close(prevWrite)
    prevWrite = fds[1]
    inc made
    if made == 3:
      writeFile(paramStr(5), $getpid() & "\n")
      deadline = getMonoTime() + initDuration(milliseconds = duration)
    sleep(interval)
  discard close(prevWrite)
  sleep(life + 50)
  quit(0)

proc forkSlowChild(slowBin, uPidFile: string; holdMs: int) =
  ## Fork a child that execs the `tgslow` copy to hold for `holdMs`, record
  ## its pid once it HAS exec'd (its close-on-exec end of a pipe closes;
  ## before that it still runs this binary under this name, and the census
  ## would read it as an ordinary non-member), then hold as long.
  var fds: array[2, cint]
  if pipe(fds) != 0: exitnow(2)
  let u = fork()
  if u == 0:
    discard close(fds[0])
    discard fcntl(fds[1], F_SETFD, FD_CLOEXEC)
    let args = allocCStringArray([slowBin, SleepArg, $holdMs])
    discard execv(cstring(slowBin), args)
    exitnow(3)
  discard close(fds[1])
  var b: char
  while read(fds[0], addr b, 1) > 0: discard
  writeFile(uPidFile, $u & "\n")
  sleep(holdMs)
  exitnow(0)

if paramCount() == 3 and paramStr(1) == HoldArg:
  # A launchd job: record this pid, then hold.
  writeFile(paramStr(2), $getpid() & "\n")
  sleep(parseInt(paramStr(3)))
  quit(0)

if paramCount() == 6 and paramStr(1) == CreatorArg:
  # <slow> <trigger> <uPidFile> <holdMs> <order>: wait until <trigger>
  # exists, then fork U, which runs the `tgslow` copy for <holdMs>, record
  # U's pid and exit, so U is an orphan whose creator is gone. When this
  # process was started before the monitored root, U's creator is older than
  # the root. <order> fixes when U execs, because an exec rewrites the
  # creator id the kernel keeps to the CURRENT parent:
  #  - "exec-first": this process waits for U's exec (U's close-on-exec end
  #    of a pipe closes) and only then exits, so U keeps this process's id;
  #  - "orphan-first": this process exits at once and U execs only once
  #    launchd has adopted it, so U reads launchd's id, 1, like a job
  #    launchd started itself.
  while not fileExists(paramStr(3)): sleep(5)
  var fds: array[2, cint]
  if pipe(fds) != 0: exitnow(2)
  let orphanFirst = paramStr(6) == "orphan-first"
  let u = fork()
  if u == 0:
    discard close(fds[0])
    discard fcntl(fds[1], F_SETFD, FD_CLOEXEC)
    if orphanFirst:
      while getppid() != 1: discard usleep(1000)
    let args = allocCStringArray([paramStr(2), SleepArg, paramStr(5)])
    discard execv(cstring(paramStr(2)), args)
    exitnow(3)
  discard close(fds[1])
  if not orphanFirst:
    var b: char
    while read(fds[0], addr b, 1) > 0: discard
  writeFile(paramStr(4), $u & "\n")
  exitnow(0)

if paramCount() == 3 and paramStr(1) == SlowRootArg:
  # The monitored root: spawn <memberBin> as a member that outlives it, and
  # exit once it is ready.
  discard startProcess(paramStr(2),
    args = @[VanishMemberArg, paramStr(3), paramStr(3) & ".child"],
    options = {poParentStreams})
  quit(if readPidFile(paramStr(3)) == Pid(0): 1 else: 0)

if paramCount() == 3 and paramStr(1) == ForkSlowArg:
  # P: the parent of an unclassifiable child U.
  forkSlowChild(paramStr(2), paramStr(3), 4000)

if paramCount() == 4 and paramStr(1) == LineageArg:
  # G: fork P (which writes its pid to <pPidFile>) and wait for it.
  let p = fork()
  if p == 0:
    writeFile(paramStr(3), $getpid() & "\n")
    forkSlowChild(paramStr(2), paramStr(4), 4000)
  var st: cint
  discard waitpid(p, st, 0)
  quit(0)

proc graceSpent(loss: string): int =
  ## The `grace-ms=` token of a guard loss, or -1.
  for token in loss.splitWhitespace():
    if token.startsWith("grace-ms="):
      return parseInt(token["grace-ms=".len .. ^1])
  -1

proc runWithFault(fault: string): tuple[res: MonitorResult; wrote: bool] =
  let dir = createTempDir("io-mon-tree-guard-fault-", "")
  defer: removeDir(dir)
  if fault.len > 0: putEnv(FaultVar, fault)
  try:
    result.res = runMonitored(FsSnoopRequest(
      command: @[getAppFilename(), WriterArg, dir / "out.txt"],
      depFilePath: dir / "evidence.iomon"))
  finally:
    delEnv(FaultVar)
  result.wrote = fileExists(dir / "out.txt")

proc losses(res: MonitorResult): seq[string] =
  for r in res.depFile.records:
    if r.kind == mrEventLoss: result.add r.detail

suite "macOS tree-lifetime guard: needle scan":
  # KERN_PROCARGS2 layout: int argc, exec path, NUL padding, argv strings,
  # environment strings, "apple" strings. An EMPTY argv[0] is a lone NUL that
  # a skip-the-padding parser eats as padding, after which skipping argc
  # strings swallows the first environment string. The scan reads every
  # string instead.
  const needle = "REPRO_MONITOR_SESSION=run-1"
  proc image(argv, env: openArray[string]): string =
    var argc = int32(argv.len)
    result = newString(4)
    copyMem(addr result[0], addr argc, 4)
    result.add "/path/to/exe\0\0\0\0"
    for a in argv: result.add a & "\0"
    for e in env: result.add e & "\0"
    result.add "executable_path=/path/to/exe\0"

  test "an empty argv[0] does not hide the first environment string":
    check testCarriesNeedle(image(["", "x"], [needle, "HOME=/h"]), needle)
    check testCarriesNeedle(image(["a", "x"], [needle, "HOME=/h"]), needle)
    check testCarriesNeedle(image([""], ["HOME=/h", needle]), needle)

  test "only a whole string matches":
    check not testCarriesNeedle(image(["a"], [needle & "0"]), needle)
    check not testCarriesNeedle(image(["a"], ["X" & needle]), needle)
    check not testCarriesNeedle(image(["a"], ["HOME=/h"]), needle)

suite "macOS tree-lifetime guard: census failure":
  putEnv(ShimLibOverrideEnv, repoRoot / "build/lib/librepro_monitor_shim.dylib")

  test "control: the disarmed seam leaves a quiesced capture complete":
    let (res, wrote) = runWithFault("")
    check res.exitCode == 0
    check wrote
    check res.completeness == mcComplete
    check losses(res).len == 0

  test "a failed census fails closed with its own diagnostic":
    let (res, wrote) = runWithFault("census")
    check res.exitCode == 0
    check wrote
    check res.completeness == mcIncomplete
    let l = losses(res)
    check l.len == 1
    if l.len == 1:
      check l[0].startsWith("macos tree-lifetime guard failed: " &
        "sysctl(KERN_PROC_ALL) census failed errno=")
      check "detached-descendant quiescence" notin l[0]

  test "a wall clock stepped backwards does not hide a live member":
    # The member outlives the root with its needles intact. Under the seam its
    # wall-clock start reads an hour before the root's; a prune that dated
    # processes by the wall clock would skip it and leave only the tree
    # ledger's report.
    let dir = createTempDir("io-mon-tree-guard-wallstep-", "")
    var member = Pid(0)
    try:
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), VanishRootArg, dir / "member.pid",
          dir / "child.pid"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      member = readPidFile(dir / "member.pid")
      require member != Pid(0)
      putEnv(FaultVar, "wallstep")
      let res = try: finishMonitor(move(h)) finally: delEnv(FaultVar)
      check posix.kill(member, 0) == 0
      check res.exitCode == 0
      check res.completeness == mcIncomplete
      let live = losses(res).filterIt(it.startsWith(StillLive))
      check live.len == 1
      if live.len == 1:
        check ("pids=" & $member) in live[0]
      if live.len != 1: echo losses(res)
    finally:
      if member != Pid(0): discard posix.kill(member, SIGKILL)
      removeDir(dir)

  test "a member that vanishes mid-sweep leaving a child is not trusted":
    # The `vanish` seam releases a REAL member between the first sweep's
    # snapshot and its strings read: the member forks a needle-carrying child
    # and exits. That sweep must not be conclusive (the member vanished, so it
    # may have forked after the snapshot, and it did), so the guard sweeps
    # again and finds the child. Trusting a vanished process as a non-member
    # would end the first sweep empty and grade this capture complete.
    let dir = createTempDir("io-mon-tree-guard-vanish-", "")
    var member, child = Pid(0)
    try:
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), VanishRootArg, dir / "member.pid",
          dir / "child.pid"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      member = readPidFile(dir / "member.pid")
      require member != Pid(0)
      putEnv(VanishVar, $member)
      let res = try: finishMonitor(move(h)) finally: delEnv(VanishVar)
      child = readPidFile(dir / "child.pid")
      # The first sweep met the member after it was gone and did NOT trust
      # it. (Checked directly: on a busy host an unrelated vanished process
      # can also make that sweep inconclusive, which the outcome alone
      # cannot tell apart.)
      check faultVanishVerdict() == "vanished"
      check child != Pid(0)
      check posix.kill(child, 0) == 0
      check posix.kill(member, 0) != 0
      check res.exitCode == 0
      check res.completeness == mcIncomplete
      let live = losses(res).filterIt(it.startsWith(StillLive))
      check live.len == 1
      if live.len == 1:
        check ("pids=" & $child) in live[0]
      if live.len != 1: echo losses(res)
    finally:
      for p in [child, member]:
        if p != Pid(0): discard posix.kill(p, SIGKILL)
      removeDir(dir)

  test "an unrelated process vanishing mid-sweep is classified through its parent":
    # The parent rule: a young process the census meets after it has gone is
    # trusted as a non-member when its snapshot parent (not launchd) is one.
    # Here the released process is an unrelated helper started by this test
    # process after the root, so it is young and its parent is the monitor
    # itself. Without the rule, every such process on a busy host would make
    # a sweep inconclusive.
    let dir = createTempDir("io-mon-tree-guard-vanish-other-", "")
    var helper, child = Pid(0)
    var helperProc: Process
    try:
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), WriterArg, dir / "out.txt"],
        depFilePath: dir / "evidence.iomon"))
      helperProc = startProcess(getAppFilename(),
        args = @[VanishMemberArg, dir / "helper.pid", dir / "child.pid"],
        options = {poParentStreams})
      helper = readPidFile(dir / "helper.pid")
      require helper != Pid(0)
      while not pollMonitor(h): sleep(2)
      putEnv(VanishVar, $helper)
      let res = try: finishMonitor(move(h)) finally: delEnv(VanishVar)
      child = readPidFile(dir / "child.pid")
      check faultVanishVerdict() == "nonmember"
      check res.exitCode == 0
      check res.completeness == mcComplete
      check losses(res).len == 0
    finally:
      for p in [child, helper]:
        if p != Pid(0): discard posix.kill(p, SIGKILL)
      if helperProc != nil:
        discard helperProc.waitForExit()
        helperProc.close()
      removeDir(dir)

suite "macOS tree-lifetime guard: a starved host":
  # Each case drives the decomposed API so the load starts only after the
  # root has exited, inside the guard's window, with the `slow` seam armed
  # for the `tgslow` copy of this binary.
  putEnv(ShimLibOverrideEnv, repoRoot / "build/lib/librepro_monitor_shim.dylib")

  proc slowCopy(dir: string): string =
    result = dir / SlowName
    copyFile(getAppFilename(), result)
    setFilePermissions(result, {fpUserRead, fpUserWrite, fpUserExec})

  proc armSlow(comm: string; ms: int) =
    putEnv(SlowCommVar, comm)
    putEnv(SlowMsVar, $ms)

  proc disarmSeams() =
    delEnv(SlowCommVar)
    delEnv(SlowMsVar)
    delEnv(ExitingVar)

  test "unclassifiable young processes that keep changing stretch the window, and the quiesced capture completes":
    # The issue's load case: orphans the census cannot read keep appearing
    # for 2 s, four times the grace window. Each is unclassified for its
    # whole life. With a fixed window the capture graded incomplete
    # ("could not classify young processes"); with the stretch it completes
    # once the churn stops, well before the ceiling.
    let dir = createTempDir("io-mon-tree-guard-churn-", "")
    var churner: Process
    try:
      let slow = slowCopy(dir)
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), WriterArg, dir / "out.txt"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      churner = startProcess(slow, args = @[ChurnArg, "2000", "150", "40",
        dir / "churn.ready"], options = {poParentStreams})
      require readPidFile(dir / "churn.ready") != Pid(0)
      armSlow(SlowName, 60_000)
      let started = getMonoTime()
      let res = try: finishMonitor(move(h)) finally: disarmSeams()
      let spentMs = inMilliseconds(getMonoTime() - started)
      check res.exitCode == 0
      check fileExists(dir / "out.txt")
      check res.completeness == mcComplete
      check losses(res).len == 0
      if losses(res).len != 0: echo losses(res)
      # The churn really kept the census unclassified past the plain window.
      check spentMs >= 1000
      check spentMs < MacosDescendantGraceCeilingMsDefault
    finally:
      if churner != nil:
        discard churner.waitForExit()
        churner.close()
      removeDir(dir)

  test "a surviving descendant that is unclassifiable too is still caught, without the stretch":
    # The member outlives the root and runs as `tgslow`, so the census
    # cannot read its strings and, to the census, it looks exactly like the
    # churn around it, whose unclassified set keeps changing. The tree
    # ledger still names it, so the stretch does not apply and the window
    # ends at the plain grace, long before the churn stops.
    let dir = createTempDir("io-mon-tree-guard-churn-member-", "")
    var member = Pid(0)
    var churner: Process
    try:
      let slow = slowCopy(dir)
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), SlowRootArg, slow, dir / "member.pid"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      member = readPidFile(dir / "member.pid")
      require member != Pid(0)
      churner = startProcess(slow, args = @[ChurnArg, "2000", "150", "40",
        dir / "churn.ready"], options = {poParentStreams})
      require readPidFile(dir / "churn.ready") != Pid(0)
      armSlow(SlowName, 60_000)
      let started = getMonoTime()
      let res = try: finishMonitor(move(h)) finally: disarmSeams()
      let spentMs = inMilliseconds(getMonoTime() - started)
      check posix.kill(member, 0) == 0
      check res.completeness == mcIncomplete
      let live = losses(res).filterIt(it.startsWith(RecordedLive) or
        it.startsWith(StillLive))
      check live.len == 1
      if live.len == 1:
        check ("pids=" & $member) in live[0]
        check graceSpent(live[0]) >= 0
      else:
        echo losses(res)
      check spentMs < 2000
    finally:
      if member != Pid(0): discard posix.kill(member, SIGKILL)
      if churner != nil:
        discard churner.waitForExit()
        churner.close()
      removeDir(dir)

  test "an unclassifiable child of an exiting parent is classified through the parent's parent":
    # G (started by this test after the root) forks P, which forks U; U
    # runs as `tgslow`, so the census cannot read it, and P is classified as
    # exiting, so its strings cannot vouch for U either. G is a readable
    # non-member, and the child of a non-member is a non-member, through P.
    let dir = createTempDir("io-mon-tree-guard-exiting-", "")
    var g: Process
    var p, u = Pid(0)
    try:
      let slow = slowCopy(dir)
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), WriterArg, dir / "out.txt"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      g = startProcess(getAppFilename(), args = @[LineageArg, slow,
        dir / "p.pid", dir / "u.pid"], options = {poParentStreams})
      p = readPidFile(dir / "p.pid")
      u = readPidFile(dir / "u.pid")
      require p != Pid(0) and u != Pid(0)
      armSlow(SlowName, 60_000)
      putEnv(ExitingVar, $p)
      let res = try: finishMonitor(move(h)) finally: disarmSeams()
      check posix.kill(u, 0) == 0
      check res.exitCode == 0
      check res.completeness == mcComplete
      check losses(res).len == 0
      if losses(res).len != 0: echo losses(res)
    finally:
      for q in [u, p]:
        if q != Pid(0): discard posix.kill(q, SIGKILL)
      if g != nil:
        discard g.waitForExit()
        g.close()
      removeDir(dir)

  test "an exiting parent does not vouch through the monitor's own process, and a stuck set ends the stretch":
    # The same chain with P started by this test process itself, which is
    # the monitor: the needles start in its children, so the walk stops
    # there and U stays unclassified. U never becomes readable, so the
    # unclassified set stops changing, and the guard gives up one grace
    # window after it last changed, far below the ceiling, naming the time
    # it spent.
    let dir = createTempDir("io-mon-tree-guard-exiting-self-", "")
    var pProc: Process
    var u = Pid(0)
    try:
      let slow = slowCopy(dir)
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), WriterArg, dir / "out.txt"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      pProc = startProcess(getAppFilename(), args = @[ForkSlowArg, slow,
        dir / "u.pid"], options = {poParentStreams})
      u = readPidFile(dir / "u.pid")
      require u != Pid(0)
      armSlow(SlowName, 60_000)
      putEnv(ExitingVar, $pProc.processID)
      let res = try: finishMonitor(move(h)) finally: disarmSeams()
      check res.completeness == mcIncomplete
      let unresolved = losses(res).filterIt(it.startsWith(Unclassified))
      check unresolved.len == 1
      if unresolved.len == 1:
        check ("," & $u & ",") in ("," & unresolved[0].split("pids=")[1].
          splitWhitespace()[0] & ",")
        let spent = graceSpent(unresolved[0])
        check spent >= MacosDescendantGraceMsDefault
        check spent < MacosDescendantGraceCeilingMsDefault - 1000
        check " load1=" in unresolved[0]
      else:
        echo losses(res)
    finally:
      if u != Pid(0): discard posix.kill(u, SIGKILL)
      if pProc != nil:
        discard posix.kill(Pid(pProc.processID), SIGKILL)
        discard pProc.waitForExit()
        pProc.close()
      removeDir(dir)

  test "churn that never stops ends at the ceiling, and the loss names it":
    # The stretch's liveness bound. The churn outlasts a lowered ceiling, so
    # the unclassified set is still changing when the window reaches it: the
    # guard must stop there, grade the capture incomplete, and say so.
    let dir = createTempDir("io-mon-tree-guard-ceiling-", "")
    var churner: Process
    try:
      let slow = slowCopy(dir)
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), WriterArg, dir / "out.txt"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      churner = startProcess(slow, args = @[ChurnArg, "8000", "150", "40",
        dir / "churn.ready"], options = {poParentStreams})
      require readPidFile(dir / "churn.ready") != Pid(0)
      armSlow(SlowName, 60_000)
      putEnv(CeilingVar, "1500")
      let started = getMonoTime()
      let res = try: finishMonitor(move(h))
                finally:
                  disarmSeams()
                  delEnv(CeilingVar)
      let spentMs = inMilliseconds(getMonoTime() - started)
      check res.completeness == mcIncomplete
      let unresolved = losses(res).filterIt(it.startsWith(Unclassified))
      check unresolved.len == 1
      if unresolved.len == 1:
        let spent = graceSpent(unresolved[0])
        check spent >= 1500
        check spent < 2500
        check " ceiling-ms=1500 ceiling-reached " in unresolved[0]
      else:
        echo losses(res)
      check spentMs < 4000
    finally:
      if churner != nil:
        discard posix.kill(Pid(churner.processID), SIGKILL)
        discard churner.waitForExit()
        churner.close()
      removeDir(dir)

  test "a launchd job is not classified by its creator id, and fails closed":
    # A real job submitted to launchd while the guard runs, unreadable to
    # the census (`tgslow`), with launchd as its parent. Its creator id reads
    # launchd's (1), but so does an orphan of the tree that exec'd after
    # launchd adopted it (the next case), so the id cannot clear it: the
    # capture stays incomplete, naming the job.
    let dir = createTempDir("io-mon-tree-guard-launchd-", "")
    let label = "io-mon-test-tree-guard-" & $getCurrentProcessId()
    var job = Pid(0)
    try:
      let slow = slowCopy(dir)
      var h = startMonitor(FsSnoopRequest(
        command: @[getAppFilename(), WriterArg, dir / "out.txt"],
        depFilePath: dir / "evidence.iomon"))
      while not pollMonitor(h): sleep(2)
      let submit = execCmdEx(LaunchctlExe & " submit -l " & quoteShell(label) &
        " -- " & quoteShell(slow) & " " & HoldArg & " " &
        quoteShell(dir / "job.pid") & " 8000")
      require submit.exitCode == 0
      job = readPidFile(dir / "job.pid")
      require job != Pid(0)
      armSlow(SlowName, 60_000)
      let res = try: finishMonitor(move(h)) finally: disarmSeams()
      checkpoint("losses: " & $losses(res))
      check posix.kill(job, 0) == 0
      check res.completeness == mcIncomplete
      check losses(res).anyIt(it.startsWith(Unclassified) and
        ("," & $job & ",") in ("," & it.split("pids=")[1].
          splitWhitespace()[0] & ","))
    finally:
      discard execCmdEx(LaunchctlExe & " remove " & quoteShell(label))
      if job != Pid(0): discard posix.kill(job, SIGKILL)
      removeDir(dir)

  test "an orphan whose creator is older than the root is classified; one whose creator is younger and gone still fails closed":
    # C starts BEFORE the monitored root, waits, then (after the root has
    # exited) forks U, waits for U's exec and exits: U is an unreadable
    # orphan of launchd whose creator is older than the root, so it cannot be
    # a descendant. The control with the creator rule off shows it is
    # unresolved otherwise. Then C started AFTER the root: U's creator is
    # younger and gone, which nothing on macOS can place outside the tree,
    # so the capture stays incomplete, naming U, both when U keeps C's id and
    # when U exec'd after launchd adopted it and so reads launchd's id, as a
    # launchd job does.
    for (olderCreator, withRule, order) in [
        (true, false, "exec-first"), (true, true, "exec-first"),
        (false, true, "exec-first"), (false, true, "orphan-first")]:
      let dir = createTempDir("io-mon-tree-guard-creator-", "")
      var creator: Process
      var u = Pid(0)
      try:
        let slow = slowCopy(dir)
        let trigger = dir / "go"
        proc startCreator(): Process =
          startProcess(getAppFilename(), args = @[CreatorArg, slow, trigger,
            dir / "u.pid", "4000", order], options = {poParentStreams})
        if olderCreator:
          creator = startCreator()
          sleep(50)   # C's unique id is assigned at its creation
        var h = startMonitor(FsSnoopRequest(
          command: @[getAppFilename(), WriterArg, dir / "out.txt"],
          depFilePath: dir / "evidence.iomon"))
        while not pollMonitor(h): sleep(2)
        if not olderCreator:
          creator = startCreator()
        writeFile(trigger, "")
        u = readPidFile(dir / "u.pid")
        require u != Pid(0)
        discard creator.waitForExit()  # C is gone: U is an orphan
        if order == "orphan-first":
          # U execs only after launchd adopted it; wait for that exec, so
          # the census meets U as `tgslow`, not as a fork of this binary.
          var uExecSeen = false
          for _ in 0 ..< 1000:
            if execCmdEx(PsExe & " -o comm= -p " & $u).output.strip().endsWith(
                SlowName):
              uExecSeen = true
              break
            sleep(5)
          require uExecSeen
        armSlow(SlowName, 60_000)
        if not withRule: putEnv(NoCreatorVar, "1")
        let res = try: finishMonitor(move(h))
                  finally:
                    disarmSeams()
                    delEnv(NoCreatorVar)
        checkpoint("older creator: " & $olderCreator & ", rule: " &
          $withRule & ", order: " & order & ", losses: " & $losses(res))
        check posix.kill(u, 0) == 0
        if olderCreator and withRule:
          check res.completeness == mcComplete
          check losses(res).len == 0
        else:
          check res.completeness == mcIncomplete
          check losses(res).anyIt(it.startsWith(Unclassified) and
            ("," & $u & ",") in ("," & it.split("pids=")[1].
              splitWhitespace()[0] & ","))
      finally:
        if u != Pid(0): discard posix.kill(u, SIGKILL)
        if creator != nil: creator.close()
        removeDir(dir)
