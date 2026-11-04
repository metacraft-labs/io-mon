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

import std/[os, osproc, posix, sequtils, strutils, tempfiles, unittest]
import io_mon
import io_mon/macos_tree_guard

const
  WriterArg = "--guard-fault-writer"
  VanishRootArg = "--guard-vanish-root"
  VanishMemberArg = "--guard-vanish-member"
  FaultVar = "IO_MON_TEST_MACOS_TREE_GUARD_FAULT"
  VanishVar = "IO_MON_TEST_MACOS_TREE_GUARD_VANISH_PID"
  StillLive = "macos descendants still live after root exit"
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
