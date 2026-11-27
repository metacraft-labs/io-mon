## test_io_mon_linux_tree_guard_settle — the Linux descendant guard
## (`fs_snoop.waitForLinuxInjectedDescendants`) does not end its window on a
## round that only saw the tree ledger grow.
##
## A fork child writes its own tree-ledger entry before it runs program code
## (`linux_preload.markForkChildInTreeLedger`) and may clear its
## `REPRO_MONITOR_*` needles right after. If both happen between the guard
## round's first ledger read and its `/proc` sweep, that round sees neither the
## needles nor the entry; only its second ledger read shows the new entry. The
## guard used to end the window on such a round whenever it was the last one,
## publishing "could not settle the tree ledger: entries kept appearing" for a
## descendant the next round would have named as live (and failing a capture
## whose new entry belonged to a process that had already exited). On a loaded
## host the scheduler puts that write at the end of the window often enough
## that `test_io_mon_linux_tree_ledger.nim` cases 9 and 12 failed there
## (a 32-core host at a load average of 85-287).
##
## WHY A SEAM, NOT A LOADED HOST. The failure needs the entry to land inside
## one specific guard round, the one that crosses the window; no fixture can
## time a write against the guard's reads, so a reproduction that waits for
## the scheduler to do it fails a few times in a hundred and proves nothing
## when it passes. `-d:ioMonLinuxTreeGuardFaultTest` (this file's `.nims`)
## compiles a hook into the guard that runs exactly at that point of each
## round, after the first read has been checked and before the second. The
## hook does what the late fork child does: it writes the ledger entry of a
## REAL process (`markTreeLedger`, the writer the shim uses, with the
## process's real `/proc/<pid>/stat` start time) into the run's real fragment
## directory. Everything else is real: the shim is injected into a real root,
## the guard reads the real ledger and the real `/proc`, and the verdict is
## decoded from the depfile io-mon wrote. The one thing the seam replaces is
## the scheduler's timing, and the process it registers is started by the test
## rather than by the tree, which the ledger cannot tell apart (an entry is a
## pid and a start time).
##
## The window is 0 ms in every case, so the first round is already past it:
##
##  1. an entry for a LIVE process that appears in that round is reported by
##     name (`linux recorded descendants still live … pids=<p>`), not as a
##     ledger that could not settle;
##  2. an entry for a process that has already EXITED that appears in that
##     round is complete: the next round reads the same ledger twice and finds
##     nothing live;
##  3. a ledger that keeps growing in every round, with nothing live, ends at
##     the ceiling (`IO_MON_LINUX_DESCENDANT_GRACE_CEILING_MS`) with the settle
##     loss, which names the time spent and the ceiling;
##  4. control: with no hook the same root is complete in one round.
##
## Neuter: restore the old exit (end the window on any round past it) and 1
## reports "could not settle", 2 is `mcIncomplete`, and 3 ends at once
## without the `grace-ms=`/`ceiling-ms=` tokens.
import foreign_preload_isolation

import std/[monotimes, os, osproc, posix, sequtils, strutils, tempfiles,
  times, unittest]
import io_mon
import io_mon/tree_ledger

when not defined(ioMonLinuxTreeGuardFaultTest):
  {.error: "compile with test_io_mon_linux_tree_guard_settle.nims".}

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
const RecordedLive = "linux recorded descendants still live after root exit"
const NotSettled = "linux descendant guard could not settle the tree ledger"

proc procStartTicks(pid: int): uint64 =
  ## Field 22 of /proc/<pid>/stat, the start time the shim records.
  let text = readFile("/proc/" & $pid & "/stat")
  result = parseLinuxProcStatStart(text, text.len)
  doAssert result != 0, "no start time for pid " & $pid

proc losses(dep: MonitorDepFile): seq[string] =
  for r in dep.records:
    if r.kind == mrEventLoss: result.add r.detail

# The hook runs inside the guard, which is `raises: []`; a failure in it is
# recorded here and asserted by the test, never raised through the guard.
var
  hookMode = ""            ## "live", "exited", "grow"; "" = do nothing
  hookCalls = 0
  hookError = ""
  registeredPid = 0        ## the process whose entry the hook wrote
  liveProcess: Process

proc roundHook(fragmentDir: string; round: int) {.nimcall, gcsafe,
    raises: [].} =
  {.cast(gcsafe).}:
    inc hookCalls
    try:
      case hookMode
      of "live":
        if round == 0:
          liveProcess = startProcess("sleep", args = ["30"],
            options = {poUsePath})
          registeredPid = liveProcess.processID
          let rc = markTreeLedger(fragmentDir, registeredPid,
            procStartTicks(registeredPid))
          if rc != 0: hookError = "markTreeLedger errno=" & $rc
      of "exited":
        if round == 0:
          let p = startProcess("true", options = {poUsePath})
          let pid = p.processID
          # Read the start time while the process exists (a zombie keeps its
          # /proc entry until it is reaped), then reap it.
          let ticks = procStartTicks(pid)
          discard p.waitForExit()
          p.close()
          registeredPid = pid
          let rc = markTreeLedger(fragmentDir, pid, ticks)
          if rc != 0: hookError = "markTreeLedger errno=" & $rc
      of "grow":
        # A pid above any pid_max (2^22) never names a process, so the entry
        # is never live; a new one every round keeps the ledger growing.
        let rc = markTreeLedger(fragmentDir, 5_000_000 + round, 1)
        if rc != 0: hookError = "markTreeLedger errno=" & $rc
      else:
        discard
    except CatchableError as e:
      hookError = e.msg

suite "Linux descendant guard: a round that only saw the ledger grow":
  let work = expandFilename(createTempDir("io-mon-linux-settle-", ""))
  let buildShim = execCmdEx("bash " & quoteShell(repoRoot / "scripts" /
    "build_shim.sh"))
  doAssert buildShim.exitCode == 0, buildShim.output
  doAssert findShimLibrary().len > 0
  let sh = findExe("sh")
  doAssert sh.len > 0
  var serial = 0
  proc capture(): MonitorResult =
    inc serial
    hookCalls = 0
    hookError = ""
    registeredPid = 0
    runMonitored(FsSnoopRequest(command: @[sh, "-c", "true"],
      depFilePath: work / ("capture-" & $serial & ".iomon")))

  putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", "0")
  putEnv("IO_MON_LINUX_DESCENDANT_POLL_MS", "10")
  linuxTreeGuardRoundHook = roundHook

  teardown:
    hookMode = ""
    delEnv("IO_MON_LINUX_DESCENDANT_GRACE_CEILING_MS")

  test "1. a live process whose entry appears in the last round is named":
    hookMode = "live"
    try:
      let res = capture()
      check hookError == ""
      check registeredPid > 0
      check res.exitCode == 0
      check res.completeness == mcIncomplete
      let losses = res.depFile.losses
      let recorded = losses.filterIt(it.startsWith(RecordedLive))
      check recorded.len == 1
      if recorded.len == 1:
        check ("pids=" & $registeredPid) in recorded[0]
      check not losses.anyIt(it.startsWith(NotSettled))
      if recorded.len != 1: echo losses
      # The guard ran a round after the one the entry appeared in.
      check hookCalls >= 2
    finally:
      if liveProcess != nil:
        liveProcess.terminate()
        discard liveProcess.waitForExit()
        liveProcess.close()
        liveProcess = nil

  test "2. an exited process whose entry appears in the last round is complete":
    hookMode = "exited"
    let res = capture()
    check hookError == ""
    check registeredPid > 0
    check res.exitCode == 0
    check res.completeness == mcComplete
    check res.depFile.losses.len == 0
    if res.depFile.losses.len != 0: echo res.depFile.losses
    check hookCalls >= 2

  test "3. a ledger that keeps growing ends at the ceiling, naming it":
    hookMode = "grow"
    putEnv("IO_MON_LINUX_DESCENDANT_GRACE_CEILING_MS", "300")
    let t0 = getMonoTime()
    let res = capture()
    let elapsed = inMilliseconds(getMonoTime() - t0)
    check hookError == ""
    check res.completeness == mcIncomplete
    let settle = res.depFile.losses.filterIt(it.startsWith(NotSettled))
    check settle.len == 1
    if settle.len == 1:
      check "ceiling-ms=300" in settle[0]
      let parts = settle[0].split(" grace-ms=")
      check parts.len == 2
      if parts.len == 2:
        check parseInt(parts[1].split(' ')[0]) >= 300
    else:
      echo res.depFile.losses
    check elapsed >= 300
    check hookCalls >= 2

  test "4. control: without the hook the root is complete in one round":
    let res = capture()
    check res.exitCode == 0
    check res.completeness == mcComplete
    check res.depFile.losses.len == 0
    if res.depFile.losses.len != 0: echo res.depFile.losses
    check hookCalls == 1
