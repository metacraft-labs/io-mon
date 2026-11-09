## macOS tree-lifetime guard: the kernel census.
##
## Root exit does not prove that a monitored tree has exited: a detached
## descendant can outlive the root and keep reading and writing files after the
## evidence is merged. macOS has no Job Object and no subreaper, and `kqueue`'s
## `NOTE_TRACK` (automatic fork following) has not been supported since 10.5.
## What it does have is a cheap, unprivileged, point-in-time process listing
## (`sysctl(KERN_PROC_ALL)`) and a way to read a same-user process's live
## argument/environment area (`KERN_PROCARGS2`). That is the same shape as the
## Linux guard's `/proc/*/environ` scan, and the guard mirrors that contract:
## after the root has exited, the capture is complete only once a sweep finds no
## live process carrying this run's injection needles
## (`REPRO_MONITOR_SESSION=<runId>` or `REPRO_MONITOR_FRAGMENT_DIR=<dir>`) AND
## no live process in this run's tree ledger (`io_mon/tree_ledger`), within a
## grace window.
##
## The argument/environment area is the process's OWN memory, not a copy the
## kernel took at exec, so a process can overwrite its needles in place
## (setproctitle-style; PostgreSQL reuses the whole argv+environ area for its
## process title on Darwin). The census cannot see such a process. The tree
## ledger, checked against the same snapshot, can: see "WHAT THE NEEDLE CENSUS
## CANNOT SEE" below.
##
## User contract: `docs/usage.md`, "The macOS tree-lifetime guard
## (normative)".
##
## ── WHY ONE CLEAN SWEEP IS A PROOF (and why the Linux scan's is not) ──────
##
## (Here "member" means a process whose area still carries a needle; the tree
## ledger covers the rest, below.) A sweep is CONCLUSIVE only when it finds no
## member AND no process it could not classify. Then no member was alive at
## the snapshot instant `t0`:
##
##  * every process alive at `t0` is in the snapshot (the kernel fills it under
##    the process-list lock, and a fork adds its child to that list before the
##    parent's `fork` returns);
##  * a member in the snapshot is either still alive when its strings are read
##    (it is a hit) or gone by then (it VANISHED, which is also inconclusive:
##    it may have created a child after `t0`);
##  * the root had already been reaped before the first sweep, so every member
##    created after `t0` would need a member alive at `t0` to create it.
##
## A vanished or unreadable process (one caught mid-fork or mid-exec) is
## classified through its snapshot parent unless that parent is launchd: macOS
## reparents an orphan to launchd and to nothing else, so any other parent
## created it, and the child of a non-member is a non-member (it inherits its
## creator's environment, and the needles travel only through the root's spawn
## environment). Without that rule, unrelated short-lived processes on a busy
## host kept every sweep inconclusive until the window closed (measured: 1 of
## 60 trivial captures incomplete under four loops of process churn; 0 of 100
## with the rule).
##
## The Linux scan stops at the first sweep that finds no live carrier, so a
## carrier that forks after `readdir` passed its slot and then exits before its
## own entry is read can hand the tree to a child the scan never lists. The
## vanished rule closes that here. Its cost is a retry when an unrelated young
## process happens to exit mid-sweep; a host whose churn never allows a clean
## sweep inside the window grades the capture incomplete, never complete.
##
## ── WHAT THE CENSUS CANNOT SEE, AND WHY THAT IS STILL SOUND ───────────────
##
## While SIP is on, the kernel withholds the environment of platform
## (SIP-protected) binaries, and it never discloses that of other users'
## processes. Neither can be a REPORTING member then: dyld strips
## `DYLD_INSERT_LIBRARIES` from both, so neither ever loads the shim. (XNU's
## `sysctl_procargsx` omits a `CS_RESTRICT` target's environment unless SIP
## is off or the caller is entitled:
## https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sysctl.c.)
## With SIP off (`csrutil disable`, as on GitHub's hosted macOS runners),
## neither holds for a platform binary: dyld loads the shim into it and the
## kernel discloses its environment (measured on macOS 26.5.1 with
## /usr/bin/caffeinate). It is then a member the census finds by its needles,
## as well as through its creator's ledger entry. That only adds evidence.
## The rest of this section is about the SIP-on case.
## Such a process can only enter a monitored tree as an UNMONITORED subtree:
## as the root (the root guard), or created by an injected process (its
## `mrProcessSpawn` / `mrProcessExec` record then has no matching
## `mrProcessStart`), or created by another unmonitored process (which is
## itself one of those cases). Each of those already grades `mcIncomplete`
## through `writer.unmonitoredSubtreeLossDetails`, whatever the census says.
## The creating record also survives a creator that is SIGKILLed right after
## the spawn: the exec record is flushed before the image is replaced, and a
## `posix_spawn` record reaches the fragment before the call returns (pinned
## by case 8c of `tests/macos/test_io_mon_macos_tree_lifetime_guard.nim`). A
## same-user, non-platform process whose strings cannot be
## read is NOT skipped: it is unresolved, and the sweep is inconclusive.
##
## ── WHAT THE NEEDLE CENSUS CANNOT SEE: AN OVERWRITTEN AREA ──────────────
##
## A descendant that overwrote its needles (or inherited an area its creator
## had overwritten) is a non-member to the census. Every round therefore also
## matches the TREE LEDGER against the same snapshot: one entry, named by
## (pid, kernel start time), for each process the shim saw come into
## existence, written synchronously and ungated by the event interest (see
## `io_mon/tree_ledger` for why the record stream cannot serve). An entry that
## is a live, non-exiting process with the same start time in the snapshot is
## a live descendant, whatever its memory says. A round is conclusive only when
## the census is conclusive and empty, no entry is live, and a second read of
## the ledger after the snapshot finds no new entry.
##
## Why census + ledger leave no descendant out. Take any descendant D alive
## at the snapshot instant. By how D came to exist:
##
##  1. D loaded the shim (the root, or any exec into an injectable image).
##     Shim init wrote D's entry before `main`, so before D could overwrite
##     anything. The LEDGER finds D.
##  2. D is the child of a hooked `fork` or `posix_spawn(p)` in a shim
##     process. The parent wrote D's entry before the call returned to it, so
##     the entry exists before the parent can exit; D writes it again itself.
##     The LEDGER finds D.
##  3. D is a `vfork` child (no fork hook runs) that went on to exec. The exec
##     hook writes the calling pid's entry before the image is replaced. The
##     LEDGER finds D. (A `vfork` child that does not exec only `_exit`s.)
##  4. D is an image that never loaded the shim (a SIP binary, another user's
##     process, an exec with the injection stripped) or was created by one. It
##     was created by case 1-3 or is the root, and that creation is an
##     unmonitored subtree that already grades `mcIncomplete` (above). When it
##     was created by a shim process, its entry also exists (case 2 or 3).
##  5. D was created by a raw `fork` syscall that bypasses the hooks, so no
##     entry exists: the CENSUS finds D while its area still carries the
##     needles it inherited. D that ALSO overwrites its area (or whose creator
##     did) is the residual case, and it needs code that both issues a raw
##     fork and rewrites its own argument area. A binary whose own text issues
##     raw syscalls is already graded incomplete at shim init (the
##     raw-syscall scan); the residual is such code in a library.
##
## Outside the argument: the ledger is files in the run's fragment directory,
## which the monitored tree can write. A descendant that DELETES its own entry
## and then overwrites its area is seen by neither check. That is tampering
## with io-mon's own evidence, not accidental software behaviour, which is
## all the trusted profile asks io-mon to detect; wholesale removal of the
## directory or of the root's entry still fails closed (no root entry). A
## creator SIGKILLed between the kernel's posix_spawn returning and its hook
## writing the child's entry leaves a non-shim (SIP) child with no entry and
## no spawn record; that needs an external kill inside that window.
##
## Why the second ledger read is needed: a process P in the first read may
## create D and exit between that read and the snapshot. D's entry (written
## by P, case 2) then appears only in the second read, the round is not
## conclusive, and the next round checks D. Between two reads that agree, no
## entry was added, so every process created before the second read by a
## process in the ledger is in the ledger.
##
## The ledger fails closed in both directions it can fail: a write that fails
## is published by the shim as an `mrEventLoss` and flushed at once, and a
## ledger with no entry for the root (a shim that predates it, or a root that
## never loaded the shim) is itself a loss. An entry whose start time the
## writer could not read matches any live process with that pid that is not
## provably older than the root, which can only err towards "live".
##
## Linux had the same blind spot (its scan reads `/proc/<pid>/environ`, which
## is also live memory); its guard now checks the same ledger
## (`fs_snoop.waitForLinuxInjectedDescendants`,
## `tests/linux/test_io_mon_linux_tree_ledger.nim`).
##
## ── THE START-TIME PRUNE USES THE MONOTONIC CLOCK ─────────────────────────
##
## The census skips processes that started before the root, which cannot be
## its descendants. "Before" is decided on the kernel's MONOTONIC start time
## (`proc_pid_rusage`'s `ri_proc_start_abstime`), never on
## `kp_proc.p_starttime`: that is wall-clock time, and a wall clock stepped
## backwards after the root started (NTP step, manual set) would date every
## process created after the step before the root, and the prune would skip
## real descendants. Comparing wall-clock elapsed time with monotonic elapsed
## time cannot detect that either: a step back and then forward again leaves
## them equal while the processes created in between stay misdated. A process
## whose monotonic start cannot be read (another user's process, or one that
## is gone) is not pruned. The wall-clock start is still used, but only as an
## identity: a ledger entry and the snapshot must agree on it exactly, and a
## step cannot change a value the kernel recorded at creation.
##
## This module only gathers facts. The DECISIONS (when the guard runs, how
## long it waits, what a failure means for the capture) live in `fs_snoop`'s
## private `settleMonitorDescendants`, inside the single evidence funnel
## (`collectMonitorEvidence`). Nothing here can promote a capture: the
## caller fails closed on anything but a conclusive empty sweep.

when not defined(macosx):
  {.error: "io_mon/macos_tree_guard is macOS-only".}

import std/[algorithm, hashes, monotimes, os, sequtils, strutils, times]
import io_mon/tree_ledger

when defined(ioMonMacosTreeGuardFaultTest):
  {.passC: "-DIOMON_TG_FAULT_TEST".}
# The object is named after a hash of the C source, so it is rebuilt whenever
# the SOURCE changes. A plain `{.compile.}` reuses the object whenever it is
# newer than the .c file, so a C-only edit that leaves an older mtime (a file
# restored with `cp -p`, `tar`, `rsync -t`, or edited within the object's
# timestamp) silently links the previous code. `staticRead` also makes the
# module depend on the file.
const TreeGuardCHash = $cast[uint](hash(staticRead("macos_tree_guard.c")))
{.compile: ("macos_tree_guard.c", "macos_tree_guard_" & TreeGuardCHash & ".o").}

const
  MacosDescendantGraceMsDefault* = 500
    ## Same defaults as the Linux and Windows guards' windows.
  MacosDescendantPollMsDefault* = 25
  MacosDescendantGraceCeilingMsDefault* = 5000
    ## The hard ceiling on the extended window (see `waitForTreeQuiescence`,
    ## "WHY THE WINDOW STRETCHES"). Never below the grace window itself.
  HitCapacity = 256

type
  TgHit {.bycopy.} = object
    pid: int32
    reason: int32
    comm: array[17, char]

  TreeQuiescence* = object
    quiesced*: bool     ## a conclusive sweep found no member
    lossDetail*: string ## why not, without `run=`; empty when quiesced
    sweeps*: int        ## sweeps taken (diagnostics and tests)

proc iomon_tg_start_abs(pid: int32): uint64 {.importc, cdecl.}
proc iomon_tg_unique_ids(pid: int32; uniq, puniq: ptr uint64): cint
  {.importc, cdecl.}
proc iomon_tg_sweep(self: int32; rootStartAbs, rootUniqueId: uint64;
                    n1: cstring; n1len: csize_t; n2: cstring; n2len: csize_t;
                    ledgerPids: ptr int32; ledgerStarts: ptr uint64;
                    ledgerN: cint;
                    hits: ptr TgHit; cap: cint; nHits: ptr cint;
                    young: ptr cint): cint {.importc, cdecl.}

when defined(ioMonMacosTreeGuardFaultTest):
  # TEST SEAMS, compiled ONLY under `-d:ioMonMacosTreeGuardFaultTest` (the
  # sibling `.nims` of the faults test). `census` makes the REAL census sysctl
  # fail with a real bad selector, so the diagnostic carries the errno macOS
  # really returned. `vanish` releases a real member between the snapshot and
  # its strings read. Neither can make the guard succeed.
  var iomon_tg_fault_census {.importc.}: cint
  var iomon_tg_fault_vanish_pid {.importc.}: int32
  var iomon_tg_fault_wall_shift_usec {.importc.}: int64
  proc armInjectedFault() =
    let fault = getEnv("IO_MON_TEST_MACOS_TREE_GUARD_FAULT")
    iomon_tg_fault_census = if fault == "census": 1 else: 0
    # `wallstep`: the census sees every process start time as if the wall
    # clock had been stepped back an hour after the root started (see the C
    # side). The root's own start, taken at the spawn, is unaffected.
    iomon_tg_fault_wall_shift_usec =
      if fault == "wallstep": 3_600_000_000'i64 else: 0
    # `vanish` seam: release a real member right after the snapshot (see the
    # C side). The pid comes from IO_MON_TEST_MACOS_TREE_GUARD_VANISH_PID.
    iomon_tg_fault_vanish_pid =
      try: int32(parseInt(getEnv("IO_MON_TEST_MACOS_TREE_GUARD_VANISH_PID", "0")))
      except ValueError: 0

  proc iomon_tg_test_carries_needle(buf: cstring; n: csize_t; n1: cstring;
                                    n1len: csize_t): cint {.importc, cdecl.}
  proc testCarriesNeedle*(image, needle: string): bool =
    ## TEST SEAM: the census's needle scan over a crafted KERN_PROCARGS2
    ## image.
    iomon_tg_test_carries_needle(cstring(image), csize_t(image.len),
      cstring(needle), csize_t(needle.len)) != 0

  var iomon_tg_fault_slow_comm {.importc.}: array[17, char]
  var iomon_tg_fault_slow_ms {.importc.}: int64
  var iomon_tg_fault_exiting_pid {.importc.}: int32
  var iomon_tg_fault_no_creator_rule {.importc.}: cint
  proc armLoadSeams() =
    # `slow` seam: processes named IO_MON_TEST_MACOS_TREE_GUARD_SLOW_COMM
    # have their strings refused for IO_MON_TEST_MACOS_TREE_GUARD_SLOW_MS
    # after they start (see the C side). `exiting` seam: the non-member
    # IO_MON_TEST_MACOS_TREE_GUARD_EXITING_PID is classified as exiting.
    let comm = getEnv("IO_MON_TEST_MACOS_TREE_GUARD_SLOW_COMM")
    zeroMem(addr iomon_tg_fault_slow_comm[0], iomon_tg_fault_slow_comm.len)
    for i in 0 ..< min(comm.len, iomon_tg_fault_slow_comm.len - 1):
      iomon_tg_fault_slow_comm[i] = comm[i]
    iomon_tg_fault_slow_ms =
      try: int64(parseInt(getEnv("IO_MON_TEST_MACOS_TREE_GUARD_SLOW_MS", "0")))
      except ValueError: 0
    iomon_tg_fault_exiting_pid =
      try: int32(parseInt(getEnv("IO_MON_TEST_MACOS_TREE_GUARD_EXITING_PID",
        "0")))
      except ValueError: 0
    # `nocreator` seam: skip the creator-id rule, so a test can show what
    # the rule alone classifies.
    iomon_tg_fault_no_creator_rule =
      if getEnv("IO_MON_TEST_MACOS_TREE_GUARD_NO_CREATOR_RULE") == "1": 1
      else: 0

  var iomon_tg_fault_vanish_verdict {.importc.}: cint
  proc faultVanishVerdict*(): string =
    ## TEST SEAM: how the last capture's census classified the pid the
    ## `vanish` seam released ("vanished", "nonmember", ...; "unseen" if the
    ## census never classified it).
    case iomon_tg_fault_vanish_verdict
    of 1: "nonmember"
    of 2: "member"
    of 3: "vanished"
    of 4: "unreadable"
    of 5: "dead"
    else: "unseen"

proc processStartAbs*(pid: int): uint64 =
  ## The kernel's MONOTONIC start time of `pid` (mach absolute time,
  ## `proc_pid_rusage`'s `ri_proc_start_abstime`), or 0 when it cannot be
  ## read. Taken for the monitored root right after the spawn, it arms the
  ## start-time prune: a process that started before the root cannot be its
  ## descendant. Monotonic on purpose: the wall-clock start
  ## (`kp_proc.p_starttime`) moves with the wall clock, and a clock stepped
  ## backwards after the root started would date a real descendant before
  ## it. 0 disables the prune (slower, never blinder).
  iomon_tg_start_abs(int32(pid))

proc processUniqueId*(pid: int): uint64 =
  ## The kernel's 64-bit unique id of `pid` (assigned at creation, never
  ## reused), or 0 when it cannot be read. Taken for the monitored root right
  ## after the spawn, it arms the census's creator rule: an unreadable orphan
  ## whose creator's id is below the root's was created by a process older
  ## than the root (see `creator_predates_root` in the C side). 0 disables
  ## the rule (fail closed).
  var uniq, puniq: uint64
  if iomon_tg_unique_ids(int32(pid), addr uniq, addr puniq) == 1: uniq
  else: 0

proc sanitizeToken(s: string): string =
  ## Keep a detail token one token: no whitespace, `,` or `=`.
  result = newStringOfCap(s.len)
  for c in s:
    result.add(if c in Whitespace or c in {',', '='}: '_' else: c)

type Sweep = object
  failedErr: int
  members, unresolved, recordedLive: seq[(int, string)]
  total: int

proc sweepOnce(runId, fragmentDir: string; rootStartAbs, rootUniqueId: uint64;
               ledger: seq[TreeLedgerEntry]): Sweep =
  when defined(ioMonMacosTreeGuardFaultTest):
    armInjectedFault()
    armLoadSeams()
  let sessionNeedle = "REPRO_MONITOR_SESSION=" & runId
  let fragmentNeedle = "REPRO_MONITOR_FRAGMENT_DIR=" & fragmentDir
  var ledgerPids = newSeq[int32](max(ledger.len, 1))
  var ledgerStarts = newSeq[uint64](max(ledger.len, 1))
  for i, e in ledger:
    ledgerPids[i] = int32(e.pid)
    ledgerStarts[i] = e.startUsec
  var hits: array[HitCapacity, TgHit]
  var n, young: cint
  let err = iomon_tg_sweep(int32(getCurrentProcessId()), rootStartAbs,
    rootUniqueId,
    cstring(sessionNeedle), csize_t(sessionNeedle.len),
    cstring(fragmentNeedle), csize_t(fragmentNeedle.len),
    addr ledgerPids[0], addr ledgerStarts[0], cint(ledger.len),
    addr hits[0], cint(HitCapacity), addr n, addr young)
  if err != 0:
    result.failedErr = int(err)
    return
  result.total = int(n)
  for i in 0 ..< min(int(n), HitCapacity):
    let comm = sanitizeToken($cast[cstring](unsafeAddr hits[i].comm[0]))
    let entry = (int(hits[i].pid), if comm.len == 0: "unknown" else: comm)
    case hits[i].reason
    of 0: result.members.add entry
    of 3: result.recordedLive.add entry
    else: result.unresolved.add entry

proc describe(entries: seq[(int, string)]): string =
  var pids, images: seq[string]
  for (pid, image) in entries:
    pids.add $pid
    images.add image
  "pids=" & pids.join(",") & " images=" & images.join(",")

proc c_getloadavg(loadavg: ptr cdouble; nelem: cint): cint
  {.importc: "getloadavg", header: "<stdlib.h>".}

proc spentToken(elapsedMs, ceilingMs: int; ceilingReached: bool): string =
  ## ` grace-ms=<spent> ceiling-ms=<ceiling>[ ceiling-reached]
  ## load1=<1-minute load average>`: how long the guard actually waited,
  ## the bound on the stretch, whether the stretch ran into that bound (the
  ## unclassified set was still changing when the window ended), and how
  ## busy the host was, so a consumer can tell a starved host's unresolved
  ## census from a real surviving descendant. `load1=unknown` when the
  ## kernel does not answer.
  result = " grace-ms=" & $elapsedMs & " ceiling-ms=" & $ceilingMs
  if ceilingReached:
    result.add " ceiling-reached"
  var load: array[1, cdouble]
  if c_getloadavg(addr load[0], 1) == 1:
    result.add " load1=" & formatFloat(float(load[0]), ffDecimal, 2)
  else:
    result.add " load1=unknown"

proc waitForTreeQuiescence*(runId, fragmentDir: string; rootPid: int;
                            rootStartAbs: uint64;
                            graceMs, pollMs: int;
                            ceilingMs = MacosDescendantGraceCeilingMsDefault;
                            rootUniqueId = 0'u64): TreeQuiescence =
  ## After the root has exited, sweep until one sweep is conclusive and empty,
  ## or the window ends. The first sweep is immediate.
  ##
  ## Each round: read the tree ledger, take one census snapshot and match
  ## BOTH the needle census and every ledger entry against it, then read the
  ## ledger again. A round is conclusive only when the census is conclusive
  ## and empty, no ledger entry is live in the snapshot, and the second ledger
  ## read found no entry the first did not (an entry written meanwhile is a
  ## process created after the first read, by a process that was alive then;
  ## the next round checks it).
  ##
  ## WHY THE WINDOW STRETCHES. The window is `graceMs`, except when the only
  ## thing keeping the last round inconclusive is young processes the census
  ## could not classify (alive, same user, strings refused: caught between
  ## fork and exec, or not yet scheduled). On a starved host that set is
  ## rarely empty at a fixed instant even though the tree has quiesced: new
  ## young processes keep appearing and each takes long to become readable.
  ## So the window is extended while that set is still changing, up to the
  ## hard ceiling `ceilingMs` (never below `graceMs`); once it has stayed the
  ## same for a whole `graceMs` (a process that is not going to become
  ## readable soon), the guard stops waiting. The extension cannot make a
  ## capture complete by itself: completion still needs a conclusive, empty
  ## round, and a live member, a live ledger process, a ledger that keeps
  ## growing or an overflowing census ends the window at `graceMs` exactly as
  ## before. Every loss published after the window names the time actually
  ## spent and the host's load (`spentToken`).
  let start = getMonoTime()
  let ceiling = max(ceilingMs, graceMs)
  var lastUnresolved: seq[int]
  var unresolvedChangedMs = 0
  while true:
    var before, after: seq[TreeLedgerEntry]
    if not readTreeLedger(fragmentDir, before):
      result.lossDetail = "macos tree-lifetime guard failed: " &
        "the tree ledger could not be read"
      return
    if rootPid > 0 and not before.anyIt(it.pid == rootPid):
      # The root loads the shim before `main`, and shim init writes the
      # root's entry or publishes a loss for the failed write. A ledger
      # without it was not kept (a shim that predates the ledger, or a root
      # that never loaded the shim), so it cannot prove anything here.
      result.lossDetail = "macos tree-lifetime guard failed: " &
        "the tree ledger has no entry for the root pid=" & $rootPid
      return
    let s = sweepOnce(runId, fragmentDir, rootStartAbs, rootUniqueId, before)
    inc result.sweeps
    if s.failedErr != 0:
      result.lossDetail = "macos tree-lifetime guard failed: " &
        "sysctl(KERN_PROC_ALL) census failed errno=" & $s.failedErr
      return
    if not readTreeLedger(fragmentDir, after):
      result.lossDetail = "macos tree-lifetime guard failed: " &
        "the tree ledger could not be read"
      return
    let ledgerGrew = after != before
    if s.total == 0 and not ledgerGrew:
      result.quiesced = true
      return
    let elapsedMs = int(inMilliseconds(getMonoTime() - start))
    var unresolvedNow: seq[int]
    for (pid, _) in s.unresolved: unresolvedNow.add pid
    unresolvedNow.sort()
    if unresolvedNow != lastUnresolved:
      lastUnresolved = unresolvedNow
      unresolvedChangedMs = elapsedMs
    let overflow = s.total >
      s.members.len + s.unresolved.len + s.recordedLive.len
    let onlyUnresolved = s.unresolved.len > 0 and s.members.len == 0 and
      s.recordedLive.len == 0 and not overflow and not ledgerGrew
    let stillChanging = elapsedMs - unresolvedChangedMs < graceMs
    let stretch = onlyUnresolved and elapsedMs < ceiling and stillChanging
    if elapsedMs >= graceMs and not stretch:
      var censusPids: seq[int]
      for (pid, _) in s.members: censusPids.add pid
      let ledgerOnly = s.recordedLive.filterIt(it[0] notin censusPids)
      if s.members.len > 0 or overflow:
        result.lossDetail =
          "macos descendants still live after root exit live=" &
            $s.members.len & " " & describe(s.members)
        if ledgerOnly.len > 0:
          result.lossDetail.add " recorded-live=" & $ledgerOnly.len &
            " recorded-" & describe(ledgerOnly)
        if s.unresolved.len > 0:
          result.lossDetail.add " unresolved=" & $s.unresolved.len
      elif ledgerOnly.len > 0:
        # Alive, in this run's ledger, and NOT found by the needle census:
        # its argument/environment area no longer carries the needles (it
        # overwrote them in place), so only the ledger can see it.
        result.lossDetail =
          "macos recorded descendants still live after root exit live=" &
            $ledgerOnly.len & " " & describe(ledgerOnly)
        if s.unresolved.len > 0:
          result.lossDetail.add " unresolved=" & $s.unresolved.len
      elif s.unresolved.len > 0:
        result.lossDetail =
          "macos tree-lifetime guard could not classify young processes " &
            "after root exit unresolved=" & $s.unresolved.len & " " &
            describe(s.unresolved)
      else:
        result.lossDetail =
          "macos tree-lifetime guard could not settle the tree ledger: " &
            "entries kept appearing after root exit entries=" & $after.len
      result.lossDetail.add spentToken(elapsedMs, ceiling,
        onlyUnresolved and stillChanging and elapsedMs >= ceiling)
      return
    let windowEnd = if elapsedMs >= graceMs: ceiling else: graceMs
    sleep(max(1, min(pollMs, windowEnd - elapsedMs)))
