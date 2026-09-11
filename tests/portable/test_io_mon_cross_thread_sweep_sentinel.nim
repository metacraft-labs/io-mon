## test_io_mon_cross_thread_sweep_sentinel — the shutdown sweep has to
## RETIRE the read-tail sentinel of the thread whose batch it rescued.
##
## `flushAllRegisteredSlots` walks the process-global registry at shutdown
## and writes out every still-live thread's buffered batch, including
## threads other than the caller. Retiring the matching `read-tail-pending`
## marker, however, goes through `clearReadingSentinel` ->
## `writeReadTailMarker`, and that proc can only ever address the CALLING
## thread's `fragmentSlot` THREADVAR. So the sweep used to make another
## thread's reads durable and leave that thread's pending marker standing,
## and `mergeFragments` — which nets pending against committed per
## (osPid, threadId) — reported a kill-before-flush loss for a batch that
## was, in fact, on disk.
##
## The cost was not cosmetic. It is why a monitored MSYS2/Cygwin shell
## could not reach `mcComplete`: its reads happen on threads other than the
## one that runs the exit hook, so every one of them was rescued AND
## charged as a loss. Measured on `research/msys-attach-2026-09/heavy.sh`:
## `eventLoss=79`, `mcIncomplete`.
##
## THE PROPERTY UNDER TEST IS THE PAIRING, NOT THE ABSENCE OF LOSSES. A
## test that only asserted "no kill-before-flush after a sweep" would pass
## just as well against a merge that had stopped detecting the loss at all
## — which is the one regression that must never ship, because it turns an
## honestly-incomplete capture into a silently-publishable one. So this
## file asserts BOTH arms against ONE merge:
##
##   * SWEPT thread   — its buffered read is on disk AND its pending is
##                      netted. No loss.
##   * UNSWEPT thread — arms its pending AFTER the sweep, so nothing ever
##                      makes its batch durable. The loss is STILL
##                      reported, under that thread's own identity.

import std/[atomics, os, strutils, tempfiles, unittest]

import io_mon
import io_mon/writer

const
  SweptPid = 700'u64
  SweptTid = 701'u64
  UnsweptPid = 800'u64
  UnsweptTid = 801'u64
  KillBeforeFlushDetail = "process killed with an un-flushed read batch"

type
  WorkerArgs = object
    dir: string
    osPid: uint64
    threadId: uint64
    armed: ptr Atomic[bool]
    release: ptr Atomic[bool]

proc armAndPark(args: WorkerArgs) {.thread.} =
  ## Append ONE captured-dependency record and then park WITHOUT flushing
  ## or closing. On return from `appendFragmentRecord` this thread has:
  ## a registered slot, a durable `read-tail-pending` marker on its
  ## fragment, and the read itself still in `batchBuf`. That is exactly the
  ## state a live worker thread is in when the process starts exiting.
  # `appendFragmentRecord` reads the module-global run token, which the
  # compiler flags as GC-unsafe for a `{.thread.}` proc. The token is set
  # once before either worker starts and never written again, so the
  # assertion is sound here; the shim itself runs this same path on every
  # worker thread it instruments.
  {.gcsafe.}:
    appendFragmentRecord(args.dir, MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead, seq: 1,
      osPid: args.osPid, threadId: args.threadId,
      path: "/tmp/swept-read", result: 4096))
  args.armed[].store(true)
  while not args.release[].load():
    sleep(2)
  # Park until the merge has been taken. Closing here would retire the
  # sentinel through the thread's OWN slot and destroy what this test
  # measures.

suite "shutdown sweep and the read-tail sentinel":

  test "a swept batch is netted; an unswept one is still reported lost":
    let dir = createTempDir("io_mon_cross_thread_sweep_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    setFragmentRunToken("")

    var sweptArmed, sweptRelease: Atomic[bool]
    var unsweptArmed, unsweptRelease: Atomic[bool]
    sweptArmed.store(false); sweptRelease.store(false)
    unsweptArmed.store(false); unsweptRelease.store(false)

    var swept: Thread[WorkerArgs]
    createThread(swept, armAndPark, WorkerArgs(dir: dir,
      osPid: SweptPid, threadId: SweptTid,
      armed: addr sweptArmed, release: addr sweptRelease))
    while not sweptArmed.load():
      sleep(2)

    # The shutdown sweep, run from a thread that is NOT the one holding the
    # dirty batch — the situation the Windows exit hook is always in.
    flushAllRegisteredSlots()

    # Only NOW does the second worker arm, so the sweep above cannot have
    # rescued it and its loss is genuine.
    var unswept: Thread[WorkerArgs]
    createThread(unswept, armAndPark, WorkerArgs(dir: dir,
      osPid: UnsweptPid, threadId: UnsweptTid,
      armed: addr unsweptArmed, release: addr unsweptRelease))
    while not unsweptArmed.load():
      sleep(2)

    let merged = mergeFragments(dir, dir / "merged.iomon")

    var sweptLosses = 0
    var unsweptLosses = 0
    var sweptReads = 0
    for record in merged.records:
      if record.kind == mrEventLoss and
          KillBeforeFlushDetail in record.detail:
        if record.osPid == SweptPid and record.threadId == SweptTid:
          inc sweptLosses
        elif record.osPid == UnsweptPid and record.threadId == UnsweptTid:
          inc unsweptLosses
      elif record.kind == mrFileRead and record.osPid == SweptPid:
        inc sweptReads

    # The rescue actually happened: the read reached the fragment file.
    # Without this the "no loss" assertion below could be satisfied by a
    # sweep that wrote nothing at all.
    check sweptReads == 1
    # ... and the pending it left behind was retired.
    check sweptLosses == 0
    # The control: the merge has NOT lost its ability to see a real
    # un-flushed tail.
    check unsweptLosses == 1

    sweptRelease.store(true)
    unsweptRelease.store(true)
    joinThread(swept)
    joinThread(unswept)
