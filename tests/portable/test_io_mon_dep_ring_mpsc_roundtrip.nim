## test_io_mon_dep_ring_mpsc_roundtrip — milestone io-mon-DEP-SHM, item
## DEP-SHM-1. Pure data-structure unit test of the shared-memory dep queue's
## ring + record codec, mirroring reprobuild's AC-2a ring tests:
##   * codec round-trip (every MonitorRecord field survives)
##   * push/drain exactly-once below capacity + FIFO order
##   * ring wraparound (drain to make room, keep pushing past DepRingCap)
##   * drop-on-full is SIGNALLED (counted) not silent
##   * oversize record is rejected (dpsOversized -> caller falls to files)
##
## Named test: `t_dep_ring_mpsc_roundtrip`.
##
## Falsifiable: dropping the release-store of `ready` in `tryPushRecord`, or
## the CAS on `tail`, breaks the exactly-once/FIFO tally below.

import std/[os, strutils, tempfiles, unittest]

import io_mon/types
import io_mon/shm/dep_queue

suite "io-mon DEP-SHM dep ring MPSC roundtrip":
  when depQueueSupported:
    test "t_dep_ring_mpsc_roundtrip":
      # --- codec: every field round-trips ---------------------------------
      block codec:
        let r = MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
          seq: 42, osPid: 1234, parentOsPid: 12, threadId: 7, childOsPid: 99,
          result: -5, flags: 0xABCD'u32, probeResult: prExistingFile,
          path: "/some/deep/path/to/a/dependency.h",
          detail: "run=xyz ctx=[phase=emit]")
        var buf: array[DepSlotRecCap, byte]
        let n = encodeDepRecord(r, buf)
        check n > 0
        var ok = false
        let d = decodeDepRecord(buf.toOpenArray(0, n - 1), ok)
        check ok
        check d.kind == r.kind
        check d.observationKind == r.observationKind
        check d.seq == r.seq
        check d.osPid == r.osPid
        check d.parentOsPid == r.parentOsPid
        check d.threadId == r.threadId
        check d.childOsPid == r.childOsPid
        check d.result == r.result
        check d.flags == r.flags
        check d.probeResult == r.probeResult
        check d.path == r.path
        check d.detail == r.detail

      # --- oversize record is rejected ------------------------------------
      block oversize:
        let tempRoot = createTempDir("io-mon-dep-ring-ovr", "")
        defer: removeDir(tempRoot)
        var cons = createDepQueue(tempRoot, "edgeOvr")
        check cons.available
        var prod = attachDepQueue(tempRoot, "edgeOvr")
        check prod.available
        let big = MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
          osPid: 1, path: "x".repeat(DepSlotRecCap + 100))
        check prod.tryPushRecord(big) == dpsOversized
        prod.detach()
        cons.detach()

      # --- push/drain exactly-once + FIFO + wraparound --------------------
      block roundtrip:
        let tempRoot = createTempDir("io-mon-dep-ring", "")
        defer: removeDir(tempRoot)
        var cons = createDepQueue(tempRoot, "edgeA")
        check cons.available
        var prod = attachDepQueue(tempRoot, "edgeA")
        check prod.available

        # Push 3x the ring capacity, draining as we go so the ring wraps around
        # many times. Each record carries a unique seq we verify on drain.
        let total = DepRingCap * 3
        var pushed = 0
        var drained = 0
        var expectSeq: uint64 = 0
        var fifoOk = true
        while pushed < total:
          let r = MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
            seq: uint64(pushed), osPid: 55, threadId: 1,
            path: "/dep/" & $pushed)
          case prod.tryPushRecord(r)
          of dpsPushed:
            inc pushed
          of dpsDropped:
            # Ring momentarily full — drain one to make room (single consumer).
            var got: MonitorRecord
            if cons.tryDrainOne(got):
              if got.seq != expectSeq: fifoOk = false
              inc expectSeq
              inc drained
          of dpsOversized, dpsUnavailable:
            check false
        # Drain the tail.
        var got: MonitorRecord
        while cons.tryDrainOne(got):
          if got.seq != expectSeq: fifoOk = false
          inc expectSeq
          inc drained

        check pushed == total
        check drained == total          # exactly-once: none lost, none dup
        check fifoOk                     # arrival (FIFO) order preserved
        prod.detach()
        cons.detach()

      # --- drop-on-full is SIGNALLED (counted), not silent ----------------
      block dropSignal:
        let tempRoot = createTempDir("io-mon-dep-ring-full", "")
        defer: removeDir(tempRoot)
        var cons = createDepQueue(tempRoot, "edgeFull")
        check cons.available
        var prod = attachDepQueue(tempRoot, "edgeFull")
        check prod.available
        # Fill WITHOUT draining so the ring saturates; the excess is a signalled
        # drop counted in the atomic `dropped`.
        var accepted = 0
        var dropped = 0
        let attempts = DepRingCap + 300
        for i in 0 ..< attempts:
          let r = MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
            seq: uint64(i), osPid: 1, path: "/x/" & $i)
          case prod.tryPushRecord(r)
          of dpsPushed: inc accepted
          of dpsDropped: inc dropped
          else: discard
        check accepted == DepRingCap
        check dropped == 300
        check cons.droppedCount() == 300'u64   # signalled via the counter
        prod.detach()
        cons.detach()
  else:
    test "t_dep_ring_mpsc_roundtrip":
      skip()   # non-POSIX host: dep queue unavailable, file path is the channel
