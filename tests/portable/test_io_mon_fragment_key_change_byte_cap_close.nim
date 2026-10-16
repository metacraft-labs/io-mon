## test_io_mon_fragment_key_change_byte_cap_close — the fragment writer closes
## each descriptor it owns exactly once when a key change retires a fragment at
## the byte cap.
##
## ``appendFragmentRecord`` reacts to a new (osPid, threadId, fragmentDir) key
## by flushing the previous key's batch and closing its handle. The flush ends
## in ``accountFragmentBytes``, which RETIRES the fragment once it reaches
## ``fragmentByteCap``: it writes the cap marker and closes the descriptor
## itself. The key-change path then closed the same handle a second time. In
## the shim that second ``close`` is not harmless: by then the descriptor
## number may have been reused by the tracee, and closing it closes the
## tracee's file. ``closeFragmentSlot`` already guards this with
## ``if slot.isOpen``; the key-change path did not.
##
## The second close cannot be observed through the file system in one thread
## (nothing reuses the number between the two closes, so it fails with
## ``EBADF`` on Linux and on macOS' ``fclose``). The test therefore counts the
## closes the writer issues (``fragmentLogCloseCount``) against the handles it
## opened (``fragmentLogOpenCount``): a close count above the open count is a
## close of a handle the writer no longer owns.
##
## No mocks: the test drives the real writer against real files in a temp dir.

import std/[os, tempfiles, unittest]

import io_mon
import io_mon/writer

proc writeRecord(seq: uint64; osPid, threadId: uint64;
                 path: string): MonitorRecord =
  # A write, not a read: reads raise the read-tail sentinel, whose marker is a
  # descriptor touch of its own and is not what this test is about.
  MonitorRecord(kind: mrFileWrite, observationKind: moFileWrite, seq: seq,
    osPid: osPid, parentOsPid: 1, threadId: threadId, result: 3,
    probeResult: prUnknown, path: path)

suite "io-mon fragment writer — key change at the byte cap":

  test "a key change that retires the fragment closes its handle once":
    closeFragmentSlot()
    setFragmentRunToken("")
    # One byte: the first flush of any frame reaches the cap, so the flush the
    # key change issues is the one that retires the fragment.
    setFragmentByteCap(1)
    let dir = createTempDir("io_mon_key_change_cap_", "")
    defer:
      closeFragmentSlot()
      setFragmentByteCap(0)
      try: removeDir(dir)
      except CatchableError: discard
    resetFragmentLogOpenCount()
    resetFragmentLogCloseCount()

    appendFragmentRecord(dir, writeRecord(1, 100, 200, dir / "first"))
    # Precondition: the record is still buffered, so the cap has not been
    # reached yet and the key change below is what retires the fragment.
    require sigSafeSlotIsOpen()
    require not fragmentSlotIsOverCap()
    require sigSafeBatchLen() > 0
    check fragmentLogOpenCount() == 1
    check fragmentLogCloseCount() == 0

    # Same thread, different osPid: the key change flushes key A's batch,
    # which reaches the cap and closes A's handle, then opens key B.
    appendFragmentRecord(dir, writeRecord(2, 101, 200, dir / "second"))
    check fragmentLogOpenCount() == 2
    check fragmentLogCloseCount() == 1
    check sigSafeSlotIsOpen()

    closeFragmentSlot()
    check fragmentLogOpenCount() == 2
    check fragmentLogCloseCount() == 2

    # The retired fragment carries the cap marker, so the run reads as
    # incomplete; key B's fragment exists beside it.
    check fileExists(fragmentPath(dir, 100, 200))
    check fileExists(fragmentPath(dir, 101, 200))
    let dep = mergeFragments(dir, dir / "merged.iomon")
    check dep.completeness == mcIncomplete
