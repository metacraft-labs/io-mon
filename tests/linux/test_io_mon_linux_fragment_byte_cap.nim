## test_io_mon_linux_fragment_byte_cap — LEAK-GUARD regression pin.
##
## Reproduces (and pins the fix for) the live-workstation resource leak in which
## the long-running reprobuild dev daemon held ONE monitor "data fragment" file
## (`repro-monitor-<pid>-<pid>.iomon-frag`) open WRITE-ONLY, kept appending to it
## for ~17.5h with no rotation / size cap, and — after the launcher's grace-period
## timeout removed the fragment dir (`fs_snoop.waitForLinuxInjectedDescendants`) —
## kept growing the now-UNLINKED (`(deleted)`) inode until it reached ~61 GiB and
## filled the tmpfs.
##
## Two intertwined defects, one regression each:
##   A. unbounded growth — `appendFragmentRecord` cached the per-thread fragment
##      fd and appended forever; only the in-MEMORY batch was bounded, never the
##      FILE. The fix caps the on-disk fragment at `fragmentByteCap`, writes a
##      single event-loss marker (⇒ `mcIncomplete`, fail-incomplete) and stops.
##   B. fd retained after unlink — a producer that outlived its monitor kept the
##      deleted inode's blocks alive through its still-open fd. The fix CLOSES the
##      fd at the cap, releasing the space.
##
## No mocks: the test drives the REAL writer (`appendFragmentRecord`,
## `flushFragmentBatch`, `mergeFragments`) against a real on-disk fragment and,
## for defect B, against a real UNLINKED inode observed through `/proc/self/fd`.

import std/[os, strutils, unittest]

import io_mon
import io_mon/writer

const
  # A small cap keeps the test fast; it is still several batch buffers
  # (the writer's internal batch is 64 KiB) so the cap trips on a batch boundary
  # the way it does in production, not on a hand-forced per-record flush.
  CapBytes = 256 * 1024
  # The writer flushes the on-disk fragment one 64 KiB batch at a time, so the
  # cap can overshoot by at most one batch before the next flush retires it.
  BatchBytes = 64 * 1024
  # How many bytes we ATTEMPT to write — far past the cap. On the pre-fix code
  # every one of these lands on disk (unbounded); post-fix the file is retired
  # near the cap and the rest are dropped.
  AttemptBytes = 16 * 1024 * 1024

proc fdPointsToDeletedFrag(fdLink: string): bool =
  ## True while `fdLink` (a `/proc/self/fd/<n>` entry) is a LIVE symlink whose
  ## target is a deleted `.iomon-frag` inode — i.e. the exact leaked state
  ## (`... .iomon-frag (deleted)`, fd still open). A closed fd leaves no symlink,
  ## so this reads false. `symlinkExists` inspects the LINK itself; `fileExists`
  ## would FOLLOW it to the already-removed target and always report false.
  if not symlinkExists(fdLink):
    return false
  let target =
    try: expandSymlink(fdLink)
    except OSError: return false
  ".iomon-frag" in target and target.endsWith("(deleted)")

proc victimRecord(dir: string; osPid, threadId, seqNo: uint64): MonitorRecord =
  MonitorRecord(
    kind: mrFileRead, observationKind: moFileRead, seq: seqNo,
    osPid: osPid, threadId: threadId,
    path: dir & "/victim-input-" & $seqNo & ".dat",
    detail: "leak-guard-victim-read")

suite "io-mon Linux fragment byte cap (LEAK-GUARD)":

  setup:
    setFragmentRunToken("")
    setFragmentByteCap(CapBytes)

  teardown:
    closeFragmentSlot()
    setFragmentByteCap(0)  # restore the built-in default for later suites.

  test "an over-cap fragment is bounded, retired, and marked incomplete":
    let dir = getTempDir() / ("io-mon-frag-cap-" & $getCurrentProcessId())
    createDir(dir)
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    let osPid = 4242'u64
    let threadId = 8484'u64
    let path = fragmentPath(dir, osPid, threadId)

    check fragmentByteCapValue() == CapBytes

    var written = 0
    var seqNo = 0'u64
    while written < AttemptBytes:
      inc seqNo
      let rec = victimRecord(dir, osPid, threadId, seqNo)
      appendFragmentRecord(dir, rec)
      # ~header + path + detail; the exact figure is irrelevant, we only need to
      # attempt FAR more than the cap.
      written += rec.path.len + rec.detail.len + 80
    flushFragmentBatch()

    # Defect A — the on-disk fragment is BOUNDED near the cap, not the many MiB
    # we attempted. Allow one extra full batch plus a small marker margin.
    check fileExists(path)
    let size = getFileSize(path)
    checkpoint("fragment size on disk: " & $size)
    check size <= CapBytes + BatchBytes + 4096
    check size.int < AttemptBytes  # would FAIL on the pre-fix unbounded writer.

    # Defect B — the slot's fd is CLOSED once the cap is hit (so a deleted inode's
    # blocks would be released), and the producer is retired.
    check fragmentSlotIsOverCap()
    check not sigSafeSlotIsOpen()

    # Further records for the same producer key are DROPPED, not appended.
    let sizeAfterCap = getFileSize(path)
    for extra in 0 ..< 5000:
      appendFragmentRecord(dir, victimRecord(dir, osPid, threadId,
        seqNo + 1 + uint64(extra)))
    flushFragmentBatch()
    check getFileSize(path) == sizeAfterCap

    # Fail-incomplete — the cap marker downgrades the merged depfile.
    let depOut = dir / "capped.iomon"
    let dep = mergeFragments(dir, depOut)
    check dep.completeness == mcIncomplete

  test "an UNLINKED fragment's fd is released at the cap (space reclaimed)":
    # Mirrors the production state directly: the launcher removed the fragment
    # dir, so the fragment is `(deleted)` while the producer still holds it open.
    let dir = getTempDir() / ("io-mon-frag-unlink-" & $getCurrentProcessId())
    createDir(dir)
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    let osPid = 909'u64
    let threadId = 1818'u64
    let path = fragmentPath(dir, osPid, threadId)

    # Open the fragment + grab its live fd.
    appendFragmentRecord(dir, victimRecord(dir, osPid, threadId, 1))
    flushFragmentBatch()
    let fd = sigSafeSlotFd()
    require fd >= 0
    let fdLink = "/proc/self/fd/" & $fd
    require fileExists(path)

    # Unlink the fragment out from under the still-open fd — now `(deleted)`.
    removeFile(path)
    check not fileExists(path)
    when defined(linux):
      check fdPointsToDeletedFrag(fdLink)  # the exact leaked state, reproduced.

    # Keep appending far past the cap against the deleted inode.
    var written = 0
    var seqNo = 1'u64
    while written < AttemptBytes:
      inc seqNo
      let rec = victimRecord(dir, osPid, threadId, seqNo)
      appendFragmentRecord(dir, rec)
      written += rec.path.len + rec.detail.len + 80
    flushFragmentBatch()

    # The producer retired and CLOSED the fd — the deleted inode is no longer
    # pinned, so its blocks are released instead of growing toward 61 GiB.
    check fragmentSlotIsOverCap()
    check not sigSafeSlotIsOpen()
    when defined(linux):
      # The fd is closed, so it no longer pins the deleted fragment inode — the
      # blocks are reclaimable. On the pre-fix writer the fd stays open and this
      # would still report the `... .iomon-frag (deleted)` leak.
      check not fdPointsToDeletedFrag(fdLink)
