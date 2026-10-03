## Cooperating macOS hosts hand observed child evidence to their enclosing run.
## A pending loss fragment remains until publication succeeds, including when
## the host dies or abandons its monitor. No dependency observations are invented.
import std/[os, strutils]
import io_mon/[encode, types]
from io_mon/paths import extendedPath

type NestedCapture* = object
  parentRun, sourceRun, pendingPath, evidencePath: string

proc active*(capture: NestedCapture): bool = capture.pendingPath.len > 0

proc checkedClose(file: File) =
  # Nim's default close/flushFile discard stdio errors. A buffered final write
  # must reach the OS before the pending loss marker may disappear.
  proc cClose(file: File): cint {.importc: "fclose", header: "<stdio.h>".}
  if cClose(file) != 0:
    raise newException(IOError, "cannot flush nested monitor evidence")

proc writeRecord(file: File; record: MonitorRecord) =
  let frame = encodeFrame(record)
  if frame.len > 0 and file.writeBuffer(unsafeAddr frame[0], frame.len) != frame.len:
    raise newException(IOError, "short write publishing nested monitor evidence")

proc startNestedCapture*(fragmentDir, parentRun, sourceRun: string): NestedCapture =
  if fragmentDir.len == 0 or parentRun.len == 0:
    return
  result.parentRun = parentRun
  result.sourceRun = sourceRun
  # sourceRun is the host's freshly generated nonce, not a caller-supplied path.
  let prefix = fragmentDir / ("nested-" & sourceRun)
  result.pendingPath = prefix & "-pending.iomon-frag"
  result.evidencePath = prefix & ".iomon-frag"
  let file = open(extendedPath(result.pendingPath), fmWrite)
  try:
    file.writeRecord(MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
      detail: "nested monitor evidence handoff pending run=" & parentRun &
        " nested-run=" & sourceRun))
  finally:
    checkedClose(file)

proc parentDetail(detail, parentRun, sourceRun: string): string =
  # Only identity tokens change. Preserve the rest byte-for-byte, including
  # whitespace in descriptive fields. mergeFragments already validated these
  # records and rejected duplicate or stale run identities.
  var pos = 0
  while pos < detail.len:
    if (pos == 0 or detail[pos - 1] in Whitespace) and
        detail.continuesWith("run=", pos):
      while pos < detail.len and detail[pos] notin Whitespace:
        inc pos
    else:
      result.add detail[pos]
      inc pos
  result.add " run=" & parentRun & " nested-run=" & sourceRun

proc finishNestedCapture*(capture: NestedCapture;
                          records: openArray[MonitorRecord]) =
  if not capture.active:
    return
  let staging = capture.evidencePath & ".partial"
  try:
    let file = open(extendedPath(staging), fmWrite)
    try:
      for source in records:
        # Each consumer stamps its own output scope. Loss and capability-gap
        # records still flow, so an incomplete inner run cannot become complete.
        if source.kind == mrBackendProfile:
          continue
        var record = source
        record.detail = parentDetail(source.detail, capture.parentRun, capture.sourceRun)
        file.writeRecord(record)
    finally:
      checkedClose(file)
    moveFile(staging, capture.evidencePath)
    removeFile(capture.pendingPath)
  finally:
    if fileExists(staging):
      removeFile(staging)
