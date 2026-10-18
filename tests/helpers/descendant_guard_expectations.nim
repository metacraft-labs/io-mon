## Subsystem oracles must keep rejecting every loss besides the explicit
## platform-wide tree-lifetime limitation. This helper first grades the REAL
## capture, then rebuilds its grade with only that exact diagnostic removed.
## It is for tests only; consumers must always honor the original verdict.
import std/[sets, strutils]
import io_mon

proc isDescendantLimitation*(record: MonitorRecord): bool =
  when defined(macosx) or defined(windows):
    const platform = when defined(macosx): "macos" else: "windows"
    const description = "detached-descendant quiescence cannot be established: " &
      platform & " backend has no complete tree-lifetime guard"
    if record.kind != mrEventLoss or record.observationKind != moEventLoss or
        not record.detail.startsWith(description): return false
    if record.detail.len <= description.len or
        record.detail[description.len] notin Whitespace: return false
    # nested_capture preserves descriptive whitespace, removes the old run=
    # token and appends run=<parent> nested-run=<child>. Further nesting retains
    # the earlier provenance tokens. Accept only this exact token vocabulary.
    let tokens = record.detail[description.len .. ^1].splitWhitespace()
    var runs = 0
    for token in tokens:
      let separator = token.find('=')
      if separator <= 0 or separator == token.high: return false
      let name = token[0 ..< separator]
      if name == "run": inc runs
      elif name != "nested-run": return false
      for ch in token[separator + 1 .. ^1]:
        if ch notin {'a'..'z', 'A'..'Z', '0'..'9', '-', '_', '.'}: return false
    return runs == 1
  else:
    false

proc subsystemEvidence*(dep: MonitorDepFile): MonitorDepFile =
  when defined(macosx) or defined(windows):
    var records: seq[MonitorRecord]
    var runMarkers = initHashSet[string]()
    for record in dep.records:
      if isDescendantLimitation(record):
        doAssert record.detail notin runMarkers, "duplicate run guard marker"
        runMarkers.incl record.detail
      else: records.add record
    # Direct shim + mergeFragments tests never call finishMonitor and have no
    # host guard marker. Their existing metadata and grade stay untouched.
    if runMarkers.len == 0: return dep
    doAssert dep.completeness == mcIncomplete,
      "real capture carrying the platform guard must fail incomplete"
    result = depFileFromRecords(records)
  else:
    result = dep

proc subsystemEvidence*(capture: MonitorResult): MonitorDepFile =
  subsystemEvidence(capture.depFile)
