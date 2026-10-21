## Adversarial controls for the test-only normalization used by live suites.
import std/[strutils, unittest]
import io_mon
import descendant_guard_expectations

suite "descendant limitation oracle keeps unrelated losses":
  test "manual evidence without a guard is returned unchanged":
    let dep = depFileFromRecords(@[MonitorRecord(kind: mrFileRead,
      observationKind: moFileRead, path: "/input")])
    check subsystemEvidence(dep) == dep

  when defined(macosx):
    const detail = "detached-descendant quiescence cannot be established: " &
      "macos backend has no complete tree-lifetime guard run=test-run"
    let guard = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
      osPid: 1, detail: detail)

    test "exact diagnostic is the only loss removed":
      let dep = depFileFromRecords(@[guard])
      check dep.completeness == mcIncomplete
      check subsystemEvidence(dep).completeness == mcComplete
      check subsystemEvidence(dep).summary.eventLossCount == 0

    test "a similar diagnostic stays incomplete":
      var similar = guard
      similar.detail.add " extra-loss"
      let dep = depFileFromRecords(@[similar])
      check not isDescendantLimitation(similar)
      check subsystemEvidence(dep) == dep
      check subsystemEvidence(dep).completeness == mcIncomplete

    test "an unrelated loss survives beside the exact diagnostic":
      let other = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
        detail: "actual missing file observation")
      let dep = depFileFromRecords(@[guard, other])
      let normalized = subsystemEvidence(dep)
      check normalized.completeness == mcIncomplete
      check normalized.summary.eventLossCount == 1
      check normalized.records == @[other]

    test "a missing token separator cannot hide a loss":
      var malformed = guard
      malformed.detail = detail.replace(" guard run=", " guardrun=")
      check not isDescendantLimitation(malformed)
      check subsystemEvidence(depFileFromRecords(@[malformed])).completeness == mcIncomplete

    test "nested handoff provenance preserves the exact diagnostic":
      var nested = guard
      nested.detail = detail.replace(" run=test-run", "  run=parent nested-run=child")
      check isDescendantLimitation(nested)
      check subsystemEvidence(depFileFromRecords(@[nested])).completeness == mcComplete
      nested.detail.add " unrelated=loss"
      check not isDescendantLimitation(nested)
      check subsystemEvidence(depFileFromRecords(@[nested])).completeness == mcIncomplete

    test "a duplicate run marker is rejected":
      expect AssertionDefect:
        discard subsystemEvidence(depFileFromRecords(@[guard, guard]))

  when defined(windows):
    # Windows has a real tree-lifetime guard, so the oracle must normalize
    # NOTHING there. In particular the retired blanket marker, and every one of
    # the guard's own losses, must keep a capture incomplete: a Windows suite
    # that grades through `subsystemEvidence` asserts the real verdict.
    const retired = "detached-descendant quiescence cannot be established: " &
      "windows backend has no complete tree-lifetime guard run=test-run"

    test "the retired Windows marker is not a limitation":
      let marker = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
        osPid: 1, detail: retired)
      check not isDescendantLimitation(marker)
      let dep = depFileFromRecords(@[marker])
      check subsystemEvidence(dep) == dep
      check subsystemEvidence(dep).completeness == mcIncomplete

    test "a Windows guard loss is never normalized away":
      for detail in [
          "windows job descendants still live after root exit active=1 " &
            "pids=4242 images=sleeper.exe run=test-run",
          "windows tree-lifetime guard unavailable: CreateJobObjectW " &
            "failed err=6 run=test-run"]:
        let loss = MonitorRecord(kind: mrEventLoss,
          observationKind: moEventLoss, osPid: 1, detail: detail)
        check not isDescendantLimitation(loss)
        check subsystemEvidence(depFileFromRecords(@[loss])).completeness ==
          mcIncomplete
