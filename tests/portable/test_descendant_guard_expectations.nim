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
    # macOS has a real tree-lifetime guard now (the kernel census), so the
    # oracle must normalize NOTHING here either. The retired blanket marker,
    # and every one of the guard's own losses, must keep a capture incomplete.
    const retired = "detached-descendant quiescence cannot be established: " &
      "macos backend has no complete tree-lifetime guard run=test-run"

    test "the retired macOS marker is not a limitation":
      for detail in [retired, retired.replace(" run=test-run",
          "  run=parent nested-run=child")]:
        let marker = MonitorRecord(kind: mrEventLoss,
          observationKind: moEventLoss, osPid: 1, detail: detail)
        check not isDescendantLimitation(marker)
        let dep = depFileFromRecords(@[marker])
        check subsystemEvidence(dep) == dep
        check subsystemEvidence(dep).completeness == mcIncomplete

    test "a macOS guard loss is never normalized away":
      for detail in [
          "macos descendants still live after root exit live=1 " &
            "pids=4242 images=sleeper run=test-run",
          "macos tree-lifetime guard could not classify young processes " &
            "after root exit unresolved=1 pids=4243 images=tool run=test-run",
          "macos tree-lifetime guard failed: sysctl(KERN_PROC_ALL) census " &
            "failed errno=22 run=test-run"]:
        let loss = MonitorRecord(kind: mrEventLoss,
          observationKind: moEventLoss, osPid: 1, detail: detail)
        check not isDescendantLimitation(loss)
        check subsystemEvidence(depFileFromRecords(@[loss])).completeness ==
          mcIncomplete

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
