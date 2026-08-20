## The Windows backend must declare itself, and declare only what it does.
##
## `defaultHooksMonitorProfile` had no Windows branch and fell through to the
## macOS one, so every Windows depfile carried
## `backend=macos-interpose-hooks` and the macOS capability set. That is not a
## labelling nit. The advertised set is what a consumer reads to decide which
## observation channels the evidence covers, and `InputEvidenceCapabilities`
## is the subset whose absence forces `mcIncomplete` -- so inheriting macOS's
## list let Windows assert coverage of channels it had no record kind for, and
## `mcComplete` on Windows was asserted rather than earned.
##
## The most consequential entry was `mcapLibraryLoad`: the loaded-DLL closure
## was observed by nothing, while the profile said it was covered. An in-place
## upgrade of a toolchain DLL behind an unchanged path would not have
## invalidated a cached action.
##
## These tests pin both halves of the contract -- that the declaration is
## Windows', and that it stays honest -- so a future capability added to the
## set has to come with the records that justify it.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, strutils, tempfiles, unittest]

import io_mon
import io_mon/capabilities
import io_mon/fs_snoop
import io_mon/types

suite "Windows backend profile":

  test "the default profile is the Windows one":
    let profile = defaultHooksMonitorProfile()
    check profile.backendFamily == mbfWindowsInterposeHooks
    check backendFamilyId(profile.backendFamily) == "windows-interpose-hooks"

  test "every advertised capability is met by the floor it participates in":
    # A backend may advertise more than the floor; it may not advertise less
    # of the floor while claiming completeness. This is the check that would
    # have failed while Windows lacked library-load observation.
    let profile = defaultHooksMonitorProfile(WindowsInterposeSupportedCapabilities)
    for capability in InputEvidenceCapabilities:
      check capability in profile.supportedCapabilities

  test "supported and known-unsupported are disjoint":
    # A capability in both lists would produce a gap record contradicting the
    # supported list in the same banner.
    for capability in WindowsInterposeSupportedCapabilities:
      check capability notin WindowsInterposeKnownUnsupportedCapabilities

  test "unsupported capabilities are reported as gaps, not omitted":
    let profile = defaultHooksMonitorProfile(WindowsInterposeSupportedCapabilities)
    var reported: set[MonitorCapability] = {}
    for gap in profile.gaps:
      reported.incl gap.capability
    for capability in WindowsInterposeKnownUnsupportedCapabilities:
      check capability in reported

  test "a gap outside the required set does not clear evidenceComplete":
    # The gaps are real but none of them is an unobserved INPUT channel, so
    # they must not make every Windows capture incomplete -- that would
    # destroy the signal rather than sharpen it.
    let profile = defaultHooksMonitorProfile(WindowsInterposeSupportedCapabilities)
    check profile.evidenceComplete
    for gap in profile.gaps:
      check not gap.required

suite "Windows library-load observation":

  test "a monitored process reports the images it mapped":
    ## The capability has to be backed by records, not just declared. `cmd`
    ## maps its own import closure, so a live run must produce several.
    let dir = createTempDir("io_mon_libload_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    let depFilePath = dir / "run.rdep"
    var request = FsSnoopRequest(
      command: @[getEnv("ComSpec", r"C:\Windows\System32\cmd.exe"), "/c", "ver"],
      depFilePath: depFilePath,
      captureChildStdio: true)
    let result = runMonitored(request)

    var libraryLoads = 0
    for r in result.records:
      if r.kind == mrLibraryLoad:
        inc libraryLoads
    check libraryLoads > 0

    # And the run stays complete: the enumeration runs on the injector's
    # remote init thread, whose read batch has to be flushed before that
    # thread exits or the records become a kill-before-flush loss instead.
    check result.completeness == mcComplete

  test "library loads are recorded as reads so their bytes are fingerprinted":
    # `moFileRead` is what makes an in-place DLL upgrade bust a cached action.
    # Recording the load under any other observation kind would leave the
    # dependency visible to inspection but absent from the cache key.
    let dir = createTempDir("io_mon_libload_kind_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard

    var request = FsSnoopRequest(
      command: @[getEnv("ComSpec", r"C:\Windows\System32\cmd.exe"), "/c", "ver"],
      depFilePath: dir / "run.rdep",
      captureChildStdio: true)
    let result = runMonitored(request)

    for r in result.records:
      if r.kind == mrLibraryLoad:
        check r.observationKind == moFileRead
        check r.path.len > 0
