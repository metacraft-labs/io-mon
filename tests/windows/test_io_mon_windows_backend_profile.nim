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

  test "M5's three capabilities are advertised":
    ## They were moved out of the gap list only once records flowed; the live
    ## tests in test_io_mon_windows_ipc_connect / _external_content /
    ## _non_determinism are what justify the move. This pins the declaration
    ## against a silent revert.
    for capability in [mcapIpcConnect, mcapExternalContent,
                       mcapNonDeterminism]:
      check capability in WindowsInterposeSupportedCapabilities
      check capability notin WindowsInterposeKnownUnsupportedCapabilities

  test "the capabilities still unattempted are declared as gaps":
    ## Closing some and quietly advertising the rest would be the exact
    ## over-claim M4 exists to prevent. These have no Windows record kind
    ## behind them and must keep saying so.
    ##
    ## The list was five after M5 and is FOUR after M10, which moved
    ## `mcapObservedEnv` out by giving it records. Nothing else moved: the
    ## four below are output-side or identity fidelity, exactly as they were.
    for capability in [mcapFileCreate, mcapFileTruncate, mcapFileAppend,
                       mcapRename, mcapSymlink, mcapPathMutation]:
      check capability in WindowsInterposeKnownUnsupportedCapabilities
      check capability notin WindowsInterposeSupportedCapabilities
    check mcapObservedEnv notin WindowsInterposeKnownUnsupportedCapabilities
    check mcapObservedEnv in WindowsInterposeSupportedCapabilities

  test "adding M5's capabilities did not make every Windows capture incomplete":
    ## None of the three is in `InputEvidenceCapabilities`, so advertising them
    ## must not move the completeness floor. The live tests cover the other
    ## direction -- that a real out-of-tree channel DOES downgrade.
    for capability in [mcapIpcConnect, mcapExternalContent,
                       mcapNonDeterminism]:
      check capability notin InputEvidenceCapabilities
    let profile = defaultHooksMonitorProfile()
    check profile.evidenceComplete

  test "no Windows gap is an INPUT channel any more, and the record says so":
    ## This case used to read "the ONE remaining input-channel gap says so in
    ## the record", and the one was `mcapObservedEnv`. M10 gave it records, so
    ## the count is now ZERO and the assertion is the stronger one: every gap
    ## Windows declares is output-side, identity fidelity, an alternative
    ## backend or a threat model, and each says `input=false` in the record a
    ## depfile actually carries.
    ##
    ## The distinction is still what decides what a consumer must DO about a
    ## capture, and it still lives in the record rather than in the free-text
    ## `reason`, where "renames are not classified" and "environment reads are
    ## not recorded" are one string-match apart and demand opposite responses.
    ## `required` does not answer it either -- `required` says only whether the
    ## CALLER asked for the capability. So a future capability added to the gap
    ## list without this being considered fails here.
    let profile = defaultHooksMonitorProfile()
    check profile.gaps.len > 0                # not vacuous
    for gap in profile.gaps:
      checkpoint("gap: " & capabilityId(gap.capability))
      check not gap.inputChannel
      # Serialised, parsed back, and still false -- the record is what a
      # depfile consumer actually reads, and this is the half a set-membership
      # assertion alone would not pin.
      let detail = gapDetail(gap)
      check detail.contains(";input=false;")
      check not parseGapDetail(detail).inputChannel

  test "the input= key still carries BOTH answers through the depfile":
    ## With no input-channel gap left on Windows, the profile above can only
    ## exercise `input=false`. That would let the true arm rot: a change that
    ## hard-coded `false` would pass every assertion in this file while
    ## silently telling every consumer that no gap anywhere is ever an input
    ## channel.
    ##
    ## So the true arm is pinned directly, on the capability that used to
    ## supply it. `mcapObservedEnv` is still in `InputChannelCapabilities` --
    ## being an input channel is a property of the CAPABILITY, not of whether
    ## this backend happens to implement it -- so a profile that does not
    ## support it must still emit `input=true`, which is what an older depfile
    ## from a pre-M10 shim contains and what a consumer reading one must get.
    check mcapObservedEnv in InputChannelCapabilities
    let gap = MonitorCapabilityGap(
      backendFamily: mbfWindowsInterposeHooks,
      capability: mcapObservedEnv,
      required: false,
      inputChannel: mcapObservedEnv in InputChannelCapabilities,
      reason: "pre-M10 Windows shim")
    let detail = gapDetail(gap)
    check detail.contains(";input=true;")
    check parseGapDetail(detail).inputChannel
    # And the derivation an OLD depfile relies on -- one written before the
    # `input=` key existed at all -- still answers true rather than defaulting
    # to false, which would be the same over-claim in a new place.
    let legacyDetail = "backend=windows-interpose-hooks;capability=" &
      "observed-env;required=false;reason=pre-M10 Windows shim"
    check parseGapDetail(legacyDetail).inputChannel

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
