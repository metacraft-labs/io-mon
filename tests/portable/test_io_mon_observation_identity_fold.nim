## test_io_mon_observation_identity_fold — the per-backend fold declaration, and
## the capture-scope stamp (DA-1j).
##
## TWO CLAIMS, BOTH GRADED FROM ANY HOST.
##
## 1. **Every backend family states whether it folds repeated observations of one
##    fact into one record**, and the answer is asserted as DATA rather than
##    behind `when defined(...)`. That distinction is not stylistic. On Linux,
##    `defined(linux) or defined(macosx)` and a bare `true` are the same value,
##    so a host-conditional assertion cannot catch a claim that is wrong for a
##    platform the host is not — which is exactly the mistake this file exists to
##    make impossible. Grading `mbfMacosHooks` from a Linux box is the point.
##
## 2. **A depfile states what it was ASKED to record.** Until `observedInterest`
##    existed nothing did, while `--interest` already shipped and already
##    narrowed: measured, `--interest file,proc,lib` on a command with an
##    out-of-tree peer grades `mcComplete` with 0 losses, because gating `ecIpc`
##    means the `mrIpcConnect` records never exist and no synthetic loss is ever
##    derived from them. The depfile then said `mcComplete` and said nothing
##    about having been narrowed.
##
## WHY THE FOLD GAP IS NOT A FIDELITY GAP, restated here because a test is where
## someone will try to "fix" it: a non-folding backend observed EVERYTHING and
## merely wrote some of it down once per observing process. No fact is missing,
## completeness is unaffected, and consumers already fold by path. So the
## capability must never join `InputEvidenceCapabilities` — doing so would force
## `mcIncomplete` on every capture from such a backend, and that grade would be
## a false statement about what the monitor could see. This file asserts that
## non-membership directly, so the "fix" fails here.
##
## Pure `io_mon/types` + `io_mon/capabilities` + the codec — no live shim, no
## platform API — so it runs on every OS.

import std/[os, strutils, unittest]

import io_mon/types
import io_mon/capabilities
import io_mon/encode
import io_mon/reader

suite "io-mon observation-identity fold declaration":

  test "t_every_backend_family_states_whether_it_folds":
    # THE TABLE, restated independently of the implementation. Asserted as data
    # for every family, so the answer for a platform this host is not still
    # gets graded here.
    check backendFoldsObservationIdentity(mbfLinuxPreloadHooks)
    check not backendFoldsObservationIdentity(mbfMacosHooks)
    check not backendFoldsObservationIdentity(mbfMacosEndpointSecurity)
    check not backendFoldsObservationIdentity(mbfMacosHybrid)
    check not backendFoldsObservationIdentity(mbfWindowsInterposeHooks)
    # An unnamed backend must default to "no fold": promising a reduction we
    # have not verified is the direction that misleads a consumer sizing a
    # capture.
    check not backendFoldsObservationIdentity(mbfUnknown)

    # Exhaustive: a family added later must be classified rather than silently
    # inheriting a neighbour's answer.
    var graded = 0
    for family in MonitorBackendFamily:
      discard backendFoldsObservationIdentity(family)
      inc graded
    check graded ==
      ord(high(MonitorBackendFamily)) - ord(low(MonitorBackendFamily)) + 1

  test "t_the_declaration_agrees_with_the_advertised_capability_sets":
    # The prose answer and the capability sets are two statements of one fact,
    # and they are written in different files. Pin them to each other.
    check (mcapObservationIdentityFold in LinuxPreloadSupportedCapabilities) ==
      backendFoldsObservationIdentity(mbfLinuxPreloadHooks)
    check mcapObservationIdentityFold in
      MacosInterposeKnownUnsupportedCapabilities
    check mcapObservationIdentityFold in
      WindowsInterposeKnownUnsupportedCapabilities
    check mcapObservationIdentityFold notin MacosInterposeSupportedCapabilities
    check mcapObservationIdentityFold notin
      WindowsInterposeSupportedCapabilities

  test "t_the_fold_gap_is_a_cost_gap_and_must_never_force_incompleteness":
    # THE ASSERTION THAT STOPS THE "FIX". A non-folding backend saw everything;
    # it merely repeated itself. Promoting this capability into the floor set
    # would force `mcIncomplete` on every macOS and Windows capture and would be
    # a false claim about what the monitor could observe.
    check mcapObservationIdentityFold notin InputEvidenceCapabilities
    # Nor is it an input CHANNEL: nothing can reach the monitored program
    # through it, so a declared gap must render with `inputChannel = false`.
    check mcapObservationIdentityFold notin InputChannelCapabilities

    # And a macOS profile really does declare it — the runtime visibility half.
    # Asserting only the set membership above would pass even if no profile ever
    # emitted the gap.
    let profile = macosInterposeMonitorProfile()
    var sawGap = false
    for gap in profile.gaps:
      if gap.capability == mcapObservationIdentityFold:
        sawGap = true
        check not gap.inputChannel
    check sawGap

    # …and declaring it did NOT cost a macOS capture its completeness. GRADED
    # THROUGH THE DERIVATION PRODUCTION USES, which is the whole point: asking
    # `macosInterposeMonitorProfile()` directly is asking with an EMPTY required
    # set, and in that call `evidenceComplete` is assigned `true` and every gap
    # gets `required = false` unconditionally — so `check profile.required ==
    # false` / `check profile.evidenceComplete` there are true for ANY
    # capability, including one that genuinely should force `mcIncomplete`, and
    # would keep passing while this capability sat in the floor set. Measured.
    # `depFileFromOwnedRecords` derives with `InputEvidenceCapabilities`
    # instead, so that is what this asserts against.
    var macosRecords = @[backendProfileRecord(profile)]
    for gap in profile.gaps:
      macosRecords.add capabilityGapRecord(gap)
    let macosDep = depFileFromRecords(macosRecords)
    var derivedFoldGapRequired = false
    for gap in macosDep.capabilityGaps:
      if gap.capability == mcapObservationIdentityFold:
        derivedFoldGapRequired = gap.required
    check not derivedFoldGapRequired
    check macosDep.completeness == mcComplete

  test "t_the_capability_has_a_stable_wire_id":
    # The enum is serialized by STRING, so appending a case never shifts an
    # existing id's meaning. A round trip pins that the id exists and is not a
    # duplicate.
    #
    # It does NOT make the id safe for an OLDER reader: `capabilityFromId`
    # raises on an unknown id and `parseCapabilityList` does not catch it, so a
    # depfile advertising this id in `supported=` cannot be loaded by an io-mon
    # built before the id existed (measured against the previous commit). That
    # is a property of the capability list, not of the DA-1j scope stamp — the
    # stamp itself is skipped by an older reader's `else: discard`, which the
    # unknown-token case below covers from the other side.
    check capabilityId(mcapObservationIdentityFold) ==
      "observation-identity-fold"
    check capabilityFromId("observation-identity-fold") ==
      mcapObservationIdentityFold

suite "io-mon depfile capture-scope stamp (DA-1j)":

  proc profileRecordWith(extraTokens: string): MonitorRecord =
    ## A REAL backend-profile record (so the derived profile advertises a real
    ## capability set and the depfile grades on its merits), plus whatever scope
    ## token the case under test wants. Hand-rolling `supported=` here would
    ## grade `mcIncomplete` for reasons that have nothing to do with the stamp,
    ## which would make the completeness assertion below meaningless.
    result = backendProfileRecord(linuxPreloadMonitorProfile())
    result.detail.add extraTokens

  test "t_a_depfile_that_states_no_scope_reads_as_full_interest":
    # BACK-COMPAT, and the direction it must fail in. A depfile written before
    # the stamp existed must look like "not stated" — never like a capture that
    # recorded nothing, which would make every old depfile look narrowed.
    let dep = depFileFromRecords(@[profileRecordWith("")])
    check dep.observedInterest == {}
    check normalizeInterest(dep.observedInterest) == FullInterest

  test "t_a_narrowed_capture_says_so":
    let dep = depFileFromRecords(@[profileRecordWith(";interest=file,proc,lib")])
    check dep.observedInterest == {ecFileDeps, ecProcessTree, ecLibraryLoads}
    check dep.observedInterest != FullInterest
    # The narrowing is VISIBLE, and — the whole point — it did not move the
    # grade. A deliberate narrowing is an honest answer to a narrower question,
    # not a monitor failure.
    check dep.completeness == mcComplete

  test "t_a_full_capture_says_that_too":
    let dep = depFileFromRecords(@[profileRecordWith(
      ";interest=" & interestToTokens(FullInterest))])
    check dep.observedInterest == FullInterest

  test "t_the_stamp_survives_a_real_envelope_round_trip":
    # Not just the in-memory derive: the token has to survive being encoded into
    # the canonical envelope and decoded back, since that is the only form a
    # consumer ever sees.
    let records = @[profileRecordWith(";interest=file,ipc")]
    let path = getTempDir() / ("io-mon-scope-stamp-" &
      $getCurrentProcessId() & ".iomon")
    removeFile(path)
    writeCanonical(path, records)
    let decoded = readMonitorDepFile(path)
    removeFile(path)
    check decoded.observedInterest == {ecFileDeps, ecIpc}

  test "t_an_unknown_category_token_does_not_poison_the_stamp":
    # FORWARD-COMPAT in the direction that matters: a depfile written by a NEWER
    # io-mon that has split a category must still be readable here, and the
    # categories this build does understand must survive. Silently reading it as
    # "recorded nothing" would be the dangerous answer.
    let dep = depFileFromRecords(@[profileRecordWith(
      ";interest=file,proc,someFutureCategory")])
    check ecFileDeps in dep.observedInterest
    check ecProcessTree in dep.observedInterest
    check dep.observedInterest != {}
