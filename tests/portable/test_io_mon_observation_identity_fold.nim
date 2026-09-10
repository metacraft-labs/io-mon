## test_io_mon_observation_identity_fold — the per-backend fold declaration, and
## the capture-scope stamp (DA-1j).
##
## THREE CLAIMS, ALL GRADED FROM ANY HOST. (Claim 3 is stated after the fold-gap
## digression below, which belongs with claim 1.)
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
## 3. **A reader survives a writer from the future.** The depfile format grows by
##    APPENDING capability ids, and until now an id an older build could not name
##    escaped `readMonitorDepFile` as an unhandled `ValueError` — the whole file
##    unreadable because of one token in a `supported=` list. The decode path now
##    degrades and REPORTS the id instead. Graded here over real bytes.
##
## Pure `io_mon/types` + `io_mon/capabilities` + the codec, plus `io_mon/writer`'s
## `mergeFragments` — which is a pure merge over a fragment directory, so this
## file still needs no live shim and no platform API and runs on every OS. The
## write side is imported deliberately: DA-1j's stamp is WRITTEN there, and a
## milestone graded only on the read side survived deleting the writer entirely.

import std/[options, os, strutils, unittest]

import io_mon/types
import io_mon/capabilities
import io_mon/encode
import io_mon/reader
import io_mon/writer

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
    # That was only ever HALF the compatibility story, and the other half is now
    # fixed rather than merely documented: `capabilityFromId` raised on an
    # unknown id and `parseCapabilityList` did not catch it, so a depfile
    # advertising a newly-added id in `supported=` could not be loaded AT ALL by
    # an io-mon built before that id existed (measured against `715266b`: rc=1,
    # unhandled `ValueError`). The decode path now degrades — see the two cases
    # below. It cannot be fixed for binaries that were ALREADY built, which is
    # why those cases assert the degrade rather than the raise.
    check capabilityId(mcapObservationIdentityFold) ==
      "observation-identity-fold"
    check capabilityFromId("observation-identity-fold") ==
      mcapObservationIdentityFold
    # The strict form still raises for a caller that has decided an unknown id
    # is a bug; the tolerant form is what the decoder uses.
    expect ValueError:
      discard capabilityFromId("no-such-capability-id")
    check tryCapabilityFromId("no-such-capability-id").isNone
    check tryCapabilityFromId("observation-identity-fold").isSome

suite "io-mon depfile tolerance of a writer from the future":

  proc profileRecordWithUnknownCapability(): MonitorRecord =
    ## A REAL Linux backend-profile record with ONE extra id spliced into both
    ## capability lists — the exact shape a newer io-mon writes after appending a
    ## capability, and the shape that used to make this file unreadable.
    result = backendProfileRecord(linuxPreloadMonitorProfile(
      {mcapFileRead, mcapProcessTree}))
    result.detail = result.detail
      .replace(";supported=", ";supported=quantum-observation-collapse,")
      .replace(";required=", ";required=quantum-observation-collapse,")

  test "t_a_capability_id_this_build_cannot_name_does_not_kill_the_read":
    # THE HEADLINE, over REAL BYTES rather than an in-memory derive: the file has
    # to survive `writeCanonical` + `readMonitorDepFile`, which is the only path
    # a consumer ever uses and the exact path the `ValueError` used to escape
    # from.
    let path = getTempDir() / ("io-mon-unknown-cap-" &
      $getCurrentProcessId() & ".iomon")
    removeFile(path)
    writeCanonical(path, @[profileRecordWithUnknownCapability()])
    # No `expect`, no `try`: the point is that NOTHING is raised. A raise here
    # fails the case by escaping it, which is the correct verdict.
    let dep = readMonitorDepFile(path)
    removeFile(path)

    # The ids this build DOES know survived the unknown one sitting beside them —
    # the degrade is per-id, not "give up on the list".
    check mcapFileRead in dep.profile.supportedCapabilities
    check mcapProcessTree in dep.profile.supportedCapabilities
    check mcapObservationIdentityFold in dep.profile.supportedCapabilities

    # And the grade did not move. An unnamable id in `supported=` is counted as
    # UNSUPPORTED, which under-claims the backend; it can never clear
    # `evidenceComplete`, because only a capability the CALLER required does that
    # and a caller's required set is enum-typed.
    check dep.completeness == mcComplete

  test "t_a_capability_id_this_build_cannot_name_is_reported_not_dropped":
    # Degrading must not mean going quiet. Dropping the id silently would be
    # simpler and would leave a consumer unable to tell "the producer declared
    # nothing else" from "the producer declared something I am too old to
    # understand" — attribution, not suppression, is the rule this project is
    # built on. The id is enum-typed and so cannot be carried in the SET; a
    # diagnostic naming it verbatim is the closest honest thing.
    let dep = depFileFromRecords(@[profileRecordWithUnknownCapability()])
    var named = false
    for diag in dep.profile.diagnostics:
      if "quantum-observation-collapse" in diag.message:
        named = true
        check diag.level == mdlWarning
    check named

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
    check not dep.observedInterestStated
    check dep.observedInterestTokens == ""
    check effectiveObservedInterest(dep) == FullInterest
    # …and a consumer that needs everything accepts it, exactly as before.
    check observedInterestCovers(dep, FullInterest)

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

  test "t_an_unknown_token_beside_known_ones_narrows_the_scope_and_is_kept":
    # RENAMED, and the old name is the point. This was
    # `t_an_unknown_category_token_does_not_poison_the_stamp`, which reads like
    # coverage of the whole unknown-token axis and is not: it passes because TWO
    # of its three tokens are namable, so the surviving set is non-empty whatever
    # the reader does with the third. The case that decides the axis is the
    # all-unknown one, and it did not exist — someone grepping for forward-compat
    # coverage found this, saw green, and stopped, which is worse than finding
    # nothing. That case is now the next test in this file, and this one is named
    # for the MIXED stamp it actually exercises.
    #
    # What it asserts: a depfile written by a NEWER io-mon that has split or
    # added a category is still readable here, the categories this build does
    # understand survive, the one it does not drops out of the SET but stays in
    # the FILE, and the resulting narrower read errs toward rejection.
    let dep = depFileFromRecords(@[profileRecordWith(
      ";interest=file,proc,someFutureCategory")])
    check ecFileDeps in dep.observedInterest
    check ecProcessTree in dep.observedInterest
    check dep.observedInterest != {}
    # The unknown token drops out of the SET but not out of the FILE: the raw
    # stamp is kept verbatim so the part this build cannot evaluate can be named
    # in a report rather than merely inferred from a missing category.
    check "someFutureCategory" in dep.observedInterestTokens
    # And what dropped out narrowed the scope this build reads, so the error is
    # toward rejection: a consumer needing everything says no.
    check not observedInterestCovers(dep, FullInterest)
    check observedInterestCovers(dep, {ecFileDeps, ecProcessTree})

  test "t_a_stamp_naming_only_unknown_categories_is_not_read_as_full_scope":
    # THE RESIDUAL DA-1j's own verification named, closed. `interest=gpu` is what
    # a FUTURE io-mon writes for a capture narrowed to a category added after
    # this build — and it parses to `{}` here, the same value an ABSENT stamp
    # produces. Reading the two the same way meant a NARROWED capture was
    # reported as full scope and ACCEPTED by a full-scope consumer: the exact
    # false complete this stamp exists to end, pointing forward in time instead
    # of backward.
    #
    # Not reachable from today's CLI (`parseInterestFlag` refuses a value naming
    # no known token) and that is not a defence: this is a WIRE FORMAT, and the
    # writer on the other end of a wire format is a future build, not this one.
    let dep = depFileFromRecords(@[profileRecordWith(";interest=gpu")])
    check dep.observedInterest == {}
    # …but it is STATED, and that is the whole difference.
    check dep.observedInterestStated
    check statesUnevaluableInterest(dep)
    check dep.observedInterestTokens == "gpu"
    check effectiveObservedInterest(dep) != FullInterest
    check effectiveObservedInterest(dep) == {}

    # THE CONSUMER'S VERDICT. A consumer needing full evidence must REJECT: the
    # honest reading is "this file states a scope I cannot evaluate", which is
    # not the same as "this file recorded everything".
    check not observedInterestCovers(dep, FullInterest)
    # Nor may it be accepted by a consumer that needs merely ONE category — an
    # unevaluable scope cannot be shown to cover anything at all.
    check not observedInterestCovers(dep, {ecFileDeps})

    # And the contrast that is the bug, side by side: an ABSENT stamp is
    # accepted, a STATED-but-unnamable one is not, though both parse to `{}`.
    let unstated = depFileFromRecords(@[profileRecordWith("")])
    check unstated.observedInterest == dep.observedInterest
    check observedInterestCovers(unstated, FullInterest)
    check not observedInterestCovers(dep, FullInterest)

  test "t_a_stamp_whose_value_is_empty_is_not_read_as_full_scope_either":
    # THE SAME OVERLOAD, ONE INPUT FURTHER ALONG — and it arrived UNGRADED. An
    # `interest=` key with an EMPTY value is neither of the two cases above:
    # the key is present, so something was stated, but nothing in the value can
    # be evaluated.
    #
    # It has to be answered separately because `parseInterestTokens` widens `""`
    # to `FullInterest`. That is right for the ENV channel — an unset
    # `REPRO_MONITOR_INTEREST` means "capture everything" — and catastrophic
    # here: routing the empty value through it makes a stamp that states nothing
    # evaluable read as a capture that recorded EVERYTHING, and a full-scope
    # consumer ACCEPTS it. Measured, by deleting the branch that separates them:
    # `interest=` then reports `stated = true` with `FullInterest`, and
    # `observedInterestCovers(dep, FullInterest)` answers `true`. That is the
    # same false complete as `interest=gpu`, reached through the one input the
    # case above cannot produce.
    #
    # "`mergeFragments` cannot write this today" is true (`interestToTokens` is
    # non-empty for every set, and the `!= {}` guard covers the rest) and is
    # exactly as weak an argument as it was for `interest=gpu`: the writer at
    # the other end of a wire format is a future build, and a truncated or
    # hand-edited stamp is not hypothetical either.
    for stamp in [";interest=", ";interest=   "]:
      let dep = depFileFromRecords(@[profileRecordWith(stamp)])
      check dep.observedInterestStated
      check dep.observedInterest == {}
      check statesUnevaluableInterest(dep)
      check effectiveObservedInterest(dep) != FullInterest
      check effectiveObservedInterest(dep) == {}
      check not observedInterestCovers(dep, FullInterest)
      check not observedInterestCovers(dep, {ecFileDeps})

    # Over REAL BYTES too, because the verdict has to survive the envelope.
    let path = getTempDir() / ("io-mon-scope-empty-value-" &
      $getCurrentProcessId() & ".iomon")
    removeFile(path)
    writeCanonical(path, @[profileRecordWith(";interest=")])
    let decoded = readMonitorDepFile(path)
    removeFile(path)
    check decoded.observedInterestStated
    check not observedInterestCovers(decoded, FullInterest)

    # …and the contrast that makes this a defect shape rather than a taste: the
    # ABSENT stamp parses to the same `{}` and is still ACCEPTED.
    let unstamped = depFileFromRecords(@[profileRecordWith("")])
    check unstamped.observedInterest == decoded.observedInterest
    check observedInterestCovers(unstamped, FullInterest)

  test "t_an_unevaluable_scope_survives_a_real_envelope_round_trip":
    # The distinction has to live in the FILE, not only in the derive: `stated`
    # is reconstructed from the record on every read, so a consumer reading real
    # bytes gets the same verdict as one deriving in memory.
    let path = getTempDir() / ("io-mon-scope-unevaluable-" &
      $getCurrentProcessId() & ".iomon")
    removeFile(path)
    writeCanonical(path, @[profileRecordWith(";interest=gpu")])
    let decoded = readMonitorDepFile(path)
    removeFile(path)
    check decoded.observedInterestStated
    check decoded.observedInterestTokens == "gpu"
    check not observedInterestCovers(decoded, FullInterest)

  test "t_a_caller_that_states_no_scope_leaves_the_file_unstamped":
    # THE WRITE SIDE, at the library boundary — `mergeFragments` is where the
    # stamp is applied, and until now nothing graded it at all. The default
    # argument means "the caller said nothing", and the file must come back
    # UNSTAMPED rather than with `FullInterest` asserted on the caller's behalf:
    # stamping `{}` as "all categories" would put a claim in the file that the
    # caller never made, which is the same class of invention this milestone is
    # about. Deleting the `!= {}` guard reddens here.
    let work = getTempDir() / ("io-mon-merge-scope-" &
      $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let silent = mergeFragments(work, work / "silent.iomon")
    check not silent.observedInterestStated
    check silent.observedInterest == {}
    check effectiveObservedInterest(silent) == FullInterest
    # The on-disk file and the returned value must agree — the stamp is applied
    # before the write for exactly this reason.
    let silentOnDisk = readMonitorDepFile(work / "silent.iomon")
    check not silentOnDisk.observedInterestStated

    # …and a caller that DOES state a scope gets it written down. Deleting the
    # stamp block entirely reddens here.
    let narrowed = mergeFragments(work, work / "narrowed.iomon",
      observedInterest = {ecFileDeps, ecProcessTree})
    check narrowed.observedInterestStated
    check narrowed.observedInterest == {ecFileDeps, ecProcessTree}
    check not observedInterestCovers(narrowed, FullInterest)
    let narrowedOnDisk = readMonitorDepFile(work / "narrowed.iomon")
    check narrowedOnDisk.observedInterest == {ecFileDeps, ecProcessTree}
    check narrowedOnDisk.observedInterestTokens == "file,proc"

    removeDir(work)
