## test_io_mon_evidence_scope — DA-1i, everything that does not need a live capture.
##
## `--evidence=reads-only` writes down only the lookups that FOUND something.
## Three separable claims live here; the fourth — that the real CLI produces two
## different record sets and says which is which — cannot be made from
## hand-built records and is
## `tests/posix/test_io_mon_cli_evidence_scope.nim`.
##
##   1. THE PREDICATE. Which records are "failed EXISTENCE lookups", asserted
##      EXHAUSTIVELY over `MonitorRecordKind` so a kind added later must state
##      its answer here rather than inherit one. Three boundaries matter more
##      than the rest: META/loss kinds are never droppable (LF-1); a READ or a
##      WRITE is not a lookup at all, so it is never dropped either; and the
##      predicate answers on the RESULT of a call and CANNOT see why it failed,
##      which is the documented blind spot (row 4 of the hazard table) rather
##      than a defect — the record shape carries no errno.
##
##   2. THE GRADE DOES NOT MOVE. A narrowing is the operator asking a narrower
##      question; `mcIncomplete` means the monitor could not observe everything.
##      DA-1i's first draft forced `mcIncomplete` and was withdrawn for exactly
##      this, so the invariant is asserted against a real merge, both with and
##      without an `mrEventLoss` in the capture.
##
##   3. THE STAMP, read and written. Absent ⇒ full scope (an old depfile keeps
##      its meaning); present-and-recognised ⇒ that scope; present-but-
##      UNRECOGNISED ⇒ reject, with the token kept so the residual is nameable.
##      Three fields, not one, because a future io-mon writing
##      `evidence=writes-only` must not read as `esFull` — DA-1j found that exact
##      false accept live on the interest axis and this file exists partly so the
##      evidence axis does not have to learn it again.
##
## NO MOCKS. Records are built by the real backend-profile constructor, depfiles
## are derived by the real `depFileFromRecords` / written by the real
## `writeCanonical` / `mergeFragments` and read back by the real
## `readMonitorDepFile`. Nothing here substitutes a stand-in for a production
## component; the only thing constructed by hand is the CONTENT of records,
## which is what a monitored program would have caused a shim to construct.
##
## Assertion helpers are `template`s, never `proc`s: a `check` inside a plain
## `proc` prints "Check failed" and the enclosing test still reports `[OK]`.

import std/[options, os, osproc, streams, strutils, unittest]

import io_mon

const
  MetaKinds = {mrEventLoss, mrBackendProfile, mrCapabilityGap}
    ## The kinds `categoryOf` answers `none` for. Restated here so the case
    ## below is an INDEPENDENT statement of what META means rather than a
    ## tautology over the implementation it is grading.

proc lookupRecord(kind: MonitorRecordKind; obs: MonitorObservationKind;
                  path: string; res: int64;
                  probe = prUnknown): MonitorRecord =
  MonitorRecord(kind: kind, observationKind: obs, osPid: 4242,
    path: path, result: res, probeResult: probe)

proc profileRecordWith(extraTokens: string): MonitorRecord =
  ## A REAL backend-profile record — so the derived depfile grades on the merits
  ## of a real capability set — plus whatever stamp the case under test wants.
  ## Hand-rolling `supported=` would grade `mcIncomplete` for reasons that have
  ## nothing to do with the stamp, and every completeness assertion below would
  ## then be meaningless.
  result = backendProfileRecord(linuxPreloadMonitorProfile())
  result.detail.add extraTokens

suite "io-mon evidence scope predicate (DA-1i)":

  test "t_a_failed_existence_lookup_is_exactly_the_three_lookup_kinds":
    # The positive half. These are the records a SEARCH produces and that a
    # compiler-emitted depfile structurally never reports — the whole content of
    # what `reads-only` removes, and the reason the comparison with `gcc -MD`
    # evidence is like for like.
    let failedOpen = lookupRecord(mrFileOpen, moFileOpen, "/nope/a.h", -1)
    let failedProbe = lookupRecord(mrPathProbe, moPathProbe, "/nope/b.h", -1,
      prAbsent)
    let failedEnum = lookupRecord(mrDirectoryEnumerate, moDirectoryEnumerate,
      "/nope/dir", -1)
    check recordIsFailedExistenceLookup(failedOpen)
    check recordIsFailedExistenceLookup(failedProbe)
    check recordIsFailedExistenceLookup(failedEnum)
    for rec in [failedOpen, failedProbe, failedEnum]:
      check not recordInEvidenceScope(esReadsOnly, rec)
      # …and `esFull` keeps every one of them, or the two modes would not
      # differ and every count comparison in the live case would be vacuous.
      check recordInEvidenceScope(esFull, rec)

    # A Windows probe site that leaves `probeResult` at `prUnknown` and carries
    # a negative NTSTATUS instead is the same fact spelled differently, and must
    # not survive by spelling.
    check recordIsFailedExistenceLookup(
      lookupRecord(mrPathProbe, moPathProbe, "/nope/c.h", -1073741772))

  test "t_a_lookup_that_found_something_is_never_dropped":
    # The negative half, and the one the live case measures: `reads-only` keeps
    # SUCCESSFUL probes. A probes-CATEGORY gate does not — measured, it discards
    # 2,066 successful probes on one `nim c` — which is why this is a predicate
    # on the RESULT and not a refinement of `EventCategory`.
    let okOpen = lookupRecord(mrFileOpen, moFileOpen, "/real/a.h", 7)
    let okProbe = lookupRecord(mrPathProbe, moPathProbe, "/real/a.h", 0,
      prExistingFile)
    let okDirProbe = lookupRecord(mrPathProbe, moPathProbe, "/real", 0,
      prExistingDirectory)
    let okEnum = lookupRecord(mrDirectoryEnumerate, moDirectoryEnumerate,
      "/real", 1)
    for rec in [okOpen, okProbe, okDirProbe, okEnum]:
      check not recordIsFailedExistenceLookup(rec)
      check recordInEvidenceScope(esReadsOnly, rec)

    # A failed `fopen` records its NULL `FILE*` as 0, which is also a legal fd.
    # The predicate FAILS TOWARD KEEPING there rather than risk dropping a
    # successful `open` that happened to get fd 0: over-keeping costs records,
    # under-keeping costs correctness.
    check not recordIsFailedExistenceLookup(
      lookupRecord(mrFileOpen, moFileOpen, "/real/b.h", 0))

  test "t_a_read_or_write_is_never_an_existence_lookup_and_is_always_kept":
    # THE BOUNDARY, and the reason the predicate names three KINDS instead of
    # testing `result < 0` on everything that touches a file. A read or a write
    # is not a lookup at all: the path was already in hand, so whatever it
    # reports is not the answer to "is there something here?".
    #
    # THE OLD REASON GIVEN HERE WAS NOT TRUE AND IS NOT USED. This case, and the
    # predicate's comment, used to say a failed read is "an error the consumer
    # must still see" and presented that as a LIVE case being protected. It is
    # not live on Linux. Counted: `linux_preload.nim` builds an `mrFileRead` at
    # SIX sites and none can emit a negative result — four guard on the byte
    # count (`recordFdRead`, `repro_hook_fread` and the `sendfile` arm on `> 0`,
    # `recordRawSplice` on `> 0`, `recordRawRead` returning early on a negative
    # result) and two hard-code `result = 0` (`recordPathRead`, and the
    # inherited-fd reclassification in `classifyEmptyFdRead`). The
    # negative-result record
    # below is therefore CONSTRUCTED, and it guards the PREDICATE against a
    # future backend that does record failed reads and against anyone widening
    # `mrFileOpen`'s `result < 0` arm to cover `mrFileRead` as well.
    let failedRead = lookupRecord(mrFileRead, moFileRead, "/real/a.h", -1)
    check not recordIsFailedExistenceLookup(failedRead)
    check recordInEvidenceScope(esReadsOnly, failedRead)

    # Nor is a failed WRITE a lookup — same argument, output side.
    let failedWrite = lookupRecord(mrFileWrite, moFileWrite, "/out/x", -1)
    check not recordIsFailedExistenceLookup(failedWrite)
    check recordInEvidenceScope(esReadsOnly, failedWrite)

    # WHAT IS ACTUALLY LIVE, AND IS KEPT. A SHORT read (`0 < n < requested`) is
    # what the shim really produces when a read does not deliver everything
    # asked for, and a zero-length read at EOF, and the synthetic `result = 0`
    # reads (`recordPathRead`, the inherited-fd reclassification). These are the
    # records this arm protects in practice, so they are the ones asserted.
    for res in [1'i64, 0'i64]:
      let liveRead = lookupRecord(mrFileRead, moFileRead, "/real/a.h", res)
      check not recordIsFailedExistenceLookup(liveRead)
      check recordInEvidenceScope(esReadsOnly, liveRead)

  test "t_the_predicate_answers_on_the_result_and_cannot_see_why_a_call_failed":
    # THE NARROWED CLAIM, PINNED — so that the documented blind spot is a
    # property under test and not a paragraph that can drift away from the code.
    #
    # `recordIsFailedExistenceLookup` says "this lookup DID NOT SUCCEED". It
    # cannot say "this path is ABSENT", because the fields never carried the
    # distinction: `result` is `-1` for every `open` failure whatever the reason,
    # `probeFromResult` stamps `prAbsent` on every non-zero `stat` return, and NO
    # ERRNO REACHES `MonitorRecord` — there is no field for it. Four measured
    # shapes where the path EXISTS are dropped as a result: `EACCES` (mode 000),
    # `EISDIR`, `EACCES` on a `stat` through a no-exec directory, and `ELOOP`.
    #
    # These records are BYTE-IDENTICAL to the ones an absent path produces,
    # which IS the finding: the two cases are indistinguishable here, so this
    # case asserts the identity rather than a behaviour that could be fixed
    # without touching the record shape. Row 4 of the normative hazard table is
    # this fact written where an operator meets the flag.
    let absent = lookupRecord(mrFileOpen, moFileOpen, "/some/path", -1)
    let eacces = lookupRecord(mrFileOpen, moFileOpen, "/some/path", -1)
    check absent.kind == eacces.kind
    check absent.result == eacces.result
    check absent.probeResult == eacces.probeResult
    check absent.detail == eacces.detail
    check recordIsFailedExistenceLookup(absent)
    check recordIsFailedExistenceLookup(eacces)
    check not recordInEvidenceScope(esReadsOnly, eacces)

    # Same on the probe side: a `stat` that failed with `EACCES` on a path that
    # EXISTS is classified `prAbsent`, because `probeFromResult` keys on the
    # return value and a non-zero return is all it has.
    let eaccesProbe = lookupRecord(mrPathProbe, moPathProbe, "/some/path", -1,
      prAbsent)
    check recordIsFailedExistenceLookup(eaccesProbe)
    check not recordInEvidenceScope(esReadsOnly, eaccesProbe)

    # AND THE CONVERSE, so this is a statement about the RECORD and not about
    # the predicate being indiscriminate: a probe that resolved to an EXISTING
    # path is kept, whatever the path is. The blind spot is exactly the set of
    # lookups that failed — no wider.
    for probe in [prExistingFile, prExistingDirectory, prExistingOther]:
      let found = lookupRecord(mrPathProbe, moPathProbe, "/some/path", 0, probe)
      check not recordIsFailedExistenceLookup(found)
      check recordInEvidenceScope(esReadsOnly, found)

  test "t_no_meta_or_loss_record_can_ever_be_dropped_by_a_narrowing":
    # THE LF-1 ASSERTION, at the predicate. `recordWanted` returns true for META
    # kinds precisely so a narrowed capture cannot drop an `mrEventLoss` and
    # manufacture a false `mcComplete`; this axis has to hold the same line, and
    # holds it BY CONSTRUCTION — `recordIsFailedExistenceLookup` asks
    # `categoryOf`, the one definition of what META is, before it looks at
    # anything else. Asserted rather than relied upon.
    #
    # EXHAUSTIVE over `MonitorRecordKind`, with ADVERSARIAL field values: every
    # kind is offered the exact shape that makes the three lookup kinds
    # droppable (`result = -1`, `probeResult = prAbsent`). A META kind that
    # answered on its fields rather than on its category would fail here.
    for kind in MonitorRecordKind:
      let hostile = MonitorRecord(kind: kind, osPid: 1, path: "/nope",
        result: -1, probeResult: prAbsent)
      if kind in MetaKinds:
        check categoryOf(kind).isNone
        check not recordIsFailedExistenceLookup(hostile)
        check recordInEvidenceScope(esReadsOnly, hostile)
      else:
        # …and the complement is checked too, so "META is never dropped" is not
        # passing because NOTHING is ever dropped.
        check categoryOf(kind).isSome

  test "t_every_record_kind_states_its_own_answer":
    # An anti-vacuity guard on the case above. `MonitorRecordKind` is a wire
    # enum that grows; a kind added later must be classified deliberately. If
    # this list and the predicate disagree, one of them was not updated.
    const DroppableWhenFailed = {mrFileOpen, mrPathProbe, mrDirectoryEnumerate}
    for kind in MonitorRecordKind:
      let failed = MonitorRecord(kind: kind, osPid: 1, path: "/nope",
        result: -1, probeResult: prAbsent)
      check recordIsFailedExistenceLookup(failed) == (kind in DroppableWhenFailed)
    # And the set really is a proper, non-empty subset — otherwise the equality
    # above would hold for a predicate that is constantly true or false.
    check DroppableWhenFailed.len == 3
    check MetaKinds * DroppableWhenFailed == {}

  test "t_an_unrecognised_scope_records_everything_rather_than_nothing":
    # `esUnrecognized` cannot reach a gate — it is a READING of a depfile a
    # newer io-mon wrote, and `parseEvidenceScopeFlag` refuses an unknown value
    # — but if it ever did, the safe direction is to capture MORE. An over-full
    # capture is slower and still honest; an under-full one is the cardinal sin.
    let failedOpen = lookupRecord(mrFileOpen, moFileOpen, "/nope/a.h", -1)
    check recordInEvidenceScope(esUnrecognized, failedOpen)

suite "io-mon evidence scope: the grade does not move (DA-1i)":

  let work = getTempDir() / ("io-mon-evidence-grade-" & $getCurrentProcessId())

  setup:
    removeDir(work)
    createDir(work)

  teardown:
    removeDir(work)

  test "t_a_reads_only_capture_is_not_graded_incomplete_for_being_narrow":
    # DA-1i's FIRST DRAFT FORCED `mcIncomplete` AND WAS WITHDRAWN, because
    # `mcIncomplete` means "the monitor could not observe everything" — a claim
    # about capture fidelity — and using it to encode "the operator asked
    # something narrower" makes a deliberate narrowing indistinguishable from a
    # monitor failure. That corrupts precisely the signal DA-2/DA-4 exist to
    # make trustworthy. Graded through the REAL merge, not through the derive.
    let full = mergeFragments(work, work / "full.iomon")
    let narrow = mergeFragments(work, work / "narrow.iomon",
      observedEvidenceScope = esReadsOnly)
    check full.completeness == mcComplete
    check narrow.completeness == mcComplete
    check narrow.completeness == full.completeness
    # The narrowing IS visible in the file — otherwise "the grade did not move"
    # would be a statement about two identical captures.
    check narrow.observedEvidenceScopeStated
    check not full.observedEvidenceScopeStated

  test "t_an_event_loss_still_downgrades_under_reads_only":
    # THE LF-1 ASSERTION, end to end this time. Construct a capture that
    # genuinely lost data, narrow it, and the file must still say so. If a
    # narrowing could suppress the marker the grade is derived from, a capture
    # that lost records would publish as `mcComplete` — the cardinal sin, one
    # flag away.
    #
    # `setRecords` is the real Linux transport argument, so the loss travels the
    # path a shim-published loss travels.
    let loss = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
      osPid: 4242, detail: "synthetic loss for the DA-1i narrowing guard")
    let narrow = mergeFragments(work, work / "loss-narrow.iomon",
      setRecords = @[loss], observedEvidenceScope = esReadsOnly)
    check narrow.completeness == mcIncomplete
    check narrow.summary.eventLossCount == 1'u64
    check narrow.observedEvidenceScopeStated
    check effectiveObservedEvidenceScope(narrow) == esReadsOnly

    # …and identically at full scope, so the downgrade is not an artefact of the
    # narrowing either. Same capture, same verdict, both ways.
    let full = mergeFragments(work, work / "loss-full.iomon",
      setRecords = @[loss])
    check full.completeness == mcIncomplete
    check narrow.completeness == full.completeness

    # The marker is in the FILE, not merely in the returned value: a consumer
    # only ever sees the bytes.
    let onDisk = readMonitorDepFile(work / "loss-narrow.iomon")
    check onDisk.completeness == mcIncomplete
    check onDisk.summary.eventLossCount == 1'u64

suite "io-mon evidence scope stamp (DA-1i)":

  test "t_a_depfile_that_states_no_evidence_scope_reads_as_full":
    # BACK-COMPAT, and the direction it must fail in. Every depfile written
    # before this stamp existed recorded every observation, so "not stated"
    # means `esFull` — never "narrowed", which would make every old depfile
    # unusable to a full-evidence consumer.
    let dep = depFileFromRecords(@[profileRecordWith("")])
    check not dep.observedEvidenceScopeStated
    check dep.observedEvidenceScope == esFull
    check dep.observedEvidenceScopeToken == ""
    check effectiveObservedEvidenceScope(dep) == esFull
    check not statesUnevaluableEvidenceScope(dep)
    check observedEvidenceScopeCovers(dep, esFull)
    check observedEvidenceScopeCovers(dep, esReadsOnly)

  test "t_a_reads_only_capture_says_so_and_a_full_consumer_declines_it":
    let dep = depFileFromRecords(@[profileRecordWith(";evidence=reads-only")])
    check dep.observedEvidenceScopeStated
    check dep.observedEvidenceScope == esReadsOnly
    check dep.observedEvidenceScopeToken == "reads-only"
    check effectiveObservedEvidenceScope(dep) == esReadsOnly
    # THE PARTIAL ORDER, in both directions. A consumer that needs full evidence
    # declines; a consumer that opted into the reduced scope accepts.
    check not observedEvidenceScopeCovers(dep, esFull)
    check observedEvidenceScopeCovers(dep, esReadsOnly)
    # …and the narrowing did not move the grade.
    check dep.completeness == mcComplete

  test "t_full_evidence_is_strictly_stronger_and_a_reads_only_consumer_takes_it":
    # THE DIRECTION KEYING ON THE SCOPE WOULD HAVE BLOCKED. Trust here is a
    # partial order, not a partition: the careful teammate captures at full
    # scope and the fast teammate must still be able to consume the result.
    # Folding the scope into the cache key would make the two disjoint.
    let full = depFileFromRecords(@[profileRecordWith(";evidence=full")])
    check full.observedEvidenceScopeStated
    check full.observedEvidenceScope == esFull
    check observedEvidenceScopeCovers(full, esFull)
    check observedEvidenceScopeCovers(full, esReadsOnly)
    # Stated `full` and UNSTATED must be indistinguishable to a consumer, since
    # they are the same claim.
    let unstated = depFileFromRecords(@[profileRecordWith("")])
    check observedEvidenceScopeCovers(unstated, esFull) ==
      observedEvidenceScopeCovers(full, esFull)
    # The bare relation, stated once so no consumer has to rediscover it.
    check evidenceScopeCovers(esFull, esReadsOnly)
    check not evidenceScopeCovers(esReadsOnly, esFull)
    check evidenceScopeCovers(esReadsOnly, esReadsOnly)

  test "t_the_partial_order_is_graded_on_every_pair_including_the_unnamable":
    # THE PREDICATE, NOT ONLY ITS SCOPE. Every arm of `evidenceScopeCovers` had a
    # grader except one, and the ungraded one is the arm its doc comment argues
    # most emphatically: `esUnrecognized` covers NOTHING, INCLUDING ITSELF —
    # "two builds that both fail to name a scope have not thereby agreed on it".
    # MEASURED: making `evidenceScopeCovers(esUnrecognized, esUnrecognized)`
    # return `true` survived every case in this suite and every live case, so the
    # property lived in prose alone. It is a 3x3 relation; grade the 3x3.
    const Expected = [
      #  have            required          covers?
      (esFull,          esFull,          true),
      (esFull,          esReadsOnly,     true),
      (esFull,          esUnrecognized,  false),
      (esReadsOnly,     esFull,          false),
      (esReadsOnly,     esReadsOnly,     true),
      (esReadsOnly,     esUnrecognized,  false),
      (esUnrecognized,  esFull,          false),
      (esUnrecognized,  esReadsOnly,     false),
      (esUnrecognized,  esUnrecognized,  false)]
    for (have, required, covers) in Expected:
      checkpoint("covers(have=" & $have & ", required=" & $required &
        ") expected " & $covers)
      check evidenceScopeCovers(have, required) == covers

    # EXHAUSTIVE over the enum in BOTH positions: the table must name every pair
    # exactly once, so a scope added later leaves a pair unstated here rather
    # than inheriting an answer silently.
    for have in EvidenceScope:
      for required in EvidenceScope:
        var stated = 0
        for (h, r, _) in Expected:
          if h == have and r == required: inc stated
        checkpoint("pair (" & $have & ", " & $required & ") stated " &
          $stated & " time(s)")
        check stated == 1

    # The three properties the table encodes, restated so a wrong table is not
    # simply copied from a wrong implementation:
    #
    # 1. REFLEXIVE ON THE TWO REAL SCOPES — a capture always satisfies a consumer
    #    asking for exactly what it did.
    check evidenceScopeCovers(esFull, esFull)
    check evidenceScopeCovers(esReadsOnly, esReadsOnly)
    # 2. AND NOT REFLEXIVE ON `esUnrecognized`, which is the whole point of it
    #    being a READING rather than a scope. Both sides of this pair mean "a
    #    scope I cannot name", and two builds that cannot name a scope have not
    #    agreed on one — they may not even be failing to name the SAME scope.
    #    Accepting here would let a capture narrowed by a future io-mon satisfy a
    #    consumer that is equally in the dark, which is the false accept DA-1j
    #    found live on the interest axis.
    check not evidenceScopeCovers(esUnrecognized, esUnrecognized)
    # 3. AND UNNAMABLE ON BOTH SIDES. A consumer cannot REQUIRE `esUnrecognized`
    #    either — there is no such requirement to state — so even full evidence
    #    does not cover it. Without this the row above could pass for a
    #    predicate that merely special-cased `have`.
    check not evidenceScopeCovers(esFull, esUnrecognized)
    check not evidenceScopeCovers(esReadsOnly, esUnrecognized)

    # ANTI-VACUITY: the relation is neither constantly true nor constantly false.
    # Exactly three of the nine pairs hold, so "covers nothing" is a statement
    # about `esUnrecognized` and not about the predicate.
    var trues = 0
    for have in EvidenceScope:
      for required in EvidenceScope:
        if evidenceScopeCovers(have, required): inc trues
    check trues == 3
    check Expected.len == 9

  test "t_a_scope_this_build_cannot_name_is_rejected_not_read_as_full":
    # THE FALSE ACCEPT DA-1j FOUND LIVE ON THE INTEREST AXIS, closed here before
    # it can happen. `evidence=writes-only` is the shape a FUTURE io-mon writes
    # for a capture narrowed in a way this build has never heard of. Collapsing
    # "absent" and "present but unrecognised" into one value would report that
    # NARROWED capture as full scope and a full-evidence consumer would ACCEPT
    # it — the exact defect this stamp exists to prevent, pointing forward in
    # time instead of backward.
    #
    # Not reachable from today's CLI, and that is not a defence: this is a WIRE
    # FORMAT, and the writer at the other end of a wire format is a future
    # build.
    let dep = depFileFromRecords(@[profileRecordWith(";evidence=writes-only")])
    check dep.observedEvidenceScopeStated
    check dep.observedEvidenceScope == esUnrecognized
    check statesUnevaluableEvidenceScope(dep)
    # THE RESIDUAL IS NAMEABLE, not merely detectable: a consumer can report
    # "declares `writes-only`, which I cannot evaluate".
    check dep.observedEvidenceScopeToken == "writes-only"
    # THE VERDICT. Rejected by a full-evidence consumer AND by a reads-only one
    # — an unevaluable scope cannot be shown to cover anything at all.
    check not observedEvidenceScopeCovers(dep, esFull)
    check not observedEvidenceScopeCovers(dep, esReadsOnly)
    # And it did not move the GRADE either: an unreadable scope stamp is not a
    # monitoring failure.
    check dep.completeness == mcComplete

    # The contrast that makes this a defect shape rather than a taste: an ABSENT
    # stamp is accepted by the same consumer.
    let unstated = depFileFromRecords(@[profileRecordWith("")])
    check observedEvidenceScopeCovers(unstated, esFull)
    check not observedEvidenceScopeCovers(dep, esFull)

  test "t_a_stamp_whose_value_is_empty_is_not_read_as_full_scope_either":
    # THE SAME OVERLOAD ONE INPUT FURTHER ALONG — the arm that arrived UNGRADED
    # on the interest axis and let `interest=` read as full scope with the whole
    # suite green. `parseEvidenceScopeToken` widens `""` to `esFull`, which is
    # right for the ENV channel (an unset `REPRO_MONITOR_EVIDENCE` means "write
    # everything down") and a false accept here, because the KEY'S PRESENCE
    # already proves the producer meant to state something.
    for stamp in [";evidence=", ";evidence=   "]:
      let dep = depFileFromRecords(@[profileRecordWith(stamp)])
      check dep.observedEvidenceScopeStated
      check dep.observedEvidenceScope == esUnrecognized
      check statesUnevaluableEvidenceScope(dep)
      check not observedEvidenceScopeCovers(dep, esFull)
      check not observedEvidenceScopeCovers(dep, esReadsOnly)

  test "t_the_two_scope_axes_are_read_independently":
    # A capture can be narrowed on both axes at once, and a consumer must be
    # able to evaluate each without the other. Conflating them is how a category
    # gate came to be mistaken for a `reads-only` mechanism in the first place.
    let dep = depFileFromRecords(@[
      profileRecordWith(";interest=file,proc;evidence=reads-only")])
    check dep.observedInterest == {ecFileDeps, ecProcessTree}
    check dep.observedEvidenceScope == esReadsOnly
    check not observedInterestCovers(dep, FullInterest)
    check not observedEvidenceScopeCovers(dep, esFull)
    check observedInterestCovers(dep, {ecFileDeps})
    check observedEvidenceScopeCovers(dep, esReadsOnly)

    # …and narrowing ONE axis leaves the other reading as full, so neither
    # stamp is silently answering for the other.
    let interestOnly = depFileFromRecords(@[
      profileRecordWith(";interest=file,proc")])
    check not observedInterestCovers(interestOnly, FullInterest)
    check observedEvidenceScopeCovers(interestOnly, esFull)
    let evidenceOnly = depFileFromRecords(@[
      profileRecordWith(";evidence=reads-only")])
    check observedInterestCovers(evidenceOnly, FullInterest)
    check not observedEvidenceScopeCovers(evidenceOnly, esFull)

  test "t_the_stamp_survives_a_real_envelope_round_trip":
    # The distinction has to live in the FILE, not only in the derive: a
    # consumer reading real bytes must reach the same verdict as one deriving in
    # memory. The stamp rides on a RECORD — the envelope carries only records,
    # which is why this needed no version bump — so the round trip is the only
    # thing that proves it survives encoding.
    let path = getTempDir() / ("io-mon-evidence-roundtrip-" &
      $getCurrentProcessId() & ".iomon")
    for (stamp, stated, scope, token) in [
        (";evidence=reads-only", true, esReadsOnly, "reads-only"),
        (";evidence=writes-only", true, esUnrecognized, "writes-only"),
        (";evidence=", true, esUnrecognized, ""),
        ("", false, esFull, "")]:
      removeFile(path)
      writeCanonical(path, @[profileRecordWith(stamp)])
      let decoded = readMonitorDepFile(path)
      check decoded.observedEvidenceScopeStated == stated
      check decoded.observedEvidenceScope == scope
      check decoded.observedEvidenceScopeToken == token
    removeFile(path)

  test "t_the_wire_codec_round_trips_and_refuses_to_spell_the_unnamable":
    # `esUnrecognized` has NO wire spelling on purpose: it is what a token this
    # build does not know parses TO. Giving it a token would make it producible
    # and destroy the very distinction it exists to draw — and the merge would
    # then be able to write a stamp that reads back as unevaluable.
    check evidenceScopeToken(esFull) == "full"
    check evidenceScopeToken(esReadsOnly) == "reads-only"
    check evidenceScopeToken(esUnrecognized) == ""
    for scope in [esFull, esReadsOnly]:
      check parseEvidenceScopeToken(evidenceScopeToken(scope)) == scope
    # The ENV channel's back-compat rule, which is the opposite of the FILE
    # channel's for the empty input, and deliberately so.
    check parseEvidenceScopeToken("") == esFull
    check parseEvidenceScopeToken("   ") == esFull
    check parseEvidenceScopeToken("writes-only") == esUnrecognized
    check parseEvidenceScopeToken("Reads-Only") == esUnrecognized

  test "t_esUnrecognized_is_the_only_scope_without_a_wire_token":
    # THE INVARIANT THE WRITE SIDE RESTS ON, stated over the WHOLE enum instead
    # of over the members someone remembered to list. `mergeFragments` guards
    # with `!= esFull and != esUnrecognized` — it tests the VALUE — while the
    # hazard its own comment names is the TOKEN's emptiness. Those are the same
    # statement only while this holds.
    #
    # This case is the READER's copy of the rule, not its grader: a runtime loop
    # cannot see a member that does not exist yet, which is exactly when the
    # rule gets broken. The grader is the `static:` block in `types.nim`, driven
    # by the compile-refusal suite at the bottom of this file.
    var spellable, unspellable: seq[EvidenceScope]
    for scope in EvidenceScope:
      if evidenceScopeToken(scope).len == 0: unspellable.add scope
      else: spellable.add scope
    check unspellable == @[esUnrecognized]
    # …and "has a token" has to mean "has a token this build can read back",
    # not merely "is non-empty", or the two directions of the codec could still
    # disagree about a member both of them name.
    check spellable.len > 0        # …so the round trip below is not vacuous.
    for scope in spellable:
      checkpoint("scope: " & $scope)
      check parseEvidenceScopeToken(evidenceScopeToken(scope)) == scope

suite "io-mon evidence scope: the write side at the library boundary (DA-1i)":

  let work = getTempDir() / ("io-mon-evidence-merge-" & $getCurrentProcessId())

  setup:
    removeDir(work)
    createDir(work)

  teardown:
    removeDir(work)

  test "t_only_a_narrowing_is_stamped_and_it_reaches_the_bytes":
    # THE WRITE SIDE, GRADED. DA-1j shipped with its entire stamp-write side
    # ungraded: deleting the block in `mergeFragments` left the portable suite
    # green while the CLI reproduced the original defect exactly. Deleting this
    # milestone's stamp block reddens here AND in the live CLI case.
    #
    # `esFull` is deliberately left UNSTAMPED, because "not stated" has always
    # meant exactly `esFull`: stamping it would say nothing new while changing
    # the profile-detail bytes of every capture that exists, and the depfile is
    # byte-reproducible on purpose.
    let full = mergeFragments(work, work / "full.iomon")
    check not full.observedEvidenceScopeStated
    check effectiveObservedEvidenceScope(full) == esFull
    check observedEvidenceScopeCovers(full, esFull)
    # The on-disk file and the returned value must agree — the stamp is applied
    # BEFORE the write for exactly this reason.
    let fullOnDisk = readMonitorDepFile(work / "full.iomon")
    check not fullOnDisk.observedEvidenceScopeStated

    let narrow = mergeFragments(work, work / "narrow.iomon",
      observedEvidenceScope = esReadsOnly)
    check narrow.observedEvidenceScopeStated
    check narrow.observedEvidenceScope == esReadsOnly
    check not observedEvidenceScopeCovers(narrow, esFull)
    let narrowOnDisk = readMonitorDepFile(work / "narrow.iomon")
    check narrowOnDisk.observedEvidenceScope == esReadsOnly
    check narrowOnDisk.observedEvidenceScopeToken == "reads-only"

    # An explicit `esFull` is the same as saying nothing, in the RETURNED value
    # and in the BYTES.
    let statedFull = mergeFragments(work, work / "stated-full.iomon",
      observedEvidenceScope = esFull)
    check not statedFull.observedEvidenceScopeStated
    check readFile(work / "stated-full.iomon") == readFile(work / "full.iomon")

  test "t_the_merge_refuses_to_write_a_scope_it_cannot_spell":
    # `esUnrecognized` reaching the merge would otherwise append a bare
    # `;evidence=` — which reads back as STATED and UNEVALUABLE, turning a
    # library caller's confusion into a depfile no consumer will accept. It is
    # unreachable from the CLI and from `parseEvidenceScopeToken`'s known
    # tokens; this pins the guard rather than the reachability argument.
    let dep = mergeFragments(work, work / "unnamable.iomon",
      observedEvidenceScope = esUnrecognized)
    check not dep.observedEvidenceScopeStated
    check not statesUnevaluableEvidenceScope(dep)
    check "evidence=" notin readFile(work / "unnamable.iomon")
    let onDisk = readMonitorDepFile(work / "unnamable.iomon")
    check not onDisk.observedEvidenceScopeStated

  test "t_the_two_stamps_do_not_overwrite_each_other":
    # Both stamps append to the SAME backend-profile detail. A capture narrowed
    # on both axes must come back with both readable — an append that clobbered
    # the other's key would make one axis silently read as full.
    let dep = mergeFragments(work, work / "both.iomon",
      observedInterest = {ecFileDeps},
      observedEvidenceScope = esReadsOnly)
    check dep.observedInterestStated
    check dep.observedInterest == {ecFileDeps}
    check dep.observedEvidenceScopeStated
    check dep.observedEvidenceScope == esReadsOnly
    let onDisk = readMonitorDepFile(work / "both.iomon")
    check onDisk.observedInterest == {ecFileDeps}
    check onDisk.observedEvidenceScope == esReadsOnly

# ---------------------------------------------------------------------------
# A SCOPE WITH NO WIRE TOKEN — the instrument is the compiler, not this process.
#
# `evidenceScopeToken` used to be a plain array of `(scope, token)` pairs while
# every other consumer of `EvidenceScope` (`recordInEvidenceScope`,
# `evidenceScopeCovers`) is a compiler-policed exhaustive `case`. MEASURED on
# that code, end to end and on real bytes: adding an `esWritesOnly` member and
# doing EXACTLY what the compiler and this suite demanded — an arm in each of
# those two `case`s plus a row in the relation table above — compiled clean,
# and `mergeFragments(…, observedEvidenceScope = esWritesOnly)` then wrote a
# bare `;evidence=` into the depfile. That file reads back `stated = true`,
# `esUnrecognized`, `token = ""`, so it is REJECTED BY EVERY CONSUMER —
# including one asking for exactly that scope — and the residual is unnameable,
# leaving the operator only "caching stopped".
#
# NO RUNTIME TEST OVER TODAY'S MEMBERS CAN SEE THAT: every member that exists
# has a token, and the defect appears only at the moment a member is ADDED. So
# the subject of these cases is a mutated COPY of the real
# `src/io_mon/types.nim` and the instrument is the real compiler's exit code —
# the same reason `test_io_mon_monitor_handle_exclusivity.nim` drives
# `nim c --compileOnly` instead of `compiles()`.
#
# WHY THE GUARD IN `mergeFragments` STILL TESTS THE VALUE. The obvious one-line
# fix — test the token there instead — was measured on the pre-fix code and is
# strictly worse: the stamp is then omitted, the capture reads as NOT STATED,
# `effectiveObservedEvidenceScope` defines not-stated as `esFull`, and a
# FULL-evidence consumer ACCEPTS a narrowed capture. There was no safe default
# at the write site in either spelling. What these cases pin instead makes the
# two spellings PROVABLY EQUIVALENT — empty token ⟺ `esUnrecognized` — so
# substituting one for the other now reddens nothing (also measured), and the
# question the write site could not answer is no longer asked there.
#
# AND "HAS A TOKEN" IS NOT "HAS A USABLE TOKEN", which is the round after that
# and the reason the last two cases in the first suite below exist. With only
# the emptiness assertion in place, `of esWritesOnly: "writes;only"` compiled,
# satisfied it, round-tripped IN MEMORY (so the runtime enum case above stayed
# green), left the WHOLE portable suite green — and still produced a depfile
# read back as `esUnrecognized` with the residual MISnamed `writes`, because
# the `evidence=` stamp rides inside a `;`-joined record detail. A DUPLICATE
# token is worse: the narrowed capture reads back as `esFull` and a
# full-evidence consumer ACCEPTS it. Both measured on real bytes, both now
# compile errors. The property the `static:` block holds is therefore the ROUND
# TRIP THROUGH THE WIRE, and a length check was never it.
# ---------------------------------------------------------------------------

const
  RepoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  TypesSource = RepoRoot / "src" / "io_mon" / "types.nim"

  EnumAnchor = "    esUnrecognized    ## READ SIDE ONLY"
    ## Where the probe's new member goes — BEFORE `esUnrecognized`, so the
    ## mutation has the realistic shape (a new real scope; the read-side
    ## sentinel stays last) rather than one appended past the sentinel.

  TokenCaseAnchor = "  of esUnrecognized: \"\"\n"
    ## `evidenceScopeToken`'s sentinel arm. Distinct from `evidenceScopeCovers`'
    ## `of esUnrecognized: false`, which is why both can be anchored uniquely.

  ScopeCaseAnchor = "  of esFull, esUnrecognized: true\n"
    ## `recordInEvidenceScope`'s arm.

  CoversCaseAnchor = "  of esUnrecognized: false\n"
    ## `evidenceScopeCovers`' arm.

  CategoryEnumAnchor = "    ecIpc            ## mrIpcConnect"
    ## Where the interest-axis probe's new category goes. `EventCategory` has no
    ## read-side sentinel, so a new member simply goes last.

  CategoryTokenAnchor = "  of ecIpc: \"ipc\"\n"
    ## `interestToken`'s last arm.

  ProbeProgram = """
import io_mon/types

# Touch BOTH directions of BOTH codecs and the partial order, so nothing here
# can be discarded before the compiler has had to check it.
echo evidenceScopeToken(esFull)
echo $parseEvidenceScopeToken("reads-only")
echo $evidenceScopeCovers(esFull, esReadsOnly)
echo interestToTokens({ecFileDeps})
echo $parseInterestTokens("proc")
"""

proc spliceOnce(text, anchor, insertion: string): string =
  ## Insert `insertion` immediately BEFORE the sole occurrence of `anchor`.
  ## Raises when the anchor is missing or repeated: a source-rewriting probe
  ## that silently failed to mutate measures nothing, and that is the one
  ## failure mode this shape has which an ordinary test does not.
  let n = text.count(anchor)
  if n != 1:
    raise newException(ValueError,
      "anchor occurs " & $n & " times, expected exactly 1: " & anchor)
  let at = text.find(anchor)
  text[0 ..< at] & insertion & text[at .. ^1]

proc mutatedTypes(tokenArm: string): string =
  ## The REAL `types.nim` with an `esWritesOnly` member added, arms supplied for
  ## every OTHER exhaustive `case` over `EvidenceScope` in the file, and
  ## `tokenArm` (possibly empty) supplied for `evidenceScopeToken`.
  ##
  ## Filling those other two cases is what makes the measurement ATTRIBUTABLE: a
  ## new member reddens them too, so without their arms every probe below would
  ## fail and none of the failures would be about the token.
  result = readFile(TypesSource)
  result = spliceOnce(result, EnumAnchor,
    "    esWritesOnly      ## PROBE-ONLY, never a member of the shipped enum.\n")
  result = spliceOnce(result, ScopeCaseAnchor, "  of esWritesOnly: true\n")
  result = spliceOnce(result, CoversCaseAnchor, "  of esWritesOnly: false\n")
  if tokenArm.len > 0:
    result = spliceOnce(result, TokenCaseAnchor, tokenArm)

proc mutatedCategories(tokenArm: string): string =
  ## The REAL `types.nim` with an `ecProvenance` member added to `EventCategory`
  ## and `tokenArm` (possibly empty) supplied for `interestToken`.
  ##
  ## Shorter than `mutatedTypes` for a reason worth stating: NOTHING ELSE in
  ## this file switches exhaustively on `EventCategory`, so a new category costs
  ## exactly one arm. That is also why the axis was unpoliced for two rounds —
  ## there was no compiler complaint to prompt anyone.
  result = readFile(TypesSource)
  result = spliceOnce(result, CategoryEnumAnchor,
    "    ecProvenance     ## PROBE-ONLY, never a member of the shipped enum.\n")
  if tokenArm.len > 0:
    result = spliceOnce(result, CategoryTokenAnchor, tokenArm)

proc compileAgainstTypes(name, typesText: string):
                        tuple[output: string; code: int] =
  ## Compile `ProbeProgram` against a COPY of `types.nim` — never against the
  ## repo's own `src`, so a probe can neither perturb the tree the rest of the
  ## suite runs from nor be rescued by it. The probe lives OUTSIDE the repo so
  ## this repo's `config.nims` (which would put the real `src` on the path)
  ## never applies, and it carries its own `--nimcache` because sibling io-mon
  ## checkouts otherwise share one under `~/.cache/nim`.
  let dir = getTempDir() /
    ("io-mon-evidence-token-probe-" & $getCurrentProcessId() & "-" & name)
  removeDir(dir)
  createDir(dir / "io_mon")
  writeFile(dir / "io_mon" / "types.nim", typesText)
  let main = dir / "probe.nim"
  writeFile(main, ProbeProgram)
  let p = startProcess(getEnv("NIM", "nim"), workingDir = dir, args = @[
      "c", "--hints:off", "--warnings:off", "--compileOnly",
      "--nimcache:" & (dir / "cache"), "--path:" & dir, main],
    options = {poStdErrToStdOut, poUsePath})
  result = (p.outputStream.readAll(), p.waitForExit())
  p.close()
  removeDir(dir)

suite "io-mon evidence scope: a scope with no wire token cannot reach a depfile (DA-1i)":

  test "t_the_unmutated_codec_compiles":
    # NEGATIVE CONTROL 1. Without it, both refusals below would also "pass"
    # against a probe that fails to compile for some unrelated reason — the
    # standard way a compile-refusal test becomes a test that cannot fail.
    let (output, code) = compileAgainstTypes("control", readFile(TypesSource))
    checkpoint("control: exit " & $code & "\n" & output)
    check code == 0

  test "t_a_new_scope_given_a_real_token_compiles":
    # NEGATIVE CONTROL 2, and the sharper one: ADDING A MEMBER IS NOT ITSELF
    # REFUSED. What the two cases below refuse is adding one without a token,
    # so their refusals are attributable to the token and not to the member.
    let (output, code) = compileAgainstTypes("with-token",
      mutatedTypes("  of esWritesOnly: \"writes-only\"\n"))
    checkpoint("with-token: exit " & $code & "\n" & output)
    check code == 0

  test "t_a_new_scope_with_no_token_arm_does_not_compile":
    # ARM 1 — the exhaustive `case`. A member simply FORGOTTEN in the codec is a
    # compile error, where the array of pairs could only answer `""` and let the
    # capture proceed to a depfile nobody accepts.
    let (output, code) = compileAgainstTypes("no-arm", mutatedTypes(""))
    checkpoint("no-arm: exit " & $code & "\n" & output)
    check code != 0
    # …and it must fail FOR THE STATED REASON, naming the member.
    check "not all cases are covered" in output
    check "esWritesOnly" in output

  test "t_a_new_scope_whose_token_is_empty_does_not_compile":
    # ARM 2 — the `static:` coupling in `types.nim`, and the reason the
    # exhaustive `case` alone is NOT enough: its author can satisfy the compiler
    # with `of esWritesOnly: ""` and land straight back in the original defect
    # with the whole suite green. This is the exact mutation that shipped the
    # unacceptable depfile.
    let (output, code) = compileAgainstTypes("empty-token",
      mutatedTypes("  of esWritesOnly: \"\"\n"))
    checkpoint("empty-token: exit " & $code & "\n" & output)
    check code != 0
    check "non-empty wire token" in output
    check "esWritesOnly" in output

  test "t_a_new_scope_whose_token_cannot_survive_the_wire_does_not_compile":
    # ARM 3, and the one that shows "non-empty" was never the property. MEASURED
    # on the real bytes with only ARMS 1 and 2 in place: `writes;only` compiled,
    # satisfied the emptiness assertion, ROUND-TRIPPED IN MEMORY (so the runtime
    # enum case above stayed green), the whole portable suite stayed green — and
    # `mergeFragments` wrote a depfile that reads back `esUnrecognized` with the
    # residual named `writes`, because the `evidence=` stamp rides inside a
    # `;`-joined record detail and the decoder splits on `;` before `=`. That is
    # the original defect with a WRONG name attached instead of no name.
    let (output, code) = compileAgainstTypes("unsafe-token",
      mutatedTypes("  of esWritesOnly: \"writes;only\"\n"))
    checkpoint("unsafe-token: exit " & $code & "\n" & output)
    check code != 0
    check "is not wire-safe" in output
    check "esWritesOnly" in output

  test "t_a_new_scope_reusing_an_existing_token_does_not_compile":
    # ARM 4 — the highest-severity shape, and the only one whose failure
    # direction is ACCEPT. A duplicate token decodes to the FIRST member holding
    # it, so a capture taken under the new scope reads back as `esFull` and a
    # full-evidence consumer accepts a narrowed capture: this milestone's
    # cardinal defect, reached without a single test going red before this arm.
    let (output, code) = compileAgainstTypes("duplicate-token",
      mutatedTypes("  of esWritesOnly: \"full\"\n"))
    checkpoint("duplicate-token: exit " & $code & "\n" & output)
    check code != 0
    check "decodes back to" in output
    check "esWritesOnly" in output

suite "io-mon interest: a category with no wire token cannot reach a depfile (DA-1j)":
  # THE SAME CONSTRUCTION ON THE OTHER AXIS. `interestTokenPairs` was a plain
  # array while `evidenceScopeToken` was being made exhaustive, which left it as
  # the LAST unpoliced token table of the two — and "now the only one" is how
  # these persist. The harm is genuinely lesser (a missing token can only shrink
  # what a stamp declares, and `observedInterestCovers` is a subset test, so
  # every consequence points at rejection rather than at a false accept), which
  # is the argument for closing it cheaply rather than for leaving it open.

  test "t_the_unmutated_interest_codec_compiles":
    # NEGATIVE CONTROL 1 for this axis. Shares `ProbeProgram`, which now touches
    # both directions of BOTH codecs.
    let (output, code) = compileAgainstTypes("cat-control", readFile(TypesSource))
    checkpoint("cat-control: exit " & $code & "\n" & output)
    check code == 0

  test "t_a_new_category_given_a_real_token_compiles":
    # NEGATIVE CONTROL 2: adding a category is not itself refused.
    let (output, code) = compileAgainstTypes("cat-with-token",
      mutatedCategories("  of ecProvenance: \"provenance\"\n"))
    checkpoint("cat-with-token: exit " & $code & "\n" & output)
    check code == 0

  test "t_a_new_category_with_no_token_arm_does_not_compile":
    let (output, code) = compileAgainstTypes("cat-no-arm", mutatedCategories(""))
    checkpoint("cat-no-arm: exit " & $code & "\n" & output)
    check code != 0
    check "not all cases are covered" in output
    check "ecProvenance" in output

  test "t_a_new_category_whose_token_is_empty_does_not_compile":
    let (output, code) = compileAgainstTypes("cat-empty-token",
      mutatedCategories("  of ecProvenance: \"\"\n"))
    checkpoint("cat-empty-token: exit " & $code & "\n" & output)
    check code != 0
    check "needs a wire token" in output
    check "ecProvenance" in output

  test "t_a_new_category_whose_token_cannot_survive_the_wire_does_not_compile":
    # The interest value is COMMA-joined, so this axis has one more separator to
    # exclude than the evidence axis does.
    let (output, code) = compileAgainstTypes("cat-unsafe-token",
      mutatedCategories("  of ecProvenance: \"prov,enance\"\n"))
    checkpoint("cat-unsafe-token: exit " & $code & "\n" & output)
    check code != 0
    check "is not wire-safe" in output
    check "ecProvenance" in output
