## Event-interest category API — docs/contributors/event-interest-filter.md.
##
## Pure/portable: exercises `categoryOf`, the interest token codec,
## normalization, `recordWanted`, and DA-5's legacy-alias vocabulary. No
## monitoring, no platform hooks, and NO MOCKS — every assertion below is over
## the shipped `io_mon/types` functions. (The pre-DA-5 reader modelled in
## `oldReaderCategories` is not a mock either: it is built from
## `legacyInterestToken`, which is the real token table this build still ships,
## applied by the same "match the token, ignore the rest" rule
## `parseInterestTokens` has always used.)
##
## WHAT DA-5 CHANGED, AND WHY THE SHAPE OF THIS FILE CHANGED WITH IT. The five
## pre-split categories grouped record kinds that LOOK alike; they are now
## grouped by the CONSUMER that reads them, and `ecIpc` is gone entirely because
## its one kind is completeness-bearing and therefore ungate-able. The
## membership case below is exhaustive over `MonitorRecordKind` on purpose: a
## record kind added later must state which consumer wants it before this file
## compiles, which is the only construction that keeps a new kind from
## inheriting a category — or an ungate-able status — by default.

import std/[unittest, options, strutils, sequtils]
import io_mon/types

const
  Ungateable = {mrEventLoss, mrBackendProfile, mrCapabilityGap,
                mrIpcConnect, mrExternalContent}
    ## Every kind `categoryOf` must answer `none` for, restated here
    ## INDEPENDENTLY of `categoryOf` so the assertions below are not a tautology
    ## over the thing they grade. Two classes, one property: META (LF-1) and
    ## completeness-bearing (`mergeFragments` derives a synthetic `mrEventLoss`
    ## from `mrIpcConnect` / `mrExternalContent` AFTER the shim's gate has run,
    ## so a category holding them converts `mcIncomplete` into `mcComplete`).

func expectedCategory(kind: MonitorRecordKind): Option[EventCategory] =
  ## THE MEMBERSHIP TABLE, WRITTEN OUT BY HAND AND EXHAUSTIVELY. Deliberately
  ## not derived from anything in `types.nim`: an expectation computed from the
  ## implementation grades nothing. One kind per arm — no grouping — so a
  ## reviewer reads "every kind states its own answer" rather than having to
  ## verify a grouping matches the grouping it is checking.
  case kind
  of mrFileOpen: some(ecFileReads)
  of mrFileRead: some(ecFileReads)
  of mrPathProbe: some(ecPathProbes)
  of mrDirectoryEnumerate: some(ecPathProbes)
  of mrFileWrite: some(ecFileWrites)
  of mrPathMutation: some(ecFileWrites)
  of mrProcessStart: some(ecProcessTree)
  of mrProcessExec: some(ecProcessTree)
  of mrProcessSpawn: some(ecProcessTree)
  of mrLibraryLoad: some(ecLibraryLoads)
  of mrEnvRead: some(ecEnvReads)
  of mrNonDeterministic: some(ecEntropy)
  of mrTimeRead: some(ecAmbientReads)
  of mrSysctlRead: some(ecAmbientReads)
  of mrIpcConnect: none(EventCategory)        # completeness-bearing
  of mrExternalContent: none(EventCategory)   # completeness-bearing
  of mrEventLoss: none(EventCategory)         # META (LF-1)
  of mrBackendProfile: none(EventCategory)    # META
  of mrCapabilityGap: none(EventCategory)     # META

func oldReaderCategories(s: string): set[LegacyEventCategory] =
  ## THE PRE-DA-5 DECODER, in the pre-DA-5 vocabulary. Not a reimplementation
  ## from memory and not a mock: the token table is `legacyInterestToken`, which
  ## this build still ships precisely because those bytes exist on disk, and the
  ## rule ("split on `,`, strip, keep what matches, ignore the rest") is the one
  ## `parseInterestTokens` has had since the flag shipped. Used to grade the
  ## new→old wire direction without needing an old binary.
  for raw in s.strip().split(','):
    let tok = raw.strip()
    for legacy in LegacyEventCategory:
      if tok == legacyInterestToken(legacy): result.incl(legacy)

func wantedKinds(interest: set[EventCategory]): set[MonitorRecordKind] =
  ## The record kinds `interest` asks for, by the shipped gate.
  for kind in MonitorRecordKind:
    if recordWanted(interest, kind): result.incl(kind)

func preDA5ShimKinds(value: string): set[MonitorRecordKind] =
  ## WHAT A SHIM BUILT BEFORE DA-5 EMITS under a `REPRO_MONITOR_INTEREST` value.
  ## `oldReaderCategories` answers the same question in the pre-split
  ## vocabulary; this one carries it through to the kinds, which is the level the
  ## harm is measured at — a category an old shim fails to name is a record that
  ## never exists, and the host filter only ever removes records.
  ##
  ## Built from the shipped `legacyInterestToken` / `legacyMemberKinds` (which
  ## exist precisely because those binaries and bytes do) plus the two rules the
  ## old build had: ignore unknown tokens, and normalise an empty result to
  ## "capture everything". Checked against a REAL shim built at `0c312f2`: its
  ## records match this prediction kind for kind, in the default arm, under
  ## DA-5's safe subset and under `--interest file-reads`.
  var cats = oldReaderCategories(value)
  if cats == {}:
    for legacy in LegacyEventCategory: cats.incl(legacy)
  for legacy in cats: result.incl(legacyMemberKinds(legacy))
  # The three META kinds belonged to no category in EITHER vocabulary.
  result.incl({mrEventLoss, mrBackendProfile, mrCapabilityGap})

suite "event-interest categories (DA-5: one category per consumer)":

  test "t_categoryOf_is_exhaustive_and_every_kind_states_its_own_answer":
    # THE EXHAUSTIVENESS PROOF, in two halves that fail for different reasons.
    #
    # (a) `expectedCategory` is an exhaustive `case` with no `else`, so adding a
    #     `MonitorRecordKind` is a COMPILE ERROR in this file until someone
    #     writes its arm. That half cannot be observed as a red test — it is the
    #     compiler refusing — and it is the half that matters, because a kind
    #     that silently inherited a category would be gated by a consumer that
    #     never asked about it.
    # (b) the loop below grades the shipped answer against that table, so a
    #     kind moved between categories without updating the expectation reddens
    #     here by name.
    var checkedKinds = 0
    for kind in MonitorRecordKind:
      inc checkedKinds
      check categoryOf(kind) == expectedCategory(kind)
    # A count, so a `MonitorRecordKind` that stopped being iterable (a hole cut
    # into the enum) cannot quietly shrink this case to nothing.
    check checkedKinds == 19

  test "t_the_ungateable_kinds_are_exactly_the_meta_and_completeness_bearing_ones":
    # The set equality in BOTH directions, because either inclusion alone is
    # satisfiable by an accident. A kind that wrongly became ungate-able is
    # over-capture (slower, still honest); a kind that wrongly became gate-able
    # is the cardinal sin if it is one of these five.
    var actual: set[MonitorRecordKind] = {}
    for kind in MonitorRecordKind:
      if categoryOf(kind).isNone: actual.incl(kind)
    check actual == Ungateable
    check mrIpcConnect in actual
    check mrExternalContent in actual
    check mrEventLoss in actual

  test "t_every_category_is_reachable_from_some_record_kind":
    # A category no kind maps to is a token a consumer can ask for that gates
    # nothing — the mirror image of a kind with no category, and just as silent.
    var covered: set[EventCategory] = {}
    for kind in MonitorRecordKind:
      let c = categoryOf(kind)
      if c.isSome: covered.incl(c.get)
    check covered == FullInterest

  test "t_LF1_no_interest_set_whatsoever_can_gate_a_loss_marker":
    # THE LF-1 ASSERTION, OVER EVERY SET THERE IS rather than over a chosen few.
    # `EventCategory` has 8 members, so this is 256 interest sets × 5 kinds =
    # 1280 answers, including the empty set and every single-category set. A
    # narrowed capture that could drop an `mrEventLoss` would manufacture a
    # false `mcComplete` out of a capture that lost data.
    #
    # It covers `mrIpcConnect` and `mrExternalContent` for the SAME reason and
    # not by analogy: `mergeFragments` derives the synthetic `mrEventLoss` from
    # them, and the shim's gate runs first, so gating them deletes the loss
    # marker one step earlier in the chain. Measured before DA-5 on Linux with
    # one out-of-tree `socat` peer: full interest graded `mcIncomplete` (1 loss,
    # 32 records), `--interest file,proc,lib` graded `mcComplete` (0 losses, 23
    # records).
    var sets = 0
    for bits in 0'u16 ..< 256'u16:
      var interest: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: interest.incl(cat)
      inc sets
      for kind in Ungateable:
        check recordWanted(interest, kind)
    check sets == 256

  test "t_a_gateable_kind_is_kept_exactly_when_its_category_is_asked_for":
    # The other side of the same sweep: for every set and every GATE-ABLE kind,
    # `recordWanted` must agree with plain membership of the normalized set.
    # Without this the LF-1 case above is satisfiable by a `recordWanted` that
    # returns `true` unconditionally.
    for bits in 0'u16 ..< 256'u16:
      var interest: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: interest.incl(cat)
      for kind in MonitorRecordKind:
        let c = categoryOf(kind)
        if c.isSome:
          check recordWanted(interest, kind) ==
            (c.get in normalizeInterest(interest))

  test "t_the_split_separates_the_cache_key_from_the_publish_gate":
    # THE DEFECT DA-5 CLOSED, stated as the property that was false before.
    # `mrEnvRead` reaches an action's CACHE KEY and `mrNonDeterministic` gates
    # cache PUBLICATION; before the split one bit controlled both, so no
    # consumer could keep one and drop the other. Now it can.
    check categoryOf(mrEnvRead) != categoryOf(mrNonDeterministic)
    let keyOnly = {ecEnvReads}
    check recordWanted(keyOnly, mrEnvRead)
    check not recordWanted(keyOnly, mrNonDeterministic)
    let gateOnly = {ecEntropy}
    check not recordWanted(gateOnly, mrEnvRead)
    check recordWanted(gateOnly, mrNonDeterministic)
    # And the two kinds nothing reads are separable from both.
    check categoryOf(mrTimeRead) == categoryOf(mrSysctlRead)
    check categoryOf(mrTimeRead) notin
      [categoryOf(mrEnvRead), categoryOf(mrNonDeterministic)]

  test "t_a_safe_subset_now_exists_and_drops_only_what_nothing_reads":
    # THE MILESTONE'S DELIVERABLE, as a set identity rather than as prose.
    # `FullInterest - {ecAmbientReads}` keeps every category a reprobuild
    # consumer reads — the input set, the probe/membership set, the output set,
    # the process tree, the library closure, the cache key and the publish gate
    # — and the kinds it does drop (`mrTimeRead`, `mrSysctlRead`) reach that
    # engine's record fold only to land on its `else: discard` arm.
    #
    # It is also the assertion that reddens if a later change gives
    # `ecAmbientReads` a second member whose consumer is real.
    const SafeSubset = FullInterest - {ecAmbientReads}
    check SafeSubset != FullInterest
    var droppedKinds: set[MonitorRecordKind] = {}
    for kind in MonitorRecordKind:
      if not recordWanted(SafeSubset, kind): droppedKinds.incl(kind)
    check droppedKinds == {mrTimeRead, mrSysctlRead}
    # Nothing completeness-bearing and nothing META is in there.
    check (droppedKinds * Ungateable) == {}

  test "t_empty_interest_normalizes_to_FullInterest_so_unset_never_disables_all":
    check normalizeInterest({}) == FullInterest
    check normalizeInterest({ecFileReads}) == {ecFileReads}
    check parseInterestTokens("") == FullInterest
    check parseInterestTokens("   ") == FullInterest

  test "t_the_interest_token_codec_round_trips_over_every_subset":
    # All 256 subsets, not a sample. The codec is a wire format and the
    # interesting failures (a duplicated token, a token carrying a separator)
    # show up on particular combinations, not on a representative one.
    for bits in 0'u16 ..< 256'u16:
      var s: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: s.incl(cat)
      check parseInterestTokens(interestToTokens(s)) == normalizeInterest(s)

  test "t_every_category_has_a_distinct_wire_safe_token":
    # The runtime twin of the `static:` block in `types.nim`. It cannot catch
    # the case that block exists for (a member ADDED without a token never
    # compiles, so no runtime case ever sees it) — it catches the tokens that
    # ARE here drifting into each other, and it names which.
    var seen: seq[string] = @[]
    for cat in EventCategory:
      let tok = interestToken(cat)
      check tok.len > 0
      check tok == tok.strip()
      check ',' notin tok
      check ';' notin tok
      check tok notin seen
      seen.add tok
    check seen.len == 8

  test "t_FullInterest_encodes_non_empty_so_all_is_distinct_from_unset":
    check interestToTokens(FullInterest).len > 0
    check interestToTokens(FullInterest) ==
      "file-reads,path-probes,file-writes,proc,lib,env,entropy,ambient"

  test "t_unknown_tokens_are_ignored_and_an_all_unknown_value_is_empty":
    check parseInterestTokens("file-reads,bogus,lib") ==
      {ecFileReads, ecLibraryLoads}
    check parseInterestTokens("nope") == {}   # nothing valid -> empty, NOT full

suite "event-interest legacy aliases (DA-5: old depfiles must still read)":

  test "t_every_legacy_token_expands_to_where_its_kinds_actually_went":
    # THE ALIAS SAFETY PROPERTY, and the only one on this axis whose failure
    # direction is ACCEPT. An expansion naming a category the old capture never
    # observed widens every stamp carrying that token, and a widened stamp is
    # accepted by a consumer that should have rejected it. Recomputed here from
    # `categoryOf` over the frozen kind list, independently of the shipped
    # `legacyInterestExpansion`.
    for legacy in LegacyEventCategory:
      var derived: set[EventCategory] = {}
      for kind in legacyMemberKinds(legacy):
        let c = categoryOf(kind)
        if c.isSome: derived.incl(c.get)
      check legacyInterestExpansion(legacy) == derived
      check parseInterestTokens(legacyInterestToken(legacy)) == derived

  test "t_the_legacy_expansions_are_the_documented_ones":
    # The values themselves, written out, so a change to the split that happens
    # to keep the derivation self-consistent still has to be acknowledged here.
    check legacyInterestExpansion(lecFileDeps) ==
      {ecFileReads, ecPathProbes, ecFileWrites}
    check legacyInterestExpansion(lecProcessTree) == {ecProcessTree}
    check legacyInterestExpansion(lecLibraryLoads) == {ecLibraryLoads}
    check legacyInterestExpansion(lecNonDeterminism) ==
      {ecEnvReads, ecEntropy, ecAmbientReads}
    # `ipc` parses and expands to NOTHING, because `mrIpcConnect` is no longer
    # gate-able. That is a reading of the old stamp, not a gap in the table:
    # the scope it named contains no category this build can narrow away.
    check legacyInterestExpansion(lecIpc) == {}
    check parseInterestTokens("ipc") == {}

  test "t_an_old_full_interest_stamp_still_reads_as_full_interest":
    # THE REASON THE ALIASES EXIST. Every depfile written before DA-5 by a
    # caller that did not narrow carries this exact string. Without the aliases
    # it would read as a scope this build cannot evaluate and every consumer
    # would reject work that was done correctly.
    check parseInterestTokens("file,proc,lib,nondet,ipc") == FullInterest

  test "t_an_old_narrowed_stamp_reads_narrowed_and_never_wider":
    # The build-edge set reprobuild used to request. It observed no environment
    # read, no entropy and no clock read, and it must not read as though it had.
    let old = parseInterestTokens("file,proc,lib")
    check old == {ecFileReads, ecPathProbes, ecFileWrites, ecProcessTree,
                  ecLibraryLoads}
    check ecEnvReads notin old
    check ecEntropy notin old
    check ecAmbientReads notin old
    check old != FullInterest
    # `nondet` alone is the complement, and equally exact.
    check parseInterestTokens("nondet") ==
      {ecEnvReads, ecEntropy, ecAmbientReads}

  test "t_a_legacy_spelling_that_is_also_a_current_one_means_the_same_thing":
    # `proc` and `lib` are reused DELIBERATELY: those two categories did not
    # split, so the old token names exactly today's category. This is the case
    # that would redden if a later change split one of them while leaving its
    # token alone — which would silently widen every old stamp carrying it.
    check parseInterestTokens("proc") == {ecProcessTree}
    check parseInterestTokens("lib") == {ecLibraryLoads}
    check legacyInterestToken(lecProcessTree) == interestToken(ecProcessTree)
    check legacyInterestToken(lecLibraryLoads) == interestToken(ecLibraryLoads)
    check legacyInterestExpansion(lecProcessTree) == {ecProcessTree}
    check legacyInterestExpansion(lecLibraryLoads) == {ecLibraryLoads}

  test "t_no_split_category_reuses_a_legacy_token":
    # The converse, and the one that protects the split categories. If
    # `ecFileReads` were spelled `file`, an old stamp meaning "reads, probes and
    # writes" would decode to reads only — a NARROWING of an old stamp, which
    # errs safe — but a new stamp meaning "reads only" would be read by the
    # alias arm as all three, which does not. Distinct spellings remove the
    # question.
    var canonical: seq[string] = @[]
    for cat in EventCategory: canonical.add interestToken(cat)
    var legacyOnly: seq[string] = @[]
    for legacy in LegacyEventCategory:
      let tok = legacyInterestToken(legacy)
      if tok notin canonical: legacyOnly.add tok
    check legacyOnly == @["file", "nondet", "ipc"]
    # The three split/retired spellings are reachable ONLY through the alias
    # arm, so no DEPFILE STAMP this build writes can be re-read through them.
    # Over all 256 sets, not just the full one: the stamp is a claim a consumer
    # can be made to ACCEPT too readily, and this is the property that makes the
    # read-side aliases safe to have.
    #
    # (The ENV channel deliberately DOES carry those spellings — see the
    # `interestToShimTokens` suite. Opposite channel, opposite safe direction.)
    for bits in 0'u16 ..< 256'u16:
      var s: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: s.incl(cat)
      check interestToTokens(s).split(',').allIt(it notin legacyOnly)
      check LegacyPaddingToken notin interestToTokens(s).split(',')

  test "t_the_new_vocabulary_read_by_an_OLD_reader_never_over_claims":
    # THE new→old WIRE DIRECTION, at the token level. (The same direction over
    # real depfile BYTES is in test_io_mon_observation_identity_fold.nim.) An
    # old build sees only the two unsplit tokens, so a new FULL capture reads to
    # it as a narrowed one and it re-captures — the cost is work, not a wrong
    # answer.
    let seenByOld = oldReaderCategories(interestToTokens(FullInterest))
    check seenByOld == {lecProcessTree, lecLibraryLoads}
    check lecFileDeps notin seenByOld
    check lecNonDeterminism notin seenByOld
    # A new capture narrowed to a category the old build has no name for at all
    # reads to it as an unevaluable stamp, which its own accessor already
    # rejects for every non-empty requirement.
    check oldReaderCategories(interestToTokens({ecAmbientReads})) == {}
    check oldReaderCategories(interestToTokens({ecEnvReads, ecEntropy})) == {}

  test "t_recordWanted_under_an_old_stamp_keeps_what_the_old_capture_kept":
    # The aliases are only correct if decoding an old value and re-gating with
    # it reproduces the old gate's behaviour kind by kind. Graded over all five
    # old tokens against the frozen membership lists, so this is an equivalence
    # and not a spot check.
    for legacy in LegacyEventCategory:
      let interest = parseInterestTokens(legacyInterestToken(legacy))
      for kind in MonitorRecordKind:
        let oldWouldKeep = kind in legacyMemberKinds(legacy) or
          kind in Ungateable
        # An empty decode normalizes to FullInterest, which keeps everything —
        # strictly more than the old gate kept, never less. `ipc` is the only
        # such token and the over-keep is the safe direction.
        if interest == {}:
          check recordWanted(interest, kind)
        else:
          check recordWanted(interest, kind) == oldWouldKeep

  test "t_the_legacy_token_is_paired_with_the_kinds_it_actually_gated":
    # THE PAIRING, not the expansion. Everything above is quantified over
    # `legacy` and re-derives both sides from the same table, so SWAPPING the
    # `file` and `nondet` spellings satisfies all of it — and every old
    # `interest=file,proc,lib` depfile then reads as having observed env reads
    # and entropy, the false accept this axis has no other defence against.
    #
    # The runtime twin of the `static:` block that closes it. The pairing is
    # frozen history and cannot be derived from today's code, but it CAN be
    # pinned to the NAMES of the record kinds each legacy category gated: every
    # shipped token is a case-insensitive substring of one of its own members'
    # identifiers, and it is the ONLY shipped token that is — so the witness
    # relation is a bijection and the pairing is the unique one satisfying it.
    for legacy in LegacyEventCategory:
      var witnessed: seq[LegacyEventCategory] = @[]
      for candidate in LegacyEventCategory:
        let probe = legacyInterestToken(candidate).toLowerAscii
        var hit = false
        for kind in legacyMemberKinds(legacy):
          if probe in ($kind).toLowerAscii: hit = true
        if hit: witnessed.add candidate
      checkpoint($legacy & " `" & legacyInterestToken(legacy) &
                 "` witnessed by " & $witnessed)
      check witnessed == @[legacy]
    # The values, written out, so the bijection above is anchored to something a
    # reviewer can read rather than only to a property.
    check legacyInterestToken(lecFileDeps) == "file"
    check legacyInterestToken(lecProcessTree) == "proc"
    check legacyInterestToken(lecLibraryLoads) == "lib"
    check legacyInterestToken(lecNonDeterminism) == "nondet"
    check legacyInterestToken(lecIpc) == "ipc"

suite "event-interest env channel (the value a SHIM is told)":
  ## The channel whose safe direction is the OPPOSITE of the depfile stamp's.
  ## A stamp over-stated is a false ACCEPT; an env value under-stated is a
  ## missing dependency under `mcComplete`. One vocabulary, two encoders.

  test "t_the_shim_value_names_every_legacy_category_holding_a_wanted_kind":
    # THE RULE, over all 256 interest sets. `interestToShimTokens` emits a legacy
    # spelling exactly when that legacy category holds a record kind this
    # interest wants — so the padding is DERIVED from `legacyMemberKinds` and
    # `recordWanted`, never written down.
    for bits in 0'u16 ..< 256'u16:
      var s: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: s.incl(cat)
      let wire = interestToShimTokens(s)
      var wanted: set[MonitorRecordKind] = {}
      for kind in MonitorRecordKind:
        if recordWanted(s, kind): wanted.incl(kind)
      let tokens = wire.split(',')
      for legacy in LegacyEventCategory:
        let expected = (legacyMemberKinds(legacy) * wanted) != {}
        checkpoint($s & " -> `" & wire & "` : " & $legacy)
        check (legacyInterestToken(legacy) in tokens) == expected

  test "t_a_pre_DA5_shim_under_capture_is_impossible_over_every_interest_set":
    # THE DELIVERABLE, as a property. Let `K` be the kinds the host wants and `E`
    # the kinds a shim built before DA-5 emits under the value the host writes.
    # `E ⊇ K` must hold for EVERY interest set: the old shim over-captures and
    # the host filter narrows `E` back to `K`, which is the safe direction
    # because that filter only ever REMOVES records and can never restore one
    # the shim did not emit.
    #
    # Graded against the canonical-only encoder as the negative control, so
    # "nothing under-captures" cannot pass because the model sees no difference:
    # that encoder — what this build shipped before the fix — under-captures on
    # 193 of the 256 sets, including `FullInterest`, which is the arm that
    # measured 14 records / `mcComplete` with no file records at all.
    var underCaptured = 0
    var underCapturedControl = 0
    for bits in 0'u16 ..< 256'u16:
      var s: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: s.incl(cat)
      var wanted: set[MonitorRecordKind] = {}
      for kind in MonitorRecordKind:
        if recordWanted(s, kind): wanted.incl(kind)
      let missing = wanted - preDA5ShimKinds(interestToShimTokens(s))
      if missing != {}:
        checkpoint($s & " -> `" & interestToShimTokens(s) & "` loses " & $missing)
        inc underCaptured
      if (wanted - preDA5ShimKinds(interestToTokens(s))) != {}:
        inc underCapturedControl
    check underCaptured == 0
    check underCapturedControl == 193
    # And the default — no flag at all — is the arm the issue was filed on.
    check preDA5ShimKinds(interestToShimTokens(FullInterest)) ==
      {MonitorRecordKind.low .. MonitorRecordKind.high}
    check (wantedKinds(FullInterest) -
           preDA5ShimKinds(interestToTokens(FullInterest))) ==
      {mrFileOpen, mrFileRead, mrPathProbe, mrDirectoryEnumerate, mrFileWrite,
       mrPathMutation, mrEnvRead, mrNonDeterministic, mrTimeRead, mrSysctlRead,
       mrIpcConnect, mrExternalContent}

  test "t_every_fully_requested_legacy_category_is_named_superset_or_equal":
    # The property the two CLI cases used to assert as a literal, stated where it
    # belongs. Whenever a legacy category's members are ALL requested, its token
    # is on the wire — so an old shim reads a SUPERSET-OR-EQUAL of the correct
    # set and never a subset.
    #
    # It is also the containment proof for the weaker rule: everything the
    # "only when ALL members are requested" version emits, the shipped version
    # emits too. The converse fails, which is why the shipped one is the rule.
    for bits in 0'u16 ..< 256'u16:
      var s: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: s.incl(cat)
      let tokens = interestToShimTokens(s).split(',')
      for legacy in LegacyEventCategory:
        if legacyInterestExpansion(legacy) <= normalizeInterest(s):
          checkpoint($s & " fully requests " & $legacy)
          check legacyInterestToken(legacy) in tokens

  test "t_the_fence_keeps_the_padding_away_from_a_CURRENT_shim":
    # The padding is for shims that predate the split. A CURRENT shim shares the
    # alias arm with the depfile decoder, so without the fence it would read the
    # padding as a widening and `--interest` would quietly stop narrowing
    # anything. Round-tripped over all 256 sets.
    for bits in 0'u16 ..< 256'u16:
      var s: set[EventCategory] = {}
      for cat in EventCategory:
        if (bits and (1'u16 shl uint16(ord(cat)))) != 0: s.incl(cat)
      let wire = interestToShimTokens(s)
      checkpoint($s & " -> `" & wire & "`")
      check parseInterestTokens(wire) == normalizeInterest(s)
      check LegacyPaddingToken in wire.split(',')
    # Deleting the fence rule from `parseInterestTokens` reddens the line above.
    # This is that failure, spelled out, so the mechanism is visible: without the
    # fence, `file-reads` would come back as all three file categories.
    check parseInterestTokens("file-reads,file") ==
      {ecFileReads, ecPathProbes, ecFileWrites}
    check parseInterestTokens("file-reads," & LegacyPaddingToken & ",file") ==
      {ecFileReads}

  test "t_no_value_that_ever_existed_carries_the_fence":
    # The fence changes how a value decodes, so it must be unreachable for every
    # value that was ever written. It is not a category, so no operator asks for
    # it (the CLI refuses it — see the interest-flag file); `interestToTokens`
    # does not emit it, so no depfile stamp has it; and no pre-DA-5 build knew
    # it. Every historical value therefore decodes exactly as it always did.
    check LegacyPaddingToken notin interestToTokens(FullInterest)
    for legacy in LegacyEventCategory:
      check legacyInterestToken(legacy) != LegacyPaddingToken
    for cat in EventCategory:
      check interestToken(cat) != LegacyPaddingToken
    # The pre-DA-5 stamps, decoding unchanged.
    check parseInterestTokens("file,proc,lib,nondet,ipc") == FullInterest
    check parseInterestTokens("file,proc,lib") ==
      {ecFileReads, ecPathProbes, ecFileWrites, ecProcessTree, ecLibraryLoads}
    check parseInterestTokens("nondet") ==
      {ecEnvReads, ecEntropy, ecAmbientReads}
    check parseInterestTokens("ipc") == {}

  test "t_a_shim_that_recognises_nothing_captures_everything":
    # THE SECOND LINE OF DEFENCE, and the one that costs a line. A shim handed a
    # value in a vocabulary it does not have at all has two readings available,
    # and only one of them can be wrong in a direction the host filter cannot
    # undo: capturing too much costs work the filter then discards, capturing too
    # little is a missing dependency under a stamp saying nothing is missing.
    #
    # It is NOT what fixed the defect — that shim recognised `proc` and `lib` and
    # was confidently wrong — but it is what defends the NEXT vocabulary change,
    # including one that retires `proc` or `lib`.
    check shimInterestFromEnv("quantum,warp") == FullInterest
    check shimInterestFromEnv("ipc") == FullInterest        # retired-only value
    check shimInterestFromEnv("") == FullInterest           # unset
    check shimInterestFromEnv("   ") == FullInterest
    # A value naming something real is still honoured exactly — the widening must
    # not swallow a genuine narrowing.
    check shimInterestFromEnv("file-reads") == {ecFileReads}
    check shimInterestFromEnv("file-reads,quantum") == {ecFileReads}
    check shimInterestFromEnv(interestToShimTokens({ecEntropy})) == {ecEntropy}
    # Today this is redundant with `normalizeInterest` inside `recordWanted`, and
    # the redundancy is asserted rather than assumed so that a future reader of
    # `gInterest` outside the emit funnel inherits the property.
    for kind in MonitorRecordKind:
      check recordWanted({}, kind)
    # The CLI takes the OPPOSITE decision on the same input, deliberately: there
    # an operator is present, refusal is available, and silently widening a typo
    # would discard a reduction they asked for.
    check parseInterestTokens("quantum,warp") == {}
