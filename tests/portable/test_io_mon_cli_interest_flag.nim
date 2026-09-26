## test_io_mon_cli_interest_flag — the `run --interest` flag, and the reason it
## had to exist: WITHOUT it an out-of-process consumer had no way at all to ask
## for a reduced event-interest set.
##
## WHY THIS FILE EXISTS
## --------------------
## `docs/contributors/event-interest-filter.md` §3 says the shim learns the
## interest set from `REPRO_MONITOR_INTEREST` on the child spawn. It does — but
## `childEnv` writes that variable AFTER `request.env` and after the injected
## pairs, because io-mon's injection must WIN over anything a caller supplies
## (that layering rule is `test_io_mon_child_env_layering.nim`'s subject, and it
## is a correctness rule: a caller must not be able to disarm monitoring). The
## consequence nobody had written down is that the variable is io-mon's OWN
## channel to the shim and is NOT an input a caller can set. An out-of-process
## consumer — reprobuild's build engine, which spawns `repro internal io
## monitor` — could put `REPRO_MONITOR_INTEREST` in that process's environment
## all it liked; `parseRun` accepted no interest flag, so the request carried
## `{}` -> `FullInterest`, and `childEnv` then wrote `FullInterest` straight
## over the request. The engine's reduction was live when it hosted io-mon
## in-process and dead when it spawned the CLI, for the same action.
##
## So the property under test is not "the flag parses". It is **the value the
## caller asked for is the value the child is told**, across the whole
## parse -> `FsSnoopRequest.interest` -> `childEnv` chain — the exact chain the
## request used to be dropped in the middle of. Every case below asserts the
## composed CHILD ENVIRONMENT, not just the parsed field, because asserting the
## field alone is what would have passed on the broken code had it existed:
## `FsSnoopRequest.interest` was already there and already honoured on the
## in-process path.
##
## No mocks: this drives the real argument parser and the real `childEnv`
## against the real process environment. Portable on purpose — `childEnv` has
## one body that all three arms call and the parser is platform-independent, so
## the rule holds wherever the suite runs.
##
## `parseFsSnoopCommand` and `childEnv` are deliberately unexported, so this
## file `include`s the module, exactly as `test_io_mon_child_env_layering.nim`
## and `test_io_mon_windows_child_env_block.nim` do.

import std/[strtabs, unittest]

include io_mon/fs_snoop

const
  BuildEdge = {ecFileReads, ecPathProbes, ecFileWrites, ecProcessTree,
               ecLibraryLoads}
    ## What reprobuild's engine used to spell `file,proc,lib`. After DA-5 the
    ## same request needs five tokens, because `ecFileDeps` split three ways by
    ## consumer — and it is written out here rather than as an alias so a case
    ## below can assert the flag emits the CURRENT vocabulary to the child.
  BuildEdgeTokens = "file-reads,path-probes,file-writes,proc,lib"
  LegacyBuildEdgeTokens = "file,proc,lib"
    ## The pre-DA-5 spelling of exactly that set. Still accepted on the command
    ## line (see `LegacyEventCategory`), and it must reach the child re-encoded
    ## in the new vocabulary — the shim is always this build's shim.
  AllTokens = "file-reads,path-probes,file-writes,proc,lib,env,entropy,ambient"
  LegacyAllTokens = "file,proc,lib,nondet,ipc"

## THE CHILD'S VALUE IS NO LONGER ASSERTED AS A LITERAL, AND THAT IS THE POINT
## OF THIS REVISION. Every case below used to compare
## `REPRO_MONITOR_INTEREST` against the exact string of canonical tokens — and
## every one of them passed while the build shipped a defect that lost every
## file record: a shim built before DA-5 recognises two of the eight canonical
## spellings, gates away the other six categories, and reports `mcComplete`.
## Measured on Linux, same command line, NO flag, only the shim differing:
## current shim 20 records / `mcIncomplete`, shim built at `0c312f2` **14
## records / `mcComplete`, no file records at all**.
##
## A literal cannot see that, because the defect is not in the string — it is in
## what a DIFFERENT READER makes of the string. So the assertions are now three
## properties (`checkChildIsTold`), and the third one is graded by a model of
## that other reader. Lengthening the literal to include the back-compat padding
## would have kept the same blind spot with a longer constant: it would pin the
## bytes this build happens to emit and still say nothing about whether an old
## shim can under-capture under them. The properties hold for every future
## padding rule; the literal would have to be re-typed by whoever changes one,
## which is exactly the edit that would need grading.
##
## The canonical PREFIX is still pinned literally, per case, because that half
## genuinely is a wire format this build controls end to end.

func canonicalPart(value: string): string =
  ## The part of a child's `REPRO_MONITOR_INTEREST` before the back-compat
  ## fence: what a shim of THIS build acts on (`parseInterestTokens` drops the
  ## alias arm once it has seen `LegacyPaddingToken`).
  var keep: seq[string] = @[]
  for raw in value.split(','):
    if raw == LegacyPaddingToken: break
    keep.add raw
  keep.join(",")

func paddingPart(value: string): seq[string] =
  ## The spellings after the fence: the back-compat vocabulary, which only a
  ## shim that predates the fence ever acts on.
  var afterFence = false
  for raw in value.split(','):
    if afterFence: result.add raw
    elif raw == LegacyPaddingToken: afterFence = true

func wantedKinds(interest: set[EventCategory]): set[MonitorRecordKind] =
  ## The record kinds `interest` asks for, by the shipped gate.
  for kind in MonitorRecordKind:
    if recordWanted(interest, kind): result.incl(kind)

func preDA5ShimKinds(value: string): set[MonitorRecordKind] =
  ## WHAT A SHIM BUILT BEFORE DA-5 WOULD EMIT under `value`. Not a mock and not
  ## a reimplementation from memory: the token table is `legacyInterestToken`
  ## and the membership is `legacyMemberKinds`, both of which this build still
  ## ships precisely because they describe bytes and binaries that exist; the
  ## decode rule ("split on `,`, strip, keep what matches, ignore the rest") is
  ## the one `parseInterestTokens` has had since the flag shipped, and the
  ## widening of an empty result is `normalizeInterest` inside `recordWanted`,
  ## which the old build had too.
  ##
  ## Verified against a REAL pre-rename shim rather than trusted: a shim built
  ## at `0c312f2` and run by the current host produces, kind for kind, the
  ## records this function predicts — in the default arm, under DA-5's safe
  ## subset, and under `--interest file-reads`.
  var cats: set[LegacyEventCategory] = {}
  for raw in value.split(','):
    let tok = raw.strip()
    for legacy in LegacyEventCategory:
      if tok == legacyInterestToken(legacy): cats.incl(legacy)
  if cats == {}:
    # Recognised nothing ⇒ the old gate normalised to "capture everything".
    for legacy in LegacyEventCategory: cats.incl(legacy)
  for legacy in cats: result.incl(legacyMemberKinds(legacy))
  # The three META kinds belonged to no category in EITHER vocabulary.
  result.incl({mrEventLoss, mrBackendProfile, mrCapabilityGap})

## Assertion helpers are TEMPLATES, never procs: a failing `check` inside a
## plain `proc` prints "Check failed" and the enclosing case still reports
## `[OK]`, because `unittest`'s failure flag is bound per test body.
template childInterest(argv: seq[string]): string =
  ## Parse `argv` the way `runFsSnoopCli` does, then compose the child
  ## environment the way all three spawn arms do, and read back the one
  ## variable the shim consults at init.
  childEnv(parseFsSnoopCommand(argv).request, @[])["REPRO_MONITOR_INTEREST"]

template parsedInterest(argv: seq[string]): set[EventCategory] =
  parseFsSnoopCommand(argv).request.interest

template checkChildIsTold(argv: seq[string]; want: set[EventCategory];
                          canonical: string) =
  ## THE WHOLE CONTRACT OF THE ENV CHANNEL, in the three parts that can fail
  ## independently. Used by every case that used to compare a literal.
  block:
    let value = childInterest(argv)
    checkpoint("child REPRO_MONITOR_INTEREST: " & value)
    # (1) THE CURRENT VOCABULARY, EXACTLY. The canonical part is the request in
    #     today's spellings — no alias, nothing dropped, nothing added. This is
    #     what the old literal asserted, and it is still asserted.
    check canonicalPart(value) == canonical
    # (2) THIS BUILD'S SHIM READS BACK THE REQUEST, NOT THE PADDING. If the
    #     fence stopped working, the padding would widen a current shim's gate
    #     and `--interest` would quietly stop narrowing anything.
    check parseInterestTokens(value) == normalizeInterest(want)
    # (3) A PRE-DA-5 SHIM UNDER-CAPTURES NOTHING. The one property that grades
    #     the defect: every kind the host asked for must be a kind the old shim
    #     would still emit. Superset is fine — the host filter removes the
    #     extras — a SUBSET is the false `mcComplete`.
    check (wantedKinds(want) - preDA5ShimKinds(value)) == {}

suite "io-mon CLI event-interest flag":
  test "with no flag the child is told FullInterest — every existing caller is unchanged":
    # The back-compat contract stated in `parseInterestFlag`'s doc comment and
    # in docs/usage.md. `interest` is left zero (`{}`), and `normalizeInterest`
    # inside `interestToTokens` widens it, so "unset" and "all" reach the shim
    # as the same non-empty token list — the shim can still tell them apart
    # from a genuinely absent variable.
    let argv = @["run", "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == {}
    checkChildIsTold(argv, FullInterest, AllTokens)

  test "the requested set reaches the child — space form":
    # THE PRIMARY ASSERTION. Deleting the `--interest` arm from `parseRun`
    # leaves this reading `AllTokens`.
    let argv = @["run", "--interest", BuildEdgeTokens,
                 "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == BuildEdge
    checkChildIsTold(argv, BuildEdge, BuildEdgeTokens)

  test "the requested set reaches the child — `--interest=` form":
    let argv = @["run", "--interest=" & BuildEdgeTokens,
                 "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == BuildEdge
    checkChildIsTold(argv, BuildEdge, BuildEdgeTokens)

  test "the flag works on the `run`-less legacy form reprobuild used to use":
    # `repro internal io monitor` dispatched the verb itself before delegating,
    # so the bare `--depfile … -- <cmd>` grammar is still accepted. The flag has
    # to reach the same parser on that path or the fix covers only half the
    # callers.
    let argv = @["--interest", BuildEdgeTokens,
                 "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == BuildEdge
    checkChildIsTold(argv, BuildEdge, BuildEdgeTokens)

  test "a single category is honoured, not widened":
    # Guards the boundary the codec makes easy to get wrong: `{ecFileReads}` is
    # a legitimate reduced set and must NOT be confused with the `{}` that means
    # "unset".
    #
    # This is also the case the WEAKER padding rule fails. "Emit the legacy
    # token when ALL of a legacy category's members are requested" sends
    # `file-reads,ipc` here; a pre-DA-5 shim recognises only `ipc` and the
    # capture comes back with no file records under a stamp saying
    # `interest=file-reads`. Property (3) reddens on that rule and passes on the
    # shipped one, which is the difference between repairing the default and
    # repairing the axis.
    let argv = @["run", "--interest", "file-reads", "--", "true"]
    check parsedInterest(argv) == {ecFileReads}
    checkChildIsTold(argv, {ecFileReads}, "file-reads")

  test "the flag beats a caller-supplied REPRO_MONITOR_INTEREST in request.env":
    # The layering rule that made the flag necessary, asserted from the other
    # side. A caller cannot reach the shim through the environment — io-mon's
    # injection overwrites the variable — so the flag is the ONLY channel, and
    # a caller trying both must get the flag's answer rather than a race
    # between two mechanisms.
    var parsed = parseFsSnoopCommand(@["run", "--interest", BuildEdgeTokens,
                                       "--", "true"])
    parsed.request.env.add(("REPRO_MONITOR_INTEREST", "env,entropy"))
    let composed = childEnv(parsed.request, @[])["REPRO_MONITOR_INTEREST"]
    checkpoint("composed: " & composed)
    check canonicalPart(composed) == BuildEdgeTokens
    check parseInterestTokens(composed) == BuildEdge

  test "an explicitly empty value means the same as an absent flag":
    # BOTH SPELLINGS, because the sentence this case is named after is about the
    # FLAG and not about one of its two forms — and every other value-bearing
    # flag here means the same thing whichever way it is written.
    #
    # It used to assert the space form only, and for the `=` form the sentence
    # was FALSE. MEASURED at the binary: `io-mon run --interest "" …` exited 0
    # and stamped `interest=file,proc,lib,nondet,ipc`, while
    # `io-mon run --interest= …` exited 1 with "unsupported fs-snoop argument:
    # --interest=" and wrote no depfile at all — the parser denying the flag
    # exists, because `parseRun`'s catch-all dispatched on
    # `interestValue.len > 0`, which cannot tell "this flag with an empty value"
    # from "not this flag". Restoring that dispatch reddens this case.
    for argv in [@["run", "--interest", "", "--", "true"],
                 @["run", "--interest", "   ", "--", "true"],
                 @["run", "--interest=", "--", "true"],
                 @["run", "--interest=   ", "--", "true"],
                 # …and on the `run`-less legacy form too, which reaches the
                 # same parser by a different door.
                 @["--interest=", "--", "true"]]:
      checkpoint("argv: " & $argv)
      checkChildIsTold(argv, FullInterest, AllTokens)
      check parsedInterest(argv) == FullInterest

  test "an unknown token beside a known one is ignored (forward-compat)":
    # A newer consumer naming a category this build does not have must not fail
    # the run; the host-side filter is the source of truth either way
    # (event-interest-filter.md §5).
    check parsedInterest(@["run", "--interest", "file-reads,quantum,lib",
                           "--", "true"]) == {ecFileReads, ecLibraryLoads}

  test "a value naming NO known token is refused, not widened to all":
    # The operator-typo case. Silently widening it would hand back
    # `FullInterest` and discard the caller's reduction without a word — the
    # very failure this flag exists to end — so it is a hard parse error, the
    # same class as `--events bogus`.
    expect ValueError:
      discard parseFsSnoopCommand(@["run", "--interest", "flie,prcO",
                                    "--", "true"])
    # …and the diagnostic names the vocabulary, so the typo is fixable from the
    # message alone.
    try:
      discard parseFsSnoopCommand(@["run", "--interest", "flie", "--", "true"])
      check false        # unreachable: the line above must raise
    except ValueError as err:
      check AllTokens in err.msg

  test "--interest still requires a value":
    expect ValueError:
      discard parseFsSnoopCommand(@["run", "--interest"])

  test "t_a_pre_DA5_command_line_still_works_and_is_re_encoded_for_the_child":
    # DA-5. An operator (or a caller's stored command line) that still says
    # `--interest file,proc,lib` must get the set that value always meant — and
    # the CURRENT part of what the child is told must be in TODAY's vocabulary,
    # because the shim it is talking to is *probably* this build's shim.
    #
    # "PROBABLY" IS WHAT THIS CASE USED TO GET WRONG, and it asserted the
    # certainty as a literal: `childInterest(argv) == BuildEdgeTokens` and
    # `!= LegacyBuildEdgeTokens`, i.e. "the alias must not survive into the env
    # channel". `findShimLibrary` falls back to the canonical `build/lib`, and
    # `nim c cmd/io_mon_snoop.nim` does not rebuild the shim, so the shim on the
    # other end of this variable is whatever is on disk. The alias must therefore
    # survive into the env channel — BESIDE the canonical spellings and behind
    # the fence, so that the vintage of the reader decides which half it acts on.
    let argv = @["run", "--interest", LegacyBuildEdgeTokens,
                 "--depfile", "d.iomon", "--", "true"]
    check parsedInterest(argv) == BuildEdge
    checkChildIsTold(argv, BuildEdge, BuildEdgeTokens)
    # The canonical half is NOT the legacy spelling — the re-encoding half of
    # the original claim still holds, and is what property (1) pins.
    check canonicalPart(childInterest(argv)) != LegacyBuildEdgeTokens
    # …and the legacy spelling of this very request is in the padding, because
    # all three of `file`'s categories were asked for.
    check "file" in paddingPart(childInterest(argv))
    # The old spelling of "everything" likewise resolves to everything.
    let allArgv = @["run", "--interest", LegacyAllTokens, "--", "true"]
    check parsedInterest(allArgv) == FullInterest
    checkChildIsTold(allArgv, FullInterest, AllTokens)
    # A pre-DA-5 shim under the default request reads FULL scope — the exact
    # arm that measured 14 records / `mcComplete` before this fix, and which now
    # measures 20 / `mcIncomplete`, byte-identical to the current shim's.
    check preDA5ShimKinds(childInterest(allArgv)) ==
      {MonitorRecordKind.low .. MonitorRecordKind.high}

  test "t_a_value_naming_only_retired_categories_is_refused_with_the_reason":
    # `--interest ipc` used to be a legal request. `mrIpcConnect` is now
    # ungate-able — it is one of the kinds io-mon derives its event-loss markers
    # from, so a category holding it is a switch that turns `mcIncomplete` into
    # `mcComplete` — and the value therefore names no category this build can be
    # asked for.
    #
    # It must be REFUSED (widening it to `FullInterest` would discard the
    # operator's reduction silently, which is the failure this flag exists to
    # end) and it must be refused with its OWN sentence: sending the operator to
    # hunt for a misspelling in a token that is spelled correctly is a worse
    # diagnostic than none.
    expect ValueError:
      discard parseFsSnoopCommand(@["run", "--interest", "ipc", "--", "true"])
    try:
      discard parseFsSnoopCommand(@["run", "--interest", "ipc", "--", "true"])
      check false        # unreachable: the line above must raise
    except ValueError as err:
      checkpoint("message: " & err.msg)
      check "no longer exist" in err.msg
      check "ungate-able" in err.msg
      check AllTokens in err.msg
      # NOT the typo message — that is the whole point of the branch.
      check "names no known event category" notin err.msg
    # A genuine typo still gets the typo message, so the two branches are
    # distinguishable and the case above is not passing for a generic reason.
    try:
      discard parseFsSnoopCommand(@["run", "--interest", "ipcc", "--", "true"])
      check false
    except ValueError as err:
      check "names no known event category" in err.msg
      check "no longer exist" notin err.msg
    # And `ipc` beside a live token is still the forward/backward-compat rule:
    # accepted, contributing nothing.
    check parsedInterest(@["run", "--interest", "ipc,lib", "--", "true"]) ==
      {ecLibraryLoads}

  test "t_the_safe_subset_is_expressible_on_the_command_line":
    # DA-5's deliverable, at the surface an operator actually uses. Before the
    # split there was no non-empty proper subset of the categories that dropped
    # only records no consumer reads; now there is exactly one, and it has to be
    # sayable.
    const SafeSubsetTokens =
      "file-reads,path-probes,file-writes,proc,lib,env,entropy"
    let argv = @["run", "--interest", SafeSubsetTokens, "--", "true"]
    check parsedInterest(argv) == FullInterest - {ecAmbientReads}
    check parsedInterest(argv) != FullInterest
    checkChildIsTold(argv, FullInterest - {ecAmbientReads}, SafeSubsetTokens)
    # AND IT HAS TO BE SAYABLE TO A SHIM THAT IS NOT THIS BUILD'S, which is the
    # part the literal could not express. The safe subset is not a union of
    # pre-DA-5 categories — it asks for two of `nondet`'s three — so the weaker
    # "only when ALL members are requested" padding rule omits `nondet` here and
    # a pre-DA-5 shim then drops `mrEnvRead` (which keys the action cache),
    # `mrNonDeterministic` (which gates publication) and `mrExternalContent`
    # (from which the merge derives an event-loss marker). Measured live against
    # a shim built at `0c312f2`: 19 records / `mcIncomplete`, `env-read` and
    # `ipc-connect` and the loss marker all present, and only the two
    # `ecAmbientReads` kinds gone — identical to the current shim's capture.
    check "nondet" in paddingPart(childInterest(argv))
    let seenByOld = preDA5ShimKinds(childInterest(argv))
    check mrEnvRead in seenByOld
    check mrNonDeterministic in seenByOld
    check mrExternalContent in seenByOld
    check mrIpcConnect in seenByOld

  test "t_the_back_compat_fence_is_not_a_category_an_operator_can_ask_for":
    # `LegacyPaddingToken` is a wire marker, and on this flag it would SUPPRESS
    # the alias arm beside it — so `--interest legacy-padding,file` would quietly
    # mean `{}` rather than the file categories. Refused with its own sentence
    # rather than reinterpreted.
    for value in [LegacyPaddingToken, LegacyPaddingToken & ",file",
                  "file-reads," & LegacyPaddingToken]:
      checkpoint("value: " & value)
      expect ValueError:
        discard parseFsSnoopCommand(@["run", "--interest", value, "--", "true"])
    try:
      discard parseFsSnoopCommand(
        @["run", "--interest", LegacyPaddingToken, "--", "true"])
      check false        # unreachable: the line above must raise
    except ValueError as err:
      checkpoint("message: " & err.msg)
      check "not an event category" in err.msg
      check "older shim" in err.msg
      check AllTokens in err.msg
      # NOT the typo message and NOT the retired-category one.
      check "names no known event category" notin err.msg
      check "no longer exist" notin err.msg
