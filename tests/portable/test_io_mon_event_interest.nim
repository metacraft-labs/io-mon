## Event-interest category API — docs/contributors/event-interest-filter.md.
##
## Pure/portable: exercises `categoryOf`, the interest token codec,
## normalization, and `recordWanted`. No monitoring, no platform hooks.

import std/[unittest, options]
import io_mon/types

suite "event-interest categories":
  test "categoryOf is total and META kinds are never categorized":
    # The three META kinds carry no category, so they can never be gated (LF-1:
    # a suppressed mrEventLoss would risk a false mcComplete).
    check categoryOf(mrEventLoss).isNone
    check categoryOf(mrBackendProfile).isNone
    check categoryOf(mrCapabilityGap).isNone
    # Every other kind maps to exactly one category.
    for kind in MonitorRecordKind:
      if kind in {mrEventLoss, mrBackendProfile, mrCapabilityGap}:
        check categoryOf(kind).isNone
      else:
        check categoryOf(kind).isSome

  test "the documented groupings":
    check categoryOf(mrFileRead) == some(ecFileDeps)
    check categoryOf(mrFileWrite) == some(ecFileDeps)
    check categoryOf(mrPathProbe) == some(ecFileDeps)
    check categoryOf(mrDirectoryEnumerate) == some(ecFileDeps)
    check categoryOf(mrPathMutation) == some(ecFileDeps)
    check categoryOf(mrProcessExec) == some(ecProcessTree)
    check categoryOf(mrLibraryLoad) == some(ecLibraryLoads)
    check categoryOf(mrTimeRead) == some(ecNonDeterminism)
    check categoryOf(mrEnvRead) == some(ecNonDeterminism)
    check categoryOf(mrSysctlRead) == some(ecNonDeterminism)
    check categoryOf(mrNonDeterministic) == some(ecNonDeterminism)
    check categoryOf(mrExternalContent) == some(ecNonDeterminism)
    check categoryOf(mrIpcConnect) == some(ecIpc)

  test "empty interest normalizes to FullInterest (unset never disables all)":
    check normalizeInterest({}) == FullInterest
    check normalizeInterest({ecFileDeps}) == {ecFileDeps}
    check parseInterestTokens("") == FullInterest
    check parseInterestTokens("   ") == FullInterest

  test "interest token codec round-trips":
    for s in [FullInterest, {ecFileDeps, ecProcessTree, ecLibraryLoads},
              {ecFileDeps}, {ecNonDeterminism, ecIpc}]:
      check parseInterestTokens(interestToTokens(s)) == normalizeInterest(s)

  test "FullInterest encodes non-empty so 'all' is distinct from 'unset'":
    check interestToTokens(FullInterest).len > 0
    check interestToTokens(FullInterest) == "file,proc,lib,nondet,ipc"

  test "unknown tokens are ignored (forward-compat)":
    check parseInterestTokens("file,bogus,lib") == {ecFileDeps, ecLibraryLoads}
    check parseInterestTokens("nope") == {}   # nothing valid -> empty, NOT full

  test "recordWanted: META always kept; category kept iff in the set":
    let onlyFiles = {ecFileDeps}
    check recordWanted(onlyFiles, mrFileRead)
    check not recordWanted(onlyFiles, mrTimeRead)     # ecNonDeterminism excluded
    check not recordWanted(onlyFiles, mrIpcConnect)   # ecIpc excluded
    check recordWanted(onlyFiles, mrEventLoss)        # META always kept
    check recordWanted(onlyFiles, mrBackendProfile)   # META always kept
    # Empty interest normalizes to FullInterest -> everything kept.
    check recordWanted({}, mrTimeRead)
    # reprobuild's default build-edge set: file + proc + lib, no nondet/ipc.
    let buildEdge = {ecFileDeps, ecProcessTree, ecLibraryLoads}
    check recordWanted(buildEdge, mrFileRead)
    check recordWanted(buildEdge, mrProcessExec)
    check recordWanted(buildEdge, mrLibraryLoad)
    check not recordWanted(buildEdge, mrEnvRead)
    check not recordWanted(buildEdge, mrIpcConnect)
