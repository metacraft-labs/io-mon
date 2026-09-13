## test_io_mon_dep_set_element_key — DA-1d
## (reprobuild-specs/Dependency-Attribution.milestones.org).
##
## THE DEFECT THIS FILE CLOSES. Three sites encoded "what goes in a dep-set
## element key", and only ONE consulted the predicate that decides it:
##
##   | site                              | incarnation suffix | consulted it |
##   | `writer.appendFragmentRecord`     | per predicate      | yes          |
##   | `writer.rebuildDepSetLossElem`    | ALWAYS appended    | no           |
##   | `fs_snoop.emitLauncherLossToSet`  | NEVER appended     | no           |
##
## Two sites gave OPPOSITE hard-coded answers to the same question about the same
## kind, and both were "right" only because `mrEventLoss` happens to be
## process-scoped. DA-1b's landing comment claimed `depIdentityScope` was the one
## place the decision lived; review found that false. DA-1d makes it true, and
## this file is what holds it true: all three sites now compose their key with
## `writer.encodeDepSetElement`.
##
## DA-1b measured two mutations as INERT — reddening nothing at all:
##   * removing the incarnation suffix from `rebuildDepSetLossElem`;
##   * dropping `mrPathProbe` from the `dropObserver` result normalisation.
## Both are graded here. The first by `t_the_loss_element_is_the_shared_site`;
## the second by `t_the_normalisation_decision_table` — the probe arm is a GUARD
## against a non-Linux backend rather than a live reducer (a Linux probe's
## `result` is already only 0 or −1), so what it needed was a stated decision and
## a test, not deletion.
##
## BYTE STABILITY IS THE POINT, not a side condition. Unifying the three sites
## must not move one byte any capture produces, so the pre-DA-1d behaviour of
## each site is REIMPLEMENTED LITERALLY below and compared against the shared
## composer over a corpus that covers every record kind, several incarnations,
## and the overflow boundaries. That is an exact equivalence over the input space
## rather than a diff of one capture.
##
## Portable: pure `io_mon/types` + `io_mon/writer` + `io_mon/shm/dep_queue`. No
## shim, no shared memory, no platform API.

import std/[algorithm, os, strutils, unittest]

import io_mon/types
import io_mon/writer
import io_mon/shm/dep_queue

# ---------------------------------------------------------------------------
# The HOST claim, captured before anything in this file can perturb it.
#
# `fs_snoop.emitLauncherLossToSet` runs in the host process and used to hard-code
# "no incarnation suffix". After DA-1d it asks the shared composer, which reads
# `setElemImage` — so the bytes are unchanged ONLY IF a host's incarnation is
# empty. `setDepSetIncarnationImage` has exactly one production caller (the Linux
# shim's init/exec path), so a process that never loaded the shim has none. This
# test binary is such a process; the claim is measured here rather than argued.
# ---------------------------------------------------------------------------
let incarnationAtProcessStart = depSetIncarnationImage()

const
  LossBufLen = DepFixedHeaderLen + 64
    ## `writer.setLossElem`'s size — the small pre-encoded loss buffer.
  HotPathBufLen = 16384
    ## `writer.SetProducerBufBytes` — the shim's publish-before-return buffer.
  LauncherBufLen = 512
    ## `fs_snoop.emitLauncherLossToSet`'s stack buffer.

const
  # DA-1b/DA-1d — the incarnation decision, restated as literal sets. This is
  # deliberately a SECOND statement rather than a call into
  # `depIdentityKeepsIncarnation`: a test that asks the implementation what it
  # decided cannot notice a kind being moved. Adding a `MonitorRecordKind`
  # without placing it in exactly one set fails the partition check below.
  KeepsIncarnationKinds = {mrFileOpen, mrFileRead, mrPathProbe,
    mrDirectoryEnumerate, mrProcessStart, mrProcessExec, mrProcessSpawn,
    mrFileWrite, mrEventLoss, mrBackendProfile, mrCapabilityGap, mrIpcConnect,
    mrNonDeterministic, mrExternalContent, mrPathMutation}
  DropsIncarnationKinds = {mrLibraryLoad, mrEnvRead, mrSysctlRead, mrTimeRead}

  # DA-1d — the result/flags normalisation decision table, likewise restated.
  OutcomeFoldedKinds = {mrFileRead, mrFileWrite}
    ## byte count AND descriptor folded out entirely
  OutcomeSuccessFailureKinds = {mrFileOpen, mrPathProbe}
    ## reduced to success/failure; flags (O_* mode) stay in the key
  OutcomeVerbatimKinds = {mrDirectoryEnumerate, mrLibraryLoad, mrEnvRead,
    mrSysctlRead, mrTimeRead, mrProcessStart, mrProcessExec, mrProcessSpawn,
    mrEventLoss, mrBackendProfile, mrCapabilityGap, mrIpcConnect,
    mrNonDeterministic, mrExternalContent, mrPathMutation}

proc sampleRecord(kind: MonitorRecordKind): MonitorRecord =
  ## One representative record per kind, with every identity-bearing field
  ## non-trivial so a dropped or mis-normalised field shows up as differing
  ## bytes rather than as a coincidence of zeros.
  MonitorRecord(
    kind: kind,
    observationKind: moFileRead,
    seq: 7734,
    osPid: 4242,
    parentOsPid: 4241,
    threadId: 99,
    childOsPid: 4243,
    result: 137,
    flags: 0xA5A5_0F0F'u32,
    probeResult: prExistingFile,
    path: "/usr/include/" & $kind & ".h",
    detail: "detail:" & $kind & " run=abc123")

proc bytesOf(buf: openArray[byte]; n: int): seq[byte] =
  result = newSeq[byte](max(n, 0))
  for i in 0 ..< max(n, 0):
    result[i] = buf[i]

# ---------------------------------------------------------------------------
# The three call sites, REIMPLEMENTED EXACTLY AS THEY WERE BEFORE DA-1d.
#
# Each returns the element bytes it would have published, or `@[]` with
# `framed = false` where the site treated the record as unframable. These are
# the oracle for "no output byte changed"; they are literal transcriptions, not
# paraphrases, and they call the same `encodeDepRecordIdentity` the real sites
# called.
# ---------------------------------------------------------------------------

proc legacyHotPath(record: MonitorRecord; image: string):
    tuple[framed: bool; elem: seq[byte]] =
  ## `writer.appendFragmentRecord`, pre-DA-1d: identity encode, then append the
  ## incarnation image for the kinds `depIdentityKeepsIncarnation` selects, and
  ## treat "does not fit" as unframable (the caller then published a loss marker).
  var buf {.noinit.}: array[HotPathBufLen, byte]
  let recLen = encodeDepRecordIdentity(record, buf)
  let imageLen =
    if depIdentityKeepsIncarnation(record.kind): image.len else: 0
  if recLen >= 0 and recLen + imageLen <= HotPathBufLen:
    var total = recLen
    for i in 0 ..< imageLen:
      buf[total] = byte(image[i]); inc total
    (true, bytesOf(buf, total))
  else:
    (false, @[])

proc legacyLossElement(image: string): seq[byte] =
  ## `writer.rebuildDepSetLossElem`, pre-DA-1d: identity encode, then ALWAYS
  ## append as much of the incarnation image as still fits — no predicate.
  let lossRec = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
    detail: "dep-set-capture-loss")
  var buf {.noinit.}: array[LossBufLen, byte]
  let n = encodeDepRecordIdentity(lossRec, buf)
  if n < 0:
    return @[]
  var total = n
  var i = 0
  while i < image.len and total < LossBufLen:
    buf[total] = byte(image[i]); inc total; inc i
  bytesOf(buf, total)

proc legacyLauncherLoss(rec: MonitorRecord): tuple[framed: bool; elem: seq[byte]] =
  ## `fs_snoop.emitLauncherLossToSet`, pre-DA-1d: identity encode and publish,
  ## NEVER appending an incarnation suffix — no predicate.
  var buf {.noinit.}: array[LauncherBufLen, byte]
  let n = encodeDepRecordIdentity(rec, buf)
  if n < 0: (false, @[]) else: (true, bytesOf(buf, n))

proc legacyNormalize(kind: MonitorRecordKind; rawResult: int64;
                     rawFlags: uint32): tuple[outcome: int64; flags: uint32] =
  ## The pre-DA-1d `dropObserver` normalisation: a PARTIAL case with an `else`
  ## that answered for every kind nobody had classified.
  case kind
  of mrFileRead:
    (0'i64, 0'u32)
  of mrFileOpen, mrPathProbe:
    ((if rawResult < 0: -1'i64 else: 0'i64), rawFlags)
  else:
    (rawResult, rawFlags)

# The incarnations exercised. The real shim's is
# `<realpath(/proc/self/exe)>\x1f<execGen>`; the empty one is a host process.
const Incarnations = [
  "",
  "/x",
  "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-gcc-13.2.0/bin/gcc\x1f0",
  "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-gcc-13.2.0/bin/gcc\x1f7"]

suite "DA-1d: one site composes a dep-set element key":

  test "t_the_incarnation_decision_table_partitions_the_enum":
    var seen: set[MonitorRecordKind]
    for kind in MonitorRecordKind:
      let inKeeps = kind in KeepsIncarnationKinds
      let inDrops = kind in DropsIncarnationKinds
      check inKeeps != inDrops          # exactly one, never both, never neither
      seen.incl kind
      check depIdentityKeepsIncarnation(kind) == inKeeps
    check seen == {low(MonitorRecordKind) .. high(MonitorRecordKind)}
    echo "DA-1d: incarnation table covers ", card(seen),
      " kinds (", card(KeepsIncarnationKinds), " keep / ",
      card(DropsIncarnationKinds), " drop)"

  test "t_the_shared_site_consults_the_predicate_for_every_kind":
    # The grading test for the composer itself: for EVERY kind and EVERY
    # incarnation, the key is the bare identity followed by the suffix iff the
    # kind keeps one. A composer that hard-codes either answer reddens here for
    # 15 kinds or for 4.
    for kind in MonitorRecordKind:
      let record = sampleRecord(kind)
      var identityBuf {.noinit.}: array[HotPathBufLen, byte]
      let identityLen = encodeDepRecordIdentity(record, identityBuf)
      require identityLen > 0
      let identity = bytesOf(identityBuf, identityLen)
      for image in Incarnations:
        setDepSetIncarnationImage(image)
        var buf {.noinit.}: array[HotPathBufLen, byte]
        let n = encodeDepSetElement(record, buf)
        require n > 0
        let elem = bytesOf(buf, n)
        let expectedSuffix =
          if kind in KeepsIncarnationKinds: image else: ""
        check elem.len == identity.len + expectedSuffix.len
        check elem[0 ..< identity.len] == identity
        for i in 0 ..< expectedSuffix.len:
          check char(elem[identity.len + i]) == expectedSuffix[i]
    setDepSetIncarnationImage("")

  test "t_the_hot_path_site_is_byte_identical_to_its_pre_DA_1d_self":
    for kind in MonitorRecordKind:
      let record = sampleRecord(kind)
      for image in Incarnations:
        setDepSetIncarnationImage(image)
        let legacy = legacyHotPath(record, image)
        var buf {.noinit.}: array[HotPathBufLen, byte]
        let n = encodeDepSetElement(record, buf, dseRequireFit)
        check (n >= 0) == legacy.framed
        if legacy.framed:
          check bytesOf(buf, n) == legacy.elem
    setDepSetIncarnationImage("")

  test "t_the_loss_element_is_the_shared_site":
    # Grades DA-1b's first INERT mutation. `rebuildDepSetLossElem` used to append
    # the incarnation unconditionally; removing that reddened NOTHING, because
    # any distinct `mrEventLoss` element downgrades the edge just as well. The
    # site is now graded two ways at once: byte-identical to its pre-DA-1d self
    # (so DA-1d moved nothing), AND equal to what the shared composer produces
    # (so a site that stops feeding the composer its incarnation reddens).
    for image in Incarnations:
      setDepSetIncarnationImage(image)
      rebuildDepSetLossElem()
      let published = depSetLossElement()
      check published == legacyLossElement(image)

      let lossRec = MonitorRecord(kind: mrEventLoss,
        observationKind: moEventLoss, detail: "dep-set-capture-loss")
      var buf {.noinit.}: array[LossBufLen, byte]
      let n = encodeDepSetElement(lossRec, buf, dseTruncateSuffix)
      require n > 0
      check published == bytesOf(buf, n)
      # And the suffix really is there: a truncating buffer this small cannot
      # hold a store path, so the element must be exactly full when the
      # incarnation is long.
      if image.len > LossBufLen:
        check published.len == LossBufLen
    setDepSetIncarnationImage("")
    echo "DA-1d: loss element graded over ", Incarnations.len, " incarnations"

  test "t_the_launcher_loss_site_is_byte_identical_in_a_host_process":
    # The `fs_snoop` site's byte-stability argument, measured rather than
    # argued: a host process has no incarnation, so asking the shared composer
    # returns exactly what hard-coding "no suffix" returned.
    check incarnationAtProcessStart == ""
    setDepSetIncarnationImage("")
    for pid in [1'u64, 4242'u64]:
      let rec = MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
        osPid: pid, detail: "launcher-descendant-scan-failed run=abc123")
      let legacy = legacyLauncherLoss(rec)
      var buf {.noinit.}: array[LauncherBufLen, byte]
      let n = encodeDepSetElement(rec, buf)
      check (n >= 0) == legacy.framed
      check bytesOf(buf, n) == legacy.elem

  test "t_an_unframable_record_is_refused_rather_than_clipped":
    # `dseRequireFit` vs `dseTruncateSuffix` is an OVERFLOW policy, and the
    # distinction is load-bearing: clipping a REAL record's key could make two
    # different records collide, so the hot path refuses instead and publishes a
    # loss marker. Only the loss element — which merely has to be distinct — may
    # truncate.
    setDepSetIncarnationImage(repeat('i', 256))
    let record = sampleRecord(mrFileOpen)
    var small {.noinit.}: array[DepFixedHeaderLen + 8, byte]
    check encodeDepSetElement(record, small, dseRequireFit) == -1

    # A buffer that fits the record but not the whole suffix: still refused.
    var buf {.noinit.}: array[HotPathBufLen, byte]
    let full = encodeDepSetElement(record, buf, dseRequireFit)
    require full > 256
    var tight = newSeq[byte](full - 1)
    check encodeDepSetElement(record, tight, dseRequireFit) == -1
    # ... and truncated, not refused, under the loss-marker policy.
    let clipped = encodeDepSetElement(record, tight, dseTruncateSuffix)
    check clipped == full - 1
    setDepSetIncarnationImage("")

  test "t_the_normalisation_decision_table":
    # Grades DA-1b's second INERT mutation. `identityNormalizedOutcome` is
    # exhaustive over `MonitorRecordKind`, and the table is restated here as
    # literal sets so moving a kind in `dep_queue.nim` alone reddens instead of
    # silently agreeing with itself. Dropping `mrPathProbe` from the
    # success/failure arm, or `mrFileWrite` from the folded arm, fails here.
    var seen: set[MonitorRecordKind]
    for kind in MonitorRecordKind:
      var classes = 0
      if kind in OutcomeFoldedKinds: inc classes
      if kind in OutcomeSuccessFailureKinds: inc classes
      if kind in OutcomeVerbatimKinds: inc classes
      check classes == 1
      seen.incl kind
      for (raw, flags) in [(137'i64, 0xA5A5'u32), (-1'i64, 0'u32),
                           (0'i64, 7'u32)]:
        let got = identityNormalizedOutcome(kind, raw, flags)
        if kind in OutcomeFoldedKinds:
          check got == (0'i64, 0'u32)
        elif kind in OutcomeSuccessFailureKinds:
          check got == ((if raw < 0: -1'i64 else: 0'i64), flags)
        else:
          check got == (raw, flags)
    check seen == {low(MonitorRecordKind) .. high(MonitorRecordKind)}

  test "t_the_only_kind_whose_normalisation_changed_is_unreachable":
    # THE BYTE-STABILITY PROOF for making the normalisation exhaustive. Replacing
    # a partial `case … else` with a total table can only change output for a
    # kind whose answer moved AND that the normalisation is actually reached for.
    # It is reached only when `depIdentityScope` dropped the observer. So: the
    # set of kinds where the new table disagrees with the old partial case must
    # be exactly {mrFileWrite}, and `mrFileWrite` must be process-scoped.
    var changed: set[MonitorRecordKind]
    for kind in MonitorRecordKind:
      for (raw, flags) in [(137'i64, 0xA5A5'u32), (-1'i64, 0'u32),
                           (0'i64, 7'u32), (int64.high, uint32.high)]:
        if identityNormalizedOutcome(kind, raw, flags) !=
            legacyNormalize(kind, raw, flags):
          changed.incl kind
    check changed == {mrFileWrite}
    check depIdentityScope(mrFileWrite) == disProcessScoped
    for kind in changed:
      # …i.e. no encoder can reach the arm that moved.
      check depIdentityScope(kind) == disProcessScoped
    echo "DA-1d: normalisation table differs from the pre-DA-1d partial case ",
      "for {mrFileWrite} only, and that kind is process-scoped (unreachable)"

  test "t_a_pointer_shaped_result_never_survives_into_a_path_scoped_key":
    # The `mrFileWrite` FILE* trap, stated as a property rather than a comment.
    # `recordFopen` used to store a raw `FILE*` in `result`; DA-1d made it store
    # 0, and this asserts the second half — that path-scoping a file-touching
    # kind cannot resurrect a per-process address as the element key.
    setDepSetIncarnationImage("")
    const fakeStream = 0x7f4c_1a2b_3c40'i64   # a plausible heap address
    for kind in [mrFileOpen, mrFileRead, mrFileWrite]:
      # Same open, two runs: only the heap address differs. One key, or the
      # dedup is decorative.
      let a = identityNormalizedOutcome(kind, fakeStream, 19'u32)
      let b = identityNormalizedOutcome(kind, fakeStream + 0x1000, 19'u32)
      check a == b
      check a.outcome == 0

# ---------------------------------------------------------------------------
# THE STRUCTURAL CLAIM: three sites are ONE site.
#
# Everything above grades what the composer DOES. This grades that nothing goes
# around it — the claim DA-1b made and could not support. It is a source audit,
# so it obeys the appendix's rule for source audits: comments are stripped
# (`codeOnly`), because this milestone's own prose names the very symbol being
# counted in a dozen places, and an audit a comment can satisfy audits the prose.
# The stripper carries its own positive and negative control.
#
# REVIEW FOUND TWO WAYS PAST THE FIRST VERSION OF THESE AUDITS. Both compiled,
# both are the same call the audit exists to forbid, and both left the file
# 13/13 green — they were closed here rather than argued away:
#
#   * the needle was `"encodeDepRecordIdentity("`, so it graded ONE of Nim's
#     call syntaxes. `rec.encodeDepRecordIdentity buf` is the same call without a
#     paren, and `encode_deprecordidentity(…)` is the same identifier under Nim's
#     case/underscore folding. Both are now counted (`countIdent`).
#   * the suffix audit scanned only `setElemImage` in `writer.nim`, on the
#     reasoning that "`fs_snoop` cannot see it at all". DA-1d itself made that
#     false by EXPORTING `depSetIncarnationImage`, so any module can now finish a
#     key the composer already composed. That accessor is audited too.
#
# The general shape, for the next audit written here: a textual audit grades the
# SPELLING it names, not the CALL it means, and every accessor a milestone
# exports widens what "going around the one site" can be spelled as.
# ---------------------------------------------------------------------------

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc codeOnly(source: string): string =
  ## Nim source with `#`/`##` comments removed. String literals are tracked so a
  ## `#` inside one survives; the three audited files contain no triple-quoted
  ## strings (asserted below by the round-trip control).
  result = newStringOfCap(source.len)
  var i = 0
  var inStr = false
  while i < source.len:
    let c = source[i]
    if c == '\n':
      inStr = false
      result.add '\n'
      inc i
    elif inStr:
      if c == '\\' and i + 1 < source.len:
        result.add c
        result.add source[i + 1]
        inc i, 2
      else:
        if c == '"': inStr = false
        result.add c
        inc i
    elif c == '#':
      while i < source.len and source[i] != '\n':
        inc i
    else:
      if c == '"': inStr = true
      result.add c
      inc i

proc countIn(text, needle: string): int =
  var start = 0
  while true:
    let idx = text.find(needle, start)
    if idx < 0: break
    inc result
    start = idx + 1

func isIdentChar(c: char): bool =
  c in {'a' .. 'z', 'A' .. 'Z', '0' .. '9', '_'}

func nimIdentFold(s: string): string =
  ## Nim identifier equality: case-insensitive after the first character and
  ## underscore-insensitive. `encode_deprecordidentity` names the same proc as
  ## `encodeDepRecordIdentity`, so a literal-text audit that does not fold would
  ## count zero for it.
  result = newStringOfCap(s.len)
  for c in s:
    if c != '_':
      result.add(if c in {'A' .. 'Z'}: char(ord(c) + 32) else: c)

proc countIdent(text, name: string): int =
  ## Occurrences of `name` as a WHOLE identifier, whatever call syntax surrounds
  ## it and however it is cased. Counting `"name("` instead would audit one
  ## spelling out of several: `f(a, b)`, `a.f(b)`, `f a, b` and `a.f b` are the
  ## same call in Nim, and only the first two carry the paren. A needle a legal
  ## respelling can slip past is the same defect class as one a comment can
  ## satisfy.
  let hay = nimIdentFold(text)
  let needle = nimIdentFold(name)
  var start = 0
  while true:
    let idx = hay.find(needle, start)
    if idx < 0: break
    let beforeOk = idx == 0 or not isIdentChar(hay[idx - 1])
    let after = idx + needle.len
    let afterOk = after >= hay.len or not isIdentChar(hay[after])
    if beforeOk and afterOk:
      inc result
    start = idx + 1

iterator auditedSources(): (string, string) =
  ## Every first-party Nim source that could publish an element, as
  ## (repo-relative path, comment-stripped code). `cmd/` is included as well as
  ## `src/`: the CLI links the whole library, so a publisher added there would be
  ## just as real and an audit scoped to `src/` alone would not see it.
  for base in ["src", "cmd"]:
    for path in walkDirRec(repoRoot / base):
      if not path.endsWith(".nim"): continue
      yield (path.relativePath(repoRoot), codeOnly(readFile(path)))

suite "DA-1d: nothing composes an element key except the one site":

  test "t_the_comment_stripper_is_itself_graded":
    # POSITIVE: code survives. NEGATIVE: the identical text in a comment does
    # not. Without both, an audit that always returns 0 would look perfect.
    check countIn(codeOnly("let n = needleCall(x)\n"), "needleCall(") == 1
    check countIn(codeOnly("# let n = needleCall(x)\n"), "needleCall(") == 0
    check countIn(codeOnly("## see `needleCall(` for why\n"), "needleCall(") == 0
    check countIn(codeOnly("let s = \"a # b\"\nx = needleCall(1)\n"),
      "needleCall(") == 1
    # …and a `#` INSIDE a string literal is not a comment, so it survives.
    check countIn(codeOnly("let s = \"a # b\"\n"), "#") == 1
    # No triple-quoted strings in the audited files, or the stripper's
    # single-quote-pair model would be wrong for them.
    for rel in ["src/io_mon/writer.nim", "src/io_mon/fs_snoop.nim",
                "src/io_mon/shm/dep_queue.nim"]:
      check countIn(readFile(repoRoot / rel), "\"\"\"") == 0

    # `countIdent` matches a call however it is spelled, and does NOT match a
    # longer identifier that merely contains the name. Review found the
    # paren-carrying needle green against `rec.encodeDepRecordIdentity buf`,
    # which compiles and is the same call, so the whole-identifier form is what
    # the audits below use.
    check countIdent("let n = needleCall(x)\n", "needleCall") == 1
    check countIdent("let n = x.needleCall y\n", "needleCall") == 1
    check countIdent("let n = needleCall x, y\n", "needleCall") == 1
    check countIdent("let n = myNeedleCallHelper(x)\n", "needleCall") == 0
    check countIdent("let n = needleCallish(x)\n", "needleCall") == 0
    check countIdent(codeOnly("# needleCall(x)\n"), "needleCall") == 0
    # Nim identifier equality is case- and underscore-insensitive, so the two
    # spellings below name the same proc and must both be counted.
    check countIdent("let n = needle_call(x)\n", "needleCall") == 1
    check countIdent("let n = needlecall(x)\n", "needleCall") == 1

  test "t_encodeDepRecordIdentity_is_called_from_exactly_one_place":
    # The identity encoder is public (the consumer-side codec tests and the
    # decoder's contract need it), so "one site" cannot be enforced by
    # visibility. It is enforced by measurement instead: across all first-party
    # code, the name occurs exactly TWICE — its own definition in
    # `shm/dep_queue.nim`, and one call, inside `encodeDepSetElement`.
    #
    # Counted as a whole IDENTIFIER, not as `"…Identity("`. The paren form audits
    # one call syntax out of four: `rec.encodeDepRecordIdentity buf` compiles,
    # means exactly the same thing, and was measured GREEN against the paren
    # needle. An audit a legal respelling can walk past is the same defect class
    # as an audit a comment can satisfy.
    var total = 0
    var perFile: seq[(string, int)]
    for (rel, code) in auditedSources():
      let n = countIdent(code, "encodeDepRecordIdentity")
      if n > 0:
        perFile.add (rel, n)
      total += n
    perFile.sort()                      # walkDirRec order is not deterministic
    echo "DA-1d: encodeDepRecordIdentity mentions in src/ + cmd/: ", perFile
    check total == 2                    # one definition + one call
    check perFile.len == 2
    check perFile[0][0] == "src/io_mon/shm/dep_queue.nim"   # the definition
    check perFile[0][1] == 1
    check perFile[1][0] == "src/io_mon/writer.nim"          # the one call
    check perFile[1][1] == 1

  test "t_that_one_place_is_inside_encodeDepSetElement":
    let code = codeOnly(readFile(repoRoot / "src/io_mon/writer.nim"))
    let composerAt = code.find("proc encodeDepSetElement*(")
    let nextProcAt = code.find("proc rebuildDepSetLossElem*(")
    # Whole-identifier, for the same reason as above: a call moved out of the
    # composer and respelled without a paren must still be located.
    let callAt = code.find("encodeDepRecordIdentity")
    require composerAt >= 0
    require nextProcAt > composerAt
    check callAt > composerAt
    check callAt < nextProcAt

  test "t_no_site_appends_the_incarnation_image_on_its_own":
    # The other half of the same claim: the suffix must not be spliced in by
    # hand anywhere. `setElemImage` is the writer's own module-level state, so
    # that half of the audit is over that file.
    let code = codeOnly(readFile(repoRoot / "src/io_mon/writer.nim"))
    let composerAt = code.find("proc encodeDepSetElement*(")
    let nextProcAt = code.find("proc rebuildDepSetLossElem*(")
    var outside = 0
    var start = 0
    while true:
      let idx = code.find("setElemImage", start)
      if idx < 0: break
      if idx < composerAt or idx > nextProcAt:
        inc outside
      start = idx + 1
    echo "DA-1d: `setElemImage` uses outside the composer: ", outside
    # Its declaration, `setDepSetIncarnationImage`'s assignment and
    # `depSetIncarnationImage`'s read — and nothing that builds a key.
    check outside == 3

    # …and `fs_snoop` no longer "cannot see it at all". `depSetIncarnationImage`
    # is exported, so ANY module can now read this process's incarnation and
    # splice it onto a key the composer already finished — a site calling the
    # shared composer and then answering the incarnation question itself, which
    # is precisely the shape DA-1d exists to remove and is byte-invisible in a
    # host process. Measured GREEN against the two audits above before this
    # check existed. The accessor is for tests and introspection, so its only
    # legitimate mention in first-party code is its own definition.
    var readers: seq[string]
    for (rel, src) in auditedSources():
      for _ in 0 ..< countIdent(src, "depSetIncarnationImage"):
        readers.add rel
    readers.sort()
    echo "DA-1d: `depSetIncarnationImage` mentions in src/ + cmd/: ", readers
    check readers == @["src/io_mon/writer.nim"]
