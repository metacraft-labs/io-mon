## test_io_mon_wire_negative_oracle — the NEGATIVE half of io-mon's `.iomon`
## wire-format oracle: hand-built frames that NO legal record can produce.
##
## Before this file, io-mon's committed suite contained no negative wire-format
## case at all, and the measured consequence was concrete: narrowing
## `decodeRecordPayload`'s 16-bit `kind` load to 8 bits — so that a frame
## declaring `kind = 0x0101` is accepted as `mrProcessStart` — left the ENTIRE
## suite green. Nothing in the tree ever presented the decoder with a byte
## sequence a well-behaved encoder would not emit, so nothing could notice that
## the decoder had stopped rejecting one.
##
## WHY A POSITIVE FIXTURE CANNOT DO THIS JOB. Four header fields are pinned to
## small values by the format itself:
##
##   `kind`  1 .. 19   (`MonitorRecordKind`)
##   `obs`   1 .. 17   (`MonitorObservationKind`)
##   `probe` 0 ..  4   (`ProbeResult`)
##   `seq`   exactly 1 .. N in file order (`reader.validateSequenceOrder`)
##
## For `kind`, `obs` and `probe` this is absolute: 19, 17 and 4 all fit in a
## single byte, so no legal capture — however informative its other fields —
## can put a non-zero byte above their low byte. `seq` is bounded differently
## and the difference is worth stating exactly rather than rounding off: it is
## the RECORD COUNT, so byte 1 of it becomes non-zero at 256 records and byte 2
## at 65 536. A positive fixture could therefore reach byte 1 by carrying 256
## records — it would just be paying 256 records to grade one byte, which is
## why the fixture does not, and why the case below reaches for byte 7 instead.
## Narrowing these loads is invisible to every positive fixture the tree has,
## and visible here the moment a frame carries the high byte anyway.
##
## AND WHY ROUND-TRIP TESTS CANNOT EITHER. A COMPENSATING PAIR — narrowing a
## store and its matching load together — is a fixed point of every
## `decode(encode(R))` and `encode(decode(F))` check in the suite, of the
## encode-direct byte hashes, and of the decode-direct field dumps: all three
## agree with themselves while the decoder silently accepts files the format
## forbids. The two `*_compensating_pair_*` cases below are exactly that shape,
## sized so a narrowed reader SUCCEEDS where the real reader must refuse, so
## they separate the two readers by VERDICT rather than by luck.
##
## WHAT IS ASSERTED, AND WHY IT IS NOT THE MESSAGE TEXT. Each case pins two
## things: the `EnvelopeError.kind` raised by the frame decoder, and the
## `MonitorDepFileReaderErrorKind` the same bytes produce through
## `readMonitorDepFile` — i.e. what `reader.classifyEnvelopeError` maps the
## envelope error to. The second is what consumers branch on. It is pinned
## SEPARATELY because the two are NOT in one-to-one correspondence and the
## mapping runs through a substring test on the message:
## `classifyEnvelopeError` calls an `eeMalformed` whose text contains
## "truncated" `mrTruncated`, anything else `mrSemanticValidationFailed`, and
## every `eeUnknownType` `mrSemanticValidationFailed` regardless of text. DA-1c
## moved one case across that line (a sub-60-byte payload whose leading bytes
## are not a legal kind used to be `eeUnknownType` -> `mrSemanticValidationFailed`
## and is now `eeMalformed`/"truncated" -> `mrTruncated`), which is precisely
## why asserting the message would have been asserting the wrong thing.
##
## The positive half is `test_io_mon_wire_informative_fixture.nim`. Neither half
## subsumes the other.
##
## Pure `io_mon/{types,codec,encode,reader}` — portable tier, every OS.

import std/[options, os, unittest]

import io_mon/types
import io_mon/codec
import io_mon/encode
import io_mon/reader

const
  # A SECOND, INDEPENDENT statement of the payload layout. `encode.nim` keeps
  # these as private `Off*` constants; restating them here (rather than
  # importing them) is deliberate — a test that asks the implementation where it
  # put a field cannot notice the field moving. `RecordFixedHeaderLen` IS
  # imported, so a change to the header SIZE is a compile-visible disagreement.
  OffKind = 0
  OffObs = 2
  OffSeq = 4
  OffOsPid = 12
  OffParentOsPid = 20
  OffThreadId = 28
  OffChildOsPid = 36
  OffResult = 44
  OffFlags = 52
  OffProbe = 56
  OffPathLen = 60            # == RecordFixedHeaderLen

  CanonicalFileKind = 1'u16  # `encode.CanonicalFileKind`, which the reader
                             # reads and discards.

static:
  doAssert OffPathLen == RecordFixedHeaderLen,
    "the negative oracle's restated layout disagrees with encode.nim"

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

proc legalRecord(): MonitorRecord =
  ## A perfectly ordinary record. Every negative case below is this record's
  ## payload with ONE field overwritten, so each case isolates one defect.
  MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
    seq: 1,
    osPid: 0x1122_3344_5566_7788'u64,
    parentOsPid: 0x99AA_BBCC_DDEE_FF01'u64,
    threadId: 0x0203_0405_0607_0809'u64,
    childOsPid: 0xA1B2_C3D4_E5F6_0718'u64,
    result: cast[int64](0xF0E1_D2C3_B4A5_9687'u64),
    flags: 0xF1E2_D3C4'u32,
    probeResult: prExistingFile,
    path: "/negative/oracle/path.h",
    detail: "run=negative-oracle")

proc legalPayload(): seq[byte] = encodeRecordPayload(legalRecord())

proc frameOf(payload: seq[byte]): seq[byte] =
  result = @[]
  result.writeU32Le(uint32(payload.len))
  result.add payload

proc frameWithPrefix(payload: seq[byte]; prefix: uint32): seq[byte] =
  ## A frame whose declared length DISAGREES with the payload that follows.
  result = @[]
  result.writeU32Le(prefix)
  result.add payload

proc envelope(body: seq[byte]; count: int): seq[byte] =
  ## A structurally valid canonical envelope around an arbitrary body: correct
  ## magic, version, counts, body length and trailer checksum. Everything
  ## suspicious in a case lives in the BODY, so the reader gets past its
  ## envelope checks and reaches the frame decoder.
  result = @[]
  result.add IomonMagic.toBytes()
  result.writeU16Le(IomonVersion)
  result.writeU16Le(CanonicalFileKind)
  result.writeU64Le(uint64(count))
  result.writeU64Le(uint64(body.len))
  result.add body
  result.add IomonTrailerMagic.toBytes()
  result.writeU64Le(uint64(count))
  result.writeU64Le(checksum(body))

proc patched(payload: seq[byte]; off: int; value: uint16): seq[byte] =
  result = payload
  storeU16Le(result, off, value)

proc patched32(payload: seq[byte]; off: int; value: uint32): seq[byte] =
  result = payload
  storeU32Le(result, off, value)

proc patched64(payload: seq[byte]; off: int; value: uint64): seq[byte] =
  result = payload
  storeU64Le(result, off, value)

proc truncatedTo(payload: seq[byte]; n: int): seq[byte] =
  result = @(payload.toOpenArray(0, n - 1))

proc headerOnly(kindBytes: uint16; n: int): seq[byte] =
  ## `n` bytes of payload (n < RecordFixedHeaderLen) whose first two bytes are
  ## `kindBytes`. Used for the two sub-header cases whose verdicts DA-1c moved.
  result = newSeq[byte](n)
  if n >= 2:
    storeU16Le(result, 0, kindBytes)

proc stringPrefixCase(pathLenField: uint32; pathBody: string): seq[byte] =
  ## A payload whose `path` length prefix is `pathLenField` but which carries
  ## only `pathBody`, followed by a zero-length `detail`. Sized so a reader that
  ## MASKED the length field to 16 or 24 bits would decode the payload cleanly.
  result = legalPayload().truncatedTo(RecordFixedHeaderLen)
  result.writeU32Le(pathLenField)
  for ch in pathBody:
    result.add byte(ord(ch))
  result.writeU32Le(0'u32)

# ---------------------------------------------------------------------------
# The case table
# ---------------------------------------------------------------------------

type
  NegCase = object
    name: string
    why: string
    body: seq[byte]                       # the envelope body (one or more frames)
    count: int                            # declared record count
    envKind: Option[EnvelopeErrorKind]    # expected from `decodeFrames`
    readerKind: MonitorDepFileReaderErrorKind

proc c(name, why: string; body: seq[byte]; count: int;
       envKind: Option[EnvelopeErrorKind];
       readerKind: MonitorDepFileReaderErrorKind): NegCase =
  NegCase(name: name, why: why, body: body, count: count,
    envKind: envKind, readerKind: readerKind)

proc payloadCase(name, why: string; payload: seq[byte];
                 envKind: EnvelopeErrorKind;
                 readerKind: MonitorDepFileReaderErrorKind): NegCase =
  c(name, why, frameOf(payload), 1, some(envKind), readerKind)

proc negativeCases(): seq[NegCase] =
  let p = legalPayload()
  result = @[
    # --- fields the format PINS: high bytes a legal record can never carry ---
    payloadCase("kind_high_byte_set",
      "kind=0x0101 — an 8-bit-narrowed load reads 0x01 and accepts it as " &
      "mrProcessStart. This exact defect passed the whole suite before this file.",
      p.patched(OffKind, 0x0101'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("kind_zero",
      "kind=0 — all-zero leading bytes; below low(MonitorRecordKind)=1.",
      p.patched(OffKind, 0x0000'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("kind_one_past_high",
      "kind=20 — one past high(MonitorRecordKind)=19; an off-by-one bound.",
      p.patched(OffKind, 20'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("kind_all_bits",
      "kind=0xFFFF — every bit set; a sign/width slip reads -1 or 255.",
      p.patched(OffKind, 0xFFFF'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("obs_high_byte_set",
      "obs=0x0100 — an 8-bit-narrowed load reads 0 (itself illegal) or, with " &
      "a low byte, a legal kind.",
      p.patched(OffObs, 0x0100'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("obs_high_byte_over_legal_low",
      "obs=0x0104 — narrowed to 8 bits this is moFileRead, which is LEGAL; " &
      "only the full-width load refuses it.",
      p.patched(OffObs, 0x0104'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("obs_zero",
      "obs=0 — below low(MonitorObservationKind)=1.",
      p.patched(OffObs, 0x0000'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("obs_one_past_high",
      "obs=18 — one past high(MonitorObservationKind)=17.",
      p.patched(OffObs, 18'u16), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("probe_high_byte_set",
      "probe=0x01000002 — narrowed to 8/16/24 bits this is prExistingFile, " &
      "which is LEGAL; the u32 load must see the high byte.",
      p.patched32(OffProbe, 0x0100_0002'u32), eeUnknownType,
      mrSemanticValidationFailed),
    payloadCase("probe_one_past_high",
      "probe=5 — one past high(ProbeResult)=4.",
      p.patched32(OffProbe, 5'u32), eeUnknownType, mrSemanticValidationFailed),
    payloadCase("probe_all_bits",
      "probe=0xFFFFFFFF.",
      p.patched32(OffProbe, 0xFFFF_FFFF'u32), eeUnknownType,
      mrSemanticValidationFailed),

    # --- `seq`: legal at the FRAME level, refused by the reader ---
    c("seq_high_bytes_set",
      "seq=0x0100000000000001 — narrowed to 8/16/32 bits this reads 1 and " &
      "satisfies canonical order. The frame decoder has no opinion; the READER " &
      "must refuse. This is the only place a narrowed `seq` load is visible, " &
      "because a legal file's `seq` is 1..N and never reaches byte 1.",
      frameOf(p.patched64(OffSeq, 0x0100_0000_0000_0001'u64)), 1,
      none(EnvelopeErrorKind), mrRecordOrderInvalid),
    c("seq_zero",
      "seq=0 — canonical order starts at 1.",
      frameOf(p.patched64(OffSeq, 0'u64)), 1,
      none(EnvelopeErrorKind), mrRecordOrderInvalid),

    # --- string length prefixes: the COMPENSATING-PAIR catchers ---
    c("pathlen_compensating_pair_16bit",
      "path length = 0x00010004 with 4 bytes of path and an empty detail. A " &
      "reader that masked the length to 16 bits reads 4, consumes the 4 bytes, " &
      "finds the detail prefix exactly where it expects it and SUCCEEDS — and " &
      "so does a writer narrowed the same way, so the pair round-trips. The " &
      "real reader must see 65 540 bytes promised and only 4 present.",
      frameOf(stringPrefixCase(0x0001_0004'u32, "abcd")), 1,
      some(eeMalformed), mrTruncated),
    c("pathlen_compensating_pair_24bit",
      "path length = 0xFF000004, same shape one byte higher. Invisible to any " &
      "positive fixture short of a 16 MiB string, and a 24-bit-masked reader " &
      "decodes it cleanly.",
      frameOf(stringPrefixCase(0xFF00_0004'u32, "abcd")), 1,
      some(eeMalformed), mrTruncated),
    payloadCase("pathlen_all_bits",
      "path length = 0xFFFFFFFF — must not wrap to a negative int and index " &
      "out of bounds.",
      p.patched32(OffPathLen, 0xFFFF_FFFF'u32), eeMalformed, mrTruncated),
    payloadCase("pathlen_just_past_payload",
      "path length one byte longer than the payload can hold. NOTE that this " &
      "case does NOT separate the real bound from a bound with one byte of " &
      "slack: with the slack the over-long path is consumed, `pos` lands one " &
      "past the end, and the `detail` prefix that no longer fits raises " &
      "'truncated uint32' — the SAME mrTruncated. The case below is the one " &
      "that separates them.",
      p.patched32(OffPathLen, uint32(p.len - RecordFixedHeaderLen - 4 + 1)),
      eeMalformed, mrTruncated),
    c("detaillen_one_byte_past_the_payload",
      "the DETAIL length prefix promises exactly ONE byte more than the " &
      "payload holds, and the string it prefixes is the LAST thing in the " &
      "payload — so nothing follows to fail a second bounds check. A reader " &
      "whose bound has one byte of slack (`> bytes.len + 1`) therefore " &
      "consumes the over-long string, leaves `pos == payload.len + 1`, and " &
      "falls out at `decodeRecordPayload`'s `pos != payload.len` with " &
      "'iomon record has trailing bytes' — eeMalformed WITHOUT 'truncated', " &
      "i.e. mrSemanticValidationFailed, NOT mrTruncated. This is the only " &
      "frame in the table that separates the real bound from a slack one by " &
      "VERDICT rather than by memory safety, which is what makes " &
      "`readString`'s bounds check graded at its BOUNDARY and not merely at " &
      "its presence. Measured: with the off-by-one the whole committed suite " &
      "stayed green and only ASAN saw the read.",
      frameOf(block:
        var q = legalPayload().truncatedTo(RecordFixedHeaderLen)
        q.writeU32Le(0'u32)                    # path: empty
        const body = "abcdefgh"
        q.writeU32Le(uint32(body.len + 1))     # …one byte more than follows
        for ch in body: q.add byte(ord(ch))
        q), 1,
      some(eeMalformed), mrTruncated),
    c("detaillen_compensating_pair_16bit",
      "the same 16-bit compensating pair on the SECOND length prefix, so a " &
      "fix applied to `path` only does not pass.",
      frameOf(block:
        var q = legalPayload().truncatedTo(RecordFixedHeaderLen)
        q.writeU32Le(4'u32)
        for ch in "abcd": q.add byte(ord(ch))
        q.writeU32Le(0x0001_0004'u32)
        for ch in "wxyz": q.add byte(ord(ch))
        q), 1,
      some(eeMalformed), mrTruncated),

    # --- payloads shorter than the fixed header ---
    payloadCase("payload_one_byte_short_of_the_header",
      "59 bytes with a LEGAL leading kind: the header cannot be read.",
      p.truncatedTo(RecordFixedHeaderLen - 1), eeMalformed, mrTruncated),
    payloadCase("payload_short_with_legal_leading_kind",
      "8 bytes, leading bytes = mrFileRead. Rejected as truncated both before " &
      "and after DA-1c.",
      headerOnly(uint16(ord(mrFileRead)), 8), eeMalformed, mrTruncated),
    payloadCase("payload_short_with_illegal_leading_kind",
      "8 bytes whose leading bytes (0xFFFF) are NOT a legal kind. THE CASE " &
      "DA-1c MOVED: pre-DA-1c the per-field reads got as far as the kind bound " &
      "and gave eeUnknownType -> mrSemanticValidationFailed; post-DA-1c the " &
      "up-front length check gives eeMalformed/'truncated' -> mrTruncated. " &
      "Pinned here so the next move of this line is a decision, not a drift.",
      headerOnly(0xFFFF'u16, 8), eeMalformed, mrTruncated),
    payloadCase("payload_two_bytes",
      "2 bytes — shorter than any field but the kind.",
      headerOnly(uint16(ord(mrFileRead)), 2), eeMalformed, mrTruncated),
    payloadCase("payload_empty",
      "a zero-length payload behind a frame prefix of 0 is caught by the frame " &
      "loop; this is a 1-byte payload, the shortest the loop will hand over.",
      headerOnly(0'u16, 1), eeMalformed, mrTruncated),

    # --- trailing bytes: the payload decodes but does not END ---
    payloadCase("payload_has_trailing_bytes",
      "one byte appended after `detail`. eeMalformed WITHOUT 'truncated' in " &
      "the message, so it classifies as mrSemanticValidationFailed, not " &
      "mrTruncated — the asymmetry that makes message text the wrong assertion.",
      p & @[0x5A'u8], eeMalformed, mrSemanticValidationFailed),

    # --- the frame length prefix itself ---
    c("frame_prefix_zero",
      "a frame declaring length 0 — the loop would not advance.",
      frameWithPrefix(p, 0'u32), 1, some(eeMalformed), mrTruncated),
    c("frame_prefix_past_body_end",
      "a frame declaring one byte more than the body holds.",
      frameWithPrefix(p, uint32(p.len + 1)), 1, some(eeMalformed), mrTruncated),
    c("frame_prefix_high_byte_set",
      "a frame prefix of 0x01000000 over a small payload: a 24-bit-narrowed " &
      "read would see 0 and a 16-bit one a wrong small length; the full u32 " &
      "must see 16 MiB promised and refuse.",
      frameWithPrefix(p, 0x0100_0000'u32), 1, some(eeMalformed), mrTruncated),
    c("second_frame_corrupt",
      "a VALID frame followed by one with an illegal kind: the reader must not " &
      "accept a file because its first record parsed.",
      frameOf(p) & frameOf(p.patched(OffKind, 0x0101'u16)), 2,
      some(eeUnknownType), mrSemanticValidationFailed),
  ]

# ---------------------------------------------------------------------------

proc writeTemp(bytes: seq[byte]; tag: string): string =
  result = getTempDir() / ("io_mon_negative_" & $getCurrentProcessId() & "_" &
    tag & ".iomon")
  writeFile(result, fromBytes(bytes))

proc readerVerdict(bytes: seq[byte]; tag: string):
    tuple[raised: bool, kind: MonitorDepFileReaderErrorKind, msg: string] =
  let path = writeTemp(bytes, tag)
  try:
    discard readMonitorDepFile(path)
    result = (false, mrMissingFile, "")
  except MonitorDepFileReaderError as err:
    result = (true, err.kind, err.msg)
  finally:
    removeFile(path)

suite "io-mon wire-format negative oracle":

  test "t_every_negative_case_is_refused_with_the_pinned_verdict":
    for nc in negativeCases():
      checkpoint("case " & nc.name & " — " & nc.why)

      # 1. The frame decoder's own verdict.
      var envRaised = false
      var envKind: EnvelopeErrorKind
      var envMsg = ""
      try:
        discard decodeFrames(nc.body)
      except EnvelopeError as err:
        envRaised = true
        envKind = err.kind
        envMsg = err.msg
      if nc.envKind.isSome:
        checkpoint("  decodeFrames msg: " & envMsg)
        check envRaised
        if envRaised:
          check envKind == nc.envKind.get
      else:
        # These cases are legal FRAMES that only the reader may refuse.
        check not envRaised

      # 2. The verdict a consumer actually branches on — what
      #    `reader.classifyEnvelopeError` (and the reader's own checks) produce.
      let v = readerVerdict(envelope(nc.body, nc.count), nc.name)
      checkpoint("  reader msg: " & v.msg)
      check v.raised
      if v.raised:
        check v.kind == nc.readerKind

  test "t_envelope_level_refusals_keep_their_own_verdicts":
    # Not frame defects — the envelope checks that run BEFORE the frame loop.
    # Pinned in the same file so the whole refusal surface is one artefact.
    let body = frameOf(legalPayload())

    block tooShort:
      let v = readerVerdict(@(envelope(body, 1).toOpenArray(0, 40)), "short")
      check v.raised
      check v.kind == mrTruncated

    block badMagic:
      var e = envelope(body, 1)
      e[0] = byte('X')
      let v = readerVerdict(e, "magic")
      check v.raised
      check v.kind == mrBadMagic

    block badVersion:
      var e = envelope(body, 1)
      storeU16Le(e, 4, IomonVersion + 1)
      let v = readerVerdict(e, "version")
      check v.raised
      check v.kind == mrUnsupportedVersion

    block bodyLenLies:
      var e = envelope(body, 1)
      storeU64Le(e, 16, uint64(body.len - 1))
      let v = readerVerdict(e, "bodylen")
      check v.raised
      check v.kind == mrTruncated

    block countMismatch:
      # The TRAILER's record count disagrees with the header's. Distinct from
      # `frameCountDisagrees` below, where header and trailer agree with each
      # other and both disagree with the body.
      var e = envelope(body, 1)
      storeU64Le(e, 24 + body.len + 4, 2'u64)      # trailer record count
      let v = readerVerdict(e, "count")
      check v.raised
      check v.kind == mrSemanticValidationFailed

    block checksumMismatch:
      var e = envelope(body, 1)
      let off = 24 + body.len + 4 + 8
      storeU64Le(e, off, loadU64Le(e, off) xor 1'u64)
      let v = readerVerdict(e, "checksum")
      check v.raised
      check v.kind == mrChecksumMismatch

    block frameCountDisagrees:
      # A body holding ONE frame but a header/trailer claiming two.
      let v = readerVerdict(envelope(body, 2), "framecount")
      check v.raised
      check v.kind == mrSemanticValidationFailed

  test "t_a_legal_frame_is_still_accepted":
    # The oracle must refuse the illegal WITHOUT refusing the legal, or it grades
    # nothing. Same builders, unmutated.
    let e = envelope(frameOf(legalPayload()), 1)
    let path = writeTemp(e, "legal")
    defer: removeFile(path)
    let dep = readMonitorDepFile(path)
    check dep.records.len == 1
    let r = dep.records[0]
    let want = legalRecord()
    check r.kind == want.kind
    check r.observationKind == want.observationKind
    check r.seq == 1'u64
    check r.osPid == want.osPid
    check r.parentOsPid == want.parentOsPid
    check r.threadId == want.threadId
    check r.childOsPid == want.childOsPid
    check r.result == want.result
    check r.flags == want.flags
    check r.probeResult == want.probeResult
    check r.path == want.path
    check r.detail == want.detail

  test "t_tolerant_decode_reports_a_dirty_tail_rather_than_raising":
    # `decodeFramesTolerant` is the crash-recovery path: it must recover every
    # complete leading frame AND report `cleanEof == false`. A bulk copy that
    # reads past the end of a truncated tail would either crash here or silently
    # report a clean EOF.
    let good = frameOf(legalPayload())

    block cleanBody:
      var clean = true
      let recs = decodeFramesTolerant(good & good, clean)
      check clean
      check recs.len == 2

    block shortPrefix:
      var clean = true
      let recs = decodeFramesTolerant(good & @[0x01'u8, 0x02'u8, 0x03'u8], clean)
      check not clean
      check recs.len == 1

    block truncatedPayload:
      let half = @(good.toOpenArray(0, good.len div 2))
      var clean = true
      let recs = decodeFramesTolerant(good & half, clean)
      check not clean
      check recs.len == 1

    block corruptSecondFrame:
      var clean = true
      let bad = frameOf(legalPayload().patched(OffKind, 0x0101'u16))
      let recs = decodeFramesTolerant(good & bad, clean)
      check not clean
      check recs.len == 1

  test "t_the_restated_offsets_agree_with_the_encoder":
    # The case table patches bytes at hard-coded offsets. If those offsets ever
    # stop matching the encoder, every case above would be mutating the wrong
    # field and could pass for the wrong reason. Read the legal payload back
    # through the OFFSETS and compare to the record.
    let p = legalPayload()
    let r = legalRecord()
    check p.len >= RecordFixedHeaderLen
    check loadU16Le(p, OffKind) == uint16(ord(r.kind))
    check loadU16Le(p, OffObs) == uint16(ord(r.observationKind))
    check loadU64Le(p, OffSeq) == r.seq
    check loadU64Le(p, OffOsPid) == r.osPid
    check loadU64Le(p, OffParentOsPid) == r.parentOsPid
    check loadU64Le(p, OffThreadId) == r.threadId
    check loadU64Le(p, OffChildOsPid) == r.childOsPid
    check cast[int64](loadU64Le(p, OffResult)) == r.result
    check loadU32Le(p, OffFlags) == r.flags
    check loadU32Le(p, OffProbe) == uint32(ord(r.probeResult))
    check loadU32Le(p, OffPathLen) == uint32(r.path.len)
    check loadU32Le(p, OffPathLen + 4 + r.path.len) == uint32(r.detail.len)
    check p.len == RecordFixedHeaderLen + 4 + r.path.len + 4 + r.detail.len
