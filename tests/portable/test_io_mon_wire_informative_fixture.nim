## test_io_mon_wire_informative_fixture — the POSITIVE half of io-mon's
## `.iomon` wire-format oracle.
##
## Until this file landed, every committed `.iomon` fixture in the tree was a
## REAL CAPTURE (`tests/fixtures/dep_set_golden/*.iomon`), and a real capture
## cannot see a byte-order or field-width defect: its pids, flags, results and
## string lengths all fit in their LOW byte, so a `u64` load narrowed to 8 bits
## decodes them unchanged. That is not a hypothetical — DA-1c's first mutation
## round left FOUR mutations alive in the whole suite for exactly this reason.
##
## `tests/fixtures/wire_informative/informative.iomon` is a capture built so
## that every field the format does not pin has eight (or four) pairwise
## distinct, all-non-zero bytes. Against it:
##
##   * a narrowed load/store of `osPid`, `parentOsPid`, `threadId`,
##     `childOsPid`, `result` or `flags` changes the decoded value;
##   * a byte-order flip on any of them changes the decoded value;
##   * SWAPPING TWO FIELD OFFSETS changes the decoded values. That last one is
##     the case nothing else in the suite can reach: an offset swap is a perfect
##     fixed point of `encode(decode(F))`, so every round-trip test, every
##     encode-direct hash and every decode-direct field dump agrees with itself
##     while the FILE says something different. Only frozen bytes catch it, and
##     only frozen bytes whose fields differ from one another.
##
## The three fields the format PINS to small values (`kind` 1..19, `obs` 1..17,
## `probe` 0..4) plus `seq` (which the reader requires to be exactly 1..N) can
## never be made informative by any legal file. They are the other half of the
## oracle and live in `test_io_mon_wire_negative_oracle.nim`.
##
## Byte-identity is asserted through BOTH writers — `encodeCanonical` (buffer)
## and `writeCanonicalInPlace` (streaming) — because they are two separate
## implementations of the same envelope and a change can reach one without the
## other. Both are compared against the file bytes AS COMMITTED; nothing here
## regenerates the fixture.
##
## Pure `io_mon/{types,codec,encode,reader}` — no shim, no shared memory, no
## platform API — so this runs on every OS (portable tier).

import std/[os, strutils, unittest]

import io_mon/types
import io_mon/codec
import io_mon/encode
import io_mon/reader
import informative_wire_fixture

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  fixturePath = repoRoot / "tests" / "fixtures" / "wire_informative" /
    "informative.iomon"
  goldenDir = repoRoot / "tests" / "fixtures" / "dep_set_golden"

  # FROZEN. The FNV-1a-64 checksum (`encode.checksum`, the same function the
  # envelope trailer uses) of `encodeFrame` applied to a record whose path is
  # `informativeFill(HugePathLen, 'k')` — a frame 16 800 094 bytes long, i.e.
  # PAST THE 24-BIT LENGTH BOUNDARY. Committing a 16 MiB blob to exercise byte 3
  # of a length prefix is not worth it; a frozen checksum of a deterministically
  # generated frame pins the same bytes just as tightly.
  HugeFrameChecksum = 0x4026318398949BF5'u64
  HugeDetail = "run=informative;24-bit"
  HugeFrameLen = 4 + RecordFixedHeaderLen + 4 + HugePathLen + 4 + HugeDetail.len

proc hugeRecord(): MonitorRecord =
  MonitorRecord(kind: mrFileOpen, observationKind: moFileOpen,
    seq: 1,
    osPid:       0x7788_99AA_BBCC_DDEE'u64,
    parentOsPid: 0xFF01_0203_0405_0607'u64,
    threadId:    0x0809_0A0B_0C0D_0E0F'u64,
    childOsPid:  0x0718_293A_4B5C_6D7E'u64,
    result:      cast[int64](0xB4A5_9687_78A9_BACB'u64),
    flags:       0xB5A6_9788'u32,
    probeResult: prExistingOther,
    path: informativeFill(HugePathLen, 'k'),
    detail: HugeDetail)

proc canonicalBody(envelope: seq[byte]): seq[byte] =
  ## The frame body of a canonical envelope: 4 magic + 2 version + 2 kind +
  ## 8 count + 8 bodyLen of header, then `bodyLen` bytes, then a 20-byte trailer.
  var pos = 4 + 2 + 2 + 8
  let bodyLen = int(loadU64Le(envelope, pos))
  pos += 8
  result = @(envelope.toOpenArray(pos, pos + bodyLen - 1))

proc canonicalExpectation(): seq[MonitorRecord] =
  ## `encodeCanonical` sorts by (osPid, threadId, seq, kind, path) and then
  ## renumbers `seq` 1..N. The fixture's `osPid`s are pairwise distinct and
  ## ASCENDING in list order, so the canonical order IS the list order; the
  ## first test below asserts that rather than assuming it.
  result = informativeRecords()
  for i in 0 ..< result.len:
    result[i].seq = uint64(i + 1)

suite "io-mon informative wire fixture":

  test "t_the_fixture_is_byte_informative_by_construction":
    # The property the whole file rests on: no two header fields of a record
    # share a value, and every byte of every unpinned field is non-zero. If this
    # ever stops holding, the fixture has quietly become as blind as a real
    # capture and every other test here weakens without turning red.
    for idx, r in informativeRecords():
      checkpoint("record " & $idx)
      let u64s = [r.osPid, r.parentOsPid, r.threadId, r.childOsPid,
        cast[uint64](r.result)]
      for i in 0 ..< u64s.len:
        for j in i + 1 ..< u64s.len:
          check u64s[i] != u64s[j]
      # Records 4 and 5 deliberately pin `result`/`flags` to the extremes
      # (high(int64), low(int64), high(uint32), 0), which are not all-non-zero
      # by nature; every OTHER record must have all eight bytes non-zero.
      if idx notin {4, 5}:
        for v in u64s:
          for b in 0 ..< 8:
            check byte((v shr (8 * b)) and 0xFF'u64) != 0'u8
          # …and pairwise distinct bytes, so a byte-order flip is visible.
          var seen: set[uint8]
          for b in 0 ..< 8:
            let bb = uint8((v shr (8 * b)) and 0xFF'u64)
            check bb notin seen
            seen.incl bb
        for b in 0 ..< 4:
          check byte((r.flags shr (8 * b)) and 0xFF'u32) != 0'u8

  test "t_canonical_order_is_the_declared_order":
    # Guards the frozen expectation below: if a future edit reorders the fixture
    # records, the `seq` 1..N mapping changes and the field assertions would be
    # comparing the wrong record.
    let decoded = decodeFrames(canonicalBody(encodeCanonical(informativeRecords())))
    let expected = canonicalExpectation()
    check decoded.len == expected.len
    for i in 0 ..< min(decoded.len, expected.len):
      checkpoint("record " & $i)
      check decoded[i].osPid == expected[i].osPid
      check decoded[i].seq == uint64(i + 1)

  test "t_committed_fixture_matches_encodeCanonical_byte_for_byte":
    check fileExists(fixturePath)
    let onDisk = readFile(fixturePath).toBytes()
    let produced = encodeCanonical(informativeRecords())
    check produced.len == onDisk.len
    # Report the FIRST differing offset rather than dumping 70 KB of hex.
    var firstDiff = -1
    for i in 0 ..< min(produced.len, onDisk.len):
      if produced[i] != onDisk[i]:
        firstDiff = i
        break
    if firstDiff >= 0:
      checkpoint("first differing byte at offset " & $firstDiff &
        ": produced=0x" & toHex(int(produced[firstDiff]), 2) &
        " committed=0x" & toHex(int(onDisk[firstDiff]), 2))
    check firstDiff == -1

  test "t_committed_fixture_matches_writeCanonicalInPlace_byte_for_byte":
    # The streaming writer is a SECOND implementation of the same envelope
    # (own body-length and checksum accumulation). Compared against the
    # committed bytes, never against `encodeCanonical`'s output.
    let onDisk = readFile(fixturePath).toBytes()
    let tmp = getTempDir() /
      ("io_mon_informative_streamed_" & $getCurrentProcessId() & ".iomon")
    defer: removeFile(tmp)
    var records = informativeRecords()
    writeCanonicalInPlace(tmp, records)
    let streamed = readFile(tmp).toBytes()
    check streamed.len == onDisk.len
    var firstDiff = -1
    for i in 0 ..< min(streamed.len, onDisk.len):
      if streamed[i] != onDisk[i]:
        firstDiff = i
        break
    if firstDiff >= 0:
      checkpoint("first differing byte at offset " & $firstDiff)
    check firstDiff == -1

  test "t_committed_fixture_decodes_to_the_frozen_field_values":
    # THE OFFSET-SWAP CATCHER. Every field is compared against a value no other
    # field of the same record holds, so exchanging any two `Off*` constants in
    # `encode.nim` — a change that is a perfect fixed point of every round-trip
    # test in the suite — turns exactly this test red.
    let dep = readMonitorDepFile(fixturePath)
    let expected = canonicalExpectation()
    check dep.records.len == expected.len
    for i in 0 ..< min(dep.records.len, expected.len):
      let d = dep.records[i]
      let e = expected[i]
      checkpoint("record " & $i & " kind=" & $d.kind)
      check d.kind == e.kind
      check d.observationKind == e.observationKind
      check d.seq == e.seq
      check d.osPid == e.osPid
      check d.parentOsPid == e.parentOsPid
      check d.threadId == e.threadId
      check d.childOsPid == e.childOsPid
      check d.result == e.result
      check d.flags == e.flags
      check d.probeResult == e.probeResult
      check d.path.len == e.path.len
      check d.path == e.path
      check d.detail.len == e.detail.len
      check d.detail == e.detail

  test "t_a_committed_frame_crosses_the_16_bit_length_boundary":
    # A `u32` length prefix whose byte 2 is non-zero. A prefix narrowed to a
    # `u16` — store or load — cannot represent this frame.
    # The canonical expectation, not the raw record: `encodeCanonical` renumbers
    # `seq`, so the frame as COMMITTED carries seq = BigPathRecordIndex + 1.
    let big = canonicalExpectation()[BigPathRecordIndex]
    let frame = encodeFrame(big)
    check frame.len > 0x1_0000
    check frame.len < 0x100_0000
    let prefix = loadU32Le(frame, 0)
    check prefix == uint32(frame.len - 4)
    check byte((prefix shr 16) and 0xFF'u32) != 0'u8   # byte 2 informative
    # …and the whole frame really is inside the committed file.
    let onDisk = readFile(fixturePath).toBytes()
    var found = false
    for start in 0 .. onDisk.len - frame.len:
      if onDisk[start] == frame[0] and onDisk[start + 1] == frame[1] and
         onDisk[start + 2] == frame[2] and onDisk[start + 3] == frame[3]:
        var same = true
        for k in 0 ..< frame.len:
          if onDisk[start + k] != frame[k]:
            same = false
            break
        if same:
          found = true
          break
    check found

  test "t_a_frame_past_the_24_bit_length_boundary_is_frozen_by_checksum":
    # Byte 3 of the length prefix. Generated rather than committed (16 MiB), and
    # pinned by the same FNV-1a-64 the envelope trailer uses, so the bytes are
    # frozen even though the blob is not in git.
    let frame = encodeFrame(hugeRecord())
    check frame.len == HugeFrameLen
    check frame.len > 0x100_0000
    let prefix = loadU32Le(frame, 0)
    check prefix == uint32(frame.len - 4)
    check byte((prefix shr 24) and 0xFF'u32) != 0'u8   # byte 3 informative
    let sum = checksum(frame)
    checkpoint("huge frame len=" & $frame.len & " checksum=0x" &
      toHex(sum, 16))
    check sum == HugeFrameChecksum
    # …and the DECODER must walk a length prefix this large too: a frame-length
    # read narrowed to 24 bits sees 0x00595A here and stops in the middle.
    let back = decodeFrames(frame)
    check back.len == 1
    if back.len == 1:
      check back[0].path.len == HugePathLen
      check back[0].detail == HugeDetail
      check back[0].osPid == hugeRecord().osPid
      check back[0].path == informativeFill(HugePathLen, 'k')

  test "t_committed_real_captures_are_byte_identical_through_both_writers":
    # The three `dep_set_golden` captures were only ever re-encoded by a LINUX
    # live-shim test (`tests/linux/test_io_mon_dep_set.nim`), so on any other
    # host nothing checked them at all. They are byte-blind (see this file's
    # header) but they are REAL, and a real capture is the only thing that
    # proves the informative fixture is not itself the format.
    for name in ["exec.iomon", "marker.iomon", "probe.iomon"]:
      let path = goldenDir / name
      checkpoint(name)
      check fileExists(path)
      let onDisk = readFile(path).toBytes()
      let dep = readMonitorDepFile(path)
      let produced = encodeCanonical(dep.records)
      check produced == onDisk

      var records = dep.records
      let tmp = getTempDir() / ("io_mon_golden_streamed_" &
        $getCurrentProcessId() & "_" & name)
      defer: removeFile(tmp)
      writeCanonicalInPlace(tmp, records)
      check readFile(tmp).toBytes() == onDisk
