## informative_wire_fixture — the record list behind the committed
## `tests/fixtures/wire_informative/informative.iomon` BYTE-INFORMATIVE capture.
##
## WHY THIS EXISTS AT ALL, AND WHY A REAL CAPTURE CANNOT REPLACE IT.
##
## io-mon's other `.iomon` fixtures (`tests/fixtures/dep_set_golden/*.iomon`) are
## real captures, and real captures are BYTE-BLIND. In a real capture almost
## every multi-byte header field carries its whole value in its LOW byte:
## `osPid`/`parentOsPid`/`threadId`/`childOsPid` are small integers, `result` is
## 0 or a small errno, `flags` is a handful of low bits, and the length prefixes
## of `path`/`detail` never reach 256. A codec defect that reads or writes such
## a field at the WRONG WIDTH (a `u64` load narrowed to 8/16/32 bits) or in the
## WRONG BYTE ORDER therefore produces EXACTLY THE SAME BYTES on a real capture
## and stays green. DA-1c's first mutation round measured this directly: four
## mutations survived the entire committed suite for no other reason.
##
## This fixture removes that blindness for every field whose value the wire
## format does not constrain. Each such field is given a value whose EIGHT (or
## four) bytes are pairwise distinct and all non-zero, so:
##
##   * dropping any byte of the field changes the decoded value,
##   * swapping the field's byte order changes the decoded value,
##   * and swapping two FIELDS' offsets changes the decoded values — the
##     "perfect round-trip fixed point" that `encode(decode(F))` can never see,
##     because it is invisible to anything but frozen bytes.
##
## WHAT THIS FIXTURE STILL CANNOT COVER, BY CONSTRUCTION. Three header fields
## are pinned to small values by the format itself, so NO legal capture —
## informative or not — can make their high bytes non-zero:
##
##   * `kind`    — a `u16` whose legal range is 1 .. 19 (`MonitorRecordKind`).
##   * `obs`     — a `u16` whose legal range is 1 .. 17 (`MonitorObservationKind`).
##   * `probe`   — a `u32` whose legal range is 0 .. 4 (`ProbeResult`).
##   * `seq`     — a `u64` the reader requires to be exactly 1 .. N in file order
##                 (`validateSequenceOrder`), so reaching byte 2 of it would take
##                 a 65 536-record fixture.
##
## Narrowing the LOAD of any of those four is invisible against every positive
## fixture there can be. They are covered by the companion NEGATIVE oracle
## (`tests/portable/test_io_mon_wire_negative_oracle.nim`), which hand-builds
## frames no legal record can produce. The two halves are complementary and
## neither subsumes the other; see that file's header for the other half.
##
## The `path`/`detail` LENGTH PREFIXES are covered here rather than negatively:
## `bigPathRecordIndex`'s path is sized so its frame's `u32` length prefix has a
## non-zero BYTE 2, i.e. the frame crosses the 16-bit boundary. The 24-bit
## boundary would need a ~16 MiB blob in git, so the test generates that frame
## at run time and pins it with a frozen checksum instead of committing it.

import io_mon/types

const
  InformativeFixtureRelPath* = "tests/fixtures/wire_informative/informative.iomon"

  BigPathLen* = 70_000
    ## Chosen so the containing frame's `u32` length prefix is
    ## 60 + 4 + 70_000 + 4 + len(detail) ≈ 0x0001_1234 — byte 2 non-zero, i.e.
    ## the frame is PAST THE 16-BIT BOUNDARY. A frame-length prefix truncated to
    ## a `u16` would encode/decode this frame at a wildly wrong size.

  HugePathLen* = 16_800_000
    ## Past the 24-BIT boundary (0x1000000 = 16_777_216): the frame's length
    ## prefix has a non-zero BYTE 3. Generated at run time, never committed —
    ## a 16 MiB blob does not belong in the tree, and the property under test is
    ## a property of the ENCODER, which a frozen checksum pins just as tightly.

proc informativeFill*(len: int; seed: char): string =
  ## A deterministic, highly compressible but not constant filler. Not all-`A`:
  ## a constant body would hide a copy that reads from the wrong source offset.
  result = newString(len)
  var c = seed
  for i in 0 ..< len:
    result[i] = c
    c = char((ord(c) - ord('a') + 1) mod 26 + ord('a'))

proc informativeRecords*(): seq[MonitorRecord] =
  ## Every field the wire does not pin is byte-informative: all eight bytes of
  ## each `u64` are distinct and non-zero, `flags`' four bytes likewise, and
  ## `result` is negative with a distinct byte in every position.
  ##
  ## `osPid` / `threadId` also drive `canonicalOrder`, so the values below are
  ## chosen to be pairwise distinct AND ordered, which makes the canonical
  ## record order (and hence the assigned `seq` 1 .. N) independent of the sort's
  ## tie-breaking.
  result = @[
    # 0 — every u64 a distinct 8-byte pattern; no two fields share a value, so
    #     an offset swap between ANY two of them is visible.
    MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
      seq: 0, # rewritten to 1..N by encodeCanonical
      osPid:       0x1122_3344_5566_7788'u64,
      parentOsPid: 0x99AA_BBCC_DDEE_FF01'u64,
      threadId:    0x0203_0405_0607_0809'u64,
      childOsPid:  0xA1B2_C3D4_E5F6_0718'u64,
      result:      cast[int64](0xF0E1_D2C3_B4A5_9687'u64),
      flags:       0xF1E2_D3C4'u32,
      probeResult: prExistingFile,
      path: "/informative/\xC3\xA9\xE2\x98\x83/process-start",
      detail: "run=informative;byte=\x00\x01\x7F\x80\xFE\xFF;tail"),

    # 1 — the 16-bit-boundary crosser. Its frame's length prefix needs byte 2.
    MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
      osPid:       0x2233_4455_6677_8899'u64,
      parentOsPid: 0xAABB_CCDD_EEFF_0102'u64,
      threadId:    0x0304_0506_0708_090A'u64,
      childOsPid:  0xB2C3_D4E5_F607_1829'u64,
      result:      cast[int64](0xE1D2_C3B4_A596_8778'u64),
      flags:       0xE2D3_C4B5'u32,
      probeResult: prExistingDirectory,
      path: informativeFill(BigPathLen, 'q'),
      detail: "run=informative;big-path"),

    # 2 — an empty path AND an empty detail: both length prefixes are zero, so a
    #     bulk copy that does not special-case len==0 is exercised here.
    MonitorRecord(kind: mrPathMutation, observationKind: moPathMutation,
      osPid:       0x3344_5566_7788_99AA'u64,
      parentOsPid: 0xBBCC_DDEE_FF01_0203'u64,
      threadId:    0x0405_0607_0809_0A0B'u64,
      childOsPid:  0xC3D4_E5F6_0718_293A'u64,
      result:      cast[int64](0xD2C3_B4A5_9687_78A9'u64),
      flags:       0xD3C4_B5A6'u32,
      probeResult: prUnknown,
      path: "", detail: ""),

    # 3 — a one-byte path and a one-byte detail: the shortest non-empty copy.
    MonitorRecord(kind: mrExternalContent, observationKind: moExternalContent,
      osPid:       0x4455_6677_8899_AABB'u64,
      parentOsPid: 0xCCDD_EEFF_0102_0304'u64,
      threadId:    0x0506_0708_090A_0B0C'u64,
      childOsPid:  0xD4E5_F607_1829_3A4B'u64,
      result:      cast[int64](0xC3B4_A596_8778_A9BA'u64),
      flags:       0xC4B5_A697'u32,
      probeResult: prAbsent,
      path: "\xFF", detail: "\x80"),

    # 4 — the highest legal `kind` / `obs` / `probeResult`, so a bounds check
    #     that is off by one at the TOP turns this fixture red.
    MonitorRecord(kind: high(MonitorRecordKind),
      observationKind: high(MonitorObservationKind),
      osPid:       0x5566_7788_99AA_BBCC'u64,
      parentOsPid: 0xDDEE_FF01_0203_0405'u64,
      threadId:    0x0607_0809_0A0B_0C0D'u64,
      childOsPid:  0xE5F6_0718_293A_4B5C'u64,
      result:      high(int64),
      flags:       high(uint32),
      probeResult: high(ProbeResult),
      path: informativeFill(600, 'z'),
      detail: informativeFill(300, 'm')),

    # 5 — the lowest legal `kind` / `obs`, `result` at `low(int64)` (sign bit
    #     only) and `flags` == 0: the complement of record 4.
    MonitorRecord(kind: low(MonitorRecordKind),
      observationKind: low(MonitorObservationKind),
      osPid:       0x6677_8899_AABB_CCDD'u64,
      parentOsPid: 0xEEFF_0102_0304_0506'u64,
      threadId:    0x0708_090A_0B0C_0D0E'u64,
      childOsPid:  0xF607_1829_3A4B_5C6D'u64,
      result:      low(int64),
      flags:       0'u32,
      probeResult: low(ProbeResult),
      path: "/informative/low", detail: "run=informative;low"),
  ]

const
  BigPathRecordIndex* = 1
    ## Index into `informativeRecords()` of the 16-bit-boundary crosser.
