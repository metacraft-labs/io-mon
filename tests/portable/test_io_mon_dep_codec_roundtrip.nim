## test_io_mon_dep_codec_roundtrip — io-mon-Lossless-Event-Capture M3 (part 2b).
##
## Ring-free field-by-field round-trip coverage for the RETAINED dep-record codec
## (`encodeDepRecord` / `encodeDepRecordIdentity` -> `decodeDepRecord`). This is the
## sole assertion that the codec preserves EVERY output-affecting `MonitorRecord`
## field; it recovers the `block codec:` coverage from the removed
## `test_io_mon_dep_ring_mpsc_roundtrip.nim` (part 2b deleted the ring transport but
## kept the codec, which now travels the nim-shm-gset SET channel). The golden
## depfile tests zero several of these fields, so without this test a codec
## regression that drops e.g. `childOsPid` or `flags` would silently corrupt
## depfiles and still pass.
##
## Pure `io_mon/types` + `io_mon/shm/dep_queue` — no ring, no shm, no live shim —
## so it runs on EVERY OS (portable tier).
##
## Coverage:
##   * encodeDepRecord (real-seq variant): every field, INCLUDING `seq`, survives
##     the round-trip for several representative records (typical; empty
##     path/detail; max-ish values; non-ASCII detail).
##   * encodeDepRecordIdentity: the identity-relevant fields survive with `seq`
##     forced to 0, AND trailing bytes the caller appends (the per-exec image
##     suffix) are IGNORED by the decoder — a decoded element equals the file
##     record (the LF-6 byte-identical-depfile invariant depends on this).
##
## Falsifiable: dropping any field from `decodeDepRecord` (verified in review by
## breaking `childOsPid`/`flags` in a scratch copy) fails the matching `check`.

import std/[strutils, unittest]

import io_mon/types
import io_mon/shm/dep_queue

const CodecBufCap = 8192
  ## Comfortably larger than DepFixedHeaderLen + the longest path/detail below
  ## plus any appended identity-image suffix.

proc representativeRecords(): seq[MonitorRecord] =
  result = @[
    # 1. Typical full record — every field non-trivial.
    MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
      seq: 42, osPid: 1234, parentOsPid: 12, threadId: 7, childOsPid: 99,
      result: -5, flags: 0xABCD'u32, probeResult: prExistingFile,
      path: "/some/deep/path/to/a/dependency.h",
      detail: "run=xyz ctx=[phase=emit]"),
    # 2. Empty path AND detail (varint length 0 on both).
    MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
      seq: 0, osPid: 1, parentOsPid: 0, threadId: 0, childOsPid: 0,
      result: 0, flags: 0'u32, probeResult: prUnknown,
      path: "", detail: ""),
    # 3. Max-ish values — high enums, big unsigned fields, negative result,
    #    full u32 flags (guards against sign/width truncation).
    MonitorRecord(kind: mrPathMutation, observationKind: moPathMutation,
      seq: high(uint64), osPid: high(uint64) - 1, parentOsPid: 0xDEADBEEF01234567'u64,
      threadId: 0x0123456789ABCDEF'u64, childOsPid: high(uint64) div 3,
      result: low(int64), flags: high(uint32), probeResult: prExistingOther,
      path: "/x".repeat(400), detail: "d".repeat(300)),
    # 4. Non-ASCII detail (bytes >= 0x80 must survive the char<->byte copy).
    MonitorRecord(kind: mrLibraryLoad, observationKind: moFileRead,
      seq: 7, osPid: 555, parentOsPid: 1, threadId: 3, childOsPid: 0,
      result: 0, flags: 0x8000_0001'u32, probeResult: prExistingDirectory,
      path: "/usr/lib/libfavorité.dylib",
      detail: "détail: café — naïve ☃ \xFF\x80\x00 tail"),
  ]

template checkAllFields(d, r: MonitorRecord; expectSeq: uint64) =
  ## Assert every codec-carried field of `d` matches `r`, with `seq` compared
  ## against `expectSeq` (real `seq` for encodeDepRecord, 0 for the identity codec).
  ## A TEMPLATE (not a proc) so the `check`s expand into the test body and a
  ## failure flips the enclosing test to `[FAILED]` (unittest tracks status
  ## lexically, per test body).
  check d.kind == r.kind
  check d.observationKind == r.observationKind
  check d.seq == expectSeq
  check d.osPid == r.osPid
  check d.parentOsPid == r.parentOsPid
  check d.threadId == r.threadId
  check d.childOsPid == r.childOsPid
  check d.result == r.result
  check d.flags == r.flags
  check d.probeResult == r.probeResult
  check d.path == r.path
  check d.detail == r.detail

suite "io-mon dep record codec round-trip":

  test "t_codec_real_seq_roundtrip":
    # encodeDepRecord carries the record's real `seq`: EVERY field must survive.
    for r in representativeRecords():
      var buf: array[CodecBufCap, byte]
      let n = encodeDepRecord(r, buf)
      check n > 0
      var ok = false
      let d = decodeDepRecord(buf.toOpenArray(0, n - 1), ok)
      check ok
      checkAllFields(d, r, r.seq)

  test "t_codec_identity_drops_seq_and_ignores_suffix":
    # encodeDepRecordIdentity forces seq=0 (the dedup key) but preserves every
    # other field; the caller appends a per-exec image suffix the decoder MUST
    # ignore, so a decoded element == the file record.
    let imageSuffix = "/proc/self/exe#incarnation-image-bytes\x00\x01\x02"
    for r in representativeRecords():
      var buf: array[CodecBufCap, byte]
      let n = encodeDepRecordIdentity(r, buf)
      check n > 0

      # Bare identity element decodes with seq=0, all other fields intact.
      var okBare = false
      let bare = decodeDepRecord(buf.toOpenArray(0, n - 1), okBare)
      check okBare
      checkAllFields(bare, r, 0'u64)

      # Append the image suffix and decode again: the trailing bytes are dropped,
      # so the decoded record is byte-for-byte the bare (file) record.
      var withSuffix = buf
      var total = n
      for ch in imageSuffix:
        withSuffix[total] = byte(ch); inc total
      var okSuffix = false
      let dec = decodeDepRecord(withSuffix.toOpenArray(0, total - 1), okSuffix)
      check okSuffix
      checkAllFields(dec, r, 0'u64)
      # And it equals the file record produced without any suffix.
      check dec == bare
