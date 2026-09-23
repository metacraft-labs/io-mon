import std/[strutils]

type
  CodecFamily* = enum
    cfFixedSchemaEnvelope
    cfCborDynamicMetadata
    cfJsonInspectionView

  EnvelopeErrorKind* = enum
    eeMalformed
    eeUnknownMagic
    eeUnsupportedVersion
    eeUnknownType

  EnvelopeError* = object of CatchableError
    kind*: EnvelopeErrorKind

  EnvelopeTypeId* = distinct uint16

  EnvelopeHeader* = object
    magic*: array[4, byte]
    version*: uint16
    typeId*: EnvelopeTypeId
    payloadLength*: uint32

  BinaryCodecPolicy* = object
    fixedSchemaFamily*: CodecFamily
    dynamicMetadataFamily*: CodecFamily
    jsonPersistent*: bool

const DefaultBinaryCodecPolicy* = BinaryCodecPolicy(
  fixedSchemaFamily: cfFixedSchemaEnvelope,
  dynamicMetadataFamily: cfCborDynamicMetadata,
  jsonPersistent: false)

proc raiseEnvelopeError*(kind: EnvelopeErrorKind; message: string) {.noreturn.} =
  var err = newException(EnvelopeError, message)
  err.kind = kind
  raise err

proc writeU16Le*(outp: var seq[byte]; value: uint16) =
  outp.add(byte(value and 0xff'u16))
  outp.add(byte((value shr 8) and 0xff'u16))

proc writeU32Le*(outp: var seq[byte]; value: uint32) =
  for shift in [0, 8, 16, 24]:
    outp.add(byte((value shr shift) and 0xff'u32))

proc writeU64Le*(outp: var seq[byte]; value: uint64) =
  for shift in [0, 8, 16, 24, 32, 40, 48, 56]:
    outp.add(byte((value shr shift) and 0xff'u64))

proc readU16Le*(bytes: openArray[byte]; pos: var int): uint16 =
  if pos + 2 > bytes.len:
    raiseEnvelopeError(eeMalformed, "truncated uint16")
  result = uint16(bytes[pos]) or (uint16(bytes[pos + 1]) shl 8)
  pos += 2

proc readU32Le*(bytes: openArray[byte]; pos: var int): uint32 =
  if pos + 4 > bytes.len:
    raiseEnvelopeError(eeMalformed, "truncated uint32")
  for i in 0 ..< 4:
    result = result or (uint32(bytes[pos + i]) shl (8 * i))
  pos += 4

proc readU64Le*(bytes: openArray[byte]; pos: var int): uint64 =
  if pos + 8 > bytes.len:
    raiseEnvelopeError(eeMalformed, "truncated uint64")
  for i in 0 ..< 8:
    result = result or (uint64(bytes[pos + i]) shl (8 * i))
  pos += 8

# --------------------------------------------------------------------------
# DA-1c — FIXED-OFFSET little-endian accessors.
#
# The `writeU*Le` / `readU*Le` pair above is a CURSOR codec: it appends to (or
# walks) a growing `seq[byte]` one byte at a time, which is the right shape for
# a variable-length stream and the wrong shape for the `.iomon` frame's FIXED
# 72-byte header, whose every field offset is known at compile time. These
# accessors store/load a whole field at a known offset in a buffer the caller
# has already sized.
#
# ENDIANNESS. The wire is little-endian, by definition of `writeU16Le` &c. On a
# little-endian host the native representation of a `uintN` IS the wire
# representation, so `copyMem` is a legal encoding of it — and `copyMem` has no
# alignment requirement, so an odd `off` is fine. On a big-endian host it is
# NOT, so the shift form is kept and selected at compile time; the two branches
# are byte-for-byte equivalent by construction. This is deliberately NOT a
# `copyMem` of a Nim object: object layout carries padding and field-order
# decisions the wire must not inherit, whereas a field-at-a-time store of a
# scalar inherits only the scalar's byte order, which the `when` already
# handles.
# --------------------------------------------------------------------------

proc storeU16Le*(buf: var openArray[byte]; off: int; value: uint16) {.inline.} =
  when cpuEndian == littleEndian:
    copyMem(addr buf[off], unsafeAddr value, 2)
  else:
    buf[off] = byte(value and 0xff'u16)
    buf[off + 1] = byte((value shr 8) and 0xff'u16)

proc storeU32Le*(buf: var openArray[byte]; off: int; value: uint32) {.inline.} =
  when cpuEndian == littleEndian:
    copyMem(addr buf[off], unsafeAddr value, 4)
  else:
    for i in 0 ..< 4:
      buf[off + i] = byte((value shr (8 * i)) and 0xff'u32)

proc storeU64Le*(buf: var openArray[byte]; off: int; value: uint64) {.inline.} =
  when cpuEndian == littleEndian:
    copyMem(addr buf[off], unsafeAddr value, 8)
  else:
    for i in 0 ..< 8:
      buf[off + i] = byte((value shr (8 * i)) and 0xff'u64)

proc loadU16Le*(bytes: openArray[byte]; off: int): uint16 {.inline.} =
  when cpuEndian == littleEndian:
    copyMem(addr result, unsafeAddr bytes[off], 2)
  else:
    result = uint16(bytes[off]) or (uint16(bytes[off + 1]) shl 8)

proc loadU32Le*(bytes: openArray[byte]; off: int): uint32 {.inline.} =
  when cpuEndian == littleEndian:
    copyMem(addr result, unsafeAddr bytes[off], 4)
  else:
    result = 0'u32
    for i in 0 ..< 4:
      result = result or (uint32(bytes[off + i]) shl (8 * i))

proc loadU64Le*(bytes: openArray[byte]; off: int): uint64 {.inline.} =
  when cpuEndian == littleEndian:
    copyMem(addr result, unsafeAddr bytes[off], 8)
  else:
    result = 0'u64
    for i in 0 ..< 8:
      result = result or (uint64(bytes[off + i]) shl (8 * i))

proc writeString*(outp: var seq[byte]; value: string) =
  outp.writeU32Le(uint32(value.len))
  for ch in value:
    outp.add(byte(ord(ch)))

proc readString*(bytes: openArray[byte]; pos: var int): string =
  let length = int(readU32Le(bytes, pos))
  if pos + length > bytes.len:
    raiseEnvelopeError(eeMalformed, "truncated string")
  result = newString(length)
  for i in 0 ..< length:
    result[i] = char(bytes[pos + i])
  pos += length

proc toBytes*(text: string): seq[byte] =
  ## DA-1c — bulk copy, not a byte loop.
  ##
  ## `readMonitorDepFile` calls this on the WHOLE depfile, so the previous
  ## `for ch in text: result.add(byte(ord(ch)))` paid a per-byte bounds/capacity
  ## check and store for every byte of a multi-megabyte file: measured ~110 ms
  ## of a ~215 ms read of a 12.6 MB capture, roughly half the read path, against
  ## 8.9 ms of actual file I/O.
  ##
  ## Byte-identical by construction and on EVERY host: a Nim `char` is one byte
  ## and `byte(ord(ch))` is that same byte, so the loop and the copy write the
  ## same bytes in the same order. No endianness is involved — this is a
  ## byte-sequence copy, not a scalar encode.
  result = newSeq[byte](text.len)
  if text.len > 0:
    copyMem(addr result[0], unsafeAddr text[0], text.len)

proc fromBytes*(bytes: openArray[byte]): string =
  result = newString(bytes.len)
  for i, b in bytes:
    result[i] = char(b)

proc hexBytes*(bytes: openArray[byte]): string =
  result = newStringOfCap(bytes.len * 2)
  for b in bytes:
    result.add(toHex(int(b), 2).toLowerAscii())
