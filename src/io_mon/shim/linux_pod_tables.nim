## FUP-H — thread-safe, ORC-allocator-free global tables for the Linux
## preload shim.
##
## The shim's fd/dir/stream path maps and its dedup sets are mutated from
## EVERY host thread's ``open`` / ``close`` / ``opendir`` / ``fopen`` /
## ``getenv`` hook. Backing them with Nim ``Table`` / ``HashSet`` /
## ``string`` (the ORC GC heap) is unsafe under ``--mm:orc``: the ORC
## allocator keeps a PER-THREAD memory region, so a ``Table`` rehash /
## ``string`` realloc / ``=sink`` dealloc that runs on a thread OTHER than
## the one that first allocated the chunk frees a chunk owned by another
## thread's region and corrupts that region's free-list. The ``fdLock`` /
## ``dirLock`` / … serialise *concurrent* access but do NOT change which
## thread's region owns the chunk, so the corruption survives the lock.
##
## This is the exact mechanism FUP-C fixed for the anonymous-mmap
## ownership table (see ``linux_preload_runtime.nim``'s
## ``anonymousExecutableRanges`` note); FUP-H closes the SAME class at the
## fd/dir/stream/observed sites — the ones that crashed live-Vulkan replay
## (``rawDealloc`` SIGSEGV inside ``updateFdPath`` off Mesa's
## ``device_select`` layer opening files concurrently, plus intermittent
## ASCII-into-host-heap corruption of the replay buffers).
##
## Storage discipline: the variable-length path payloads live in libc
## ``malloc`` / ``free`` allocations — which ARE thread-safe for
## cross-thread free (glibc/musl guarantee it) — inside fixed-capacity POD
## tables guarded by their own locks. No Nim GC heap is touched on the
## mutation path. Read accessors return a fresh Nim ``string`` copy built
## on the CALLING thread (allocated and freed on that same thread, which is
## safe), so callers are unchanged.

import std/locks

proc c_malloc(size: csize_t): pointer {.importc: "malloc", header: "<stdlib.h>".}
proc c_free(p: pointer) {.importc: "free", header: "<stdlib.h>".}
proc c_memcpy(dst, src: pointer; n: csize_t): pointer
  {.importc: "memcpy", header: "<string.h>".}

const
  # fds are dense small integers; direct-index up to this cap. A build with
  # ulimit -n above this (exotic; typical is 1024–4096) simply stops tracking
  # the extra fds' paths — never a crash, never a false dependency, only a
  # bounded under-report far beyond any realistic descriptor count.
  fdPathCap = 65536
  # Live open DIR*/FILE* working sets are tiny; the observed-input dedup set
  # grows with distinct env/sysctl keys. Both are generously over-provisioned
  # power-of-two open-addressing tables.
  ptrMapCap = 16384          # must be power of two
  ptrMapMask = ptrMapCap - 1
  observedCap = 32768        # must be power of two
  observedMask = observedCap - 1
  fdBitWords = fdPathCap div 8

type
  PtrPathSlot = object
    used: bool
    key: uint
    path: cstring            # libc-malloc'd, NUL-terminated (nil when free)

  PtrPathMap = object
    lock: Lock
    slots: array[ptrMapCap, PtrPathSlot]
    count: int

  ObservedSet = object
    lock: Lock
    keys: array[observedCap, cstring]  # libc-malloc'd; nil == empty slot
    count: int

var
  fdLockV: Lock
  fdPathPtr: array[fdPathCap, cstring]
  fdPathLen: array[fdPathCap, int32]

  dirMap: PtrPathMap
  streamMap: PtrPathMap
  observed: ObservedSet

  fdSetLock: Lock
  emptyFdBits: array[fdBitWords, uint8]
  inheritedFdBits: array[fdBitWords, uint8]

  podTablesReady = false

proc initPodTables*() {.raises: [].} =
  ## Initialise every lock exactly once. Idempotent; call from the shim's
  ## one-shot init under its existing init guard.
  if podTablesReady:
    return
  initLock(fdLockV)
  initLock(dirMap.lock)
  initLock(streamMap.lock)
  initLock(observed.lock)
  initLock(fdSetLock)
  podTablesReady = true

proc dupCString(path: cstring; outLen: var int): cstring {.raises: [].} =
  ## libc-malloc a NUL-terminated copy of ``path``. Returns nil on OOM (the
  ## caller then simply does not track that entry — never a crash).
  var n = 0
  while path[n] != '\0':
    inc n
  outLen = n
  let buf = c_malloc(csize_t(n + 1))
  if buf == nil:
    return nil
  if n > 0:
    discard c_memcpy(buf, cast[pointer](path), csize_t(n))
  cast[ptr UncheckedArray[char]](buf)[n] = '\0'
  cast[cstring](buf)

proc cStringToNim(s: cstring; n: int): string {.raises: [].} =
  ## Build a Nim string copy on the calling thread (same-thread alloc/free).
  if s == nil or n <= 0:
    return ""
  result = newString(n)
  discard c_memcpy(addr result[0], cast[pointer](s), csize_t(n))

# ── fd → path (direct index) ────────────────────────────────────────────

proc podFdPathSet*(fd: cint; path: cstring) {.raises: [].} =
  if fd < 0 or fd >= fdPathCap or path == nil:
    return
  var n = 0
  let copy = dupCString(path, n)
  acquire(fdLockV)
  let old = fdPathPtr[fd]
  fdPathPtr[fd] = copy
  fdPathLen[fd] = int32(if copy == nil: 0 else: n)
  release(fdLockV)
  if old != nil:
    c_free(cast[pointer](old))

proc podFdPathDel*(fd: cint) {.raises: [].} =
  if fd < 0 or fd >= fdPathCap:
    return
  acquire(fdLockV)
  let old = fdPathPtr[fd]
  fdPathPtr[fd] = nil
  fdPathLen[fd] = 0
  release(fdLockV)
  if old != nil:
    c_free(cast[pointer](old))

proc podFdPathGet*(fd: cint): string {.raises: [].} =
  if fd < 0 or fd >= fdPathCap:
    return ""
  acquire(fdLockV)
  let p = fdPathPtr[fd]
  let n = int(fdPathLen[fd])
  result = cStringToNim(p, n)
  release(fdLockV)

# ── uint (DIR*/FILE*) → path (open addressing, backward-shift delete) ────

proc ptrMapSetLocked(m: var PtrPathMap; key: uint; path: cstring) {.raises: [].} =
  var idx = int(key and uint(ptrMapMask))
  var scanned = 0
  while m.slots[idx].used and m.slots[idx].key != key and scanned < ptrMapCap:
    idx = (idx + 1) and ptrMapMask
    inc scanned
  var n = 0
  let copy = dupCString(path, n)
  if m.slots[idx].used and m.slots[idx].key == key:
    if m.slots[idx].path != nil:
      c_free(cast[pointer](m.slots[idx].path))
    m.slots[idx].path = copy
    return
  if scanned >= ptrMapCap:
    # Table full: drop this insert (never a crash; the live DIR*/FILE* set
    # is far below cap in practice, so this branch is unreachable outside a
    # pathological leak).
    if copy != nil:
      c_free(cast[pointer](copy))
    return
  m.slots[idx] = PtrPathSlot(used: true, key: key, path: copy)
  inc m.count

proc ptrMapDelLocked(m: var PtrPathMap; key: uint) {.raises: [].} =
  var idx = int(key and uint(ptrMapMask))
  var scanned = 0
  while m.slots[idx].used and m.slots[idx].key != key and scanned < ptrMapCap:
    idx = (idx + 1) and ptrMapMask
    inc scanned
  if not (m.slots[idx].used and m.slots[idx].key == key):
    return
  if m.slots[idx].path != nil:
    c_free(cast[pointer](m.slots[idx].path))
  m.slots[idx].path = nil
  m.slots[idx].used = false
  dec m.count
  # Backward-shift deletion (Knuth 6.4 R): re-home the following run so no
  # lookup terminates early on the freed slot.
  var j = idx
  while true:
    j = (j + 1) and ptrMapMask
    if not m.slots[j].used:
      break
    let home = int(m.slots[j].key and uint(ptrMapMask))
    # Is slot idx within the probe run of the entry at j? (cyclic interval)
    let canMove =
      if idx <= j: not (home > idx and home <= j)
      else: not (home > idx or home <= j)
    if canMove:
      m.slots[idx] = m.slots[j]
      m.slots[j].used = false
      m.slots[j].path = nil
      idx = j

proc ptrMapGetLocked(m: var PtrPathMap; key: uint): string {.raises: [].} =
  var idx = int(key and uint(ptrMapMask))
  var scanned = 0
  while m.slots[idx].used and scanned < ptrMapCap:
    if m.slots[idx].key == key:
      var n = 0
      let p = m.slots[idx].path
      if p != nil:
        while p[n] != '\0': inc n
      return cStringToNim(p, n)
    idx = (idx + 1) and ptrMapMask
    inc scanned
  ""

proc podDirPathSet*(key: uint; path: cstring) {.raises: [].} =
  if path == nil: return
  acquire(dirMap.lock)
  ptrMapSetLocked(dirMap, key, path)
  release(dirMap.lock)

proc podDirPathDel*(key: uint) {.raises: [].} =
  acquire(dirMap.lock)
  ptrMapDelLocked(dirMap, key)
  release(dirMap.lock)

proc podDirPathGet*(key: uint): string {.raises: [].} =
  acquire(dirMap.lock)
  result = ptrMapGetLocked(dirMap, key)
  release(dirMap.lock)

proc podStreamPathSet*(key: uint; path: cstring) {.raises: [].} =
  if path == nil: return
  acquire(streamMap.lock)
  ptrMapSetLocked(streamMap, key, path)
  release(streamMap.lock)

proc podStreamPathDel*(key: uint) {.raises: [].} =
  acquire(streamMap.lock)
  ptrMapDelLocked(streamMap, key)
  release(streamMap.lock)

proc podStreamPathGet*(key: uint): string {.raises: [].} =
  acquire(streamMap.lock)
  result = ptrMapGetLocked(streamMap, key)
  release(streamMap.lock)

# ── observed-input dedup set (grow-only, open addressing) ───────────────

proc fnv1a(s: cstring; n: int): uint {.raises: [].} =
  var h = 0xcbf29ce484222325'u64
  for i in 0 ..< n:
    h = h xor uint64(ord(s[i]))
    h = h * 0x100000001b3'u64
  uint(h)

proc cstrEq(a: cstring; b: cstring; n: int): bool {.raises: [].} =
  for i in 0 ..< n:
    if a[i] != b[i]: return false
  b[n] == '\0'

proc podObservedInsertIsNew*(key: cstring): bool {.raises: [].} =
  ## Returns true when ``key`` was not previously present (i.e. the caller
  ## should emit). On a full table it returns true WITHOUT storing, so the
  ## record is still emitted (a harmless duplicate) rather than dropped.
  if key == nil:
    return false
  var n = 0
  while key[n] != '\0': inc n
  let h = fnv1a(key, n)
  acquire(observed.lock)
  var idx = int(h and uint(observedMask))
  var scanned = 0
  var newlyInserted = true
  while observed.keys[idx] != nil and scanned < observedCap:
    if cstrEq(observed.keys[idx], key, n):
      newlyInserted = false
      break
    idx = (idx + 1) and observedMask
    inc scanned
  if newlyInserted and scanned < observedCap:
    var cn = 0
    let copy = dupCString(key, cn)
    if copy != nil:
      observed.keys[idx] = copy
      inc observed.count
  release(observed.lock)
  newlyInserted

# ── fd bitsets: emptyFdClassified + inheritedOpenFds ────────────────────

template bitOp(bits: untyped; fd: cint; body: untyped) =
  if fd >= 0 and fd < fdPathCap:
    let w {.inject.} = int(fd) shr 3
    let m {.inject.} = uint8(1'u8 shl (int(fd) and 7))
    body

proc podEmptyFdSet*(fd: cint) {.raises: [].} =
  acquire(fdSetLock)
  bitOp(emptyFdBits, fd): emptyFdBits[w] = emptyFdBits[w] or m
  release(fdSetLock)

proc podEmptyFdExcl*(fd: cint) {.raises: [].} =
  acquire(fdSetLock)
  bitOp(emptyFdBits, fd): emptyFdBits[w] = emptyFdBits[w] and (not m)
  release(fdSetLock)

proc podEmptyFdContains*(fd: cint): bool {.raises: [].} =
  acquire(fdSetLock)
  bitOp(emptyFdBits, fd): result = (emptyFdBits[w] and m) != 0
  release(fdSetLock)

proc podInheritedFdSet*(fd: cint) {.raises: [].} =
  acquire(fdSetLock)
  bitOp(inheritedFdBits, fd): inheritedFdBits[w] = inheritedFdBits[w] or m
  release(fdSetLock)

proc podInheritedFdExcl*(fd: cint) {.raises: [].} =
  acquire(fdSetLock)
  bitOp(inheritedFdBits, fd): inheritedFdBits[w] = inheritedFdBits[w] and (not m)
  release(fdSetLock)

proc podInheritedFdContains*(fd: cint): bool {.raises: [].} =
  acquire(fdSetLock)
  bitOp(inheritedFdBits, fd): result = (inheritedFdBits[w] and m) != 0
  release(fdSetLock)

proc podInheritedFdClear*() {.raises: [].} =
  acquire(fdSetLock)
  for i in 0 ..< fdBitWords:
    inheritedFdBits[i] = 0
  release(fdSetLock)
