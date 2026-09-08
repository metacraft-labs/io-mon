## Shared-memory dependency-record codec (`MonitorRecord` ↔ opaque element bytes).
##
## io-mon-Lossless-Event-Capture M3 part 2b — the superseded DEP-SHM MPSC ring
## transport (`DepQueue`, `createDepQueueAtPath`/`attachDepQueueAtPath`,
## `tryPushRecord`/`tryDrainOne`, the drop-on-full segment) has been REMOVED: the
## M1-winning `nim-shm-gset` SET transport is the sole Linux dependency channel and
## nothing on the retained set path used the ring any longer. What remains here —
## and is RETAINED — is ONLY the dep-specific `MonitorRecord` **codec** the SET
## transport depends on: it turns a `MonitorRecord` into the opaque element bytes
## the `nim-shm-gset` producer publishes (`encodeDepRecordIdentity`) and back
## (`decodeDepRecord`), plus the real-`seq` variant (`encodeDepRecord`).
##
## The codec is domain-only (no ring, no segment, no atomics): a fixed header +
## varint-length path/detail encoding of the SAME `MonitorRecord` the iomon frames
## carry. The real-sequence codec preserves every field. The SET identity codec
## preserves every field for process/completeness records, while path-scoped and
## fact-scoped observations discard process-local coordinates that do not change
## the observed dependency (DA-1b — see `depIdentityScope`, which states the
## per-kind decision and the argument behind each one). No serialization
## dependency (pure `io_mon/types`), so the LD_PRELOAD shim that imports this
## module stays serialization-free.

import io_mon/types

# ---------------------------------------------------------------------------
# Record codec.
# ---------------------------------------------------------------------------

const
  DepFixedHeaderLen* = 2 + 2 + 8 + 8 + 8 + 8 + 8 + 8 + 4 + 4
    ## kind(u16) obsKind(u16) seq(u64) osPid(u64) parentOsPid(u64)
    ## threadId(u64) childOsPid(u64) result(i64) flags(u32) probeResult(u32)

proc putVarint(buf: var openArray[byte]; pos: var int; value: uint64): bool =
  ## LEB128 unsigned varint. Returns false if it would overrun `buf`.
  var v = value
  while true:
    if pos >= buf.len:
      return false
    var b = byte(v and 0x7F)
    v = v shr 7
    if v != 0:
      b = b or 0x80'u8
    buf[pos] = b
    inc pos
    if v == 0:
      break
  true

proc getVarint(buf: openArray[byte]; pos: var int; value: var uint64): bool =
  var shift = 0
  var result0: uint64 = 0
  while true:
    if pos >= buf.len or shift >= 64:
      return false
    let b = buf[pos]
    inc pos
    result0 = result0 or (uint64(b and 0x7F) shl shift)
    if (b and 0x80) == 0:
      break
    shift += 7
  value = result0
  true

proc putU16(buf: var openArray[byte]; pos: var int; v: uint16) =
  buf[pos] = byte(v and 0xFF); buf[pos + 1] = byte((v shr 8) and 0xFF)
  pos += 2

proc putU32(buf: var openArray[byte]; pos: var int; v: uint32) =
  buf[pos] = byte(v and 0xFF); buf[pos + 1] = byte((v shr 8) and 0xFF)
  buf[pos + 2] = byte((v shr 16) and 0xFF); buf[pos + 3] = byte((v shr 24) and 0xFF)
  pos += 4

proc putU64(buf: var openArray[byte]; pos: var int; v: uint64) =
  for i in 0 ..< 8:
    buf[pos + i] = byte((v shr (8 * i)) and 0xFF)
  pos += 8

proc getU16(buf: openArray[byte]; pos: var int): uint16 =
  result = uint16(buf[pos]) or (uint16(buf[pos + 1]) shl 8)
  pos += 2

proc getU32(buf: openArray[byte]; pos: var int): uint32 =
  result = uint32(buf[pos]) or (uint32(buf[pos + 1]) shl 8) or
    (uint32(buf[pos + 2]) shl 16) or (uint32(buf[pos + 3]) shl 24)
  pos += 4

proc getU64(buf: openArray[byte]; pos: var int): uint64 =
  result = 0
  for i in 0 ..< 8:
    result = result or (uint64(buf[pos + i]) shl (8 * i))
  pos += 8

type
  DepIdentityScope* = enum
    ## DA-1b (reprobuild-specs/Dependency-Attribution.milestones.org) — WHAT
    ## MAKES TWO OBSERVATIONS THE SAME FACT, decided per record kind. The
    ## argument for every kind's answer is in `depIdentityScope` below.
    disProcessScoped   ## the OBSERVING PROCESS is part of the observed fact
    disPathScoped      ## the observed PATH is the fact; the observer is not
    disFactScoped      ## the OBSERVATION is the fact; neither the observer nor
                       ## its executable incarnation is

func depIdentityScope*(kind: MonitorRecordKind): DepIdentityScope =
  ## DA-1b — WHICH KINDS IS THE PID LOAD-BEARING EVIDENCE FOR, AND WHICH IS IT
  ## INCIDENTAL TO?
  ##
  ## THE CLAIM. For four kinds — `mrLibraryLoad`, `mrEnvRead`, `mrSysctlRead`,
  ## `mrTimeRead` — the observation IS the entire fact. Which process made it,
  ## and which executable incarnation that process was running, cannot be
  ## recovered by any consumer into anything it can act on, so neither belongs
  ## in the element key. For every other kind at least one of those coordinates
  ## is evidence somebody reads, and the key keeps it.
  ##
  ## MEASURED, and this is why the milestone exists. On a real `nim c`
  ## (reprobuild compiling its own entrypoint: 2,435 processes, 123,837
  ## records) the four fact-scoped kinds are 57,302 records — 46.3% of the
  ## depfile — describing 89 distinct facts. `library-load` alone is 33,128
  ## records over 26 DSOs; `libpthread.so.0` appears 4,040 times, every field
  ## byte-identical including `detail`, differing only in `osPid`.
  ##
  ## Exhaustive over `MonitorRecordKind`, deliberately: a kind added later does
  ## not compile until somebody decides which side of this line it falls on.
  ##
  ## ── PROCESS-SCOPED: the pid IS the evidence ────────────────────────────
  ##
  ## `mrProcessStart` — the untouchable one. `processStartIdentities` /
  ##   `monitoredStartPids` (writer.nim) build the set of (pid, start-time)
  ##   identities from exactly this kind's `osPid`, and THAT set is what
  ##   `unmonitoredSubtreeLossDetails` consults to decide whether an
  ##   `mrIpcConnect` peer, an `mrProcessSpawn` child or an
  ##   `mrExternalContent` producer is inside the monitored tree. Zeroing the
  ##   pid here would not weaken the decision, it would delete it — measured,
  ##   the 4,059 process-starts of that `nim c` collapse to ONE element,
  ##   because on Linux their `detail` is the same constant string. The record
  ##   COUNT is load-bearing too: signal (b) is
  ##   `execCount(pid) >= startCount(pid)`.
  ## `mrProcessExec` — the other half of signal (b). One post-exec start per
  ##   exec is what proves the new image was injectable; collapse the per-pid
  ##   multiplicity and the signal reads the same on a tree that exec'd into a
  ##   hardened binary as on one that did not.
  ## `mrProcessSpawn` — signal (a). `childOsPid` names the spawned child and is
  ##   matched against the process-start set; `osPid` names the parent, and the
  ##   `childOsPid != osPid` guard needs both. There would be nothing to win
  ##   anyway: measured, zeroing only the parent-side coordinates leaves all
  ##   2,434 records distinct, because the child pid already differs.
  ## `mrIpcConnect` — the peer pid lives in `childOsPid` and the client pid in
  ##   `osPid`, and `breakawayAuthContext` keys its `connectedPeers` set on the
  ##   literal `"<osPid>:<childOsPid>"` string a cooperating daemon's breakaway
  ##   report is authenticated against. Both ends are the evidence.
  ## `mrExternalContent` — `externalContentLossCount` reads `childOsPid` as the
  ##   PRODUCER pid and tests it against the same process-start set. That is
  ##   the IM-4 process-tree-membership guard; it is a pid comparison and
  ##   nothing else.
  ## `mrFileWrite` — a write is an EFFECT, not an observation. "Two processes
  ##   wrote this path" is a real fact about a build and it is exactly what
  ##   collapsing the observer would erase. Measured cost of keeping it: zero —
  ##   all 2,413 writes in that `nim c` are to distinct paths, so there is no
  ##   repetition here to recover. NOTE FOR ANYONE WHO REVISITS THIS: a stdio
  ##   write record carries the raw `FILE*` in `result` (`recordFopen`), and the
  ##   `dropObserver` normalization below has no `mrFileWrite` arm — so moving
  ##   this kind across the line without also normalizing `result` would fold
  ##   the pid out and leave a per-process heap address in its place, deduping
  ##   nothing while looking as if it had.
  ## `mrPathMutation` — the same argument as `mrFileWrite`: mkdir/rmdir/unlink
  ##   are output-side effects on a shared tree, and who performed one is part
  ##   of what happened.
  ## `mrEventLoss` — the last record anyone should make cheaper. The pid says
  ##   WHERE capture was lost, and rule 1 of this campaign is to narrow what is
  ##   recorded, never what is detected.
  ## `mrNonDeterministic` — the honest borderline. Its documented contract is
  ##   "recorded ONCE PER PROCESS PER SOURCE … the evidence is *this process*
  ##   consumed entropy from this API" (types.nim), and its consumer is a
  ##   PUBLISH GATE (reprobuild's `applyEntropyBlessingPolicy`), not a cache
  ##   key. Deduping it would still answer "did entropy enter this action" but
  ##   would stop answering "in which process", and a blessing that names a
  ##   tool needs the second. The measurement settles it rather than the
  ##   argument: that `nim c` produced ZERO of these, so the change would buy
  ##   nothing and could only cost.
  ## `mrBackendProfile`, `mrCapabilityGap` — META records describing one
  ##   monitored process's backend and its declared gaps. One and nine records
  ##   respectively in that `nim c`, already distinct; the provenance is about
  ##   a process, so the process stays in it.
  ##
  ## ── PATH-SCOPED: the path is the fact, the observer is not ─────────────
  ##
  ## `mrFileOpen`, `mrFileRead`, `mrPathProbe` — unchanged, and the reason they
  ##   were already here is the reason the kind below joins them: the content
  ##   of `/usr/include/stdio.h` does not depend on who stat'd it. Measured,
  ##   these dedup at 1.0-1.1x, i.e. they carry essentially no cross-process
  ##   repetition left to recover.
  ## `mrDirectoryEnumerate` — NEW here, and it is the same sentence: a
  ##   directory's entries are a property of the directory. reprobuild folds it
  ##   into `monitorProbes` + `monitorDirectoryEnumerations` by PATH only, and
  ##   nothing in io-mon's completeness machinery mentions the kind at all.
  ##   Honest about the size of it: nine records in that `nim c`, so this is
  ##   classification for coherence, not for the count.
  ##
  ## ── FACT-SCOPED: neither the observer nor its incarnation ──────────────
  ##
  ## `mrLibraryLoad` — a DSO's identity is its path and its contents. The kind
  ##   deliberately carries `observationKind == moFileRead` so that every
  ##   consumer treats it as a CONTENT dependency (types.nim), and a content
  ##   dependency is a property of the file, not of the process that mapped it.
  ##   It appears in no branch of `unmonitoredSubtreeLossDetails`,
  ##   `externalContentLossCount`, `breakawayAuthContext` or
  ##   `processStartIdentities`; reprobuild folds it into `monitorReads` by
  ##   path. 33,128 records, 26 DSOs.
  ## `mrEnvRead` — the record carries the variable's NAME and never its value,
  ##   by construction: the consumer re-resolves the value from its own
  ##   environment when it builds the key (reprobuild folds the name into
  ##   `PathSetEvidence.monitorEnvReads` and `cacheEnvInputs` then pairs it with
  ##   the value the action's own env holds). So the pid was never able to
  ##   answer "what did THIS
  ##   process see for PATH?" — if two processes in a tree hold different
  ##   values for one name, the record cannot express that WITH the pid either.
  ##   Dropping it removes a coordinate that was already not answering the
  ##   question. 19,339 records, 56 names.
  ## `mrSysctlRead` — the same shape, over a machine-global source
  ##   (`sysconf:84`, `uname`, `getcpu`). 3,220 records, 4 sources.
  ## `mrTimeRead` — a diagnostic marker naming a clock source, explicitly
  ##   "record but do NOT auto-downgrade" with no consumer that acts on it.
  ##   1,615 records, 3 sources.
  ##
  ## ── WHAT THIS DOES NOT CHANGE ──────────────────────────────────────────
  ##
  ## Nothing stops being OBSERVED, and no completeness decision moves. Every
  ## fact still appears in the depfile; it appears once instead of once per
  ## process. `summary.processCount` is derived from any record with a non-zero
  ## `osPid` and every monitored process emits its own `mrProcessStart`, so the
  ## process census is unchanged. The macOS and Windows arms travel the
  ## `.iomon-frag` FILE writer, which encodes every field verbatim and never
  ## consults this function, so this is a Linux set-transport change only.
  ##
  ## It is also NOT an attribution claim. Nothing here asserts that a path is
  ## immutable, that a root is content-addressed, or that an observation may be
  ## skipped — those are DA-3's arguments and none of them is needed for this
  ## one. This is purely about how many times one fact is written down.
  case kind
  of mrFileOpen, mrFileRead, mrPathProbe, mrDirectoryEnumerate:
    disPathScoped
  of mrLibraryLoad, mrEnvRead, mrSysctlRead, mrTimeRead:
    disFactScoped
  of mrProcessStart, mrProcessExec, mrProcessSpawn, mrFileWrite, mrEventLoss,
     mrBackendProfile, mrCapabilityGap, mrIpcConnect, mrNonDeterministic,
     mrExternalContent, mrPathMutation:
    disProcessScoped

func depIdentityKeepsIncarnation*(kind: MonitorRecordKind): bool =
  ## DA-1b — should the caller append its per-exec incarnation identity
  ## (`setElemImage`: `/proc/self/exe` plus the exec generation) to this kind's
  ## element key?
  ##
  ## The incarnation is a process-local coordinate exactly like the pid, so the
  ## answer follows the same decision: a FACT-scoped kind drops it, everything
  ## else keeps it. Keeping it on a fact-scoped kind would defeat the dedup with
  ## the very coordinate the classification just called irrelevant — measured on
  ## that `nim c`, `library-load`'s 33,128 elements decode to only 25,883
  ## distinct records, so ~7,200 of today's records are duplicates the suffix
  ## alone created, before any pid is considered.
  ##
  ## It must NOT be dropped for the other two classes, and for different
  ## reasons. PROCESS-scoped: a pid's pre-exec and post-exec `mrProcessStart`
  ## are byte-identical after decode (same pid/ppid/tid, empty path, `seq`
  ## forced to 0), and the incarnation suffix is the ONLY thing keeping them
  ## two elements — which is what the `startCount == 1 + execCount` invariant
  ## counts. PATH-scoped: `encodeDepRecordIdentity` records the decided position
  ## that observations from distinct executable incarnations do not collapse,
  ## and this milestone has no evidence against it (measured: file-opens dedup
  ## at 1.0x, so there is nothing there to win by revisiting it).
  depIdentityScope(kind) != disFactScoped

proc encodeDepRecordWithSeq(record: MonitorRecord; buf: var openArray[byte];
                            seqValue: uint64;
                            applyIdentityScope = false): int =
  ## Shared codec body used by `encodeDepRecord` (carries the record's real
  ## `seq`, every field verbatim) and `encodeDepRecordIdentity` (forces
  ## `seq = 0` and applies the per-kind `depIdentityScope`). NO heap allocation:
  ## the caller supplies a stack buffer, keeping this fork/orc-safe on the shim
  ## hot path.
  var pos = 0
  let need = DepFixedHeaderLen
  if buf.len < need:
    return -1
  let scope =
    if applyIdentityScope: depIdentityScope(record.kind) else: disProcessScoped
  # DA-1b — PATH- and FACT-scoped kinds both drop the observing process; they
  # differ only in whether the CALLER also drops its incarnation suffix (see
  # `depIdentityKeepsIncarnation`).
  let dropObserver = scope in {disPathScoped, disFactScoped}
  var encodedResult = record.result
  var encodedFlags = record.flags
  if dropObserver:
    case record.kind
    of mrFileRead:
      # Byte count and descriptor number do not alter the content dependency.
      encodedResult = 0
      encodedFlags = 0
    of mrFileOpen, mrPathProbe:
      # Preserve success versus failure; successful descriptor numbers are
      # process-local. Open flags and ProbeResult remain part of the key.
      encodedResult = if record.result < 0: -1 else: 0
    else:
      discard
  putU16(buf, pos, uint16(ord(record.kind)))
  putU16(buf, pos, uint16(ord(record.observationKind)))
  putU64(buf, pos, seqValue)
  putU64(buf, pos, if dropObserver: 0'u64 else: record.osPid)
  putU64(buf, pos, if dropObserver: 0'u64 else: record.parentOsPid)
  putU64(buf, pos, if dropObserver: 0'u64 else: record.threadId)
  putU64(buf, pos, if dropObserver: 0'u64 else: record.childOsPid)
  putU64(buf, pos, cast[uint64](encodedResult))
  putU32(buf, pos, encodedFlags)
  putU32(buf, pos, uint32(ord(record.probeResult)))
  if not putVarint(buf, pos, uint64(record.path.len)):
    return -1
  if record.path.len > 0:
    if pos + record.path.len > buf.len:
      return -1
    for i in 0 ..< record.path.len:
      buf[pos + i] = byte(record.path[i])
    pos += record.path.len
  if not putVarint(buf, pos, uint64(record.detail.len)):
    return -1
  if record.detail.len > 0:
    if pos + record.detail.len > buf.len:
      return -1
    for i in 0 ..< record.detail.len:
      buf[pos + i] = byte(record.detail[i])
    pos += record.detail.len
  pos

proc encodeDepRecord*(record: MonitorRecord; buf: var openArray[byte]): int =
  ## Encode `record` into `buf` carrying its real `seq`. Returns the byte length
  ## written, or -1 if the record does not fit. The real-`seq` variant of the
  ## codec (the SET transport uses `encodeDepRecordIdentity`, which drops `seq`);
  ## retained as the codec's stream-ordinal encoder and for round-trip tests.
  encodeDepRecordWithSeq(record, buf, record.seq)

proc encodeDepRecordIdentity*(record: MonitorRecord; buf: var openArray[byte]): int =
  ## io-mon-Lossless-Event-Capture M3 (part 2a) — the DEDUP element-key encoder for
  ## the nim-shm-gset SET transport (the M1-winning Candidate-C channel). Identical
  ## to `encodeDepRecord` except that the per-record monotonic `seq` is forced to
  ## 0 and path-scoped observations discard process-local coordinates, so the
  ## encoded bytes describe the dependency identity rather than an event ordinal.
  ##
  ## FIELD CLASSIFICATION for the set dedup key (see the milestone report). The key
  ## must (a) collapse exact-duplicate probe-storm observations — "same path
  ## re-stat'd -> one element", the real Candidate-C dedup — and (b) NEVER collapse
  ## two semantically-distinct observations (the cardinal sin — a dropped dep):
  ##
  ##   PROCESS/COMPLETENESS IDENTITY (`disProcessScoped`): every field except `seq`
  ##   remains in the key. `childOsPid`/`osPid`/`parentOsPid` are load-bearing for
  ##   start/exec/spawn/IPC accounting and are never normalized on those records.
  ##
  ##   PATH-SCOPED IDENTITY (`disPathScoped`: `mrFileOpen`, `mrFileRead`,
  ##   `mrPathProbe`, `mrDirectoryEnumerate`): process and thread ids are zeroed.
  ##   File-read byte count/fd are zeroed. Open/probe result is reduced to
  ##   success/failure, while open flags, observation kind, `probeResult`, path, and
  ##   detail remain in the key. The caller's appended exec-image/generation suffix
  ##   also remains, so observations from distinct executable incarnations do not
  ##   collapse. This folds compiler include-search storms across thousands of
  ##   same-image workers without losing a distinct path, access mode, existence
  ##   outcome, probe outcome, or run scope.
  ##
  ##   FACT-SCOPED IDENTITY (DA-1b — `disFactScoped`: `mrLibraryLoad`, `mrEnvRead`,
  ##   `mrSysctlRead`, `mrTimeRead`): process and thread ids are zeroed AND the
  ##   caller drops the incarnation suffix (`depIdentityKeepsIncarnation`), because
  ##   for these kinds the observation is the whole fact and neither coordinate is
  ##   evidence any consumer reads. Everything the fact IS — observation kind, path,
  ##   detail (including the run scope), result, flags — stays in the key. See
  ##   `depIdentityScope` for the per-kind argument.
  ##
  ##   DROPPED (excluded from the key — noise for the dependency): `seq` (this
  ##   proc's whole point: the per-record monotonic ordinal is EXACTLY what
  ##   distinguishes exact-duplicate storm EVENTS from each other; it is renumbered
  ##   densely in the canonical depfile so its value never reaches the output, so
  ##   dropping it is what ENABLES source-dedup). The part-1 8-byte incarnation
  ##   nonce is also gone (replaced by the real exec-incarnation identity the caller
  ##   appends — see `appendFragmentRecord`).
  ##
  ## `decodeDepRecord` reconstructs a `MonitorRecord` with `seq = 0` from this key
  ## (plus ignores any trailing incarnation-identity bytes the caller appends), so
  ## the consumer feeds the SAME `mergeFragments` canonicalization the file path
  ## uses. Ordering determinism (two distinct keys that tie in `canonicalOrder`
  ## because `seq` is 0) is restored by the consumer sorting the snapshot by raw
  ## element bytes before decode (see fs_snoop).
  encodeDepRecordWithSeq(record, buf, 0'u64, applyIdentityScope = true)

proc decodeDepRecord*(buf: openArray[byte]; ok: var bool): MonitorRecord =
  ## Decode a record produced by `encodeDepRecord`. `ok` is false on any
  ## malformed / truncated buffer (the consumer then drops that slot — it can
  ## never corrupt the depfile because the file fallback still carries the
  ## record's authoritative copy on any oversize/failure path).
  ok = false
  if buf.len < DepFixedHeaderLen:
    return
  var pos = 0
  let kindOrd = getU16(buf, pos)
  let obsOrd = getU16(buf, pos)
  if kindOrd.int < ord(low(MonitorRecordKind)) or
      kindOrd.int > ord(high(MonitorRecordKind)):
    return
  if obsOrd.int < ord(low(MonitorObservationKind)) or
      obsOrd.int > ord(high(MonitorObservationKind)):
    return
  result.kind = MonitorRecordKind(kindOrd.int)
  result.observationKind = MonitorObservationKind(obsOrd.int)
  result.seq = getU64(buf, pos)
  result.osPid = getU64(buf, pos)
  result.parentOsPid = getU64(buf, pos)
  result.threadId = getU64(buf, pos)
  result.childOsPid = getU64(buf, pos)
  result.result = cast[int64](getU64(buf, pos))
  result.flags = getU32(buf, pos)
  let probeOrd = getU32(buf, pos)
  if probeOrd.int > ord(high(ProbeResult)):
    return
  result.probeResult = ProbeResult(probeOrd.int)
  var pathLen: uint64
  if not getVarint(buf, pos, pathLen):
    return
  if pos + int(pathLen) > buf.len:
    return
  if pathLen > 0:
    result.path = newString(int(pathLen))
    for i in 0 ..< int(pathLen):
      result.path[i] = char(buf[pos + i])
    pos += int(pathLen)
  var detailLen: uint64
  if not getVarint(buf, pos, detailLen):
    return
  if pos + int(detailLen) > buf.len:
    return
  if detailLen > 0:
    result.detail = newString(int(detailLen))
    for i in 0 ..< int(detailLen):
      result.detail[i] = char(buf[pos + i])
    pos += int(detailLen)
  ok = true
