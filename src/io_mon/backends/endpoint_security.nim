## EndpointSecurity (ES) monitoring backend — DESIGN SKELETON (T3c).
##
## STATUS: this is a DESIGN STUB, not a working backend. It compiles, defines the
## backend interface and the ES-event → io-mon-record mapping as pure, testable
## Nim, and gates the entitlement-restricted `<EndpointSecurity/EndpointSecurity.h>`
## calls behind the OFF-BY-DEFAULT `-d:ioMonEndpointSecurity` define so the normal
## io-mon build (and the shipped shim) are completely unaffected. It is NOT wired
## into the live shim and MUST NOT be presented as functional.
##
## WHY ES (the residual gap after T0–T3b):
##   The interpose + body-patch backend (`io_mon/hooks/macos_interpose_runtime`,
##   `macos_bodypatch`) is IN-PROCESS. It fundamentally cannot observe a file op
##   that bypasses libSystem entirely — a raw `svc #0x80` trap or an indirect
##   `syscall(SYS_open, …)` — because there is no userspace call site to interpose
##   or body-patch (adversarial-hardening break #6). Nor can it see XPC/Mach-port
##   brokered IPC (only socket `connect(2)` is hooked, per T3a). ES is
##   KERNEL-SOURCED: the kernel emits `ES_EVENT_TYPE_NOTIFY_OPEN/CLOSE/CREATE/
##   WRITE/RENAME/LINK/CLONE/EXEC/FORK/…` for EVERY process's REAL file activity,
##   including direct-syscall, shared-cache-internal, and SIP/hardened processes
##   that strip dyld injection. ES is therefore the complete-coverage macOS
##   "endgame" backend for macOS monitoring.
##
## HONEST GATE (proven on this host, macOS 26.3.1, see the design doc):
##   - A minimal C ES client compiles against the present SDK but
##     `es_new_client()` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED` without
##     root, and an ad-hoc binary carrying the restricted
##     `com.apple.developer.endpoint-security.client` entitlement is SIGKILLed by
##     AMFI at exec. The production backend therefore requires the Apple-granted
##     entitlement (provisioning profile) + Developer-ID signing + notarization +
##     root + macOS 10.15+. None of those are available on a dev machine, so this
##     phase ships design + feasibility + this skeleton only.
##
## References:
##   - The backend contract this skeleton fills in: every monitoring backend
##     (this kernel-sourced one, the interpose shim) produces the same
##     dependency-evidence records, so the consumer's path-set and policy
##     model does not depend on which backend observed an action.
##   - Apple ES docs: https://developer.apple.com/documentation/endpointsecurity
##   - BuildXL's lossy-ES prior art (cross-platform.md / ESClient.mm) — ES can
##     DROP events under load; a detected drop MUST conservatively invalidate.

import std/[hashes, strutils, tables]

import io_mon/types

type
  EsRecordSink* = proc(record: MonitorRecord) {.closure, gcsafe.}
    ## Where mapped records are delivered. In the live integration this would
    ## route into the SAME iomon fragment store the interpose runtime uses
    ## (`appendFragmentRecord` / `mergeFragments`), so ES-sourced records flow
    ## through the identical completeness machinery (`summarizeRecords` →
    ## `depFileFromRecords`). Kept as an injected callback here for low coupling
    ## and unit-testability — the skeleton never touches the live shim.

  EsStartResult* = object
    ## Outcome of attempting to start the ES backend. The production backend
    ## fails CLOSED and LOUDLY: an unavailable ES client is never silently
    ## downgraded to "no monitoring", because that would risk a false cache hit.
    ok*: bool
    reason*: string
      ## Human-readable reason when `ok` is false (e.g. the `es_new_client`
      ## result name, or "not compiled with -d:ioMonEndpointSecurity").

  EsAuditToken* = object
    ## Process identity as ES reports it: the `audit_token_t` of an
    ## `es_process_t`, reduced to the two fields that identify a process
    ## instance — the pid and its pidversion (`audit_token_to_pid`,
    ## `audit_token_to_pidversion`). A bare pid wraps and is reused; the pair is
    ## not, so a process that inherits a member's pid is a DIFFERENT key
    ## (MacOS-EndpointSecurity-Backend.md §4, "Identity is the audit token, not
    ## the pid").
    pid*: uint64
    pidversion*: uint32

  EsMemberState* = enum
    esmLive    ## admitted and not yet seen to exit on this view's stream
    esmExited  ## EXIT delivered; kept until the capture is fenced (§5.1)

  EsFilterVerdict* = enum
    efAdmit   ## the process is a member: map and deliver the event now
    efReject  ## not in the subtree: drop the event
    efHold    ## unknown on this view's lifecycle stream: held until resolved

  EsProcessTree* = object
    ## Process-subtree VIEW. ES is SYSTEM-GLOBAL — it delivers events for every
    ## process on the host — and orders messages within ONE client only. A
    ## build monitor keeps only the events of the build's own subtree, and it
    ## filters each client's file events against a view built from lifecycle
    ## events (FORK, EXEC, EXIT) delivered on that SAME client
    ## (`holdUnknown = false`). A topology that cannot do that filters against
    ## another client's view with `holdUnknown = true`: an event of a process
    ## the view does not yet know is held, not rejected, until a FORK/EXEC on
    ## the lifecycle stream admits its token or the fence (§5.1) proves it is
    ## out of the tree.
    ##
    ## Seeded with the token of a monitor-owned spawn helper BEFORE the helper
    ## forks the action root; the root is then admitted by its own FORK.
    ## Members are keyed on the audit token and kept after EXIT (as exited)
    ## until the capture is fenced, so the fence can require that every member
    ## has exited, and a later process that reuses a member's pid is never
    ## admitted by accident (MacOS-EndpointSecurity-Backend.md §4, §5.1).
    members*: Table[EsAuditToken, EsMemberState]
    preExec*: Table[EsAuditToken, EsAuditToken]
      ## post-exec token → the token the process ran under before that exec,
      ## so an EXIT (which names the post-exec token) also finishes the
      ## pre-exec token it was admitted under.
    holdUnknown*: bool
    held*: Table[EsAuditToken, seq[MonitorRecord]]
      ## Records whose process this view did not yet know when they arrived,
      ## per token in arrival order. Only a view built from ANOTHER client's
      ## lifecycle stream holds (§4, the hold-until-resolved rule); a
      ## same-client view rejects. Keyed so an admission releases its own
      ## token's records without scanning every unknown process on the host.
    fenced*: bool
      ## Set by `closeAtFence`. A fenced view is closed: it admits nothing new
      ## and rejects every further event.

  EsSeqTracker* = object
    ## Event-loss detector. Each `es_message_t` carries a monotonic `seq_num`
    ## (per event TYPE, per client) and a `global_seq_num` (per client, across all
    ## types). A GAP in either sequence means the kernel DROPPED messages because
    ## the client could not keep up — ES is lossy under high probe volume, exactly
    ## the failure mode that made BuildXL's ES prototype "too lossy for high-volume
    ## absent-file probes". A detected gap
    ## MUST be mapped to `mrEventLoss` → `mcIncomplete` (a conservative re-run),
    ## consistent with the T0 earned-completeness contract.
    lastGlobalSeq*: uint64
    seen*: bool
    droppedEvents*: uint64

  EsBackend* = object
    ## The ES backend instance. The live ES client handle lives behind
    ## `-d:ioMonEndpointSecurity`; in the default build only the pure
    ## bookkeeping (tree + seq tracker + sink) exists, so the module compiles and
    ## the mapping is unit-testable without the entitlement.
    tree*: EsProcessTree
      ## The single-client topology's one view. A partitioned topology keeps
      ## one `EsProcessTree` and one `EsSeqTracker` per client.
    seqTracker*: EsSeqTracker
    sink*: EsRecordSink
    started*: bool

# ---------------------------------------------------------------------------
# Process-subtree filtering (pure; testable without ES).
# ---------------------------------------------------------------------------

proc hash*(t: EsAuditToken): Hash =
  !$(hash(t.pid) !& hash(t.pidversion))

proc `$`*(t: EsAuditToken): string =
  $t.pid & "/" & $t.pidversion

proc initEsProcessTree*(helperToken: EsAuditToken;
                        holdUnknown = false): EsProcessTree =
  ## Seed one subtree view with the audit token of the monitor-owned spawn
  ## helper. The monitor seeds EVERY client's view with it before releasing the
  ## helper to fork the action root; the root's FORK then arrives on each
  ## client's stream and admits it (`onFork`). The root's own token cannot be
  ## seeded race-free: it is known only after the spawn, by which time the root
  ## may already have forked or opened files, and an exec changes it.
  ## `holdUnknown` selects the hold-until-resolved rule for a view that filters
  ## another client's events (see `EsProcessTree`).
  result.members = initTable[EsAuditToken, EsMemberState]()
  result.preExec = initTable[EsAuditToken, EsAuditToken]()
  result.held = initTable[EsAuditToken, seq[MonitorRecord]]()
  result.holdUnknown = holdUnknown
  result.members[helperToken] = esmLive

proc inSubtree*(tree: EsProcessTree; token: EsAuditToken): bool =
  ## True iff the process with this audit token belongs to the monitored
  ## subtree (live, or exited and not yet fenced). Another process holding the
  ## same pid with a different pidversion is NOT a member. A fenced view is
  ## closed and answers false for every token, as `filterEvent` rejects them.
  not tree.fenced and token in tree.members

proc isLive*(tree: EsProcessTree; token: EsAuditToken): bool =
  ## True iff `token` is a member whose EXIT this view has not yet seen.
  tree.members.getOrDefault(token, esmExited) == esmLive

proc liveMembers*(tree: EsProcessTree): seq[EsAuditToken] =
  ## Members not yet seen to exit on this view's stream.
  for token, state in tree.members:
    if state == esmLive:
      result.add token

proc allMembersExited*(tree: EsProcessTree): bool =
  ## The fence's precondition (§5.1 step 1): every admitted member has a
  ## delivered EXIT on this view's stream.
  tree.liveMembers.len == 0

proc heldCount*(tree: EsProcessTree): int =
  ## Number of records currently held, across all unresolved tokens.
  for records in tree.held.values:
    result += records.len

proc releaseHeld(tree: var EsProcessTree; token: EsAuditToken): seq[MonitorRecord] =
  ## Hand back, in arrival order, the held records of a token just admitted;
  ## every other token's records stay held.
  if tree.held.pop(token, result):
    discard

proc admit(tree: var EsProcessTree; token: EsAuditToken): seq[MonitorRecord] =
  ## An exited member is not revived: an audit token names one process
  ## instance and is never reused, so a second admission of it is a no-op.
  if token notin tree.members:
    tree.members[token] = esmLive
  tree.releaseHeld(token)

proc onFork*(tree: var EsProcessTree;
             parent, child: EsAuditToken): seq[MonitorRecord] =
  ## ES_EVENT_TYPE_NOTIFY_FORK: admit the child's token (`event.fork.child`)
  ## iff the parent (the message's `process`) is already a member. Returns the
  ## child's held events, now admitted, for the caller to map and deliver
  ## (always empty on a same-client view, which never holds).
  if parent in tree.members and not tree.fenced:
    result = tree.admit(child)

proc onExec*(tree: var EsProcessTree;
             process, target: EsAuditToken): seq[MonitorRecord] =
  ## ES_EVENT_TYPE_NOTIFY_EXEC: if the message's `process` is a member, admit
  ## the token of `event.exec.target` as well. The exec keeps the pid, but its
  ## token need not be the pre-exec one; keeping only the pre-exec token would
  ## lose the post-exec image (the hardened/SIP-binary exec injection cannot
  ## follow). Returns the target's held events, now admitted.
  if process in tree.members and not tree.fenced:
    if target != process:
      tree.preExec[target] = process
    result = tree.admit(target)

proc onExit*(tree: var EsProcessTree; token: EsAuditToken) =
  ## ES_EVENT_TYPE_NOTIFY_EXIT: the member is finished. Its token, and every
  ## pre-exec token it was admitted under, are marked exited but KEPT until the
  ## fence, which needs to know that every member has exited. A later process
  ## reusing the pid has a different token and is never admitted by accident.
  ## The walk runs post-exec → pre-exec only, because ES names a process's
  ## current (post-exec) token on its EXIT. An EXIT naming a superseded token
  ## leaves the later token live, which the fence reports as a loss: the safe
  ## direction. The step bound guards a cyclic `preExec` chain.
  var t = token
  var steps = 0
  while t in tree.members and steps <= tree.preExec.len:
    tree.members[t] = esmExited
    if t notin tree.preExec:
      break
    t = tree.preExec[t]
    inc steps

proc filterEvent*(tree: var EsProcessTree; token: EsAuditToken;
                  record: MonitorRecord): EsFilterVerdict =
  ## Decide one file event before it is mapped. A member's event is admitted.
  ## On a same-client view an unknown token is rejected: one client's stream
  ## is ordered, so the FORK/EXEC that would admit it has already been seen. On
  ## a view built from another client's stream (`holdUnknown`) an unknown token
  ## is HELD — rejecting it would lose it with no sequence gap to report it —
  ## until `onFork`/`onExec` admits it or `closeAtFence` discards it. A fenced
  ## view is closed and rejects every event.
  if tree.fenced:
    efReject
  elif token in tree.members:
    efAdmit
  elif tree.holdUnknown:
    tree.held.mgetOrPut(token, @[]).add record
    efHold
  else:
    efReject

proc fenceLossRecord(detail: string): MonitorRecord =
  MonitorRecord(kind: mrEventLoss, observationKind: moEventLoss,
    detail: "endpoint-security end-of-capture fence: " & detail)

proc closeAtFence*(tree: var EsProcessTree;
                   markerDelivered: bool): seq[MonitorRecord] =
  ## Close this view at the end-of-capture fence (§5.1) and return the loss
  ## records the capture must carry; empty means the view closed complete.
  ##   - A member still live (no delivered EXIT once the grace has ended, e.g. a
  ##     daemonized compiler server) makes the capture incomplete: its later
  ##     events, and a fork it makes after the marker, could not be captured.
  ##   - A client that did not deliver the marker within its bounded wait makes
  ##     the capture incomplete; it is never finalized as complete.
  ## Pass `markerDelivered = true` only when every client this view depends on
  ## delivered its marker: the client whose file events it filters and, for a
  ## `holdUnknown` view, also the client whose lifecycle stream it is built
  ## from.
  ## Loss BEFORE the marker is reported by `observeSeq` as a forward
  ## `global_seq_num` gap at the marker at the latest. Held events whose token
  ## is still unknown are out of the tree and are discarded: the fence follows
  ## the exit of every member, so no admission can still precede them. The view
  ## is closed afterwards; a second call returns nothing.
  if tree.fenced:
    return
  let live = tree.liveMembers
  if live.len > 0:
    var names: seq[string]
    for t in live:
      names.add $t
    result.add fenceLossRecord($live.len &
      " subtree member(s) still live at the fence (pid/pidversion " &
      names.join(", ") & ") — their later events cannot be captured")
  if not markerDelivered:
    result.add fenceLossRecord(
      "the marker event was not delivered within the bounded wait — " &
      "events before it may be lost")
  tree.held.clear()
  tree.fenced = true

# ---------------------------------------------------------------------------
# Event-loss detection (pure; testable without ES).
# ---------------------------------------------------------------------------

proc observeSeq*(tracker: var EsSeqTracker; globalSeq: uint64): uint64 =
  ## Feed the `global_seq_num` of the next received message. Returns the number
  ## of DROPPED messages implied by a forward gap (0 when contiguous). The caller
  ## emits one `mrEventLoss` per drop (or one aggregate loss record) so the depfile
  ## downgrades to `mcIncomplete`. A non-increasing seq (duplicate/reorder) yields
  ## 0 — only a forward jump signals loss.
  result = 0
  if tracker.seen and globalSeq > tracker.lastGlobalSeq + 1:
    result = globalSeq - tracker.lastGlobalSeq - 1
    tracker.droppedEvents += result
  if not tracker.seen or globalSeq > tracker.lastGlobalSeq:
    tracker.lastGlobalSeq = globalSeq
    tracker.seen = true

proc eventLossRecord*(droppedCount: uint64): MonitorRecord =
  ## Build the synthetic event-loss record for an ES drop. Mirrors the
  ## corrupt-fragment / unmonitored-subtree loss records in `writer.mergeFragments`
  ## so ES loss flows through the IDENTICAL `summarizeRecords` → `mcIncomplete`
  ## path — there is exactly one completeness mechanism in io-mon.
  MonitorRecord(
    kind: mrEventLoss,
    observationKind: moEventLoss,
    detail: "endpoint-security dropped " & $droppedCount &
      " message(s) (global_seq_num gap) — backend overran; invalidating scope")

# ---------------------------------------------------------------------------
# ES event → io-mon record mapping (pure; the heart of the backend).
#
# These take PLAIN fields (not `es_message_t`) so the mapping is fully testable
# without the SDK or the entitlement. Under `-d:ioMonEndpointSecurity` the live
# message handler extracts these fields from the `es_message_t` union and calls
# the matching builder. Records reuse the EXISTING iomon record/observation kinds
# (no new wire-format enum cases), so the codec, reader, and every consumer keep
# working unchanged — ES is just another SOURCE feeding the same record model.
# ---------------------------------------------------------------------------

const
  # open(2)/openat(2) flag bits (Darwin <fcntl.h>); duplicated here so the pure
  # classifier needs no headers. These match `observationForOpen` in the
  # interpose runtime, keeping read-vs-write classification IDENTICAL across
  # backends.
  EsOAccMode = 0x0003'u32
  EsOWrOnly = 0x0001'u32
  EsORdWr = 0x0002'u32
  EsOCreat = 0x0200'u32
  EsOTrunc = 0x0400'u32
  EsOAppend = 0x0008'u32

proc classifyOpenFlags*(flags: uint32): MonitorObservationKind =
  ## Read-vs-write classification for `ES_EVENT_TYPE_NOTIFY_OPEN`, identical to
  ## the interpose runtime's `observationForOpen`: any create/truncate/append or
  ## a writable access mode is a WRITE; a pure read-only open is a content READ
  ## (recorded as `moFileOpen`, the read-dependency observation).
  if (flags and (EsOCreat or EsOTrunc or EsOAppend)) != 0:
    moFileWrite
  else:
    let acc = flags and EsOAccMode
    if acc == EsOWrOnly or acc == EsORdWr:
      moFileWrite
    else:
      moFileOpen

proc esBaseRecord(kind: MonitorRecordKind; obs: MonitorObservationKind;
                  pid, ppid: uint64): MonitorRecord =
  MonitorRecord(kind: kind, observationKind: obs, osPid: pid, parentOsPid: ppid)

proc esOpenRecord*(pid, ppid: uint64; path: string; flags: uint32): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_OPEN → file-open/read or file-write by access mode.
  ## This is the record that closes break #6: even a raw-`svc` `open` the
  ## in-process hooks NEVER saw produces this kernel-sourced record.
  result = esBaseRecord(mrFileOpen, classifyOpenFlags(flags), pid, ppid)
  result.path = path

proc esReadRecord*(pid, ppid: uint64; path: string): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_READ-style content read (also covers a read implied by
  ## CLONE source / COPYFILE). Recorded as a genuine read dependency.
  result = esBaseRecord(mrFileRead, moFileRead, pid, ppid)
  result.path = path

proc esWriteRecord*(pid, ppid: uint64; path: string): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_WRITE / CREATE / TRUNCATE → output write.
  result = esBaseRecord(mrFileWrite, moFileWrite, pid, ppid)
  result.path = path

proc esCreateRecord*(pid, ppid: uint64; path: string): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_CREATE → a newly-created output file.
  result = esBaseRecord(mrFileWrite, moFileWrite, pid, ppid)
  result.path = path
  result.detail = "es-create"

proc esRenameRecord*(pid, ppid: uint64; destPath: string): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_RENAME → the DESTINATION is the produced output (the
  ## gnulib/autotools `mv $@t $@` atomic-output move), matching the interpose
  ## rename hook's semantics.
  result = esBaseRecord(mrFileWrite, moFileWrite, pid, ppid)
  result.path = destPath
  result.detail = "es-rename-dest"

proc esLinkRecord*(pid, ppid: uint64; sourcePath: string): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_LINK → a hardlink consumes the SOURCE's content
  ## (adversarial break #3) → record the source as a read dependency.
  result = esBaseRecord(mrFileRead, moFileRead, pid, ppid)
  result.path = sourcePath
  result.detail = "es-link-source"

proc esCloneRecord*(pid, ppid: uint64; sourcePath: string): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_CLONE (clonefile/copyfile-CLONE) → CoW copy consumes
  ## the SOURCE content (break #3) → record the source as a read dependency.
  result = esBaseRecord(mrFileRead, moFileRead, pid, ppid)
  result.path = sourcePath
  result.detail = "es-clone-source"

proc esLookupRecord*(pid, ppid: uint64; path: string;
                     existed: bool): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_LOOKUP → an existence/metadata PROBE (break #5's
  ## getattrlist family arrives here too). Absent-path probes must be recorded
  ## faithfully, and ES sees them natively. NOTE: lookups are extremely
  ## high-volume — this is the exact probe storm BuildXL found ES too lossy for,
  ## so the loss detector above is load-bearing here.
  result = esBaseRecord(mrPathProbe, moPathProbe, pid, ppid)
  result.path = path
  result.probeResult = if existed: prExistingFile else: prAbsent

proc esExecRecord*(pid, ppid: uint64; imagePath: string): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_EXEC → process-exec. Unlike the interpose backend, ES
  ## sees the exec EVEN WHEN the target is a hardened/notarized binary that
  ## strips injection (adversarial break #2): the image becomes a real read
  ## dependency and the pid stays inside the subtree.
  result = esBaseRecord(mrProcessExec, moExecute, pid, ppid)
  result.path = imagePath

proc esForkRecord*(pid, ppid, childPid: uint64): MonitorRecord =
  ## ES_EVENT_TYPE_NOTIFY_FORK → process-spawn. ES anchors the child pid even
  ## when the child never loads the shim (break #1's spawn arm, break #2's
  ## SETEXEC arm), so the subtree is built from kernel truth, not injection.
  result = esBaseRecord(mrProcessSpawn, moProcessStart, pid, ppid)
  result.childOsPid = childPid

# ---------------------------------------------------------------------------
# Backend lifecycle.
#
# The default (no `-d:ioMonEndpointSecurity`) implementation is a pure stub: it
# compiles everywhere and refuses to start with a clear reason, so nothing can
# mistake the skeleton for a working backend. The entitlement-restricted ES
# client lives ONLY inside the `when defined(ioMonEndpointSecurity)` branch.
# ---------------------------------------------------------------------------

proc newEsBackend*(helperToken: EsAuditToken; sink: EsRecordSink): EsBackend =
  ## Construct an (un-started) ES backend whose subtree view is seeded with the
  ## monitor-owned spawn helper's audit token (§4), delivering mapped records to
  ## `sink`. Pure — no ES client is created until `start`.
  EsBackend(
    tree: initEsProcessTree(helperToken),
    seqTracker: EsSeqTracker(),
    sink: sink,
    started: false)

when defined(ioMonEndpointSecurity):
  # --- ENTITLEMENT-RESTRICTED REGION ----------------------------------------
  # Everything in this branch needs the Apple-granted
  # `com.apple.developer.endpoint-security.client` entitlement, Developer-ID
  # signing + notarization, and root to actually RUN (see the feasibility probe
  # in the design doc). It compiles only when the ES SDK is present.
  when not defined(macosx):
    {.error: "ioMonEndpointSecurity is macOS-only (requires <EndpointSecurity/EndpointSecurity.h>)".}

  {.passL: "-lEndpointSecurity".}
  {.emit: """
  #include <EndpointSecurity/EndpointSecurity.h>
  """.}

  # NOTE: the full FFI surface (es_new_client, es_subscribe, the es_message_t
  # union accessors for each event type, es_mute_path for self-muting, and the
  # dispatch-queue message pump) is intentionally NOT spelled out here — wiring
  # it is the production-backend work that is GATED on the entitlement and out of
  # scope for this design phase. The block exists so the build can be exercised
  # with `-d:ioMonEndpointSecurity` against a real SDK and so the integration
  # seam is unambiguous. The handler would, per received `es_message_t`, on
  # the view and tracker of the CLIENT that delivered it:
  #   1. call `observeSeq(tracker, msg->global_seq_num)` and, on a non-zero
  #      return, `backend.sink(eventLossRecord(dropped))`;
  #   2. fold FORK/EXEC/EXIT into that client's view (`onFork`, `onExec`,
  #      `onExit`), keyed on `msg->process->audit_token` and
  #      `event.fork.child` / `event.exec.target` tokens — never the bare pid —
  #      mapping and sinking any held records they release;
  #   3. for a file event, build the record with the `es*Record` builder that
  #      matches `msg->event_type`, then `filterEvent(view,
  #      msg->process->audit_token, record)` and sink it only on `efAdmit`.
  # Before the capture is finalized: wait (bounded) for `allMembersExited` on
  # every view, run the marker, wait per client for its marker event, then
  # `closeAtFence` each view and sink the loss records it returns (§5.1).
  proc startEsClient(backend: var EsBackend): EsStartResult =
    ## PLACEHOLDER for the real `es_new_client`/`es_subscribe` start path. Kept as
    ## an explicit stub so an accidental enable of the define does not masquerade
    ## as a functioning backend. The real implementation returns the mapped
    ## `es_new_client_result_t` (e.g. ERR_NOT_PRIVILEGED / ERR_NOT_ENTITLED) on
    ## failure — fail-closed.
    EsStartResult(ok: false,
      reason: "ES client start not implemented in the T3c skeleton — " &
        "production backend is gated on the endpoint-security.client entitlement")

proc start*(backend: var EsBackend): EsStartResult =
  ## Start the ES backend. In the default build this always fails with a clear
  ## reason (the backend is a design stub). Under `-d:ioMonEndpointSecurity` it
  ## delegates to the entitlement-restricted ES client start.
  when defined(ioMonEndpointSecurity):
    result = startEsClient(backend)
    backend.started = result.ok
  else:
    backend.started = false
    result = EsStartResult(ok: false,
      reason: "io-mon EndpointSecurity backend is a design skeleton (T3c); " &
        "rebuild with -d:ioMonEndpointSecurity and the Apple-granted " &
        "endpoint-security.client entitlement + root to enable it")

proc stop*(backend: var EsBackend) =
  ## Stop the backend and release the ES client (a no-op for the default stub).
  ## The production path calls `es_unsubscribe_all` + `es_delete_client`.
  backend.started = false
