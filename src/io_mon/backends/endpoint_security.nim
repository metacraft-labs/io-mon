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
##   "endgame" backend the project already names (MacOS-Monitoring.md).
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
##   - reprobuild-specs/MacOS-EndpointSecurity-Backend.md (the full design).
##   - reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org §T3c.
##   - reprobuild-specs/Monitoring-Backend-Abstraction.md (the backend contract).
##   - Apple ES docs: https://developer.apple.com/documentation/endpointsecurity
##   - BuildXL's lossy-ES prior art (cross-platform.md / ESClient.mm) — ES can
##     DROP events under load; a detected drop MUST conservatively invalidate.

import std/sets

import io_mon/types

type
  EsRecordSink* = proc(record: MonitorRecord) {.closure, gcsafe.}
    ## Where mapped records are delivered. In the live integration this would
    ## route into the SAME RMDF fragment store the interpose runtime uses
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

  EsProcessTree* = object
    ## Process-subtree filter. ES is SYSTEM-GLOBAL — it delivers events for every
    ## process on the host. A build monitor must keep ONLY the events for the
    ## build's own process subtree (the monitored root pid + its transitive
    ## descendants), discarding the rest. The tree is seeded with the root pid and
    ## grows as `ES_EVENT_TYPE_NOTIFY_FORK`/`EXEC` events name new children whose
    ## parent is already a member. (EXEC keeps the same pid; FORK introduces a new
    ## child pid — both must be folded in before that pid's file events arrive,
    ## which the kernel ordering guarantees: a child's events follow its FORK.)
    members*: HashSet[uint64]

  EsSeqTracker* = object
    ## Event-loss detector. Each `es_message_t` carries a monotonic `seq_num`
    ## (per event TYPE, per client) and a `global_seq_num` (per client, across all
    ## types). A GAP in either sequence means the kernel DROPPED messages because
    ## the client could not keep up — ES is lossy under high probe volume, exactly
    ## the failure mode that made BuildXL's ES prototype "too lossy for high-volume
    ## absent-file probes" (MacOS-Monitoring.md §BuildXL Lessons). A detected gap
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
    seqTracker*: EsSeqTracker
    sink*: EsRecordSink
    started*: bool

# ---------------------------------------------------------------------------
# Process-subtree filtering (pure; testable without ES).
# ---------------------------------------------------------------------------

proc initEsProcessTree*(rootPid: uint64): EsProcessTree =
  ## Seed the monitored subtree with the build's root pid.
  result.members = initHashSet[uint64]()
  if rootPid != 0:
    result.members.incl rootPid

proc inSubtree*(tree: EsProcessTree; pid: uint64): bool =
  ## True iff `pid` belongs to the monitored build subtree. Events for any other
  ## pid (the rest of the system ES also reports) are dropped.
  pid in tree.members

proc onFork*(tree: var EsProcessTree; parentPid, childPid: uint64) =
  ## Fold a forked child into the subtree iff its parent is already monitored.
  ## ES delivers the child's own events only AFTER its FORK, so this admission
  ## happens in time (kernel-ordered per process).
  if parentPid in tree.members and childPid != 0:
    tree.members.incl childPid

proc onExec*(tree: var EsProcessTree; pid: uint64) =
  ## EXEC replaces the image but keeps the pid, so a pid already in the subtree
  ## stays in it across exec (including an exec into a hardened/SIP binary — the
  ## key win over injection, which such a binary strips). Idempotent.
  if pid != 0:
    tree.members.incl pid

proc onExit*(tree: var EsProcessTree; pid: uint64) =
  ## Drop an exited pid. Retained for completeness; pid reuse within a single
  ## short-lived build is unlikely, but removing the entry avoids a stale match
  ## if the OS recycles the pid for an out-of-tree process later in the build.
  tree.members.excl pid

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
# the matching builder. Records reuse the EXISTING RMDF record/observation kinds
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
  ## getattrlist family arrives here too). Absent-path probe fidelity is one of
  ## the validation criteria (MacOS-Monitoring.md §Validation Criteria); ES sees
  ## these natively. NOTE: lookups are extremely high-volume — this is the exact
  ## probe storm BuildXL found ES too lossy for, so the loss detector above is
  ## load-bearing here.
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

proc newEsBackend*(rootPid: uint64; sink: EsRecordSink): EsBackend =
  ## Construct an (un-started) ES backend rooted at `rootPid`, delivering mapped
  ## records to `sink`. Pure — no ES client is created until `start`.
  EsBackend(
    tree: initEsProcessTree(rootPid),
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
  # seam is unambiguous. The handler would, per received `es_message_t`:
  #   1. fold FORK/EXEC into `backend.tree` (process-subtree filter);
  #   2. drop the message unless `inSubtree(backend.tree, msg.process->audit_token pid)`;
  #   3. call `observeSeq(backend.seqTracker, msg->global_seq_num)` and, on a
  #      non-zero return, `backend.sink(eventLossRecord(dropped))`;
  #   4. dispatch on `msg->event_type` to the matching `es*Record` builder and
  #      `backend.sink(...)` the result.
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
