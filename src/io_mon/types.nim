import std/[options]

type
  MonitorRecordKind* = enum
    mrProcessStart = 1
    mrProcessExec = 2
    mrProcessSpawn = 3
    mrFileOpen = 4
    mrFileRead = 5
    mrPathProbe = 6
    mrFileWrite = 7
    mrEventLoss = 8
    mrDirectoryEnumerate = 9
    mrBackendProfile = 10
    mrCapabilityGap = 11
    # T3a (Phase 2 / findings-doc break #1): a `connect(2)` (or connectionless
    # `sendmsg`/`sendto`) to an AF_UNIX / AF_INET(6) peer. APPENDED AT THE END to
    # preserve RMDF wire-compat (the dgNoRuntimeDependencies lesson — never
    # renumber an existing enum case). Carries the destination in `path` and the
    # PEER PID in `childOsPid` (AF_UNIX via LOCAL_PEERPID; 0 when unobtainable).
    mrIpcConnect = 12
    # T3b (Phase 3 / findings-doc break #4 + the dlopen arm of #7): a DEPENDENT
    # DYLIB (or dlopen'd image) that dyld mapped via low-level kernel mmap,
    # BYPASSING every hooked `open`/`openat`. A real clang/ld64 link loads ~620
    # toolchain dylibs (libLLVM, libclang-cpp, …) that NEVER pass through the
    # hooked open, so without this they were recorded NOWHERE — a content-addressed
    # cache fingerprinting only the depfile would then serve a STALE result after
    # an in-place compiler-library upgrade. Captured via the `_dyld` add-image
    # callback (NOT by hooking open). APPENDED AT THE END to preserve RMDF
    # wire-compat (the dgNoRuntimeDependencies / mrIpcConnect lesson — never
    # renumber an existing case). The path is the dylib's REAL on-disk path; the
    # `observationKind` is deliberately `moFileRead` so the dylib is treated as a
    # genuine CONTENT (read) dependency by every consumer that keys on the
    # observation kind — directly closing the stale-cache hole. The distinct record
    # kind keeps a library-load identifiable for inspection + the no-flooding tests.
    mrLibraryLoad = 13
    # ROUND-2 R-D (findings-doc break R10): NON-FILE INPUT OBSERVATIONS — things a
    # build's output may depend on that are NOT file reads, so a depfile-only
    # fingerprint can false-cache-hit when they change. io-mon records evidence
    # only; callers decide whether a given observation invalidates their cache key.
    # All four APPENDED AT THE END for RMDF wire-compat (never renumber).
    #
    # 1. mrEnvRead / mrSysctlRead — OBSERVED DECLARED INPUTS (record, do NOT
    #    downgrade). The shim hooks getenv / sysctlbyname / sysctl / uname /
    #    gethostname / gethostuuid and records the NAME queried (the env-var name in
    #    `path` for mrEnvRead; the sysctl/uname source in `path` for mrSysctlRead),
    #    DEDUPED per-process. This is BuildXL's "observed environment" model: the
    #    CONSUMER folds the queried env vars'/sysctls' VALUES into its cache key, so
    #    a build that read SOURCE_DATE_EPOCH / $CFLAGS / hw.ncpu / uname re-runs iff
    #    that value changed — PRECISE, with NO false downgrade (a program that reads
    #    PATH benignly just adds PATH to the key; unchanged ⇒ no re-run). These
    #    NEVER downgrade completeness. See the consumer contract in the R-D design
    #    note (MacOS-Monitoring-Adversarial-Hardening.milestones.org §R-D).
    mrEnvRead = 14
    mrSysctlRead = 15
    # 2. mrNonDeterministic — OBSERVED ENTROPY INPUT, GATED BY CALLER ATTRIBUTION.
    #    The shim hooks getentropy / arc4random / arc4random_buf /
    #    arc4random_uniform and emits this record ONLY when the call's CALLER lies
    #    in the monitored program's OWN main-executable __TEXT range (`path` names
    #    the source). This does NOT force `mcIncomplete`: io-mon monitored the
    #    entropy read successfully, and caller policy decides whether that evidence
    #    invalidates the build/cache result.
    #    CALLER ATTRIBUTION IS ESSENTIAL (a round-1 cardinal-sin defect): an
    #    interpose hook is NOT limited to the program's own calls — on every process
    #    startup /usr/lib/libobjc, /usr/lib/swift, libsystem_malloc/_trace call
    #    arc4random_buf and libcorecrypto calls getentropy, all CROSS-DYLIB (so they
    #    cross the interpose stub). Flagging those downgraded EVERY real cc/clang/ld/
    #    bash run (the cardinal sin); attributing to the program's main-exe __TEXT
    #    excludes the /usr/lib baseline. A /dev/random or /dev/urandom OPEN is
    #    DELIBERATELY NOT flagged (mktemp opens /dev/urandom for a random temp name on
    #    essentially every build). See `nonDeterminismObservationCount`
    #    (writer.nim) and
    #    `ct_macos_addr_in_program`.
    mrNonDeterministic = 16
    # 3. mrTimeRead — RECORD but do NOT auto-downgrade (high benign false-positive).
    #    The shim hooks clock_gettime / gettimeofday / time / mach_absolute_time and
    #    records a marker (`path` names the clock source), DEDUPED per-process.
    #    ALMOST EVERY program calls these to TIME a loop / measure latency — values
    #    that never reach the output — so auto-downgrading on a time call would
    #    re-run EVERYTHING (the cardinal sin). We therefore record-not-downgrade: a
    #    consumer/build CAN choose to act on it and it aids diagnostics, but it sets
    #    NO non-determinism flag. HONEST LIMITATION: a time-dependent OUTPUT (a tool
    #    baking `__DATE__`) is the build's responsibility to declare or to drive via
    #    SOURCE_DATE_EPOCH (which, being an env read, IS now an observed input).
    mrTimeRead = 17
    # ROUND-3 S1 (content-channel hooks) — a CONTENT CHANNEL whose in-tree
    # provenance must be decided AT MERGE TIME, because the cardinal-sin guard for
    # it is cross-process: a POSIX shm object / FIFO created+consumed ENTIRELY
    # within the monitored tree is fine (no downgrade), but one fed by an
    # OUT-OF-TREE producer is an invisible content dependency that must downgrade.
    # The shim emits one of these to DESCRIBE a channel event; the merge
    # (`externalContentLossCount`) pairs the create/write side against the
    # attach/read side and injects an event-loss ONLY for an unpaired (out-of-tree)
    # consume — the SAME conservative-re-run machinery as the IPC-breakaway /
    # un-injected-subtree downgrade. APPENDED AT THE END to preserve RMDF
    # wire-compat (the dgNoRuntimeDependencies / mrIpcConnect / mrLibraryLoad lesson
    # — never renumber an existing case). The channel identity (shm name / FIFO
    # path / "" for an anonymous socket/pipe) is in `path`; `detail` carries a
    # `chan=<shm|fifo|opaque> role=<create|attach|write|read>` classification the
    # merge reads via `detailToken`. Round-3 finding S1b/S1c/S1d
    # (research/adversarial-2026-06-round3/r3_channel): an out-of-tree shm producer
    # + a monitored mmap-PROT_READ consumer, a FIFO fed by an out-of-tree writer,
    # and an inherited socket/pipe read each produced ZERO downgrade.
    mrExternalContent = 18

  MonitorObservationKind* = enum
    moProcessStart = 1
    moExecute = 2
    moFileOpen = 3
    moFileRead = 4
    moPathProbe = 5
    moFileWrite = 6
    moEventLoss = 7
    moDirectoryEnumerate = 8
    moBackendProfile = 9
    moCapabilityGap = 10
    # T3a — IPC-connect observation (appended for wire-compat, see mrIpcConnect).
    moIpcConnect = 11
    # ROUND-2 R-D — observation kinds for the non-file determinism records
    # (appended for wire-compat, see mrEnvRead/mrSysctlRead/mrNonDeterministic/
    # mrTimeRead). A consumer that keys on the observation kind treats moEnvRead /
    # moSysctlRead as OBSERVED DECLARED INPUTS (fold the value into the cache key),
    # moNonDeterministic as entropy evidence, and moTimeRead as a record-only
    # diagnostic marker. None of these is a monitoring-loss downgrade by itself.
    moEnvRead = 12
    moSysctlRead = 13
    moNonDeterministic = 14
    moTimeRead = 15
    # ROUND-3 S1 — observation kind for the content-channel record (appended for
    # wire-compat, see mrExternalContent). A consumer that keys on the observation
    # kind treats moExternalContent as a provenance marker the merge resolves; it is
    # NOT itself a read/write of a named file.
    moExternalContent = 16

  ProbeResult* = enum
    prUnknown = 0
    prAbsent = 1
    prExistingFile = 2
    prExistingDirectory = 3
    prExistingOther = 4

  MonitorCompleteness* = enum
    mcComplete
    mcIncomplete

  MonitorBackendFamily* = enum
    mbfMacosHooks
    mbfMacosEndpointSecurity
    mbfMacosHybrid
    mbfLinuxPreloadHooks
    mbfUnknown

  MonitorCapability* = enum
    mcapProcess
    mcapFileRead
    mcapFileWrite
    mcapPathProbe
    mcapDirectoryEnumerate
    mcapEventLoss
    mcapProcessTree
    mcapProcessExec
    mcapBackendProvenance
    mcapFileCreate
    mcapFileTruncate
    mcapFileAppend
    mcapEndpointSecurity
    mcapHybrid
    mcapRename
    mcapSymlink
    mcapLibraryLoad
    mcapAuthorizationEnforcement
    mcapPathMutation
    # T3a — IPC / breakaway detection: the shim hooks connect(2) and records the
    # peer (with its pid when obtainable) so the merge can prove whether a socket
    # peer is a monitored in-tree process or an out-of-tree breakaway daemon.
    mcapIpcConnect
    # ROUND-2 R-D (break R10) — non-file input observations. mcapObservedEnv covers
    # the OBSERVED-DECLARED-INPUT recording of env-var / sysctl / uname queries
    # (mrEnvRead/mrSysctlRead; the BuildXL observed-environment model). mcapNonDeterminism
    # covers entropy observations (mrNonDeterministic) plus time markers
    # (mrTimeRead). Appended at the END (the enum
    # is serialized by capabilityId STRING, so appending is wire-safe).
    mcapObservedEnv
    mcapNonDeterminism
    # ROUND-3 S1 — content-channel coverage: xattr-family metadata reads
    # (getxattr/listxattr → path-probe), POSIX shared memory (shm_open + an shm-fd
    # PROT_READ mapping → content read / out-of-tree downgrade), FIFO and inherited
    # socket/pipe content (out-of-tree → downgrade), and the sendfile/pread/readv
    # zero-copy / positioned reads (content read on the source). Appended at the END
    # (the enum is serialized by capabilityId STRING, so appending is wire-safe).
    mcapExternalContent
    # M-FW-5 — production-sensitive Linux residuals. These are intentionally
    # separate from the positive raw-syscall slices io-mon can already cover:
    # a consumer that needs adversarial/direct-syscall completeness can require
    # these IDs and receive an explicit capability gap instead of trusting a
    # default LD_PRELOAD depfile as production-complete for that threat model.
    mcapAdversarialRawSyscall
    mcapExecutableMappingLifecycle
    mcapPathIdentity

  MonitorDiagnosticLevel* = enum
    mdlInfo
    mdlWarning
    mdlError

  MonitorDiagnostic* = object
    level*: MonitorDiagnosticLevel
    message*: string

  MonitorCapabilityGap* = object
    backendFamily*: MonitorBackendFamily
    capability*: MonitorCapability
    required*: bool
    reason*: string

  MonitorBackendProfile* = object
    profileName*: string
    backendFamily*: MonitorBackendFamily
    supportedCapabilities*: set[MonitorCapability]
    requiredCapabilities*: set[MonitorCapability]
    gaps*: seq[MonitorCapabilityGap]
    evidenceComplete*: bool
    diagnostics*: seq[MonitorDiagnostic]

  MonitorRecord* = object
    kind*: MonitorRecordKind
    observationKind*: MonitorObservationKind
    seq*: uint64
    osPid*: uint64
    parentOsPid*: uint64
    threadId*: uint64
    childOsPid*: uint64
    result*: int64
    flags*: uint32
    probeResult*: ProbeResult
    path*: string
    detail*: string

  MonitorSummary* = object
    recordCount*: uint64
    processCount*: uint64
    observationCount*: uint64
    eventLossCount*: uint64

  MonitorDepFile* = object
    version*: uint16
    producerVersion*: string
    backendFamily*: MonitorBackendFamily
    requiredFeatures*: set[MonitorCapability]
    completeness*: MonitorCompleteness
    profile*: MonitorBackendProfile
    capabilityGaps*: seq[MonitorCapabilityGap]
    summary*: MonitorSummary
    records*: seq[MonitorRecord]

  MonitorDepFileReaderOptions* = object
    allowUnknownOptionalRecords*: bool
    requireTrailerChecksum*: bool
    maxPathTableBytes*: uint64
    maxObservationCount*: uint64
    streamRecords*: bool

  MonitorDepFileReaderErrorKind* = enum
    mrMissingFile
    mrBadMagic
    mrUnsupportedVersion
    mrMissingRequiredFeature
    mrTruncated
    mrChecksumMismatch
    mrRecordOrderInvalid
    mrRecordLimitExceeded
    mrSemanticValidationFailed

  MonitorDepFileReaderError* = object of CatchableError
    kind*: MonitorDepFileReaderErrorKind

  MonitorDepFileReaderResult* = object
    depFile*: Option[MonitorDepFile]
    diagnostics*: seq[MonitorDiagnostic]

  FsSnoopOutputMode* = enum
    fsoNone
    fsoText
    fsoJsonl
    fsoBinaryStream

  FsSnoopStreamItemKind* = enum
    fsiChildStdout
    fsiChildStderr
    fsiProcessStarted
    fsiProcessExited
    fsiObservation
    fsiEventLoss
    fsiDiagnostic
    fsiSummary

  FsSnoopStreamItem* = object
    kind*: FsSnoopStreamItemKind
    record*: MonitorRecord
    diagnostic*: string
    summary*: MonitorSummary

  FsSnoopRequest* = object
    command*: seq[string]
    depFilePath*: string
    eventStreamPath*: string
    streamMode*: FsSnoopOutputMode
    passthroughChildStdout*: bool
    passthroughChildStderr*: bool
    # When ``captureChildStdio`` is true, fs-snoop creates a pipe for
    # the child's stdout+stderr (merged) and drains it on its own
    # thread/poll rather than inheriting the parent's stdio. This
    # mirrors how the reprobuild engine launches monitored actions
    # (osproc.startProcess with the default pipe-captured stdio +
    # pollCompletion drain), so integration tests can reproduce the
    # build-engine-only wedges without going through repro_cli_support.
    captureChildStdio*: bool
    # Optional path to dump the captured stdio for inspection. Empty
    # means stdio is read+discarded (mimicking the engine when it
    # only cares about completion).
    captureStdioPath*: string

const
  RmdfVersion* = 1'u16
  RmdfMagic* = "RMDF"
  RmdfTrailerMagic* = "RMDT"
  ReproMonitorDepfileProducer* = "repro_monitor_depfile_m11"

proc defaultMonitorDepFileReaderOptions*(): MonitorDepFileReaderOptions =
  MonitorDepFileReaderOptions(
    allowUnknownOptionalRecords: false,
    requireTrailerChecksum: true,
    maxPathTableBytes: 64'u64 * 1024'u64 * 1024'u64,
    # M9.R.15a.8 — qt6-base cmake configure produces > 10M file
    # observations when fs-snoop captures every probe under the
    # 50+-entry WSL-inherited Windows PATH (each ``find_program()``
    # call multiplies). Bumping to 100M unblocks the qt6-base configure
    # action. The reader-side observation array is sized lazily
    # (``seq[MonitorRecord]`` grows on push) so the higher cap doesn't
    # commit memory until the writer actually fills it.
    maxObservationCount: 100'u64 * 1000'u64 * 1000'u64,
    streamRecords: false)

proc raiseMonitorDepFileReaderError*(kind: MonitorDepFileReaderErrorKind;
                                     message: string) {.noreturn.} =
  var err = newException(MonitorDepFileReaderError, message)
  err.kind = kind
  raise err
