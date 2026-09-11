import std/[options, strutils]

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
    # preserve iomon wire-compat (the dgNoRuntimeDependencies lesson — never
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
    # callback (NOT by hooking open). APPENDED AT THE END to preserve iomon
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
    # All four APPENDED AT THE END for iomon wire-compat (never renumber).
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
    # 2. mrNonDeterministic — OBSERVED ENTROPY INPUT.
    #
    #    THE CROSS-PLATFORM OBSERVATION CONTRACT. Every backend either MEETS this
    #    or DECLARES the gap; macOS and Linux used to disagree on all three
    #    clauses below, which is what stating the contract here fixes:
    #      a. COVERAGE — every entropy entry point the PLATFORM'S libc/system
    #         libraries expose is hooked, not an arbitrary subset:
    #           macOS: getentropy, arc4random, arc4random_buf, arc4random_uniform,
    #                  SecRandomCopyBytes, CCRandomGenerateBytes.
    #           Linux: getrandom (libc symbol + raw syscall + vDSO entry) plus the
    #                  glibc >= 2.36 BSD set getentropy / arc4random /
    #                  arc4random_buf / arc4random_uniform.
    #         `SecRandomCopyBytes`/`CCRandomGenerateBytes` are Apple-only and
    #         `getrandom` is Linux-only, so the sets differ by what EXISTS, never
    #         by what the shim bothered to hook. Windows hooks none of them and
    #         says so: `mcapNonDeterminism` is a DECLARED capability gap there
    #         (`WindowsInterposeKnownUnsupportedCapabilities`), so a consumer sees
    #         the absence instead of mistaking it for "no entropy was used".
    #      b. IDENTITY — `path` is the API NAME ("arc4random_buf"), and `detail`
    #         is exactly `NonDeterministicEntropyDetail` on every platform, so a
    #         consumer that matches on the detail string behaves identically
    #         everywhere.
    #      c. DEDUP — recorded ONCE PER PROCESS PER SOURCE. A program that draws
    #         entropy in a loop, or from many threads, yields ONE record per
    #         source, not one per call: the evidence is "this process consumed
    #         entropy from this API", and repeating it adds nothing while costing
    #         the depfile linearly in call volume.
    #    This does NOT force `mcIncomplete`: io-mon monitored the entropy read
    #    successfully, and caller policy decides whether that evidence invalidates
    #    the build/cache result. See `nonDeterminismObservationCount` (writer.nim).
    #
    #    CALLER ATTRIBUTION (macOS only, and deliberately so). On macOS the record
    #    is emitted ONLY when the call's CALLER lies in a NON-SYSTEM image
    #    (`ct_macos_addr_in_nonsystem`). That gate is essential there (a round-1
    #    cardinal-sin defect): on every process startup /usr/lib/libobjc,
    #    /usr/lib/swift and libsystem_malloc/_trace call arc4random_buf and
    #    libcorecrypto calls getentropy, all CROSS-DYLIB, so they cross the
    #    interpose stub and flagged EVERY real cc/clang/ld/bash run. Linux needs no
    #    equivalent gate: LD_PRELOAD interposes the PUBLIC symbol, and glibc's own
    #    internal users reach entropy by routes that never pass through an
    #    interposed PLT entry — a LOCAL, non-exported symbol
    #    (`__getrandom_nocancel`, behind `arc4random*`) or an inline `syscall`
    #    instruction in libc's own text (`getentropy`) — so what the Linux shim
    #    sees is already the program's own call. Measured: `bash -c true`, a
    #    `cc` compile+link, and a plain `printf` program each produce ZERO
    #    `mrNonDeterministic` records with all four hooks installed, i.e. the
    #    macOS /usr/lib baseline has no Linux counterpart to exclude. Building
    #    a return-address→ELF-image classifier there would add a subsystem to
    #    re-derive an attribution the interposition already gives us.
    #
    #    A /dev/random or /dev/urandom OPEN is DELIBERATELY NOT flagged (mktemp
    #    opens /dev/urandom for a random temp name on essentially every build).
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
    # un-injected-subtree downgrade. APPENDED AT THE END to preserve iomon
    # wire-compat (the dgNoRuntimeDependencies / mrIpcConnect / mrLibraryLoad lesson
    # — never renumber an existing case). The channel identity (shm name / FIFO
    # path / "" for an anonymous socket/pipe) is in `path`; `detail` carries a
    # `chan=<shm|fifo|opaque> role=<create|attach|write|read>` classification the
    # merge reads via `detailToken`. Round-3 finding S1b/S1c/S1d
    # (research/adversarial-2026-06-round3/r3_channel): an out-of-tree shm producer
    # + a monitored mmap-PROT_READ consumer, a FIFO fed by an out-of-tree writer,
    # and an inherited socket/pipe read each produced ZERO downgrade.
    mrExternalContent = 18
    # ROUND-4 RW2 (break D3): an OUTPUT-DIRECTORY MUTATION — mkdir / mkdirat /
    # rmdir / unlink / unlinkat. These take real effect on the output tree but
    # round-3 produced NO record at all (the shim hooked only rename among the
    # mutation surface), and the depfile self-declared a `path-mutation` capability
    # gap marked required=false, so completeness stayed mcComplete despite the
    # unhooked surface (research/adversarial-2026-06-round4/r4_dir/misc_probe.c).
    # The shim now records each successful mutation against the canonical path so
    # the output-dir state is tracked. APPENDED AT THE END to preserve iomon
    # wire-compat (the dgNoRuntimeDependencies / mrIpcConnect / mrExternalContent
    # lesson — never renumber an existing case). `detail` names the syscall
    # (`mkdir`/`mkdirat`/`rmdir`/`unlink`/`unlinkat`). This is an OUTPUT-side fact,
    # NOT a determinism input: the merge does not downgrade on it (a normal build
    # creates dirs + removes temp files), so a NORMAL build stays mcComplete.
    mrPathMutation = 19

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
    # ROUND-4 RW2 — observation kind for the output-directory mutation record
    # (appended for wire-compat, see mrPathMutation). A consumer that keys on the
    # observation kind treats moPathMutation as an OUTPUT-side mutation of the named
    # path (the dir/file was created or removed); it is recorded for output-tree
    # state tracking and is NOT a determinism downgrade.
    moPathMutation = 17

  EventCategory* = enum
    ## The classes of observation a consumer can opt in / out of. See
    ## docs/contributors/event-interest-filter.md. Gating a category makes io-mon
    ## skip the work (record construction + gset publish, and where cheap the hook
    ## install itself) for the `MonitorRecordKind`s in it. The META kinds
    ## (`mrEventLoss`/`mrBackendProfile`/`mrCapabilityGap`) belong to NO category
    ## and are never gated — a suppressed loss marker would risk a false
    ## `mcComplete` (LF-1).
    ecFileDeps       ## mrFileOpen, mrFileRead, mrFileWrite, mrPathProbe,
                     ## mrDirectoryEnumerate, mrPathMutation
    ecProcessTree    ## mrProcessStart, mrProcessExec, mrProcessSpawn
    ecLibraryLoads   ## mrLibraryLoad
    ecNonDeterminism ## mrNonDeterministic, mrTimeRead, mrEnvRead, mrSysctlRead,
                     ## mrExternalContent
    ecIpc            ## mrIpcConnect

  EvidenceScope* = enum
    ## DA-1i — HOW MUCH OF WHAT THE MONITOR OBSERVES IS WRITTEN DOWN.
    ##
    ## A DIFFERENT AXIS FROM `EventCategory`, and the difference is structural
    ## rather than a matter of degree. `EventCategory` gates on the KIND of an
    ## observation; this gates on its RESULT. Measured on one `nim c`:
    ##
    ##   total records                                        66,996
    ##   drop every FAILED lookup — what `esReadsOnly` means   23,049
    ##   gate a probes *category* instead                      41,736
    ##
    ## The category gate discards 2,066 SUCCESSFUL probes it should keep and
    ## leaves 20,753 FAILED `mrFileOpen`s it should drop, because **success is
    ## not a kind**. So no split of `EventCategory` can express this and the two
    ## axes are composed, never conflated: a record is written iff its category
    ## is wanted AND its result is in scope.
    ##
    ## NOT a completeness input. Narrowing the scope is the operator answering a
    ## narrower question honestly, not the monitor failing to observe something,
    ## and `mcIncomplete` means the latter. Conflating them corrupts exactly the
    ## signal DA-2/DA-4 exist to make trustworthy — see `MonitorCompleteness`.
    ##
    ## NOT a cache-key component either. Trust here is a PARTIAL ORDER, not a
    ## partition: full evidence is strictly STRONGER than reads-only evidence, so
    ## a reads-only consumer must accept a full capture while a strict consumer
    ## rejects a narrowed one. Keying on the scope would make the two disjoint
    ## and block the useful direction — the careful teammate publishes and the
    ## fast teammate cannot consume.
    esFull = 0        ## Every observation, including lookups that found nothing.
                      ## The DEFAULT and the ZERO VALUE, so a zero-initialised
                      ## request and a depfile written before this existed both
                      ## mean "full" with no special case anywhere.
    esReadsOnly       ## Drop FAILED EXISTENCE lookups — see
                      ## `recordIsFailedExistenceLookup` for the exact predicate
                      ## and for what it deliberately does not touch. Reproduces
                      ## the evidence model of a compiler-emitted depfile
                      ## (`gcc -MD` lists headers opened, never headers searched
                      ## for), and with it ninja's precise one-directional
                      ## unsoundness: a file ADDED that shadows one earlier in a
                      ## search path does not invalidate. Modified and deleted
                      ## inputs are still caught. One more shape is invisible for
                      ## the SAME reason, and the fields are why: a lookup that
                      ## failed for a reason OTHER than absence (`EACCES`,
                      ## `EISDIR`, `ELOOP`) is dropped too, because no errno
                      ## reaches `MonitorRecord` — so a file that exists but
                      ## could not be opened, later becoming openable, does not
                      ## invalidate either. Row 4 of the hazard table; see
                      ## `recordIsFailedExistenceLookup`.
    esUnrecognized    ## READ SIDE ONLY, and never producible by parsing a token
                      ## this build knows: the depfile states a scope written in
                      ## a vocabulary this build does not have (`evidence=
                      ## writes-only` from a future io-mon). It is NOT full
                      ## scope, and it is not any scope this build can evaluate,
                      ## so it covers NOTHING and every consumer rejects it. The
                      ## CLI cannot produce it (`parseEvidenceScopeFlag` refuses
                      ## an unknown value) and the gate never sees it.

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
    # Appended before mbfUnknown: the family is serialized by its STRING id
    # (backendFamilyId), so position is not wire-visible.
    mbfWindowsInterposeHooks
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
    # (mrTimeRead). Appended at the END — see the compatibility note on
    # `mcapObservationIdentityFold` below, which states BOTH halves of what
    # appending costs (this comment used to state only the enum half).
    mcapObservedEnv
    mcapNonDeterminism
    # ROUND-3 S1 — content-channel coverage: xattr-family metadata reads
    # (getxattr/listxattr → path-probe), POSIX shared memory (shm_open + an shm-fd
    # PROT_READ mapping → content read / out-of-tree downgrade), FIFO and inherited
    # socket/pipe content (out-of-tree → downgrade), and the sendfile/pread/readv
    # zero-copy / positioned reads (content read on the source). Appended at the END
    # — see the compatibility note on `mcapObservationIdentityFold` below, which
    # states BOTH halves of what appending costs (this comment used to state only
    # the enum half).
    mcapExternalContent
    # M-FW-5 — production-sensitive Linux residuals. These are intentionally
    # separate from the positive raw-syscall slices io-mon can already cover:
    # a consumer that needs adversarial/direct-syscall completeness can require
    # these IDs and receive an explicit capability gap instead of trusting a
    # default LD_PRELOAD depfile as production-complete for that threat model.
    mcapAdversarialRawSyscall
    mcapExecutableMappingLifecycle
    mcapPathIdentity
    # DA-1b follow-up — does the capture FOLD repeated observations of one fact
    # into one record? See `backendFoldsObservationIdentity`, which carries the
    # per-family answer and the argument for it.
    #
    # APPENDED AT THE END, AND "APPENDING IS WIRE-SAFE" WAS ONLY HALF TRUE.
    # It was always safe for the ENUM — the wire carries the `capabilityId`
    # STRING, so no ordinal ever shifts meaning, and an older WRITER's file
    # still reads here. It was NOT safe for an older READER: `capabilityFromId`
    # RAISED on an id it did not know and `parseCapabilityList` did not catch
    # it, so the moment a backend ADVERTISED a newly-added id in its
    # `supported=` list, every io-mon built before that id existed failed to
    # load the depfile at all. MEASURED, not inferred: a reader built at commit
    # `715266b` dies with `ValueError: unknown monitor capability:
    # observation-identity-fold` inside `readMonitorDepFile`. This is a
    # PRE-EXISTING mechanism, not something this capability introduced —
    # `mcapPathIdentity` and `mcapExecutableMappingLifecycle` were appended the
    # same way and carried the same hazard — which is why the two notes above
    # were corrected as well.
    #
    # THE READ SIDE NOW DEGRADES. `parseCapabilityList` resolves ids through
    # `tryCapabilityFromId` and collects the ones it cannot name into a profile
    # `mdlWarning` diagnostic: the file loads, the unnamable id is REPORTED
    # rather than silently dropped, and it counts as unsupported (under-claiming
    # the backend, never over-claiming it). So from this commit on, appending a
    # capability really is wire-safe in both directions.
    #
    # WHAT THAT CANNOT DO IS FIX A READER THAT IS ALREADY BUILT. Every binary
    # compiled before this change still raises on an id it does not know, so any
    # capability appended from here on remains unreadable to those builds. The
    # tolerance protects readers built from this commit forward and nothing
    # earlier; there is no retroactive fix, only the end of the growth of the
    # affected set. (Capability GAP records were always tolerant —
    # `parseGapDetail` is wrapped and degrades to a diagnostic — so it was
    # specifically the `supported=`/`required=` lists that broke.)
    #
    # DELIBERATELY NOT IN `InputEvidenceCapabilities`. Its absence is a COST and
    # SIZE shortfall, never a fidelity one: a non-folding backend observed
    # everything and merely wrote some of it down once per observing process.
    # Putting it in the floor set would force `mcIncomplete` on every capture
    # from such a backend, which would be a false statement about what the
    # monitor could see.
    mcapObservationIdentityFold

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
    ## Is the missing capability an INPUT channel -- something bytes or
    ## decisions can reach the monitored program through -- as opposed to
    ## output-side bookkeeping, identity fidelity, an alternative backend or a
    ## threat model?
    ##
    ## This exists because the distinction decides what a consumer must DO, and
    ## it was previously only expressible in the free-text `reason`. A depfile
    ## consumer weighing whether a capture may be trusted for cache publication
    ## cannot tell "renames are not classified" (nothing unseen on the way in)
    ## from "environment reads are not recorded" (a real input observed by
    ## nothing) by string-matching English prose. `required` does not answer it
    ## either: `required` says only whether the CALLER asked for the capability.
    ##
    ## `true` does NOT imply the capture is unusable -- see
    ## `InputEvidenceCapabilities` for the subset whose absence forces
    ## `mcIncomplete`. It means the shortfall is on the input side and a
    ## consumer that cares about input completeness must weigh it.
    inputChannel*: bool
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
    ## DA-1j — WHAT THIS CAPTURE WAS ASKED TO RECORD.
    ##
    ## `completeness` says whether the monitor could observe everything it
    ## tried to. It does NOT say what it was asked to try, and until this field
    ## existed nothing did — while `--interest` already shipped and already
    ## narrowed. Measured, on one command with a single out-of-tree peer:
    ## `io-mon run` grades `mcIncomplete` with 1 loss over 32 records, and
    ## `io-mon run --interest file,proc,lib` grades **`mcComplete`** with 0
    ## losses over 23 records. Gating `ecIpc` means the `mrIpcConnect` records
    ## never exist, so `mergeFragments` never derives the synthetic loss from
    ## them — and the depfile then reports `mcComplete` and says nothing about
    ## having been narrowed. That is the false complete this project calls "one
    ## flag away at all times", reachable today with a shipped flag.
    ##
    ## A consumer compares this against its own requirement and recomputes
    ## locally when the record answers a narrower question than it needs. That
    ## is the shape `evaluateMonitorEvidence` already uses on the capability
    ## axis — the depfile states what it has, the consumer supplies its own bar
    ## — applied to the interest axis.
    ##
    ## NOT a completeness input and NOT a cache-key component. A narrowed
    ## capture is an honest answer to a narrower question, not a monitor
    ## failure, so it must not move the grade (see `MonitorCompleteness`). And
    ## trust here is a PARTIAL ORDER, not a partition: full-scope evidence is
    ## strictly stronger than narrowed evidence, so a consumer that asked for
    ## less must still be able to accept a full capture. Keying on the scope
    ## would make the two disjoint and block exactly that direction.
    ##
    ## READ THIS THROUGH `effectiveObservedInterest`, NOT DIRECTLY. `{}` here is
    ## ambiguous on its own and `normalizeInterest` resolves the ambiguity the
    ## dangerous way: it cannot tell a file that stated NO scope (an old depfile,
    ## which must widen to `FullInterest`) from a file that stated a scope
    ## consisting entirely of categories this build cannot name (a NARROWED
    ## capture, which must not widen to anything). `observedInterestStated`
    ## separates them.
    observedInterest*: set[EventCategory]
    ## Was a scope stated AT ALL? False for every depfile written before the
    ## stamp existed, and for a library caller that passed no scope.
    ##
    ## This exists because the reader of a wire format meets writers from the
    ## future. `interest=gpu` — what a later io-mon writes for a capture narrowed
    ## to a category added after this build — parses to `{}` here, and reading
    ## `{}` as "not stated" would report a NARROWED capture as full scope and let
    ## a consumer that needs full evidence accept it. That is precisely the false
    ## complete this field's sibling was added to end, surviving in the forward
    ## direction. With `stated = true` and an empty parse the honest answer is
    ## "this file states a scope I cannot evaluate", and a consumer requiring
    ## full evidence must REJECT it — see `effectiveObservedInterest`.
    observedInterestStated*: bool
    ## The stamp VERBATIM, exactly as the producer wrote it (empty when nothing
    ## was stated). Kept so the residual is nameable rather than merely
    ## detectable: a consumer can report "this capture declares `gpu`, which I
    ## cannot evaluate" instead of "this capture declares something". Same
    ## attribution-not-suppression rule the unnamable-capability diagnostic
    ## follows in `profileFromRecords`.
    observedInterestTokens*: string
    ## DA-1i — HOW MUCH OF WHAT WAS OBSERVED THIS CAPTURE WROTE DOWN.
    ##
    ## `observedInterest` above says which KINDS the capture was asked for; this
    ## says which RESULTS it was asked to keep. Two axes, because a category gate
    ## provably cannot express `reads-only` (see `EvidenceScope`), and the file
    ## has to state both or a consumer cannot tell a capture that omitted every
    ## failed lookup from one that omitted nothing.
    ##
    ## Same three-field shape as `observedInterest`, and for the same reason it
    ## has three fields rather than one: a future io-mon writing
    ## `evidence=writes-only` must NOT read as `esFull` here. Absent ⇒ full scope
    ## (an old depfile keeps its meaning); present-but-unrecognised ⇒ REJECT,
    ## with the token retained so the residual is nameable.
    ##
    ## READ THIS THROUGH `effectiveObservedEvidenceScope` /
    ## `observedEvidenceScopeCovers`, NOT DIRECTLY.
    ##
    ## NOT a completeness input and NOT a cache-key component — see
    ## `EvidenceScope` for both arguments.
    observedEvidenceScope*: EvidenceScope
    ## Was an evidence scope stated AT ALL? False for every depfile written
    ## before the stamp existed, and for a capture at `esFull` — which is the
    ## same claim, since `esFull` is what an unstamped file has always meant. So
    ## a full capture's bytes are unchanged by this field's existence.
    observedEvidenceScopeStated*: bool
    ## The stamp VERBATIM, exactly as the producer wrote it (empty when nothing
    ## was stated). Kept so a consumer can report "this capture declares
    ## `writes-only`, which I cannot evaluate" instead of "this capture declares
    ## something" — attribution, not mere detection.
    observedEvidenceScopeToken*: string
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
    # IoMon-Decomposed-Host-API DH-1 — PER-CALL environment for the
    # monitored child. Entries are layered on top of the parent's own
    # environment (which the child otherwise inherits unchanged) and are
    # applied to the SPAWN, never to the hosting process: `runMonitored`
    # performs no `putEnv`, so two monitors running concurrently in one
    # process cannot clobber each other's injection variables.
    #
    # Later duplicates win over earlier ones. io-mon's OWN injection
    # variables (`LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`,
    # `REPRO_MONITOR_*`, `CT_SANDBOX_TOOLS_DIR`) are applied AFTER these,
    # so a caller can never accidentally switch monitoring off — but the
    # value a caller supplies IS honoured as the base the injection
    # extends (a caller-supplied `LD_PRELOAD` is preserved after the
    # shim, exactly as an inherited one is).
    #
    # NOTE: on EVERY arm the executable is still resolved via the HOSTING
    # process's `PATH`, but by a DIFFERENT route on each, so do not generalise
    # from one of them:
    #   * Linux   — `osproc`'s fork path calls `findExe` IN THE FORKED CHILD,
    #               whose `environ` is still the parent's, then `execve`s the
    #               resolved absolute path with this `env`. The search predates
    #               the new environment.
    #   * macOS   — `osproc` takes the `posix_spawnp(…, env)` path instead, and
    #               `posix_spawnp` reads `PATH` from the CALLING process's
    #               environment, never from the `envp` argument.
    #   * Windows — `CreateProcessW` is called with `lpApplicationName = NULL`,
    #               whose documented search runs in the calling process and
    #               never consults `lpEnvironment`.
    # So a `PATH` entry here changes what the child sees but not which binary is
    # launched. Pass an absolute `command[0]` when that distinction matters.
    # Only the Linux row is verified by execution in this workspace.
    env*: seq[(string, string)]
    # IoMon-Decomposed-Host-API DH-1 — PER-CALL working directory for the
    # monitored child. Empty means "inherit the hosting process's cwd"
    # (the historical behaviour). Set per-call rather than by `chdir`-ing
    # the host, so concurrent monitors can each resolve their relative
    # paths against their own action directory.
    #
    # `depFilePath`, `eventStreamPath` and `captureStdioPath` are resolved
    # by the HOST, not the child, so they are unaffected by this field —
    # pass them absolute if the host's cwd may differ.
    cwd*: string
    # The observation categories this consumer wants. io-mon skips the work
    # (record build + gset publish, and where cheap the hook install) for the
    # categories NOT in this set. See docs/contributors/event-interest-filter.md.
    # The empty set is normalised to `FullInterest` on ingest, so an unset field
    # captures everything (the safe, back-compatible default) rather than
    # silently disabling all observation. META/loss records are never gated.
    interest*: set[EventCategory]
    # DA-1i — how much of what is observed this capture writes down. `esFull`
    # (the zero value) records everything, which is what every caller got before
    # this field existed. `esReadsOnly` drops FAILED existence lookups: io-mon
    # still observes them, the shim skips publishing them and the host filter
    # drops any an older shim published anyway. Not a completeness input and not
    # a cache-key component — see `EvidenceScope`.
    evidenceScope*: EvidenceScope

const
  IomonVersion* = 1'u16
  IomonMagic* = "IOMN"
  IomonTrailerMagic* = "IOMT"
  IoMonDepfileProducer* = "iomon_depfile_v1"

  NonDeterministicEntropyDetail* = "non-deterministic entropy source"
    ## The `detail` text EVERY backend must put on an `mrNonDeterministic`
    ## record. It lives here — not as a literal in each shim — because the
    ## shims previously disagreed ("non-deterministic entropy source" on macOS,
    ## "linux non-deterministic source" on Linux), which made any consumer that
    ## matched on the detail string behave differently per platform for the same
    ## observation. One definition means the two cannot drift apart again.
    ## The record's `path` carries WHICH source (see `mrNonDeterministic`).

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
    maxObservationCount: 1000'u64 * 1000'u64 * 1000'u64,
    streamRecords: false)

proc raiseMonitorDepFileReaderError*(kind: MonitorDepFileReaderErrorKind;
                                     message: string) {.noreturn.} =
  var err = newException(MonitorDepFileReaderError, message)
  err.kind = kind
  raise err

# ---------------------------------------------------------------------------
# Event-interest categories — docs/contributors/event-interest-filter.md
# ---------------------------------------------------------------------------

const FullInterest* = {EventCategory.low .. EventCategory.high}
  ## Every category — io-mon's default, and what an empty request interest is
  ## normalised to. A generic consumer captures everything unless it opts out.

func categoryOf*(kind: MonitorRecordKind): Option[EventCategory] =
  ## The gate-able category a record kind belongs to, or `none` for META kinds
  ## (`mrEventLoss`/`mrBackendProfile`/`mrCapabilityGap`) that are NEVER gated.
  ## Exhaustive over `MonitorRecordKind`, so a new kind must state its category
  ## (or be declared META) here rather than silently defaulting.
  case kind
  of mrFileOpen, mrFileRead, mrFileWrite, mrPathProbe, mrDirectoryEnumerate,
     mrPathMutation:
    some(ecFileDeps)
  of mrProcessStart, mrProcessExec, mrProcessSpawn:
    some(ecProcessTree)
  of mrLibraryLoad:
    some(ecLibraryLoads)
  of mrNonDeterministic, mrTimeRead, mrEnvRead, mrSysctlRead, mrExternalContent:
    some(ecNonDeterminism)
  of mrIpcConnect:
    some(ecIpc)
  of mrEventLoss, mrBackendProfile, mrCapabilityGap:
    none(EventCategory)

func normalizeInterest*(interest: set[EventCategory]): set[EventCategory] =
  ## The empty set means "unset" -> capture everything; any non-empty set is
  ## honoured as-is. Callers normalise on ingest so a zero-initialised request
  ## never silently disables all observation.
  if interest == {}: FullInterest else: interest

func recordWanted*(interest: set[EventCategory]; kind: MonitorRecordKind): bool =
  ## Should a record of `kind` be captured under `interest`? META kinds (no
  ## category) are always wanted; a categorised kind is wanted iff its category
  ## is in the (normalised) set.
  let c = categoryOf(kind)
  if c.isNone: true
  else: c.get in normalizeInterest(interest)

# ---------------------------------------------------------------------------
# Evidence scope — DA-1i. A predicate on the RESULT of a lookup, composed with
# (never folded into) the event-interest predicate on its KIND.
# ---------------------------------------------------------------------------

func recordIsFailedExistenceLookup*(record: MonitorRecord): bool =
  ## Did this record observe an EXISTENCE LOOKUP THAT DID NOT SUCCEED? The whole
  ## of what `esReadsOnly` drops, in one place, so the shim gate and the host
  ## filter cannot disagree about what "reads only" means.
  ##
  ## The question is deliberately weaker than "did the path turn out to be
  ## absent?", because that is a question these fields cannot answer — see
  ## "LOOKUPS THAT DID NOT SUCCEED" below, which is the whole of the difference
  ## and the reason the hazard table has a fourth row.
  ##
  ## META AND LOSS KINDS CANNOT BE DROPPED, and the protection is STRUCTURAL in
  ## two independent ways rather than a matter of remembering them:
  ##
  ##   * The `case` below is EXHAUSTIVE — no `else` — exactly as `categoryOf` is,
  ##     so a `MonitorRecordKind` added later is a COMPILE ERROR here until
  ##     someone classifies it. It cannot inherit an answer by default.
  ##   * The guard on the first line asks `categoryOf`, the one definition of
  ##     what META is, so the two cannot drift apart even if the META arm below
  ##     were mis-edited. It is deliberately REDUNDANT with that arm (deleting it
  ##     changes no behaviour today); it is defence in depth and a statement of
  ##     where the definition lives, not the sole protection.
  ##
  ## Why this matters more than it looks: a narrowing that could drop an
  ## `mrEventLoss` would manufacture a false `mcComplete` out of a capture that
  ## lost data (LF-1), which is the cardinal sin this project is organised
  ## around. `recordWanted` holds the same line for the same reason, and
  ## `tests/portable/test_io_mon_evidence_scope.nim` asserts it EXHAUSTIVELY over
  ## `MonitorRecordKind` — offering every kind the exact record shape that makes
  ## the three lookup kinds droppable — rather than trusting either comment.
  ##
  ## LOOKUPS THAT DID NOT SUCCEED — NOT PROVEN ABSENCES. Read this before
  ## widening any arm, and before restoring the stronger sentence that used to
  ## stand here ("a failure is an error, not an absence"). THE RECORD SHAPE
  ## CANNOT DRAW THAT LINE:
  ##
  ##   * `result` is the raw call return, and `open`/`openat` answer **-1 for
  ##     every failure** whatever the reason;
  ##   * `probeFromResult` stamps **`prAbsent` on every non-zero `stat`
  ##     return**, again whatever the reason;
  ##   * **no errno reaches `MonitorRecord`.** There is no field for it and no
  ##     shim carries one.
  ##
  ## So `result < 0` and `prAbsent` mean "the call FAILED", never "the path is
  ## ABSENT", and four measured shapes where the path EXISTS are dropped here:
  ## `EACCES` (a mode-000 `open`), `EISDIR`, `EACCES` on a `stat` through a
  ## no-exec directory, and `ELOOP`. On a real `nim c`, 5 of 2,104 dropped
  ## records name an existing path (all `/dev/tty`, `ENXIO`).
  ##
  ## THAT IS THE NARROWING, STATED RATHER THAN PAPERED OVER. `esReadsOnly` keeps
  ## the lookups that FOUND SOMETHING USABLE — the evidence a compiler-emitted
  ## depfile carries — and an errored lookup found nothing usable. The
  ## consequence is a staleness blind spot, and it is written down as such: ROW 4
  ## of the normative hazard table (`docs/usage.md`,
  ## `docs/contributors/evidence-scope.md`, and reprobuild's `CLI/build.md`) says
  ## that a file which exists but could not be OPENED, later becoming openable (a
  ## `chmod`, a directory replaced by a file), is invisible under `reads-only` —
  ## for the same reason row 3's added file is: **it is not recorded at all**, so
  ## row 1 ("a recorded file is modified ⇒ detected") never reaches it.
  ##
  ## THE ALTERNATIVE, NAMED SO THIS IS A CHOICE AND NOT AN OVERSIGHT: carry the
  ## distinguishing fact — errno, or at minimum an ENOENT/ENOTDIR-vs-everything-
  ## else bit — and drop only proven absences. THE WIRE WOULD NOT OBJECT:
  ## `MonitorRecord.detail` is a free string every backend already writes, and
  ## the `.iomon` envelope carries only RECORDS (`depFileFromOwnedRecords`
  ## reconstructs `profile`, `capabilityGaps`, `requiredFeatures`, `completeness`
  ## and `summary` from them), so no version bump and no format break would be
  ## needed. Two costs are why it was not done here, and both are larger than the
  ## 0.24% they buy:
  ##     THREE BACKENDS — AND THE COST IS NOT WHERE THIS BULLET USED TO PUT IT.
  ##     It said macOS sites "would each have to capture errno before any
  ##     intervening libc call clobbers it". THE CAPTURE IS ALREADY THERE, on
  ##     every backend, at exactly the required position, put there for an
  ##     unrelated reason (preserving the tracee's errno across the hook):
  ##     `linux_preload` takes `c_get_errno()`, `macos_interpose` `getErrno()`
  ##     and `windows_interpose` `GetLastError()` on the line AFTER the real
  ##     call and BEFORE anything that could clobber it. One Windows probe
  ##     site's comment already reads "ERROR_FILE_NOT_FOUND on absent path".
  ##     Do not restore that claim. What WOULD have to be built is two other
  ##     things, and they are the honest cost:
  ##       - PLUMBING, not capture. The saved value is a LOCAL IN THE HOOK,
  ##         while the record is built one or two frames down in helpers
  ##         (`recordOpen`, `recordPathProbe`, `probeFromResult`,
  ##         `recordFailedOpenCanonical`, `recordCanonicalPathProbe`, …) that
  ##         receive the CALL RESULT and not the errno. Counted over the procs
  ##         that build a droppable record without the saved value in scope:
  ##         **~16 on macOS, ~5 on Linux, ~4 on Windows**. Every one is a
  ##         signature change on a hot path.
  ##       - THREE ERROR VOCABULARIES, and Windows has two of its own: a
  ##         negative NTSTATUS on the `Nt*` arms and a positive Win32 code on
  ##         the `GetLastError` arms. "Which values mean absent" therefore has
  ##         to be answered three-and-a-half times, in three files.
  ##     Until it is, this predicate's fail-toward-keeping rule makes
  ##     `reads-only` stop reducing ANYTHING on the backends that have not been
  ##     classified — a far bigger behaviour change than the blind spot it
  ##     closes. THAT consequence is the load-bearing half of this bullet.
  ##   * AND THERE IS NO SPARE FIELD THAT IS ALSO FREE. Stated carefully,
  ##     because the obvious objection to the previous wording is correct:
  ##     "carrying errno grows the `full` arm" is true of ONE carrier and false
  ##     of the other, and `full` is the BASELINE DA-1i exists to measure the
  ##     per-record cost against, so which carrier is meant decides the
  ##     argument. MEASURED on the real encoder, over a real failed-open record:
  ##       - `detail` — the free string the paragraph above says the wire would
  ##         not object to — costs **+7 bytes on a 126-byte record** for an
  ##         `errno=2` suffix, i.e. **+5.2%** on this fixture's `full` arm. Real,
  ##         and it moves the measurement.
  ##       - `result` would cost **NOTHING**: it is a FIXED-WIDTH `int64`
  ##         (`writeI64Le` → `writeU64Le`), so -1, -2 and -13 all encode in the
  ##         same 126 bytes, and `result < 0` would still select every failure.
  ##         But it is NOT AVAILABLE, and that is the real objection rather than
  ##         a cost one: `result` is defined as the RAW CALL RETURN, and Windows
  ##         already spends its sign on NTSTATUS, so a `-errno` and a genuine
  ##         negative status could not be told apart in the one field.
  ##     So the cheap carrier is the one the wire cannot spare, and the carrier
  ##     the wire can spare is the one that moves the measurement.
  ##
  ## FAILS TOWARD KEEPING. Every arm answers `true` only where the record PROVES
  ## the lookup DID NOT SUCCEED, and anything unproven is kept:
  ##   * `mrPathProbe` — `prAbsent` is the classification both POSIX shims and
  ##     the Windows `probeFromBool` sites already write. Some Windows probe
  ##     sites (the `NtCreateFile`/`NtQueryAttributesFile` arms) leave
  ##     `probeResult` at `prUnknown` and carry a negative NTSTATUS instead, so
  ##     that pairing counts too.
  ##   * `mrFileOpen` — a negative result. `open`/`openat` return -1, Windows
  ##     `CreateFileW` records `INVALID_HANDLE_VALUE` (-1) and the NT arm a
  ##     negative NTSTATUS. A FAILED `fopen` records the NULL `FILE*` as 0 and
  ##     is therefore KEPT — deliberately, because 0 is also a legal fd, and
  ##     dropping a successful `open` that happened to get fd 0 would remove a
  ##     real input. Over-keeping costs records; under-keeping costs
  ##     correctness.
  ##   * `mrDirectoryEnumerate` — a negative result. Every current backend emits
  ##     this only for an enumeration that succeeded (`result = 1`), so this arm
  ##     is a guard against a future backend that records failures, not a live
  ##     reducer.
  ##
  ## A READ IS NEVER DROPPED, AND NOT FOR THE REASON THIS COMMENT USED TO GIVE.
  ## It said a failed `mrFileRead` is "an error the consumer must still see",
  ## presented as a live case this arm protects. THAT CASE IS NOT LIVE ON LINUX.
  ## Counted: `linux_preload.nim` builds an `mrFileRead` at SIX sites, and not
  ## one of them can emit a negative result —
  ##   * four guard on the byte count: `recordFdRead`, `repro_hook_fread` and
  ##     the `sendfile` arm on `> 0`, `recordRawSplice` on `> 0`, and
  ##     `recordRawRead` returning early on a negative result;
  ##   * two hard-code `result = 0`: `recordPathRead` and the inherited-fd
  ##     reclassification in `classifyEmptyFdRead`.
  ## WHAT IS LIVE, AND IS KEPT: SHORT reads (`0 < n < requested`) and zero-length
  ## reads at EOF, emitted with their real byte count, plus those two synthetic
  ## `result = 0` reads. None of them is an existence lookup, so none is
  ## droppable. The arm is therefore a GUARD exactly as
  ## `mrDirectoryEnumerate`'s is — against a future backend that does record
  ## failed reads, and against anyone widening `mrFileOpen`'s `result < 0` test
  ## to everything that touches a file — and not a live reducer.
  if categoryOf(record.kind).isNone:
    return false
  case record.kind
  of mrPathProbe:
    record.probeResult == prAbsent or
      (record.probeResult == prUnknown and record.result < 0)
  of mrFileOpen, mrDirectoryEnumerate:
    record.result < 0
  of mrFileRead, mrFileWrite, mrPathMutation:
    # File-touching, and NOT existence lookups: the path was already in hand, so
    # whatever these report is not the answer to "is there something here?". A
    # guard, not a live reducer — see "A READ IS NEVER DROPPED" above.
    false
  of mrProcessStart, mrProcessExec, mrProcessSpawn, mrLibraryLoad,
     mrNonDeterministic, mrTimeRead, mrEnvRead, mrSysctlRead,
     mrExternalContent, mrIpcConnect:
    # Not lookups at all. `mrIpcConnect` and `mrExternalContent` are also
    # COMPLETENESS-BEARING (`mergeFragments` derives a synthetic `mrEventLoss`
    # from them), so dropping either would move the grade — which this axis must
    # never do.
    false
  of mrEventLoss, mrBackendProfile, mrCapabilityGap:
    # THE LF-1 ARM. META kinds carry the loss markers and the provenance a
    # completeness verdict is derived from. `false` here is not a default: it is
    # the statement that no narrowing may ever suppress them.
    false

func recordInEvidenceScope*(scope: EvidenceScope;
                            record: MonitorRecord): bool =
  ## Should this record be written down under `scope`? The RESULT-side half of
  ## the gate, to be composed with `recordWanted`'s KIND-side half.
  ##
  ## `esUnrecognized` records EVERYTHING. It can only arrive from reading a
  ## depfile a newer io-mon wrote, never from this build's CLI or from
  ## `FsSnoopRequest`, and if it somehow reached a gate the safe direction is to
  ## capture more rather than less — an over-full capture is slower and still
  ## honest; an under-full one is the cardinal sin.
  case scope
  of esFull, esUnrecognized: true
  of esReadsOnly: not recordIsFailedExistenceLookup(record)

const
  # Wire tokens for `REPRO_MONITOR_EVIDENCE` (the env channel to the shim) and
  # for the `evidence=` stamp on the backend-profile record. ONE vocabulary for
  # both channels and one codec, exactly as `interestTokenPairs` is for the
  # interest axis. `esUnrecognized` is deliberately absent: it is what a token
  # NOT in this table parses to, so giving it a token of its own would make it
  # producible and destroy the distinction it exists to draw.
  evidenceScopeTokenPairs = [
    (esFull, "full"), (esReadsOnly, "reads-only")]

func evidenceScopeToken*(scope: EvidenceScope): string =
  ## Encode a scope as its wire token. `esUnrecognized` has no spelling — it is
  ## a READING, not a scope — so it encodes as the empty string, and every write
  ## site guards against handing it here.
  for (value, token) in evidenceScopeTokenPairs:
    if value == scope: return token
  ""

func parseEvidenceScopeToken*(s: string): EvidenceScope =
  ## Decode a wire token. Empty/absent ⇒ `esFull` — an absent
  ## `REPRO_MONITOR_EVIDENCE` means "write everything down", which is what every
  ## shim did before this existed. An unknown token ⇒ `esUnrecognized` rather
  ## than `esFull`: on the ENV channel that is a shim being told about a scope a
  ## newer host knows and it captures everything (the host filter is the source
  ## of truth for the result); on the FILE channel it is the reading that makes
  ## a future narrowing reject instead of silently passing as full.
  let trimmed = s.strip()
  if trimmed.len == 0: return esFull
  for (value, token) in evidenceScopeTokenPairs:
    if trimmed == token: return value
  esUnrecognized

func statesUnevaluableEvidenceScope*(dep: MonitorDepFile): bool =
  ## The capture STATED an evidence scope and this build could not name it. The
  ## file is not silent about its scope and it is not full scope: it is a
  ## narrowing written in a vocabulary this build does not have. The
  ## `interest=gpu` residual DA-1j closed, on the evidence axis.
  dep.observedEvidenceScopeStated and
    dep.observedEvidenceScope == esUnrecognized

func effectiveObservedEvidenceScope*(dep: MonitorDepFile): EvidenceScope =
  ## THE ONLY CORRECT WAY TO READ THE EVIDENCE STAMP. Three inputs, three
  ## answers, and the middle one is why this exists rather than a bare field
  ## read:
  ##
  ##   not stated                 -> `esFull`. An old depfile, or a capture that
  ##                                 narrowed nothing, keeps exactly its
  ##                                 previous meaning.
  ##   stated, recognised         -> what was stated.
  ##   stated, NOT recognised     -> `esUnrecognized`. NOT full scope. It covers
  ##                                 nothing, so every consumer rejects — the
  ##                                 honest verdict for a file whose scope this
  ##                                 build cannot evaluate.
  ##
  ## Every direction of the degrade points at "reject", never at "accept": a
  ## scope this build misreads costs a re-capture, whereas the opposite mistake
  ## publishes a narrowed capture as full evidence.
  if dep.observedEvidenceScopeStated: dep.observedEvidenceScope
  else: esFull

func evidenceScopeCovers*(have, required: EvidenceScope): bool =
  ## Is `have` at least as strong as `required`? THE PARTIAL ORDER, in one
  ## place. `esFull` is strictly stronger than `esReadsOnly`, so a reads-only
  ## consumer accepts a full capture and a full-evidence consumer does not
  ## accept a reads-only one. `esUnrecognized` covers NOTHING, including itself:
  ## two builds that both fail to name a scope have not thereby agreed on it.
  case have
  of esFull: required in {esFull, esReadsOnly}
  of esReadsOnly: required == esReadsOnly
  of esUnrecognized: false

func observedEvidenceScopeCovers*(dep: MonitorDepFile;
                                  required: EvidenceScope): bool =
  ## Does this capture's stated evidence scope meet what a consumer needs? The
  ## consumer-side half of the DA-1i contract, in one place so that no consumer
  ## has to rediscover the not-stated / unrecognised distinction for itself.
  evidenceScopeCovers(effectiveObservedEvidenceScope(dep), required)

const
  # Wire tokens for `REPRO_MONITOR_INTEREST` (the env channel to the shim).
  interestTokenPairs = [
    (ecFileDeps, "file"), (ecProcessTree, "proc"), (ecLibraryLoads, "lib"),
    (ecNonDeterminism, "nondet"), (ecIpc, "ipc")]

func interestToTokens*(interest: set[EventCategory]): string =
  ## Encode an interest set as the comma-separated `REPRO_MONITOR_INTEREST`
  ## value. `FullInterest` encodes to every token (never empty, so an older
  ## reader cannot mistake "all" for "unset").
  let normalized = normalizeInterest(interest)
  var parts: seq[string] = @[]
  for (cat, tok) in interestTokenPairs:
    if cat in normalized: parts.add(tok)
  parts.join(",")

func parseInterestTokens*(s: string): set[EventCategory] =
  ## Decode a `REPRO_MONITOR_INTEREST` value. Empty/absent -> `FullInterest`
  ## (back-compat). Unknown tokens are ignored (forward-compat: an older shim
  ## treats a new category as "not mine"; the host filter is the source of truth).
  let trimmed = s.strip()
  if trimmed.len == 0: return FullInterest
  for raw in trimmed.split(','):
    let tok = raw.strip()
    for (cat, known) in interestTokenPairs:
      if tok == known: result.incl(cat)

func statesUnevaluableInterest*(dep: MonitorDepFile): bool =
  ## The capture STATED a scope, and this build could not name a single category
  ## in it. The file is not silent about its scope and it is not full scope: it
  ## is a narrowing written in a vocabulary this build does not have.
  dep.observedInterestStated and dep.observedInterest == {}

func effectiveObservedInterest*(dep: MonitorDepFile): set[EventCategory] =
  ## THE ONLY CORRECT WAY TO READ THE SCOPE STAMP. Three inputs, three answers,
  ## and the middle one is the reason this function exists rather than a call to
  ## `normalizeInterest(dep.observedInterest)`:
  ##
  ##   not stated                  -> `FullInterest`. An old depfile (or a
  ##                                  library caller that said nothing) keeps
  ##                                  exactly its previous meaning.
  ##   stated, nothing recognised  -> `{}`. NOT full scope. No non-empty
  ##                                  requirement is a subset of `{}`, so a
  ##                                  consumer needing evidence of anything at
  ##                                  all rejects the file — which is the honest
  ##                                  verdict, because the file states a scope
  ##                                  this build cannot evaluate.
  ##   stated, some recognised     -> what was recognised. Unknown tokens beside
  ##                                  known ones drop out, which narrows the read
  ##                                  scope and therefore errs toward rejection.
  ##
  ## Every direction of the degrade points at "reject", never at "accept": a
  ## scope this build misreads costs a re-capture, whereas the opposite mistake
  ## publishes a narrowed capture as complete evidence.
  if dep.observedInterestStated: dep.observedInterest
  else: FullInterest

func observedInterestCovers*(dep: MonitorDepFile;
                             required: set[EventCategory]): bool =
  ## Does this capture's stated scope cover what a consumer needs? The
  ## consumer-side half of the DA-1j contract, in one place so that no consumer
  ## has to rediscover the `{}` ambiguity for itself. `required = {}` (a consumer
  ## that needs no particular category) accepts anything, including an
  ## unevaluable stamp — it asked for nothing, so nothing can be missing.
  required <= effectiveObservedInterest(dep)
