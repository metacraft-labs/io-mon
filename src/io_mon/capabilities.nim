import std/[strutils]

import io_mon/types

const
  MacosInterposeSupportedCapabilities* = {
    mcapProcess,
    mcapFileRead,
    mcapFileWrite,
    mcapPathProbe,
    mcapDirectoryEnumerate,
    mcapEventLoss,
    mcapProcessTree,
    mcapProcessExec,
    mcapBackendProvenance,
    mcapFileCreate,
    mcapFileTruncate,
    mcapFileAppend,
    # rename/renameat are now hooked (interpose + body-patch) and recorded as an
    # output write on the destination — the gnulib/autotools `mv $@t $@` move.
    mcapRename,
    # symlink-target + /.vol firmlink resolution: a hooked open resolves the fd's
    # canonical path (fcntl F_GETPATH) and a hooked lstat of a symlink resolves
    # its realpath target, so the REAL file behind a link/inode path is recorded
    # (findings doc break #7 / T2). Moved from unsupported.
    mcapSymlink,
    # T3a (Phase 2 / break #1): connect(2) is hooked (interpose + body-patch) and
    # recorded with the peer pid, so the merge downgrades completeness when a
    # monitored client talks to an out-of-tree breakaway daemon (sccache, distcc,
    # gradle, tsserver, …) over a socket.
    mcapIpcConnect,
    # T3b (Phase 3 / break #4 + the dlopen arm of #7): the dyld IMAGE SET is
    # captured via the `_dyld` add-image callback (NOT by hooking open, which dyld
    # bypasses when it kernel-mmaps a dependent dylib). A real clang/ld64 link's
    # ~620 dependent dylibs and any runtime dlopen'd image are now recorded as
    # content (read) dependencies, so an in-place toolchain-library upgrade busts
    # a content-addressed cache instead of serving a stale result.
    mcapLibraryLoad,
    # ROUND-2 R-D (break R10) — non-file input observations. getenv / sysctlbyname /
    # sysctl / uname / gethostname / gethostuuid are hooked and recorded as OBSERVED
    # DECLARED INPUTS (mcapObservedEnv); getentropy / arc4random* are recorded as
    # entropy evidence and clock_gettime / gettimeofday / time / mach_absolute_time
    # are recorded as time-read evidence. Caller policy decides invalidation
    # (mcapNonDeterminism).
    mcapObservedEnv,
    mcapNonDeterminism,
    # ROUND-3 S1 — content-channel coverage: xattr metadata reads, POSIX shared
    # memory, FIFO / inherited socket-pipe content, and sendfile/pread/readv.
    mcapExternalContent,
    # ROUND-4 RW2 (break D3): the output-directory MUTATION surface — mkdir /
    # mkdirat / rmdir / unlink / unlinkat / symlink / symlinkat (rename/renameat
    # were already covered) — is now hooked (interpose + body-patch) and recorded as
    # an `mrPathMutation` output record on the canonical path. symlink/symlinkat ADD
    # a directory entry exactly as unlink REMOVES one, so they belong to the same
    # surface. Round-3 hooked NONE of these, so a mkdir/unlink/rmdir/symlink took
    # real effect with NO record while the depfile self-declared this as an
    # unsupported gap marked required=false — completeness stayed mcComplete despite
    # the unhooked surface (research/adversarial-2026-06-round4/r4_dir/misc_probe.c).
    # Now that the full COMMON mutation surface is hooked it is an ADVERTISED
    # capability (no gap), so an unhooked-mutation surface no longer silently
    # coexists with mcComplete. The remaining tail — mknod/mkfifo (device/FIFO
    # nodes) and the macOS-only atomic renamex_np/renameatx_np swap variants — is
    # NOT hooked, but it is exotic (a build essentially never creates a device node
    # or uses RENAME_SWAP) and is OUTPUT-side only: a missed mutation record is
    # never an INPUT false-complete (the cardinal sin), it only leaves the
    # output-tree view of that rare op uncaptured.
    mcapPathMutation
  }

  MacosInterposeKnownUnsupportedCapabilities* = {
    # T3c (adversarial-hardening break #6): the EndpointSecurity backend is now
    # DESIGNED + FEASIBILITY-PROBED + SKELETONED — see
    # reprobuild-specs/MacOS-EndpointSecurity-Backend.md and the integration stub
    # at src/io_mon/backends/endpoint_security.nim (behind the off-by-default
    # `-d:ioMonEndpointSecurity` define). It stays UNSUPPORTED here until the
    # entitled production client ships, because the kernel-sourced ES client
    # requires the Apple-granted endpoint-security.client entitlement + signing/
    # notarization + root (none available on a dev machine; proven by the on-host
    # feasibility probe: es_new_client → ERR_NOT_PRIVILEGED, AMFI-kill of an
    # ad-hoc-entitled binary). Until then, T0 earned-completeness keeps the
    # interpose backend's break-#6 default conservative.
    mcapEndpointSecurity,
    mcapHybrid,
    mcapAuthorizationEnforcement
  }

  MacosMonitorShimTaxonomyCapabilities* = {
    mcapProcess,
    mcapFileRead,
    mcapFileWrite,
    mcapPathProbe,
    mcapDirectoryEnumerate,
    mcapEventLoss,
    mcapProcessTree,
    mcapProcessExec,
    mcapBackendProvenance,
    mcapFileCreate,
    mcapFileTruncate,
    mcapFileAppend,
    mcapRename,
    mcapSymlink,
    mcapIpcConnect,
    # T3b — dyld dependent-dylib / dlopen image-set capture (see above).
    mcapLibraryLoad,
    # ROUND-2 R-D — non-file determinism inputs (see MacosInterposeSupportedCapabilities).
    mcapObservedEnv,
    mcapNonDeterminism,
    # ROUND-3 S1 — content-channel coverage (see MacosInterposeSupportedCapabilities).
    mcapExternalContent,
    # ROUND-4 RW2 — output-directory mutation surface (mkdir/rmdir/unlink/unlinkat).
    mcapPathMutation
  }

  LinuxPreloadSupportedCapabilities* = {
    mcapProcess,
    mcapFileRead,
    mcapFileWrite,
    mcapPathProbe,
    mcapDirectoryEnumerate,
    mcapEventLoss,
    mcapProcessTree,
    mcapProcessExec,
    mcapBackendProvenance,
    mcapFileCreate,
    mcapFileTruncate,
    mcapFileAppend,
    mcapRename,
    mcapIpcConnect,
    # LIBRARY-LOAD OBSERVATION. The runtime shared-library closure is captured
    # by asking the LOADER for its link map (`dl_iterate_phdr`) rather than by
    # hooking the calls that populate it — the Linux counterpart of the macOS
    # arm's `_dyld_register_func_for_add_image`, and for the same reason: ld.so
    # maps a dependency through internal `__mmap`/`__open64_nocancel` calls that
    # LD_PRELOAD symbol interposition cannot see, so the entire closure was
    # previously invisible (a monitored `gcc -c` captured ZERO of its ten loaded
    # shared objects while reporting mcComplete).
    #
    # THIS IS A PROMISE, and it is kept by arithmetic rather than by assertion:
    # every scan compares the number of newly-enumerated objects against the
    # loader's own cumulative `dlpi_adds` counter, so a load that happened
    # without being enumerated — the one case sampling cannot see, a
    # loader-internal `__libc_dlopen_mode` undone before the next scan — is
    # DETECTED and emits an event-loss marker that downgrades the capture. The
    # capability therefore means "every load was observed, or this capture is
    # mcIncomplete", which is what a supported capability has to mean.
    #
    # Residual, stated because it is not covered: a process SIGKILLed before its
    # shutdown scan loses the closing account, so a loader-internal load in that
    # window is neither observed nor detected. That is the pre-existing
    # kill-before-flush inherent-loss class, not a new one. LD_AUDIT's
    # la_objopen would close it — see docs/cases/dlopen-runpath-transparency.md
    # alternative C — at the cost of a second injected copy of io-mon per
    # process, in its own link-map namespace.
    mcapLibraryLoad,
    # M-FW-6C — Linux libc-visible getenv/uname/sysconf are recorded as
    # observed inputs; clock_gettime/gettimeofday/time are time-read evidence;
    # getrandom (libc symbol, raw syscall and vDSO entry) plus the glibc >= 2.36
    # BSD set getentropy/arc4random/arc4random_buf/arc4random_uniform are
    # entropy evidence — the same per-platform-complete entropy surface the
    # macOS profile advertises (io_mon/types.nim, record 16). Other direct raw
    # variants remain outside this positive capability.
    mcapObservedEnv,
    mcapNonDeterminism
  }

  InputChannelCapabilities* = {
    # THE CAPABILITIES THAT ARE ABOUT AN INPUT — a way for bytes, or for a
    # decision the build depends on, to reach the monitored program. A gap in
    # one of these means something may have come IN unobserved; a gap in
    # anything else means the capture describes the program's OUTPUTS, its own
    # identity, or an alternative implementation less well.
    #
    # WHY THIS IS EMITTED AND NOT LEFT TO THE PROSE. Every gap already carries a
    # `reason` string, and until now that string was the ONLY place the
    # distinction lived. So a depfile consumer deciding whether a capture may be
    # trusted had to tell "no rename record kind" from "environment reads are
    # not recorded as observed inputs" by reading English. Those two demand
    # opposite responses and are one string-match apart. The Windows profile is
    # the case that forced it: after M5 closed ipc-connect and external-content
    # it HAD five declared gaps, four of them output-side or identity fidelity
    # and exactly one -- `mcapObservedEnv` -- an input channel, with nothing in
    # the record saying which. M10 then gave that one records, so Windows now
    # declares NO input-channel gap at all. The key is not thereby decoration:
    # older Windows depfiles still carry `input=true` for it, the other
    # profiles still have gaps of both kinds, and a capability's membership
    # here is a property of the CAPABILITY rather than of whether any
    # particular backend happens to implement it.
    #
    # THIS IS NOT `InputEvidenceCapabilities`, which is a SUBSET: the floor
    # whose absence forces `mcIncomplete` outright. A capability can be an input
    # channel without being in the floor -- `mcapObservedEnv` is precisely that
    # -- meaning the shortfall is real and on the input side, but a substitute
    # record or a narrower blast radius keeps it from voiding the claim.
    #
    # WHAT IS DELIBERATELY OUT, and why, since the omissions are the load-
    # bearing part:
    #   * `mcapFileWrite` / `mcapFileCreate` / `mcapFileTruncate` /
    #     `mcapFileAppend` / `mcapRename` / `mcapPathMutation` — OUTPUT-side.
    #     A missed mutation leaves the output view poorer; it is not an input a
    #     cache key would silently omit.
    #   * `mcapSymlink` / `mcapPathIdentity` — IDENTITY FIDELITY. A read through
    #     a symlink still records a path that resolves to the same bytes.
    #   * `mcapNonDeterminism` — EVIDENCE, not an input. Nothing downgrades on
    #     it; the caller's policy decides what an entropy or clock read means.
    #   * `mcapEndpointSecurity` / `mcapHybrid` — ALTERNATIVE BACKENDS. Their
    #     absence says another implementation was not used.
    #   * `mcapAuthorizationEnforcement` — about DENYING operations. io-mon
    #     observes; it never claimed to enforce.
    #   * `mcapAdversarialRawSyscall` / `mcapExecutableMappingLifecycle` —
    #     THREAT MODELS. A hostile program can defeat an input channel through
    #     either, but that is a stance about the adversary, not a statement that
    #     an ordinary build's inputs went unseen, and the profile's diagnostics
    #     already tell a consumer to request them explicitly.
    mcapFileRead,
    mcapPathProbe,
    mcapDirectoryEnumerate,
    mcapLibraryLoad,
    mcapObservedEnv,
    mcapIpcConnect,
    mcapExternalContent
  }

  InputEvidenceCapabilities* = {
    # The capabilities WITHOUT WHICH AN INPUT-COMPLETENESS CLAIM IS NOT
    # AVAILABLE — the observation channels a depfile's own `mcComplete` asserts
    # were present. A backend that does not support one of these has an input
    # channel it cannot see at all, so a capture from it downgrades to
    # `mcIncomplete` whether or not the consumer thought to ask.
    #
    # WHY THIS SET EXISTS. `docs/contributors/architecture.md` states the
    # contract as "every uncertainty downgrades to mcIncomplete", but the
    # machinery did not enforce it: `depFileFromOwnedRecords` derived the
    # profile with an EMPTY required-set, and a gap is only ever marked
    # `required` — the thing that clears `evidenceComplete` — for capabilities
    # in that set. So every declared capability gap was emitted with
    # `required=false` and could never affect completeness. The declaration was
    # real and the consequence was missing. That is how `mcapLibraryLoad` sat
    # in `LinuxPreloadKnownUnsupportedCapabilities` while a monitored `gcc -c`
    # reported `mcComplete` having observed none of its ten loaded libraries.
    #
    # WHY IT IS THIS SET AND NOT ALL GAPS. Making every declared gap downgrade
    # would make Linux permanently `mcIncomplete` and destroy the signal, and it
    # would be wrong on the merits, because the other entries are not missing
    # input channels:
    #   * `mcapEndpointSecurity` / `mcapHybrid` are ALTERNATIVE BACKENDS. Their
    #     absence says another implementation was not used, not that anything
    #     went unobserved.
    #   * `mcapAuthorizationEnforcement` is about DENYING operations. io-mon
    #     observes; it never claimed to enforce.
    #   * `mcapPathMutation` / `mcapPathIdentity` are OUTPUT-side and identity
    #     fidelity. A missed mutation record leaves the output view poorer; it
    #     is not an input a cache key would silently omit.
    #   * `mcapSymlink` / `mcapExternalContent` are PARTIAL, with a recorded
    #     substitute — a read through a symlink still records a path that
    #     resolves to the same bytes, and the libc-visible content movers are
    #     recorded. The gaps are narrower coverage, not blindness.
    #   * `mcapAdversarialRawSyscall` / `mcapExecutableMappingLifecycle` are
    #     THREAT MODELS the profile's own diagnostics already tell consumers to
    #     request explicitly if they need them.
    # `mcapLibraryLoad` was the one entry in the Linux list that was none of
    # those: a whole class of real content inputs, observed by nothing else,
    # absent from the capture, with no substitute record anywhere.
    mcapProcess,
    mcapProcessTree,
    mcapProcessExec,
    mcapFileRead,
    mcapFileWrite,
    mcapPathProbe,
    mcapDirectoryEnumerate,
    mcapEventLoss,
    mcapLibraryLoad
  }

  LinuxPreloadKnownUnsupportedCapabilities* = {
    mcapEndpointSecurity,
    mcapHybrid,
    mcapSymlink,
    mcapAuthorizationEnforcement,
    mcapPathMutation,
    mcapAdversarialRawSyscall,
    mcapExecutableMappingLifecycle,
    mcapPathIdentity,
    # ROUND-3 S1 — xattr/shm/FIFO/sendfile content-channel hooks are macOS-only so far.
    mcapExternalContent
  }

  # What the Windows shim can actually observe, derived from the record and
  # observation kinds it emits (`shim/windows_interpose.nim`) rather than
  # from the hooks it installs -- a hooked entry point that produces no
  # record observes nothing as far as a consumer is concerned.
  #
  # Windows used to report the macOS set here, because
  # `defaultHooksMonitorProfile` had no Windows branch and fell through to
  # the macOS profile. That claimed rename, symlink, library-load,
  # ipc-connect, observed-env, non-determinism and external-content on a
  # backend that emits no such record, and labelled every Windows depfile
  # `backend=macos-interpose-hooks`. The banner is what a consumer reads to
  # decide what the evidence covers, so an over-claim there is the same
  # class of defect as a monitoring failure that reports success.
  WindowsInterposeSupportedCapabilities* = {
    mcapProcess,              # mrProcessStart
    mcapFileRead,             # mrFileRead / moFileRead
    mcapFileWrite,            # mrFileWrite / moFileWrite
    mcapPathProbe,            # mrPathProbe (GetFileAttributes*, NtQuery*)
    mcapDirectoryEnumerate,   # mrDirectoryEnumerate (FindFirstFileEx family)
    mcapEventLoss,            # mrEventLoss
    mcapProcessTree,          # mrProcessSpawn + CreateRemoteThread propagation
    mcapProcessExec,          # moExecute on the spawn record
    mcapBackendProvenance,    # this profile record
    # mrLibraryLoad, from LdrRegisterDllNotification plus an enumeration of
    # the images already mapped at init. Sourced from the LOADER rather than
    # from hooked calls, because LoadLibraryW is only one route into
    # LdrLoadDll and a statically imported DLL is mapped before any of them
    # runs. This capability is in InputEvidenceCapabilities -- the floor a
    # backend must meet before a capture may claim mcComplete.
    mcapLibraryLoad,
    # M5 --------------------------------------------------------------------
    #
    # The three gaps M4 declared that could hide a real INPUT, each moved here
    # only once records genuinely flow. The standard is M4's: a capability is
    # not advertised without a record kind behind it, so what follows names
    # the record kind for each.
    #
    # mrIpcConnect. Two arms, because Windows has two ways to reach a peer and
    # only one of them looks like a socket. `connect`/`WSAConnect` in ws2_32
    # are hooked; a named-pipe CLIENT needs no new entry point at all, since it
    # reaches its peer by OPENING `\\.\pipe\<name>` through the already hooked
    # CreateFileW/A and NtCreateFile -- so that arm is a classification of
    # paths those hooks already carried. The pipe arm also supplies what the
    # socket arm cannot: `GetNamedPipeServerProcessId` names the peer process,
    # the Windows counterpart of LOCAL_PEERPID, so the merge can PROVE whether
    # a peer is one of this run's monitored processes. A socket peer has no
    # such answer on Windows and is reported as unknown, which the merge treats
    # conservatively -- a re-run, never a false skip.
    mcapIpcConnect,
    # mrNonDeterministic (entropy) + mrTimeRead (clocks). BCryptGenRandom,
    # ProcessPrng, RtlGenRandom/SystemFunction036 and CryptGenRandom;
    # QueryPerformanceCounter, GetSystemTimeAsFileTime and GetTickCount64.
    # Evidence only: `nonDeterminismObservationCount` counts them and nothing
    # downgrades, because io-mon DID observe the read and caller policy decides
    # what it means. This is the reporting half of the entropy-blessing design
    # (M6), which had no Windows implementation at all before.
    mcapNonDeterminism,
    # mrExternalContent. Windows' content channels that are not file reads:
    # named file mappings (the shm analogue, via CreateFileMapping/
    # OpenFileMapping), anonymous pipes (CreatePipe, paired against a read from
    # a handle the shim never saw opened), and NTFS alternate data streams.
    # Plus the one Windows adds that a build actually hits constantly -- a
    # MAPPED VIEW of a file, whose bytes arrive by page fault and pass no read
    # hook anywhere -- recorded as an ordinary `moFileRead` on the underlying
    # path so the bytes land in the cache key rather than merely in the log.
    mcapExternalContent,
    # M10 -------------------------------------------------------------------
    #
    # mrEnvRead / moEnvRead, carrying the variable NAME, deduped per process,
    # never downgrading -- the SAME contract the macOS and Linux arms
    # implement, because a consumer compares captures across platforms and a
    # Windows record that meant something subtly different would be worse than
    # the honest gap it replaces.
    #
    # This was the last Windows gap that was an INPUT channel, and the only
    # one that could produce a false `mcComplete` over something unseen: a
    # build reads a variable, nothing records it, the capture grades complete,
    # and the action cache serves a stale result the next time the value
    # changes. The four gaps left below are output-side or identity fidelity.
    #
    # WHAT IS COVERED, stated as the claim rather than as a list of hooks:
    # every read that goes through a CALL. Windows keeps TWO copies of the
    # environment and a program reads exactly one of them, so both are hooked:
    #
    #   * the PEB block, through kernel32's `GetEnvironmentVariableW`/`A` and
    #     the three whole-block exports `GetEnvironmentStringsW`/`A`/
    #     `GetEnvironmentStrings` (three, because they are three separate
    #     bodies -- measured, not assumed);
    #   * each C runtime's OWN snapshot, taken from that block once at CRT
    #     startup and served by `getenv` thereafter, so a program linked
    #     against a CRT may never call a Win32 environment API at all. Both
    #     runtimes a Windows toolchain actually links are covered:
    #     `ucrtbase.dll` (`getenv`, `_wgetenv`, `getenv_s`, `_wgetenv_s`,
    #     `_dupenv_s`, `_wdupenv_s`) and `msvcrt.dll` (the same four minus
    #     `_dupenv_s`/`_wdupenv_s`, which it does not export).
    #
    # A whole-block read is expanded into per-name records ONLY when the
    # caller is the monitored program's own image. Every CRT reads the block
    # once at startup, in every process; expanding that would make every
    # Windows action depend on its entire environment, which is a monitor that
    # makes everything uncacheable.
    #
    # WHAT IS NOT COVERED, and it is a residual rather than a hole in the
    # claim: a program that walks the CRT's environment ARRAY directly --
    # `msvcrt!_environ`, `ucrtbase!__p__environ`/`__p__wenviron` -- performs no
    # call for a detour to intercept. This is the exact Windows counterpart of
    # the POSIX `environ` walk, which the macOS and Linux arms do not cover
    # either while advertising this same capability; the claim is "every
    # environment read that goes through a call", on all three platforms.
    mcapObservedEnv
  }

  # Capabilities with no Windows record kind behind them today. Reported as
  # gaps so the shortfall is visible rather than silently absent.
  #
  # EndpointSecurity / hybrid / authorization-enforcement are macOS
  # concepts with no Windows analogue at all. The rest are real gaps in
  # this backend: the entry points for several are hooked, but no record
  # kind carries the observation, so nothing reaches the depfile.
  #
  # M5 closed three of the eight gaps M4 declared -- ipc-connect,
  # non-determinism and external-content -- and DELIBERATELY left five open
  # rather than half-closing all eight. M10 then closed the one of those five
  # that was an INPUT channel, `mcapObservedEnv`, which is why the list is now
  # four. The ordering came from the consequence, not from effort: a missing
  # input channel is the only kind of gap that can produce a false
  # `mcComplete`. WHAT REMAINS IS OUTPUT-SIDE OR IDENTITY FIDELITY, none of it
  # inside `InputEvidenceCapabilities` and none of it inside
  # `InputChannelCapabilities`:
  #
  #   * mcapFileCreate / mcapFileTruncate / mcapFileAppend -- the access IS
  #     recorded, as an open/read/write; what is missing is the finer
  #     classification of the creation disposition. No input goes unseen.
  #   * mcapRename -- MoveFileExW/A is hooked and BOTH sides are recorded as
  #     writes, so the output tree is tracked; there is no distinct rename
  #     record kind. Output-side.
  #   * mcapPathMutation -- SetCurrentDirectory / DeleteFile / CreateDirectory
  #     are hooked and recorded as writes; there is no `mrPathMutation` record.
  #     Output-side.
  #   * mcapSymlink -- CreateSymbolicLinkW is not hooked and no path is
  #     resolved to its link target. Identity fidelity: a read THROUGH a
  #     symlink still records a path that resolves to the same bytes.
  #
  # `mcapObservedEnv` is NOT here any more. See the M10 block in
  # `WindowsInterposeSupportedCapabilities` for what the capability now claims
  # and for the one residual it does not (a direct walk of the CRT's `_environ`
  # array, which performs no call and is uncovered on POSIX too).
  WindowsInterposeKnownUnsupportedCapabilities* = {
    mcapEndpointSecurity,
    mcapHybrid,
    mcapAuthorizationEnforcement,
    mcapFileCreate,
    mcapFileTruncate,
    mcapFileAppend,
    mcapRename,
    mcapSymlink,
    mcapPathMutation,
    mcapAdversarialRawSyscall,
    mcapExecutableMappingLifecycle,
    mcapPathIdentity
  }

proc backendFamilyId*(family: MonitorBackendFamily): string =
  case family
  of mbfMacosHooks:
    "macos-interpose-hooks"
  of mbfMacosEndpointSecurity:
    "macos-endpoint-security"
  of mbfMacosHybrid:
    "macos-hybrid"
  of mbfLinuxPreloadHooks:
    "linux-preload-hooks"
  of mbfWindowsInterposeHooks:
    "windows-interpose-hooks"
  of mbfUnknown:
    "unknown"

proc capabilityId*(capability: MonitorCapability): string =
  case capability
  of mcapProcess:
    "process"
  of mcapFileRead:
    "file-read"
  of mcapFileWrite:
    "file-write"
  of mcapPathProbe:
    "path-probe"
  of mcapDirectoryEnumerate:
    "directory-enumerate"
  of mcapEventLoss:
    "event-loss"
  of mcapProcessTree:
    "process-tree"
  of mcapProcessExec:
    "process-exec"
  of mcapBackendProvenance:
    "backend-provenance"
  of mcapFileCreate:
    "file-create"
  of mcapFileTruncate:
    "file-truncate"
  of mcapFileAppend:
    "file-append"
  of mcapEndpointSecurity:
    "endpoint-security"
  of mcapHybrid:
    "hybrid"
  of mcapRename:
    "rename"
  of mcapSymlink:
    "symlink"
  of mcapLibraryLoad:
    "library-load"
  of mcapAuthorizationEnforcement:
    "authorization-enforcement"
  of mcapPathMutation:
    "path-mutation"
  of mcapIpcConnect:
    "ipc-connect"
  of mcapObservedEnv:
    "observed-env"
  of mcapNonDeterminism:
    "non-determinism"
  of mcapExternalContent:
    "external-content"
  of mcapAdversarialRawSyscall:
    "adversarial-raw-syscall"
  of mcapExecutableMappingLifecycle:
    "executable-mapping-lifecycle"
  of mcapPathIdentity:
    "path-identity"

proc capabilityFromId*(value: string): MonitorCapability =
  for capability in MonitorCapability:
    if capabilityId(capability) == value:
      return capability
  raise newException(ValueError, "unknown monitor capability: " & value)

proc backendFamilyFromId*(value: string): MonitorBackendFamily =
  for family in MonitorBackendFamily:
    if backendFamilyId(family) == value:
      return family
  mbfUnknown

proc parseCapabilityList(value: string): set[MonitorCapability] =
  if value.len == 0:
    return {}
  for item in value.split(','):
    if item.len > 0:
      result.incl capabilityFromId(item)

proc unsupportedReason(capability: MonitorCapability): string =
  case capability
  of mcapEndpointSecurity:
    # Designed + skeletoned under T3c (MacOS-EndpointSecurity-Backend.md;
    # src/io_mon/backends/endpoint_security.nim, behind -d:ioMonEndpointSecurity).
    # Still unsupported here: the production client needs the Apple-granted
    # endpoint-security.client entitlement + signing/notarization + root.
    "EndpointSecurity backend is designed + skeletoned (T3c) but not yet shipped; " &
      "production client is gated on the Apple endpoint-security.client entitlement"
  of mcapHybrid:
    "hybrid EndpointSecurity plus interpose profile is not implemented in M14"
  of mcapRename:
    # rename/renameat ARE now hooked on macOS (interpose + body-patch); this
    # branch is retained only for the Linux/other profiles that share this enum
    # and have not yet wired rename, and as a defensive default.
    "rename/renameat are hooked on the macOS interpose+body-patch shim; this " &
      "reason applies only where rename is not yet advertised"
  of mcapSymlink:
    "macOS interpose shim does not hook symlink/symlinkat/readlink yet"
  of mcapLibraryLoad:
    "macOS interpose shim does not hook dlopen/library-load events yet"
  of mcapAuthorizationEnforcement:
    "macOS interpose shim observes only and cannot authorize or deny operations"
  of mcapPathMutation:
    # ROUND-4 RW2: mkdir/mkdirat/rmdir/unlink/unlinkat/symlink/symlinkat (and
    # rename/renameat) ARE now hooked on the macOS interpose+body-patch shim and
    # recorded as `mrPathMutation` output records; this branch is retained only for
    # profiles that share this enum and have not wired the mutation surface, and as
    # a defensive default.
    "mkdir/rmdir/unlink/unlinkat/symlink are hooked on the macOS " &
      "interpose+body-patch shim; this reason applies only where path-mutation " &
      "is not yet advertised"
  of mcapAdversarialRawSyscall:
    "direct/raw syscall completeness requires a native kernel-sourced backend"
  of mcapExecutableMappingLifecycle:
    "executable mapping lifecycle completeness requires a native mapping source"
  of mcapPathIdentity:
    "path identity coverage for hardlink/inode aliases is not advertised by this profile"
  of mcapIpcConnect:
    # connect(2) IS hooked on the macOS interpose+body-patch shim; this branch is
    # retained only for profiles that share this enum and have not wired it, and
    # as a defensive default.
    "connect(2) is hooked on the macOS interpose+body-patch shim; this reason " &
      "applies only where IPC-connect is not yet advertised"
  of mcapObservedEnv:
    # getenv/sysctlbyname/sysctl/uname/gethostname/gethostuuid ARE hooked on the
    # macOS interpose shim (ROUND-2 R-D); this reason applies only where the
    # observed-env capability is not yet advertised.
    "getenv/sysctl/uname are hooked on the macOS interpose shim; this reason " &
      "applies only where observed-env recording is not yet advertised"
  of mcapNonDeterminism:
    "entropy/time sources are hooked on the macOS interpose shim; this reason " &
      "applies only where non-determinism handling is not yet advertised"
  else:
    "capability is not advertised by the selected macOS interpose profile"

proc windowsUnsupportedReason(capability: MonitorCapability): string =
  ## Why the Windows interpose backend does not advertise a capability.
  ##
  ## The distinction that matters here is between "no Win32 analogue exists"
  ## and "the entry point IS hooked but no record kind carries the
  ## observation". The second is a gap a reader can close; the first is not.
  case capability
  of mcapEndpointSecurity:
    "EndpointSecurity is a macOS kernel facility with no Windows analogue"
  of mcapHybrid:
    "hybrid native plus interpose profile is macOS-specific"
  of mcapAuthorizationEnforcement:
    "the Windows interpose shim observes only and cannot authorize or deny " &
      "operations"
  of mcapFileCreate, mcapFileTruncate, mcapFileAppend:
    "CreateFileW/A is hooked, but the shim does not yet classify the " &
      "creation disposition into create/truncate/append observations -- the " &
      "access is recorded as an open/read/write"
  of mcapRename:
    "MoveFileExW/A is hooked but no rename record kind is emitted"
  of mcapSymlink:
    "CreateSymbolicLinkW is not hooked and no symlink resolution is performed"
  of mcapLibraryLoad:
    "LoadLibrary is not hooked and the loaded-module set is not enumerated, " &
      "so a DLL the process maps is not recorded as a content dependency"
  of mcapPathMutation:
    "SetCurrentDirectory/DeleteFile/CreateDirectory are hooked but no " &
      "path-mutation record kind is emitted"
  of mcapIpcConnect:
    # M5: connect/WSAConnect ARE hooked and a named-pipe client open IS
    # classified with its server pid. This branch is retained only for
    # profiles that share this enum and have not wired it, and as a defensive
    # default.
    "connect/WSAConnect and named-pipe client opens are recorded by the " &
      "Windows interpose shim; this reason applies only where IPC-connect " &
      "is not yet advertised"
  of mcapObservedEnv:
    # M10: environment reads ARE recorded now, through both the Win32 block
    # and both C runtimes' getenv families. This branch is retained only for
    # profiles that share this enum and have not wired it, and as a defensive
    # default -- the same status the ipc-connect / non-determinism /
    # external-content branches took when M5 closed them.
    #
    # It is worth saying why the sentence this replaces mattered. It was the
    # one Windows gap that was an INPUT channel, and the record carried
    # `input=true` from `InputChannelCapabilities` precisely so a consumer did
    # not have to tell it apart from "renames are not classified" by reading
    # English. That machinery is unchanged and still distinguishes the four
    # remaining gaps, all of which are `input=false`.
    "environment reads are recorded as observed inputs by the Windows " &
      "interpose shim (kernel32's GetEnvironmentVariable/Strings plus the " &
      "getenv families of both ucrtbase and msvcrt); this reason applies " &
      "only where observed-env recording is not yet advertised"
  of mcapNonDeterminism:
    # M5: entropy (BCryptGenRandom / ProcessPrng / RtlGenRandom /
    # CryptGenRandom) and clocks (QueryPerformanceCounter /
    # GetSystemTimeAsFileTime / GetTickCount64) ARE hooked. Defensive default
    # only, as above.
    "entropy and clock sources are hooked on the Windows interpose shim; " &
      "this reason applies only where non-determinism handling is not yet " &
      "advertised"
  of mcapExternalContent:
    # M5: file mappings, anonymous pipes and NTFS alternate data streams ARE
    # covered. Defensive default only, as above.
    "file mappings, anonymous pipes and alternate data streams are recorded " &
      "by the Windows interpose shim; this reason applies only where " &
      "external-content coverage is not yet advertised"
  of mcapAdversarialRawSyscall:
    "direct NTDLL syscall stubs bypass the IAT and the detoured entry " &
      "points; no adversarial completeness is claimed"
  of mcapExecutableMappingLifecycle:
    "executable mapping lifecycle (VirtualAlloc/VirtualProtect of RX pages) " &
      "is not tracked"
  of mcapPathIdentity:
    "paths are recorded as the caller spelled them, without resolving to a " &
      "canonical file identity"
  else:
    "not supported by the Windows interpose backend"

proc linuxUnsupportedReason(capability: MonitorCapability): string =
  case capability
  of mcapEndpointSecurity:
    "EndpointSecurity is macOS-only; Linux native backend is future eBPF work"
  of mcapHybrid:
    "hybrid native plus preload profile is not implemented"
  of mcapRename:
    "Linux preload shim hooks libc-visible rename/renameat/renameat2; this " &
      "reason applies only where rename is not advertised"
  of mcapSymlink:
    "Linux preload shim does not yet normalize symlink/readlink as path mutations"
  of mcapLibraryLoad:
    "Linux preload shim observes the loader's link map (dl_iterate_phdr) and " &
      "emits library-load records; this reason applies only where library-load " &
      "observation is not advertised"
  of mcapAuthorizationEnforcement:
    "Linux preload shim observes only and cannot authorize or deny operations"
  of mcapPathMutation:
    "Linux preload shim records libc-visible link/linkat and " &
      "rename/renameat/renameat2 path mutations, but does not cover the full " &
      "raw mutation surface yet"
  of mcapAdversarialRawSyscall:
    "Linux LD_PRELOAD covers libc syscall(2), selected application inline " &
      "syscall sites, and tracked anonymous executable mappings, but does " &
      "not claim adversarial/direct raw-syscall completeness for excluded " &
      "runtime-prefix DSOs, executable mappings outside the preload mmap " &
      "lifecycle, or unclassified syscall families"
  of mcapExecutableMappingLifecycle:
    "Linux LD_PRELOAD scans executable mappings only when they are owned by " &
      "the preload mmap/mprotect/munmap/mremap lifecycle; mappings created " &
      "outside that lifecycle are not production-complete"
  of mcapPathIdentity:
    "Linux preload shim records libc-visible hardlink creation source/alias " &
      "and rename-staging final paths, but does not yet provide full " &
      "pre-existing hardlink/inode alias or raw-mutation identity fidelity"
  of mcapIpcConnect:
    "Linux preload shim hooks connect(2); this reason applies only where " &
      "IPC-connect is not advertised"
  of mcapObservedEnv:
    "Linux preload shim records libc-visible getenv/uname/sysconf observed " &
      "inputs; this reason applies only where direct raw/vDSO or broader " &
      "system-configuration coverage is required"
  of mcapNonDeterminism:
    "Linux preload shim records libc-visible clock_gettime/gettimeofday/time " &
      "as time reads and getrandom/getentropy/arc4random/arc4random_buf/" &
      "arc4random_uniform as non-determinism; this reason applies " &
      "only where direct raw or broader entropy/time APIs are required"
  of mcapExternalContent:
    "Linux preload shim records libc-visible positioned/vector and zero-copy " &
      "file movers, but broader external content channels and direct raw " &
      "zero-copy syscalls are not advertised by this profile"
  else:
    "capability is not advertised by the selected Linux preload profile"

proc gapDetail*(gap: MonitorCapabilityGap): string =
  ## `input=` goes BEFORE `reason=` deliberately: `reason` is free text and is
  ## therefore always last, so a key appended after it would be swallowed by
  ## the reason of any consumer that split on the first `;` after `reason=`.
  ## An older parser ignores the unknown key (`parseGapDetail`'s `else: discard`
  ## arm), so adding it does not break a depfile written before it existed.
  "backend=" & backendFamilyId(gap.backendFamily) &
    ";capability=" & capabilityId(gap.capability) &
    ";required=" & (if gap.required: "true" else: "false") &
    ";input=" & (if gap.inputChannel: "true" else: "false") &
    ";reason=" & gap.reason

proc parseGapDetail*(detail: string): MonitorCapabilityGap =
  result.backendFamily = mbfUnknown
  result.capability = mcapProcess
  var sawInput = false
  for part in detail.split(';'):
    let pair = part.split("=", 1)
    if pair.len != 2:
      continue
    case pair[0]
    of "backend":
      result.backendFamily = backendFamilyFromId(pair[1])
    of "capability":
      result.capability = capabilityFromId(pair[1])
    of "required":
      result.required = pair[1] == "true"
    of "input":
      result.inputChannel = pair[1] == "true"
      sawInput = true
    of "reason":
      result.reason = pair[1]
    else:
      discard
  if not sawInput:
    # A depfile written before `input=` existed. Derive it rather than leaving
    # it false: silently answering "not an input channel" for every gap in an
    # older capture is the same over-claim in a new place.
    result.inputChannel = result.capability in InputChannelCapabilities

proc capabilityGapRecord*(gap: MonitorCapabilityGap): MonitorRecord =
  MonitorRecord(
    kind: mrCapabilityGap,
    observationKind: moCapabilityGap,
    osPid: 0,
    parentOsPid: 0,
    threadId: 0,
    probeResult: prUnknown,
    path: capabilityId(gap.capability),
    detail: gapDetail(gap))

proc backendProfileRecord*(profile: MonitorBackendProfile): MonitorRecord =
  var caps: seq[string] = @[]
  for capability in profile.supportedCapabilities:
    caps.add capabilityId(capability)
  var requiredCaps: seq[string] = @[]
  for capability in profile.requiredCapabilities:
    requiredCaps.add capabilityId(capability)
  MonitorRecord(
    kind: mrBackendProfile,
    observationKind: moBackendProfile,
    osPid: 0,
    parentOsPid: 0,
    threadId: 0,
    probeResult: prUnknown,
    path: profile.profileName,
    detail: "backend=" & backendFamilyId(profile.backendFamily) &
      ";supported=" & caps.join(",") &
      ";required=" & requiredCaps.join(",") &
      ";evidenceComplete=" & (if profile.evidenceComplete: "true" else: "false"))

proc macosInterposeMonitorProfile*(
    required: set[MonitorCapability] = {}): MonitorBackendProfile =
  result.profileName = "macos-interpose-hooks-m14"
  result.backendFamily = mbfMacosHooks
  result.supportedCapabilities = MacosInterposeSupportedCapabilities
  result.requiredCapabilities = required
  result.evidenceComplete = true
  result.diagnostics.add MonitorDiagnostic(
    level: mdlInfo,
    message: "selected macOS interpose/hooks backend; EndpointSecurity and " &
      "hybrid backends are unavailable in M14")

  var gapCapabilities = MacosInterposeKnownUnsupportedCapabilities
  for capability in required:
    if capability notin result.supportedCapabilities:
      gapCapabilities.incl capability
      result.evidenceComplete = false

  for capability in gapCapabilities:
    let requiredGap = capability in required and
      capability notin result.supportedCapabilities
    result.gaps.add MonitorCapabilityGap(
      backendFamily: result.backendFamily,
      capability: capability,
      required: requiredGap,
      inputChannel: capability in InputChannelCapabilities,
      reason: unsupportedReason(capability))
    if requiredGap:
      result.diagnostics.add MonitorDiagnostic(
        level: mdlError,
        message: "required monitor capability is unsupported by " &
          backendFamilyId(result.backendFamily) & ": " &
          capabilityId(capability))

proc linuxPreloadMonitorProfile*(
    required: set[MonitorCapability] = {}): MonitorBackendProfile =
  result.profileName = "linux-preload-hooks-m14"
  result.backendFamily = mbfLinuxPreloadHooks
  result.supportedCapabilities = LinuxPreloadSupportedCapabilities
  result.requiredCapabilities = required
  result.evidenceComplete = true
  result.diagnostics.add MonitorDiagnostic(
    level: mdlInfo,
    message: "selected Linux LD_PRELOAD/hooks backend; future native eBPF " &
      "backend is unavailable in M14")
  result.diagnostics.add MonitorDiagnostic(
    level: mdlInfo,
    message: "Linux raw syscall coverage is stackable-backed; io-mon " &
      "classifies common file/probe syscalls from libc, main-executable, " &
      "startup non-system application-DSO, and late dlopen/dlmopen " &
      "application-DSO raw syscall sites, plus tracked anonymous/private " &
      "mmap/mprotect executable ranges with munmap/mremap lifecycle " &
      "bookkeeping; libc-visible pread/readv/preadv/sendfile/" &
      "copy_file_range/splice content movers record source reads and " &
      "destination writes; libc-visible link/linkat and rename/renameat/" &
      "renameat2 record hardlink source/alias and final rename destinations; " &
      "libc-visible getenv/uname/sysconf are observed inputs, " &
      "clock_gettime/gettimeofday/time are time-read evidence, and " &
      "getrandom/getentropy/arc4random/arc4random_buf/arc4random_uniform are " &
      "entropy evidence (deduped per process per source) left to caller " &
      "invalidation policy; " &
      "and io-mon fails closed for unsupported raw syscall numbers, " &
      "untracked or partially tracked anonymous executable mprotect, " &
      "partial-overlap mremap ownership escapes, or anonymous writable+" &
      "executable mappings")
  result.diagnostics.add MonitorDiagnostic(
    level: mdlWarning,
    message: "Linux LD_PRELOAD completeness excludes adversarial residuals " &
      "unless they are represented by event-loss at runtime: excluded-prefix " &
      "startup DSOs, executable mappings outside the preload mmap lifecycle, " &
      "direct raw zero-copy/mutation syscalls, pre-existing hardlink/inode " &
      "aliases, direct raw/vDSO non-file determinism paths, and broader Linux " &
      "non-file APIs beyond getenv/uname/sysconf/clock/gettimeofday/time/" &
      "getrandom/getentropy/arc4random(_buf|_uniform). " &
      "Consumers that require those " &
      "threat models must request the corresponding capability and treat the " &
      "gap as incomplete.")

  var gapCapabilities = LinuxPreloadKnownUnsupportedCapabilities
  for capability in required:
    if capability notin result.supportedCapabilities:
      gapCapabilities.incl capability
      result.evidenceComplete = false

  for capability in gapCapabilities:
    let requiredGap = capability in required and
      capability notin result.supportedCapabilities
    result.gaps.add MonitorCapabilityGap(
      backendFamily: result.backendFamily,
      capability: capability,
      required: requiredGap,
      inputChannel: capability in InputChannelCapabilities,
      reason: linuxUnsupportedReason(capability))
    if requiredGap:
      result.diagnostics.add MonitorDiagnostic(
        level: mdlError,
        message: "required monitor capability is unsupported by " &
          backendFamilyId(result.backendFamily) & ": " &
          capabilityId(capability))

proc windowsInterposeMonitorProfile*(
    required: set[MonitorCapability] = {}): MonitorBackendProfile =
  result.profileName = "windows-interpose-hooks-m14"
  result.backendFamily = mbfWindowsInterposeHooks
  result.supportedCapabilities = WindowsInterposeSupportedCapabilities
  result.requiredCapabilities = required
  result.evidenceComplete = true
  result.diagnostics.add MonitorDiagnostic(
    level: mdlInfo,
    message: "selected Windows interpose/hooks backend (inline detours with " &
      "an IAT-patching fallback, injected via CreateRemoteThread)")
  result.diagnostics.add MonitorDiagnostic(
    level: mdlInfo,
    message: "M5 coverage: connect/WSAConnect plus named-pipe client opens " &
      "are recorded as ipc-connect (the pipe peer carries its server pid " &
      "from GetNamedPipeServerProcessId; a socket peer is reported unknown " &
      "and treated conservatively); named file mappings, anonymous pipes and " &
      "NTFS alternate data streams are recorded as external content, and a " &
      "mapped view of a file is recorded as a read of that file; entropy " &
      "(BCryptGenRandom, ProcessPrng, RtlGenRandom, CryptGenRandom) and " &
      "clocks (QueryPerformanceCounter, GetSystemTimeAsFileTime, " &
      "GetTickCount64) are recorded as evidence that never downgrades")
  result.diagnostics.add MonitorDiagnostic(
    level: mdlWarning,
    message: "Windows non-determinism coverage is limited to calls through " &
      "the exported entry points. GetTickCount64 and GetSystemTimeAsFileTime " &
      "are served from KUSER_SHARED_DATA, and a program that reads that page " &
      "directly -- or issues rdtsc -- performs NO call for a detour to " &
      "intercept, so such a read is neither observed nor detected. Entropy " &
      "and clock observations are recorded once per source per caller origin " &
      "(program vs system image), so they are evidence that a source was " &
      "used, not a count of uses.")
  result.diagnostics.add MonitorDiagnostic(
    level: mdlInfo,
    message: "M10 coverage: environment reads are recorded as observed " &
      "declared inputs (mrEnvRead, the variable name, deduped " &
      "case-insensitively per process, never downgrading). Windows keeps two " &
      "copies of the environment and a program reads exactly one, so both " &
      "are hooked: the PEB block through kernel32 " &
      "GetEnvironmentVariableW/A and GetEnvironmentStringsW/A/" &
      "GetEnvironmentStrings, and each C runtime's own startup snapshot " &
      "through its getenv family -- ucrtbase (getenv, _wgetenv, getenv_s, " &
      "_wgetenv_s, _dupenv_s, _wdupenv_s) and msvcrt (the same minus " &
      "_dupenv_s/_wdupenv_s, which it does not export). A lookup that found " &
      "nothing is recorded too: absence is a dependency. The monitor's own " &
      "per-run control variables (REPRO_MONITOR_*, IO_MON_*) are excluded, " &
      "because folding them into a consumer's cache key would change that " &
      "key on every run.")
  result.diagnostics.add MonitorDiagnostic(
    level: mdlWarning,
    message: "Windows observed-env coverage is limited to reads that go " &
      "through a CALL. A program that walks the C runtime's environment " &
      "ARRAY directly -- msvcrt's _environ, ucrtbase's __p__environ / " &
      "__p__wenviron -- performs no call for a detour to intercept, so such " &
      "a read is neither observed nor detected. This is the Windows " &
      "counterpart of the POSIX environ walk, which the macOS and Linux arms " &
      "do not cover either. A whole-block read (GetEnvironmentStrings*) is " &
      "expanded into one record per variable only when the CALLER is the " &
      "monitored program's own image: every C runtime reads the block once " &
      "at startup in every process, and expanding that would make every " &
      "action depend on its entire environment. A program whose block read " &
      "comes through a bundled DLL is attributed to the system image and " &
      "gets no expansion; its named reads are still recorded.")

  var gapCapabilities = WindowsInterposeKnownUnsupportedCapabilities
  for capability in required:
    if capability notin result.supportedCapabilities:
      gapCapabilities.incl capability
      result.evidenceComplete = false

  for capability in gapCapabilities:
    let requiredGap = capability in required and
      capability notin result.supportedCapabilities
    result.gaps.add MonitorCapabilityGap(
      backendFamily: result.backendFamily,
      capability: capability,
      required: requiredGap,
      inputChannel: capability in InputChannelCapabilities,
      reason: windowsUnsupportedReason(capability))
    if requiredGap:
      result.diagnostics.add MonitorDiagnostic(
        level: mdlError,
        message: "required monitor capability is unsupported by " &
          backendFamilyId(result.backendFamily) & ": " &
          capabilityId(capability))

proc defaultHooksMonitorProfile*(
    required: set[MonitorCapability] = {}): MonitorBackendProfile =
  when defined(linux):
    linuxPreloadMonitorProfile(required)
  elif defined(windows):
    windowsInterposeMonitorProfile(required)
  else:
    macosInterposeMonitorProfile(required)

proc profileRecords*(profile: MonitorBackendProfile): seq[MonitorRecord] =
  result.add backendProfileRecord(profile)
  for gap in profile.gaps:
    result.add capabilityGapRecord(gap)

proc profileFromRecords*(records: openArray[MonitorRecord];
                         required: set[MonitorCapability] = {}):
                         MonitorBackendProfile =
  result = defaultHooksMonitorProfile(required)
  var sawProfile = false
  var gaps: seq[MonitorCapabilityGap] = @[]
  for record in records:
    case record.kind
    of mrBackendProfile:
      sawProfile = true
      for part in record.detail.split(';'):
        let pair = part.split("=", 1)
        if pair.len != 2:
          continue
        case pair[0]
        of "backend":
          result.backendFamily = backendFamilyFromId(pair[1])
        of "supported":
          result.supportedCapabilities = parseCapabilityList(pair[1])
        of "required":
          result.requiredCapabilities = parseCapabilityList(pair[1])
        of "evidenceComplete":
          result.evidenceComplete = pair[1] == "true"
        else:
          discard
    of mrCapabilityGap:
      try:
        var gap = parseGapDetail(record.detail)
        if gap.capability in required and
            gap.capability notin result.supportedCapabilities:
          gap.required = true
        gaps.add gap
      except ValueError:
        result.diagnostics.add MonitorDiagnostic(
          level: mdlWarning,
          message: "malformed monitor capability gap record: " & record.detail)
    else:
      discard

  if sawProfile and gaps.len > 0:
    result.gaps = gaps

  for capability in required:
    result.requiredCapabilities.incl capability
    if capability notin result.supportedCapabilities:
      result.evidenceComplete = false
      var found = false
      for gap in result.gaps.mitems:
        if gap.capability == capability:
          gap.required = true
          found = true
      if not found:
        result.gaps.add MonitorCapabilityGap(
          backendFamily: result.backendFamily,
          capability: capability,
          required: true,
          inputChannel: capability in InputChannelCapabilities,
          reason: if result.backendFamily == mbfLinuxPreloadHooks:
              linuxUnsupportedReason(capability)
            else:
              unsupportedReason(capability))

proc evaluateMonitorEvidence*(dep: MonitorDepFile;
                              required: set[MonitorCapability]):
                              MonitorBackendProfile =
  result = profileFromRecords(dep.records, required)
  if dep.summary.eventLossCount != 0:
    result.evidenceComplete = false
    result.diagnostics.add MonitorDiagnostic(
      level: mdlError,
      message: "monitor evidence contains event-loss records")
