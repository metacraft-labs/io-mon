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
    # getrandom is entropy evidence. Direct raw/vDSO variants remain outside
    # this positive capability.
    mcapObservedEnv,
    mcapNonDeterminism
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
    mcapLibraryLoad
  }

  # Capabilities with no Windows record kind behind them today. Reported as
  # gaps so the shortfall is visible rather than silently absent.
  # 
  # EndpointSecurity / hybrid / authorization-enforcement are macOS
  # concepts with no Windows analogue at all. The rest are real gaps in
  # this backend: the entry points for several are hooked, but no record
  # kind carries the observation, so nothing reaches the depfile.
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
    mcapIpcConnect,
    mcapObservedEnv,
    mcapNonDeterminism,
    mcapAdversarialRawSyscall,
    mcapExecutableMappingLifecycle,
    mcapPathIdentity,
    mcapExternalContent
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
    "no socket hooks; a named-pipe or socket peer is not identified, so an " &
      "out-of-tree breakaway daemon cannot be distinguished from an " &
      "in-tree process"
  of mcapObservedEnv:
    "environment and system-info queries are not recorded as observed inputs"
  of mcapNonDeterminism:
    "entropy and clock sources are not hooked, so a randomness or time read " &
      "leaves no evidence"
  of mcapExternalContent:
    "shared-memory, pipe and alternate-data-stream content channels are not " &
      "covered"
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
      "as time reads and getrandom as non-determinism; this reason applies " &
      "only where direct raw/vDSO or broader entropy/time APIs are required"
  of mcapExternalContent:
    "Linux preload shim records libc-visible positioned/vector and zero-copy " &
      "file movers, but broader external content channels and direct raw " &
      "zero-copy syscalls are not advertised by this profile"
  else:
    "capability is not advertised by the selected Linux preload profile"

proc gapDetail*(gap: MonitorCapabilityGap): string =
  "backend=" & backendFamilyId(gap.backendFamily) &
    ";capability=" & capabilityId(gap.capability) &
    ";required=" & (if gap.required: "true" else: "false") &
    ";reason=" & gap.reason

proc parseGapDetail*(detail: string): MonitorCapabilityGap =
  result.backendFamily = mbfUnknown
  result.capability = mcapProcess
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
    of "reason":
      result.reason = pair[1]
    else:
      discard

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
      "getrandom is entropy evidence left to caller invalidation policy; " &
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
      "getrandom. Consumers that require those " &
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
