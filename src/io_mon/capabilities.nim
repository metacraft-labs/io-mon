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
    # ROUND-2 R-D (break R10) — non-file determinism inputs. getenv / sysctlbyname /
    # sysctl / uname / gethostname / gethostuuid are hooked and recorded as OBSERVED
    # DECLARED INPUTS (mcapObservedEnv); getentropy / arc4random* / a /dev/urandom
    # open are flagged non-deterministic (auto-downgrade) and clock_gettime /
    # gettimeofday / time / mach_absolute_time are recorded-not-downgraded
    # (mcapNonDeterminism).
    mcapObservedEnv,
    mcapNonDeterminism,
    # ROUND-3 S1 — content-channel coverage: xattr metadata reads, POSIX shared
    # memory, FIFO / inherited socket-pipe content, and sendfile/pread/readv.
    mcapExternalContent
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
    mcapAuthorizationEnforcement,
    mcapPathMutation
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
    mcapExternalContent
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
    mcapIpcConnect
  }

  LinuxPreloadKnownUnsupportedCapabilities* = {
    mcapEndpointSecurity,
    mcapHybrid,
    mcapRename,
    mcapSymlink,
    mcapLibraryLoad,
    mcapAuthorizationEnforcement,
    mcapPathMutation,
    mcapAdversarialRawSyscall,
    mcapExecutableMappingLifecycle,
    mcapPathIdentity,
    # ROUND-2 R-D — the Linux preload shim does not yet hook getenv/sysctl/uname or
    # the entropy/time sources; non-file determinism handling is macOS-only so far.
    mcapObservedEnv,
    mcapNonDeterminism,
    # ROUND-3 S1 — xattr/shm/FIFO/sendfile content-channel hooks are macOS-only so far.
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
    "macOS interpose shim does not cover the full mutation surface yet"
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

proc linuxUnsupportedReason(capability: MonitorCapability): string =
  case capability
  of mcapEndpointSecurity:
    "EndpointSecurity is macOS-only; Linux native backend is future eBPF work"
  of mcapHybrid:
    "hybrid native plus preload profile is not implemented"
  of mcapRename:
    "Linux preload shim does not yet normalize rename/renameat as path mutations"
  of mcapSymlink:
    "Linux preload shim does not yet normalize symlink/readlink as path mutations"
  of mcapLibraryLoad:
    "Linux preload shim does not yet emit library-load records"
  of mcapAuthorizationEnforcement:
    "Linux preload shim observes only and cannot authorize or deny operations"
  of mcapPathMutation:
    "Linux preload shim does not cover the full mutation surface yet"
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
    "Linux preload shim does not yet provide full hardlink/inode alias and " &
      "rename-staging path identity fidelity"
  of mcapIpcConnect:
    "Linux preload shim hooks connect(2); this reason applies only where " &
      "IPC-connect is not advertised"
  of mcapObservedEnv:
    "Linux preload shim does not yet hook getenv/sysctl/uname as observed inputs"
  of mcapNonDeterminism:
    "Linux preload shim does not yet hook entropy/time sources for non-determinism"
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
      "destination writes, and io-mon fails closed for unsupported raw syscall numbers, " &
      "untracked or partially tracked anonymous executable mprotect, " &
      "partial-overlap mremap ownership escapes, or anonymous writable+" &
      "executable mappings")
  result.diagnostics.add MonitorDiagnostic(
    level: mdlWarning,
    message: "Linux LD_PRELOAD completeness excludes adversarial residuals " &
      "unless they are represented by event-loss at runtime: excluded-prefix " &
      "startup DSOs, executable mappings outside the preload mmap lifecycle, " &
      "direct raw zero-copy/mutation syscalls, hardlink/path-identity aliases, and " &
      "non-file determinism inputs. Consumers that require those threat models " &
      "must request the corresponding capability and treat the gap as incomplete.")

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

proc defaultHooksMonitorProfile*(
    required: set[MonitorCapability] = {}): MonitorBackendProfile =
  when defined(linux):
    linuxPreloadMonitorProfile(required)
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
