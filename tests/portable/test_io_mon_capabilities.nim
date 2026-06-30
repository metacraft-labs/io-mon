## Capability-surface tests for production consumers. These are pure RMDF/profile
## checks: they do not depend on a live shim, but they exercise the same
## backend-profile records that merged depfiles carry.

import std/[sequtils, unittest]

import io_mon

suite "io-mon capability profiles":

  test "Linux LD_PRELOAD profile gaps adversarial residual requirements":
    let required = {
      mcapAdversarialRawSyscall,
      mcapExecutableMappingLifecycle,
      mcapExternalContent,
      mcapLibraryLoad,
      mcapPathMutation,
      mcapPathIdentity
    }

    let profile = linuxPreloadMonitorProfile(required)

    check profile.backendFamily == mbfLinuxPreloadHooks
    check profile.evidenceComplete == false
    for capability in required:
      check capability notin profile.supportedCapabilities
      check profile.gaps.anyIt(
        it.capability == capability and it.required and it.reason.len > 0)

  test "required Linux residual gaps make depfile evidence incomplete":
    let required = {
      mcapAdversarialRawSyscall,
      mcapExecutableMappingLifecycle,
      mcapExternalContent,
      mcapLibraryLoad,
      mcapPathMutation,
      mcapPathIdentity
    }
    var records = profileRecords(linuxPreloadMonitorProfile(required))
    records.add MonitorRecord(
      kind: mrFileRead,
      observationKind: moFileRead,
      osPid: 10,
      threadId: 10,
      path: "/tmp/input")

    let dep = depFileFromRecords(records)
    let evidence = evaluateMonitorEvidence(dep, required)

    check dep.backendFamily == mbfLinuxPreloadHooks
    check dep.completeness == mcIncomplete
    check evidence.evidenceComplete == false
    check evidence.gaps.countIt(it.required) >= required.len
    for capability in required:
      check evidence.gaps.anyIt(it.capability == capability and it.required)

  test "Linux profile still advertises captured M-FW-4 raw syscall slices honestly":
    let profile = linuxPreloadMonitorProfile()

    check mcapFileRead in profile.supportedCapabilities
    check mcapPathProbe in profile.supportedCapabilities
    check mcapIpcConnect in profile.supportedCapabilities
    check mcapObservedEnv in profile.supportedCapabilities
    check mcapNonDeterminism in profile.supportedCapabilities
    check mcapAdversarialRawSyscall notin profile.supportedCapabilities
    check mcapExecutableMappingLifecycle notin profile.supportedCapabilities

  test "Linux profile advertises M-FW-6C libc-visible non-file subset":
    let profile = linuxPreloadMonitorProfile({mcapObservedEnv, mcapNonDeterminism})

    check profile.evidenceComplete
    check mcapObservedEnv in profile.supportedCapabilities
    check mcapNonDeterminism in profile.supportedCapabilities
    check not profile.gaps.anyIt(it.capability == mcapObservedEnv and it.required)
    check not profile.gaps.anyIt(it.capability == mcapNonDeterminism and it.required)
