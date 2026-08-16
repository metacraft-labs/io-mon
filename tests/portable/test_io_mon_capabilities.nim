## Capability-surface tests for production consumers. These are pure RMDF/profile
## checks: they do not depend on a live shim, but they exercise the same
## backend-profile records that merged depfiles carry.

import std/[sequtils, unittest]

import io_mon

suite "io-mon capability profiles":

  test "Linux LD_PRELOAD profile gaps adversarial residual requirements":
    # `mcapLibraryLoad` is deliberately NOT in this set any more: the Linux
    # shim now observes the loader's link map (`dl_iterate_phdr`) and emits
    # library-load records, so it is an ADVERTISED capability. It has its own
    # test below. The entries that remain are the genuine residuals.
    let required = {
      mcapAdversarialRawSyscall,
      mcapExecutableMappingLifecycle,
      mcapExternalContent,
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
    # `mcapLibraryLoad` is deliberately NOT in this set any more: the Linux
    # shim now observes the loader's link map (`dl_iterate_phdr`) and emits
    # library-load records, so it is an ADVERTISED capability. It has its own
    # test below. The entries that remain are the genuine residuals.
    let required = {
      mcapAdversarialRawSyscall,
      mcapExecutableMappingLifecycle,
      mcapExternalContent,
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

  test "library-load is an advertised Linux capability, and it is load-bearing":
    # The capability flip is a PROMISE — that a monitored process's runtime
    # shared-library closure was actually observed. Two halves, both asserted:
    let profile = linuxPreloadMonitorProfile()
    check mcapLibraryLoad in profile.supportedCapabilities
    check not profile.gaps.anyIt(it.capability == mcapLibraryLoad)

    # ...and that it is one of the capabilities whose ABSENCE forces a
    # downgrade. Without this, flipping the capability back would silently
    # restore the original defect (a declared gap coexisting with mcComplete)
    # rather than turning the capture mcIncomplete.
    check mcapLibraryLoad in InputEvidenceCapabilities

  test "a missing INPUT-EVIDENCE capability downgrades with an empty consumer ask":
    # THE PLUMBING REGRESSION. `depFileFromOwnedRecords` used to derive the
    # profile with an empty required-set, so a declared capability gap was
    # always emitted with `required=false` and could never clear
    # `evidenceComplete`. A backend could therefore declare that it cannot
    # observe an entire input channel and still report `mcComplete` — which is
    # exactly what Linux did for library loads.
    #
    # The consumer here asks for NOTHING. The downgrade must happen anyway,
    # because the depfile's own `mcComplete` is a claim about input coverage,
    # not about whatever this particular consumer remembered to request.
    var profile = linuxPreloadMonitorProfile()
    profile.supportedCapabilities.excl mcapLibraryLoad
    profile.gaps.add MonitorCapabilityGap(
      backendFamily: mbfLinuxPreloadHooks,
      capability: mcapLibraryLoad,
      required: false,
      reason: "simulated: backend cannot observe library loads")
    var records = profileRecords(profile)
    records.add MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead,
      osPid: 10, threadId: 10, path: "/tmp/input")

    let dep = depFileFromRecords(records)
    check dep.completeness == mcIncomplete
    check dep.capabilityGaps.anyIt(
      it.capability == mcapLibraryLoad and it.required)

  test "a NON-input capability gap does not destroy the completeness signal":
    # The over-correction guard, and the reason the downgrade set is
    # `InputEvidenceCapabilities` rather than "every declared gap". Linux
    # permanently does not support EndpointSecurity (a macOS backend) and does
    # not enforce authorization (io-mon observes, it never claimed to deny).
    # If those downgraded, every Linux capture would be mcIncomplete forever and
    # the signal would carry no information at all — a different way of being
    # useless, not a fix.
    check mcapEndpointSecurity notin InputEvidenceCapabilities
    check mcapAuthorizationEnforcement notin InputEvidenceCapabilities
    check mcapPathMutation notin InputEvidenceCapabilities

    var records = profileRecords(linuxPreloadMonitorProfile())
    records.add MonitorRecord(
      kind: mrFileRead, observationKind: moFileRead,
      osPid: 10, threadId: 10, path: "/tmp/input")
    let dep = depFileFromRecords(records)
    check dep.completeness == mcComplete
