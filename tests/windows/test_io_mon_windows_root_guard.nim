## test_io_mon_windows_root_guard — the ROUND-2 R1 root-guard, now ARMED on
## Windows.
##
## WHAT IS NEW HERE (this is capability, not a regression fix). macOS and Linux
## have always handed `mergeFragments` the pid of the root they spawned, so the
## merge can PROVE the root reported. Windows never has: the arm referencing
## `injection.rootPid` did not compile until IoMon-Decomposed-Host-API DH-1, and
## even then `WindowsInjectionResult` carried no such field, so DH-1 passed the
## honest `expectedRootPid = 0`. nim-stackable-hooks 485a30c added `rootPid`
## (the pid `CreateProcessW` produced); io-mon now passes it.
##
## What that changes, in one sentence: an injected root that emits NOTHING used
## to be published as `mcComplete` over an empty record set — a zero-effort
## false cache hit for the whole action — and is now downgraded to
## `mcIncomplete`.
##
## THE DEFECT REPRODUCED. The `fs_snoop.nim` call site names it: "a WOW64 child
## whose shim loaded but never initialised emitted nothing at all". No 32-bit
## toolchain is needed to produce that state — point `REPRO_MONITOR_SHIM_LIB` at
## a DLL that loads cleanly and exports no `repro_runtime_init`. `kernel32.dll`
## is exactly that, and is already used as a stand-in shim by
## `test_io_mon_windows_msys_fallback.nim`. `runWithMonitorShim` then:
## `CreateProcessW` succeeds; `LoadLibraryW` in the child succeeds, so injection
## is NOT skipped and `monitoringSkipped` stays false; the init export is not
## found, so no hooks are installed; the child runs and exits having written no
## fragment at all. That is precisely a monitoring failure wearing the costume of
## "this process had no dependencies", which is why asserting on the records that
## ARE present cannot catch it and the completeness grade must be asserted too
## (see this directory's README).
##
## COVERAGE STATUS — READ BEFORE TRUSTING THIS FILE. It has never been executed.
## The workspace it was written in has no Windows toolchain; it was verified only
## by `nim check --os:windows --cpu:amd64`, which proves it compiles and type-
## checks and proves nothing about its runtime behaviour. Its PREMISE is not
## taken on trust, though: that an empty fragment set grades `mcComplete` under
## `expectedRootPid = 0` and `mcIncomplete` under a real pid is asserted
## EXECUTABLY on the development host by
## `tests/portable/test_io_mon_t0_completeness.nim`, suite "io-mon R1
## ROOT-process completeness guard (mergeFragments)".

import std/[os, tempfiles, unittest]

import io_mon

proc runUninitialisedShimRoot(inertShim, cmdExe: string): MonitorResult =
  ## Monitor a native root under a DLL that loads but never initialises, and
  ## return the evidence. Deliberately assertion-free: `check` inside a plain
  ## `proc` prints "Check failed" and still reports `[OK]`, so every assertion
  ## belongs in the `test` block below.
  let work = createTempDir("io-mon-", "-win-root-guard")
  # `findShimLibrary` resolves `REPRO_MONITOR_SHIM_LIB` from the LAUNCHER's own
  # environment — the override is a host-side lookup, not part of the injection
  # set DH-1 moved into the child — so setting it here is test setup and not a
  # reintroduction of the `putEnv` this milestone removed.
  let hadOverride = existsEnv(ShimLibOverrideEnv)
  let oldOverride = getEnv(ShimLibOverrideEnv)
  putEnv(ShimLibOverrideEnv, inertShim)
  try:
    result = runMonitored(FsSnoopRequest(
      command: @[cmdExe, "/c", "exit 0"],
      depFilePath: work / "evidence.iomon"))
  finally:
    if hadOverride: putEnv(ShimLibOverrideEnv, oldOverride)
    else: delEnv(ShimLibOverrideEnv)
    try: removeDir(work)
    except OSError: discard

suite "Windows R1 root-guard (an injected root that reports nothing)":
  test "a root whose shim never initialises grades mcIncomplete":
    let systemRoot = getEnv("SystemRoot", r"C:\Windows")
    let inertShim = systemRoot / "System32" / "kernel32.dll"
    let cmdExe = systemRoot / "System32" / "cmd.exe"
    require fileExists(inertShim)
    require fileExists(cmdExe)

    let monitored = runUninitialisedShimRoot(inertShim, cmdExe)

    # The child really ran…
    check monitored.exitCode == 0
    # …and really was not monitored: no process-start reached the depfile.
    var starts = 0
    for record in monitored.records:
      if record.kind == mrProcessStart:
        inc starts
    check starts == 0
    # So the edge must say so rather than publish an empty set as complete.
    #
    # MUTATION, PREDICTED AND NOT OBSERVED: pass `0'u64` as `expectedRootPid` in
    # the Windows arm of `fs_snoop.runMonitored` and this line should redden with
    # `mcComplete`. That was RUN from the development host and it did NOT redden
    # anything, because the only check available here is `nim check --os:windows`
    # and a type-correct value swap is invisible to it. Nothing in this workspace
    # can confirm the prediction — it rests on the merge behaviour, which IS
    # asserted executably (`tests/portable/test_io_mon_t0_completeness.nim`,
    # where disarming the guard in `mergeFragments` does redden), plus the
    # assumption that this arm reaches that merge on a real Windows host.
    check monitored.completeness == mcIncomplete
