## A monitored child that runs with a hardware shadow stack must survive its
## own injection -- as the ROOT of the monitored tree and as a GRANDCHILD.
##
## Live on purpose, like `test_io_mon_windows_process_start_survives.nim`:
## the defect is in how a child is injected, which no synthetic fragment can
## see.
##
## WHAT BROKE. Both injection paths -- the root injector and the shim's own
## `CreateProcessW` hook -- borrow the child's parked main thread to call
## `LoadLibraryW` and the shim's init export
## (`stackable_hooks/windows_entry_park.callOnParkedThread`). That proc used
## to fake the call: it wrote a return address onto the ordinary stack and
## pointed `RIP` at the callee, so no `call` ever reached the shadow stack.
## Every image linked `/CETCOMPAT` runs with user-mode shadow stacks on a host
## that enforces them (Intel CET, "Hardware-enforced Stack Protection"), and
## there the callee's `ret` raised `#CP`: the child died with
## STATUS_STACK_BUFFER_OVERRUN (0xC0000409), fast-fail subcode 0x39
## FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS, before running a single
## instruction of its own.
##
## How it showed up: reprobuild's interface-extraction edge runs a long
## `nim c` through `pwsh` (a `/CETCOMPAT` .NET apphost), as a grandchild of
## the monitored `repro` helper. `pwsh` died at injection, and the edge
## reported `nim.exe ... command failed (-1073740791)` for a compiler that had
## never been started. `repro build .#apps` could not get past it on Windows
## from 2026-09-18 to 2026-10-05.
##
## THE FIXTURE is `%SystemRoot%\System32\curl.exe --version`: it ships with
## every supported Windows 10/11, it is linked `/CETCOMPAT`, and it exits 0
## without touching the network. On a host without CET hardware the cases
## still have to pass but cannot discriminate; the precise, host-reporting
## gate for the borrowed call itself is nim-stackable-hooks'
## `tests/test_windows_entry_park_shadow_stack.nim`.

when not defined(windows):
  {.error: "windows-only test".}

import descendant_guard_expectations
import std/[os, strutils, tempfiles, unittest]

import io_mon
import io_mon/fs_snoop

proc curlExe(): string =
  getEnv("SystemRoot", r"C:\Windows") / "System32" / "curl.exe"

proc monitor(command: seq[string]; depFilePath: string): MonitorResult =
  var request = FsSnoopRequest(
    command: command,
    depFilePath: depFilePath,
    passthroughChildStdout: false,
    passthroughChildStderr: false,
    captureChildStdio: true)
  runMonitored(request)

suite "Windows: a /CETCOMPAT child survives injection":
  test "as the root of the monitored tree":
    require fileExists(curlExe())
    let dir = createTempDir("io_mon_cetcompat_root_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard
    let result = monitor(@[curlExe(), "--version"], dir / "run.iomon")
    # Before the fix this case did not even get an exit code: the root
    # injector's borrowed `LoadLibraryW` killed `curl` with 0xC0000409 and
    # `runMonitored` raised "the parked child's main thread could not be
    # borrowed to load the shim".
    checkpoint("exit code " & $result.exitCode)
    check result.exitCode == 0
    # Surviving is not enough: the child must also have been MONITORED. A
    # monitoring failure looks like a process with no dependencies, so the
    # grade is what is asserted (see tests/windows/README.md).
    check subsystemEvidence(result).completeness == mcComplete
    var rootStarted = false
    for r in result.records:
      if r.kind == mrProcessStart:
        rootStarted = true
    check rootStarted

  test "as a grandchild injected by the shim's CreateProcessW hook":
    require fileExists(curlExe())
    let dir = createTempDir("io_mon_cetcompat_grandchild_", "")
    defer:
      try: removeDir(dir)
      except CatchableError: discard
    # `cmd.exe` is not `/CETCOMPAT`, so the root injection is not what is
    # under test here: the shim inside `cmd` injects `curl`.
    let result = monitor(@[getEnv("ComSpec", r"C:\Windows\System32\cmd.exe"),
      "/d", "/c", curlExe() & " --version"], dir / "run.iomon")
    # Before the fix `curl` died inside the shim's borrowed `LoadLibraryW`
    # (0xC0000409, subcode 0x39, measured under `cdb -o`) and the run
    # reported 0xC0000005 (3221225477) to this test, deterministically.
    checkpoint("exit code " & $result.exitCode)
    check result.exitCode == 0
    # The grandchild must have been spawned under monitoring, injected
    # without a recorded failure, AND have reported in. The root's own
    # synthetic `io-mon-root-spawn` record also carries a child pid and no
    # `inject=`, so a check that only looks for "some spawn record without
    # `inject=`" passes even when `curl` was never injected; it has to be
    # `curl`'s own `CreateProcessW` record, paired with `curl`'s
    # `mrProcessStart`, and the run must grade complete. Measured: a shim
    # whose borrowed `LoadLibraryW` is forced to time out leaves `curl`
    # running uninjected (exit 0, `inject=ioInjectFailed`, `mcIncomplete`),
    # and only these assertions catch it.
    check subsystemEvidence(result).completeness == mcComplete
    var curlPid = 0'u64
    for r in result.records:
      if r.kind == mrProcessSpawn and r.childOsPid != 0 and
          r.detail.startsWith("CreateProcessW") and
          "curl.exe" in r.path.toLowerAscii:
        checkpoint("curl spawn record: " & r.detail)
        if "inject=" notin r.detail:
          curlPid = r.childOsPid
    check curlPid != 0
    var curlStarted = false
    for r in result.records:
      if r.kind == mrProcessStart and r.osPid == curlPid:
        curlStarted = true
    check curlStarted
