## test_io_mon_windows_spawn_abandoned_injection — a child the injector had
## to TERMINATE fails the spawn; it is never resumed.
##
## THE DEFECT
## ----------
## The injector (nim-stackable-hooks) maps this shim into a child by borrowing
## the child's parked main thread for ``LoadLibraryW`` and then for
## ``repro_runtime_init``. It used to give up after 5 s, return
## ``ioInjectFailed`` / ``ioInitFailed`` with the thread suspended MID-CALL,
## and leave ``snoopCreateProcessW``'s ``finally`` to resume it. The child
## then finished the borrowed call and returned into its real entry point on
## the borrowed stack. On an I/O-starved Windows CI host that is how gcc died,
## with "SIGSEGV: Illegal storage access" printed by this shim's own Nim signal
## handler (the shim was built without ``-d:noSignalHandler``; see
## ``src/io_mon/shim/windows_interpose.nim.cfg``).
##
## The injector now waits while the child lives. When a borrowed call outlives
## the HARD deadline, it terminates the child instead of resuming it
## (``ioChildTerminated``). This file pins the shim's half of that contract:
## ``CreateProcessW`` must FAIL, returning ``FALSE`` with ``ERROR_TIMEOUT``,
## with the handles closed and ``PROCESS_INFORMATION`` zeroed. The resume the
## hook owes the child is cancelled, and the child's own exit code is never
## observed.
##
## HOW THE SLOW PATH IS FORCED, FOR REAL
## -------------------------------------
## ``selfDllPath()`` is pointed at ``tests/windows/fixtures/slow_load_lib.nim``,
## a real DLL whose ``DllMain`` sleeps for ``IO_MON_TEST_SLOW_LOAD_MS``. The
## child is a real ``cmd.exe /c exit 42``. The park is real, and so are the
## borrowed ``LoadLibraryW``, the deadline and the termination. The only thing
## the test changes is ``spawnInjectionConfig.parkTimeoutMs``, shortened so
## the deadline expires in seconds rather than minutes.
##
## MOCKS, AND WHY THIS ONE IS JUSTIFIED
## -----------------------------------
## One, the same as ``test_io_mon_windows_spawn_resume``: the hook chain's
## ``original`` is a stub that calls the REAL ``kernel32!CreateProcessW``.
## Patching this test process's own ``kernel32`` would instrument the test
## runner itself. The stub also opens its own handle to the child, so the test
## can read the exit code after the hook has closed the caller's handles.
##
## WHAT IS NOT STAGED HERE
## -----------------------
## The slow-but-successful path. It would reach ``repro_runtime_init``, whose
## address the injector computes from THIS test executable's export table
## (``selfDllPath`` is normally this very DLL), so it would call garbage in
## the fixture. nim-stackable-hooks' ``test_windows_entry_park_slow_call``
## covers that path with a slow ``LoadLibraryW`` and no init.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, osproc, unittest]

include io_mon/shim/windows_interpose

const
  CREATE_NO_WINDOW = 0x08000000'u32
  WAIT_OBJECT_0 = 0x00000000'u32
  SYNCHRONIZE = 0x00100000'u32
  PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000'u32
  ChildExitCode = 42'u32
  SlowLoadEnvVar = "IO_MON_TEST_SLOW_LOAD_MS"
  # Far past the shortened hard deadline, so the deadline is the only way
  # out of the borrowed LoadLibraryW.
  WedgedMs = 120_000
  ShortHardDeadlineMs = 1_500'u32
  ChildRunBudgetMs = 60_000'u32

proc RealCreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                        bInheritHandles: BOOL, dwCreationFlags: DWORD,
                        lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
                        lpStartupInfo: ptr STARTUPINFOW,
                        lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
  {.importc: "CreateProcessW", stdcall, dynlib: "kernel32".}
proc OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD): HANDLE
  {.importc, stdcall, dynlib: "kernel32".}
proc GetExitCodeProcess(hProcess: HANDLE, lpExitCode: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc TerminateProcess(hProcess: HANDLE, uExitCode: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

var
  gChildHandle: HANDLE = nil
  gChildFlags: DWORD = 0

proc originalCreateProcessWStub(ctx: var hr.HookContext) {.raises: [].} =
  let pi = cast[ptr PROCESS_INFORMATION](ctx.args[9])
  gChildFlags = DWORD(ctx.args[5])
  let r = RealCreateProcessW(
    cast[LPCWSTR](ctx.args[0]), cast[LPWSTR](ctx.args[1]),
    cast[LPSECURITY_ATTRIBUTES](ctx.args[2]),
    cast[LPSECURITY_ATTRIBUTES](ctx.args[3]),
    BOOL(ctx.args[4]), DWORD(ctx.args[5]), cast[LPVOID](ctx.args[6]),
    cast[LPCWSTR](ctx.args[7]), cast[ptr STARTUPINFOW](ctx.args[8]), pi)
  ctx.result = uint64(uint32(r))
  if r != 0:
    # Our own handle, independent of the ones the hook may close.
    gChildHandle = OpenProcess(SYNCHRONIZE or
      PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pi[].dwProcessId)

proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0'u16

proc comSpec(): string =
  result = getEnv("ComSpec")
  if result.len == 0:
    result = getEnv("SystemRoot", r"C:\Windows") / "System32" / "cmd.exe"

proc buildFixtureDll(): string =
  let root = currentSourcePath().parentDir()
  result = getTempDir() / "io-mon-slow-load" / "slow_load_lib.dll"
  createDir(result.parentDir)
  let p = startProcess(findExe("nim"), args = @["c", "--hints:off",
    "--app:lib", "--threads:on", "--mm:orc", "--out:" & result,
    root / "fixtures" / "slow_load_lib.nim"],
    options = {poUsePath, poParentStreams})
  let rc = waitForExit(p)
  close(p)
  doAssert rc == 0, "building the slow-load fixture failed with " & $rc
  doAssert fileExists(result)

proc armShim(dll: string) =
  ## A live, injected shim's state WITHOUT any kernel32 patch, as in
  ## `test_io_mon_windows_spawn_resume.armShim`. `fragmentDir` stays empty so
  ## no evidence files are written. `selfDllPathW` names the slow fixture: it
  ## is what the hook injects.
  if not locksReady:
    initLock(initLockVar)
    initLock(recordLock)
    initLock(fdLock)
    locksReady = true
  initialized = true
  disabled = 0
  selfDllPathW = toWide(dll)
  selfDllPathReady = true
  hr.initShimRegistry()
  hr.setOriginalCallback(hr.HookCreateProcessW, originalCreateProcessWStub)
  hr.registerMonitorHook(hr.HookCreateProcessW, snoopCreateProcessW)

suite "windows CreateProcess snoop: an injection that had to kill the child fails the spawn":

  test "W: ioChildTerminated -> CreateProcessW returns FALSE/ERROR_TIMEOUT":
    let dll = buildFixtureDll()
    armShim(dll)
    putEnv(SlowLoadEnvVar, $WedgedMs)
    defer: putEnv(SlowLoadEnvVar, "0")
    let savedCfg = spawnInjectionConfig
    spawnInjectionConfig.parkTimeoutMs = ShortHardDeadlineMs
    defer: spawnInjectionConfig = savedCfg

    var app = toWide(comSpec())
    var cmd = toWide("\"" & comSpec() & "\" /c exit " & $ChildExitCode)
    var si = STARTUPINFOW(cb: DWORD(sizeof(STARTUPINFOW)))
    var pi: PROCESS_INFORMATION
    var ctx = hr.HookContext(args: newSeq[uint64](10))
    ctx.args[0] = cast[uint64](addr app[0])
    ctx.args[1] = cast[uint64](addr cmd[0])
    ctx.args[5] = uint64(CREATE_NO_WINDOW)
    ctx.args[8] = cast[uint64](addr si)
    ctx.args[9] = cast[uint64](addr pi)
    gChildHandle = nil
    hr.dispatchShimHook(hr.HookCreateProcessW, ctx)
    let err = GetLastError()
    defer:
      if gChildHandle != nil:
        if WaitForSingleObject(gChildHandle, 0) != WAIT_OBJECT_0:
          discard TerminateProcess(gChildHandle, 1)
        discard CloseHandle(gChildHandle)

    checkpoint("result=" & $ctx.result & " lastError=" & $err)
    # The child really was created, and created suspended by the hook, so
    # the deadline path was genuinely reached rather than skipped.
    require gChildHandle != nil
    check (gChildFlags and CREATE_SUSPENDED) != 0
    # The spawn failed, visibly and with a meaningful error.
    check (ctx.result and 0xFFFF_FFFF'u64) == 0'u64
    check err == shProp.ERROR_TIMEOUT
    # The caller gets nothing it could act on.
    check pi.hProcess == nil
    check pi.hThread == nil
    check pi.dwProcessId == 0
    # The child died of the deadline, and was never resumed into its own
    # `main`: its own exit code is never observed.
    check WaitForSingleObject(gChildHandle, ChildRunBudgetMs) == WAIT_OBJECT_0
    var code: DWORD = 0
    check GetExitCodeProcess(gChildHandle, addr code) != 0
    checkpoint("child exit code: " & $code)
    check code == shProp.InjectionAbandonedExitCode
    check code != ChildExitCode
