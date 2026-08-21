## test_io_mon_windows_spawn_resume — every ``CREATE_SUSPENDED`` this
## shim FORCES owes exactly one ``ResumeThread``, on every exit path;
## and a suspension the CALLER asked for owes none.
##
## THE HAZARD
## ----------
## ``snoopCreateProcessW`` / ``snoopCreateProcessA`` OR ``CREATE_SUSPENDED``
## into the caller's creation flags BEFORE running the rest of the hook
## chain, so the child is frozen on its initial thread when the real
## ``CreateProcessW`` returns and can be injected before it executes a
## single instruction. That force creates an obligation with no other
## owner: nothing else in the system knows the child is suspended, so if
## this hook does not resume it, it NEVER runs. The caller sees
## ``CreateProcessW`` succeed and then waits forever.
##
## The obligation is created before ``callNext`` and discharged after it,
## and the code in between has several ways to give up on the snooping:
##
##   * the shim is re-entered during ``callNext`` (``disabled > 0``);
##   * the shim is torn down between the force and the epilogue
##     (``not initialized``);
##   * record building or the injection call raises.
##
## Each of those used to hand the caller a permanently frozen child,
## because the resume lived on the happy path — after a bare ``return``
## that the first two took, and inside a ``try`` whose
## ``except CatchableError: discard`` swallowed the third.
##
## The symmetric bug is a DOUBLE resume. If the caller passed
## ``CREATE_SUSPENDED`` themselves they own the resume, and resuming on
## their behalf runs a child they deliberately froze (to set up its
## environment, patch its memory, put it in a job object...) before they
## were ready. So the two halves have to be pinned together: resume iff
## WE forced it.
##
## WHY THIS TEST IS BEHAVIOURAL
## ----------------------------
## The interesting arms are not observable from the outside of a live
## build, but they ARE drivable in-process: the hook chain is an ordinary
## priority-ordered registry (``windows_hook_registry``), so this test
## registers the real ``snoopCreateProcessW`` against a chain whose
## ``original`` is a stub that calls the real ``CreateProcessW`` and then
## arranges the disruption — bumping ``disabled`` to model a re-entrant
## hook invocation, or clearing ``initialized`` to model teardown —
## exactly as it would happen inside a live spawn. No kernel32 patching
## is involved, so the test process is not itself instrumented.
##
## The assertion is then about the real child, not about the source: for
## a suspension the shim forced, the child must REACH ITS EXIT with
## nobody else touching its main thread; for one the caller asked for, it
## must still be suspended (``ResumeThread`` reports a suspend count of
## exactly 1) when the hook returns.
##
## WHAT THIS FILE DELIBERATELY DOES NOT STAGE
## ------------------------------------------
## The UNDISTURBED path. On it the hook does a real cross-process
## injection of ``selfDllPath()`` into the child before resuming it, and
## in a test EXE ``selfDllPath()`` resolves to the test binary rather
## than to the shim DLL. The injector then computes the init entry point
## from an RVA that means nothing in the child and starts a remote thread
## there; the child dies with ``0xC0000409`` and the test would be
## reporting on the injector, not on the resume. That path is covered
## live instead, by ``test_io_mon_windows_process_start_survives`` and
## ``test_io_mon_windows_msys_fallback``, which run real monitored
## children through the real shim — a happy path that stopped resuming
## would wedge both. It is also not where the defect was: the happy path
## always resumed.
##
## The raising arm cannot be driven at all — it needs an allocation
## failure or equivalent inside the epilogue. The last suite in this file
## covers it structurally, by pinning that no exit between the force and
## the end of the proc can skip the ``finally`` and that there is exactly
## one resume call site. That is a complement to the behavioural cases
## above, not a substitute for them.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, strutils, unittest]

# `include`, not `import`, and deliberately so: the invariant lives inside
# `snoopCreateProcessW` / `snoopCreateProcessA` (private) and is decided by
# private shim state (`initialized`, the `disabled` re-entrancy counter,
# `selfDllPathW`). Including the module puts all of that in this module's
# scope, which is what makes a behavioural test possible at all — otherwise
# the only thing left to check is the shape of the source.
include io_mon/shim/windows_interpose

const
  CREATE_NO_WINDOW = 0x08000000'u32
  WAIT_OBJECT_0 = 0x00000000'u32
  ChildExitCode = 42'u32
  # A `cmd /c exit 42` takes tens of milliseconds. This budget only has to
  # separate "ran" from "frozen forever", so it is generous.
  ChildRunBudgetMs = 20_000'u32
  # Long enough that a resumed child would certainly have exited, short
  # enough not to pad the suite. Only used to assert a child stayed frozen.
  StillSuspendedProbeMs = 750'u32

proc RealCreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR,
                        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                        bInheritHandles: BOOL, dwCreationFlags: DWORD,
                        lpEnvironment: LPVOID, lpCurrentDirectory: LPCWSTR,
                        lpStartupInfo: ptr STARTUPINFOW,
                        lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
  {.importc: "CreateProcessW", stdcall, dynlib: "kernel32".}

proc RealCreateProcessA(lpApplicationName: LPCSTR, lpCommandLine: LPSTR,
                        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                        bInheritHandles: BOOL, dwCreationFlags: DWORD,
                        lpEnvironment: LPVOID, lpCurrentDirectory: LPCSTR,
                        lpStartupInfo: ptr STARTUPINFOA,
                        lpProcessInformation: ptr PROCESS_INFORMATION): BOOL
  {.importc: "CreateProcessA", stdcall, dynlib: "kernel32".}

proc GetExitCodeProcess(hProcess: HANDLE, lpExitCode: ptr DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}
proc TerminateProcess(hProcess: HANDLE, uExitCode: DWORD): BOOL
  {.importc, stdcall, dynlib: "kernel32".}

type
  Disruption = enum
    ## What goes wrong between the force and the epilogue. Both of the
    ## disrupted arms make the hook abandon the snooping for this call,
    ## which means neither of them reaches `injectShimIntoChild` — see
    ## `armShim` for why that matters here.
    drNone            ## nothing; not staged by this file, see the header
    drReentered       ## the shim is re-entered during the call (`disabled > 0`)
    drTornDown        ## the shim is torn down during the call (`initialized`)

  SpawnOutcome = object
    created: bool
    flagsSeenByWin32: DWORD   ## what the chain's tail actually received
    pi: PROCESS_INFORMATION

var gDisruption = drNone

proc applyDisruption() {.raises: [].} =
  ## Runs at the tail of the chain, i.e. after the real CreateProcess has
  ## returned but before the snoop hook's epilogue — the exact window in
  ## which a re-entrant hook invocation or a shim teardown lands.
  case gDisruption
  of drNone: discard
  of drReentered: inc disabled
  of drTornDown: initialized = false

proc originalCreateProcessWStub(ctx: var hr.HookContext) {.raises: [].} =
  let flags = DWORD(ctx.args[5])
  let r = RealCreateProcessW(
    cast[LPCWSTR](ctx.args[0]), cast[LPWSTR](ctx.args[1]),
    cast[LPSECURITY_ATTRIBUTES](ctx.args[2]),
    cast[LPSECURITY_ATTRIBUTES](ctx.args[3]),
    BOOL(ctx.args[4]), flags, cast[LPVOID](ctx.args[6]),
    cast[LPCWSTR](ctx.args[7]), cast[ptr STARTUPINFOW](ctx.args[8]),
    cast[ptr PROCESS_INFORMATION](ctx.args[9]))
  ctx.result = uint64(uint32(r))
  applyDisruption()

proc originalCreateProcessAStub(ctx: var hr.HookContext) {.raises: [].} =
  let flags = DWORD(ctx.args[5])
  let r = RealCreateProcessA(
    cast[LPCSTR](ctx.args[0]), cast[LPSTR](ctx.args[1]),
    cast[LPSECURITY_ATTRIBUTES](ctx.args[2]),
    cast[LPSECURITY_ATTRIBUTES](ctx.args[3]),
    BOOL(ctx.args[4]), flags, cast[LPVOID](ctx.args[6]),
    cast[LPCSTR](ctx.args[7]), cast[ptr STARTUPINFOA](ctx.args[8]),
    cast[ptr PROCESS_INFORMATION](ctx.args[9]))
  ctx.result = uint64(uint32(r))
  applyDisruption()

proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(ord(c))
  result[s.len] = 0'u16

proc comSpec(): string =
  result = getEnv("ComSpec")
  if result.len == 0:
    result = getEnv("SystemRoot", r"C:\Windows") / "System32" / "cmd.exe"

proc childCommandLine(): string =
  "\"" & comSpec() & "\" /c exit " & $ChildExitCode

proc armShim() =
  ## Put the shim into the state the hook bodies expect of a live,
  ## injected shim — WITHOUT installing any inline/IAT patch, so the test
  ## process's own kernel32 is untouched.
  ##
  ## `fragmentDir` is deliberately left empty: `emitRecord` short-circuits
  ## on it, so no evidence files are written and the test stays hermetic.
  ##
  ## `selfDllPathW` is what gates the force — a shim that cannot find its
  ## own DLL does not suspend anything — so it has to be non-empty for
  ## there to be an obligation at all. It is pre-seeded (rather than left
  ## to `ensureSelfDllPath`) with a path that is deliberately NOT a
  ## loadable library, because it must never be used as one: see the
  ## header note on why the undisrupted path is not staged here. Every
  ## case in this file abandons the snooping before `injectShimIntoChild`
  ## is reached, so this value is only ever read as "non-empty".
  # Same three locks `repro_monitor_shim_init` arms; `baseRecord` takes
  # `recordLock` for the per-process sequence number.
  if not locksReady:
    initLock(initLockVar)
    initLock(recordLock)
    initLock(fdLock)
    locksReady = true
  initialized = true
  disabled = 0
  selfDllPathW = toWide(r"C:\io-mon-test\not-a-real-shim.dll")
  selfDllPathReady = true
  hr.initShimRegistry()

var gChainsWired = false

proc wireChains() =
  if gChainsWired:
    return
  hr.setOriginalCallback(hr.HookCreateProcessW, originalCreateProcessWStub)
  hr.setOriginalCallback(hr.HookCreateProcessA, originalCreateProcessAStub)
  hr.registerMonitorHook(hr.HookCreateProcessW, snoopCreateProcessW)
  hr.registerMonitorHook(hr.HookCreateProcessA, snoopCreateProcessA)
  gChainsWired = true

proc spawnThroughHookW(callerFlags: DWORD; disruption: Disruption):
    SpawnOutcome =
  armShim()
  wireChains()
  gDisruption = disruption
  var app = toWide(comSpec())
  var cmd = toWide(childCommandLine())
  var si = STARTUPINFOW(cb: DWORD(sizeof(STARTUPINFOW)))
  var pi: PROCESS_INFORMATION
  var ctx = hr.HookContext(args: newSeq[uint64](10))
  ctx.args[0] = cast[uint64](addr app[0])
  ctx.args[1] = cast[uint64](addr cmd[0])
  ctx.args[5] = uint64(callerFlags)
  ctx.args[8] = cast[uint64](addr si)
  ctx.args[9] = cast[uint64](addr pi)
  hr.dispatchShimHook(hr.HookCreateProcessW, ctx)
  # Whatever the hook did to the shim's state, put it back before the next
  # case; `disabled` is a threadvar and `initialized` a global.
  gDisruption = drNone
  disabled = 0
  initialized = true
  SpawnOutcome(created: ctx.result != 0'u64,
               flagsSeenByWin32: DWORD(ctx.args[5]),
               pi: pi)

proc spawnThroughHookA(callerFlags: DWORD; disruption: Disruption):
    SpawnOutcome =
  armShim()
  wireChains()
  gDisruption = disruption
  var app = comSpec()
  var cmd = childCommandLine()
  var si = STARTUPINFOA(cb: DWORD(sizeof(STARTUPINFOA)))
  var pi: PROCESS_INFORMATION
  var ctx = hr.HookContext(args: newSeq[uint64](10))
  ctx.args[0] = cast[uint64](app.cstring)
  ctx.args[1] = cast[uint64](cmd.cstring)
  ctx.args[5] = uint64(callerFlags)
  ctx.args[8] = cast[uint64](addr si)
  ctx.args[9] = cast[uint64](addr pi)
  hr.dispatchShimHook(hr.HookCreateProcessA, ctx)
  gDisruption = drNone
  disabled = 0
  initialized = true
  SpawnOutcome(created: ctx.result != 0'u64,
               flagsSeenByWin32: DWORD(ctx.args[5]),
               pi: pi)

proc reap(outcome: SpawnOutcome) =
  ## Never leave a frozen child behind, whatever the assertions said.
  if not outcome.created:
    return
  discard ResumeThread(outcome.pi.hThread)
  if WaitForSingleObject(outcome.pi.hProcess, 5000) != WAIT_OBJECT_0:
    discard TerminateProcess(outcome.pi.hProcess, 1)
    discard WaitForSingleObject(outcome.pi.hProcess, 5000)
  discard CloseHandle(outcome.pi.hThread)
  discard CloseHandle(outcome.pi.hProcess)

proc childRanToCompletion(outcome: SpawnOutcome): bool =
  ## The behavioural question: did the child make forward progress on its
  ## own, i.e. did somebody resume the thread we know was suspended? The
  ## test resumes nothing before asking.
  if WaitForSingleObject(outcome.pi.hProcess, ChildRunBudgetMs) !=
      WAIT_OBJECT_0:
    return false
  var code: DWORD = 0
  if GetExitCodeProcess(outcome.pi.hProcess, addr code) == 0:
    return false
  code == ChildExitCode

proc suspendCountAfterHook(outcome: SpawnOutcome): int =
  ## ``ResumeThread`` returns the thread's PREVIOUS suspend count. Only
  ## called on children asserted to be still suspended, so the thread
  ## cannot have exited underneath the call and the answer is exact.
  let prev = ResumeThread(outcome.pi.hThread)
  if prev == 0xFFFFFFFF'u32: -1 else: int(prev)

suite "windows CreateProcess snoop: a forced CREATE_SUSPENDED is always resumed":

  test "W: a re-entrant hook invocation still resumes the child it froze":
    # `disabled > 0` by the time the epilogue runs — the shim gives up on
    # snooping this call. It may not give up on the resume it already owes.
    let outcome = spawnThroughHookW(CREATE_NO_WINDOW, drReentered)
    defer: reap(outcome)
    require outcome.created
    # Sanity: the shim really did force the suspension, so there IS an
    # obligation to discharge. Without this the test could pass vacuously.
    check (outcome.flagsSeenByWin32 and CREATE_SUSPENDED) != 0
    check childRanToCompletion(outcome)

  test "W: a shim torn down mid-call still resumes the child it froze":
    let outcome = spawnThroughHookW(CREATE_NO_WINDOW, drTornDown)
    defer: reap(outcome)
    require outcome.created
    check (outcome.flagsSeenByWin32 and CREATE_SUSPENDED) != 0
    check childRanToCompletion(outcome)

  test "A: a re-entrant hook invocation still resumes the child it froze":
    let outcome = spawnThroughHookA(CREATE_NO_WINDOW, drReentered)
    defer: reap(outcome)
    require outcome.created
    check (outcome.flagsSeenByWin32 and CREATE_SUSPENDED) != 0
    check childRanToCompletion(outcome)

  test "A: a shim torn down mid-call still resumes the child it froze":
    let outcome = spawnThroughHookA(CREATE_NO_WINDOW, drTornDown)
    defer: reap(outcome)
    require outcome.created
    check (outcome.flagsSeenByWin32 and CREATE_SUSPENDED) != 0
    check childRanToCompletion(outcome)

suite "windows CreateProcess snoop: a caller's CREATE_SUSPENDED is left alone":

  # The other direction. A caller that froze the child on purpose owns the
  # wakeup; resuming on their behalf runs the child before they are ready,
  # and their own later ResumeThread then double-resumes.

  test "W: the child stays suspended when the caller asked for it":
    let outcome = spawnThroughHookW(CREATE_NO_WINDOW or CREATE_SUSPENDED,
      drReentered)
    defer: reap(outcome)
    require outcome.created
    check suspendCountAfterHook(outcome) == 1

  test "A: the child stays suspended when the caller asked for it":
    let outcome = spawnThroughHookA(CREATE_NO_WINDOW or CREATE_SUSPENDED,
      drReentered)
    defer: reap(outcome)
    require outcome.created
    check suspendCountAfterHook(outcome) == 1

suite "windows CreateProcess snoop: the exit paths a test cannot drive":

  # The raising arm needs an allocation failure (or equivalent) inside the
  # epilogue, which cannot be arranged from here. What CAN be checked is
  # the structure that makes the behavioural cases above hold for EVERY
  # exit rather than for the two this file happens to enumerate: no way
  # out between the force and the end of the proc except the `finally`,
  # and one resume call site so a second, unguarded one cannot creep back.

  const interposeSource = currentSourcePath().parentDir().parentDir()
    .parentDir() / "src" / "io_mon" / "shim" / "windows_interpose.nim"

  proc procBody(source, name: string): seq[string] =
    var collecting = false
    for line in source.splitLines():
      if line.startsWith("proc " & name & "("):
        collecting = true
        result.add line
        continue
      if collecting:
        if line.len > 0 and line[0] notin {' ', '\t', '#'}:
          break
        result.add line

  proc firstLineWith(body: seq[string]; needle: string): int =
    for i, line in body:
      if needle in line:
        return i
    -1

  let source = readFile(interposeSource)

  for hookName in ["snoopCreateProcessW", "snoopCreateProcessA"]:

    test hookName & ": no exit between the force and the epilogue skips the resume":
      let body = procBody(source, hookName)
      require body.len > 0
      let forceAt = firstLineWith(body, "ctx.args[5] = uint64(")
      require forceAt >= 0
      var offending: seq[string] = @[]
      for i in forceAt ..< body.len:
        let stripped = body[i].strip()
        if stripped == "return" or stripped.startsWith("return "):
          offending.add "line " & $i & ": " & stripped
      if offending.len > 0:
        checkpoint(hookName & " can exit without discharging the forced " &
          "suspension: " & offending.join("; "))
      check offending.len == 0

    test hookName & ": the resume has exactly one call site, inside a finally":
      let body = procBody(source, hookName)
      require body.len > 0
      var resumeSites = 0
      for line in body:
        if "ResumeThread(" in line:
          inc resumeSites
      check resumeSites == 1
      let finallyAt = firstLineWith(body, "finally:")
      let resumeAt = firstLineWith(body, "ResumeThread(")
      check finallyAt >= 0
      check resumeAt > finallyAt
