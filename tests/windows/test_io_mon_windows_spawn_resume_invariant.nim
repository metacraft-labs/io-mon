## The CreateProcess snoop hooks force `CREATE_SUSPENDED` into every child's
## creation flags so they can inject the shim before the child runs. That
## makes the hook the OWNER of a suspension the caller never asked for, and
## the invariant this file pins is the one that ownership implies:
##
##   whatever path leaves the hook, a child whose suspension THIS HOOK
##   introduced is resumed -- and a child the CALLER asked to be suspended
##   is not touched.
##
## Both halves are liveness properties of a real process, so they are tested
## on real processes. A source-shape assertion would not do: the failure is a
## live process frozen before its first instruction, holding the injected
## shim image open, and it was found in the field as parentless `cc1.exe` /
## `gcc.exe` at 0 ms user and 0 ms kernel time twenty hours after the build
## that spawned them had gone.
##
## Three ways out of `snoopCreateProcessW` used to skip the resume: the early
## `return` when `disabled`/`initialized` flip between forcing the suspension
## and the post-call check (a genuine race with the exit handler), a raise
## from anywhere in the body that the hook's own `except CatchableError`
## swallows, and the plain fact that the resume sat under a condition
## narrower than the one that forced the suspension. Neither of the first two
## can be provoked from outside the process -- one turns on a thread-local,
## the other on an allocation failing -- so the shim exposes them for this
## test through `REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE` (`return` / `raise`),
## read once at init. The third needed no knob; it is covered by every case
## here because the resume no longer has a condition of its own at all.
##
## That knob is compiled out of the shipped shim (`-d:ioMonShimSpawnEscapeTest`
## gates it), because taking either escape suppresses the spawn record AND the
## injection, so the child subtree goes unobserved while the run still grades
## `mcComplete` -- an env var that silently voids a monitor's evidence has no
## business in the artefact people run. So the two escape cases build their
## own shim, into `build/test-bin/`, and the other two run against the real
## `build/lib/librepro_monitor_shim.dll`.
##
## Layout, mirroring `test_io_mon_windows_msys_fallback.nim`: this binary is
## its own fixture. It re-invokes itself as the monitored *spawner*, and the
## spawner re-invokes it once more as the *child*. The spawner bounds its own
## wait and terminates a stranded child, so a regression shows up as a
## non-zero exit code within seconds instead of as a hung suite and a fresh
## pair of frozen orphans on the host.

when not defined(windows):
  {.error: "windows-only test".}

import std/[os, osproc, strutils, tempfiles, unittest, winlean]

import io_mon

const
  ChildArg = "--spawn-resume-child"
  PlainSpawnerArg = "--spawn-resume-plain-spawner"
  SuspendedSpawnerArg = "--spawn-resume-suspended-spawner"
  PlainProbeArg = "--spawn-resume-probe-plain"
  EscapeReturnProbeArg = "--spawn-resume-probe-escape-return"
  EscapeRaiseProbeArg = "--spawn-resume-probe-escape-raise"
  SuspendedProbeArg = "--spawn-resume-probe-caller-suspended"

  EscapeEnvVar = "REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE"

  CreateSuspended = 0x00000004'i32
    ## `winlean` binds `CREATE_NO_WINDOW` but not this one.

  ChildExitCode = 43
    ## Distinctive so "the child ran" cannot be confused with "something
    ## else exited 0".
  ChildWaitMs = 10_000'i32
    ## Generous next to a `quit()` that is reached in milliseconds once the
    ## thread is running at all. A child that misses this deadline is not
    ## slow, it is asleep.
  SuspendedSettleMs = 750
    ## How long a caller-suspended child is left alone before we assert it
    ## has NOT run. The hook's inject-and-resume work is over long before
    ## this, so a wrong resume has had its chance.

let
  RepoRoot = currentSourcePath.parentDir.parentDir.parentDir
  BuiltShim = RepoRoot / "build" / "lib" / "librepro_monitor_shim.dll"
  EscapeShim = RepoRoot / "build" / "test-bin" /
    "librepro_monitor_shim_spawnescape.dll"
    ## The fault-injection build. Deliberately NOT in `build/lib`: that
    ## directory is what gets packaged and what every consumer's shim
    ## discovery looks at, and a knob-carrying shim sitting next to the real
    ## one would hand back most of what the compile gate takes away.

# --- The fixture's two inner roles -----------------------------------------

proc spawnSelfAsChild(creationFlags: int32;
                      pi: var PROCESS_INFORMATION): bool =
  ## `CreateProcessW` straight at kernel32 -- this is the call the shim's
  ## inline hook sits on. `dynlib` dispatch rather than an IAT entry is
  ## deliberate on the shim's side (the 5-byte JMP at the function body
  ## catches every dispatch mechanism), so winlean's binding is a fair
  ## stand-in for what a compiler driver does.
  var si = STARTUPINFO(cb: int32(sizeof(STARTUPINFO)))
  var cmdLine = newWideCString("\"" & getAppFilename() & "\" " & ChildArg)
  createProcessW(nil, cmdLine, nil, nil, 0, creationFlags, nil, nil,
                 si, pi) != 0

proc closeBoth(pi: PROCESS_INFORMATION) =
  discard closeHandle(pi.hThread)
  discard closeHandle(pi.hProcess)

proc runPlainSpawner(): int =
  ## Spawn an ORDINARY child -- no `CREATE_SUSPENDED` from us -- and require
  ## that it reaches its own `quit`. Any suspension it is born with is the
  ## hook's, so this is the direct test of "the hook resumes what it froze".
  var pi: PROCESS_INFORMATION
  if not spawnSelfAsChild(0'i32, pi):
    return 10
  if waitForSingleObject(pi.hProcess, ChildWaitMs) != WAIT_OBJECT_0:
    # Separate "stranded" from "merely slow" before cleaning up: resumeThread
    # reports the suspend count it found, so a positive answer IS the defect
    # and is worth saying in the exit code rather than leaving to inference.
    let previousSuspendCount = resumeThread(pi.hThread)
    # Resume first, then terminate: never leave this test's own frozen
    # orphan behind, which is the very thing the defect produces.
    discard terminateProcess(pi.hProcess, 1)
    discard waitForSingleObject(pi.hProcess, 5000'i32)
    closeBoth(pi)
    return (if previousSuspendCount > 0: 11 else: 12)
  var exitCode: int32 = -1
  discard getExitCodeProcess(pi.hProcess, exitCode)
  closeBoth(pi)
  if int(exitCode) != ChildExitCode:
    return 13
  0

proc runSuspendedSpawner(): int =
  ## The other half of the invariant. We ask for `CREATE_SUSPENDED`
  ## ourselves, so the hook must leave the main thread exactly as it found
  ## it. Suspend counts are counted, not boolean: an extra `ResumeThread`
  ## here drops the count to zero and starts the child before we meant it
  ## to, and cannot be taken back. `resumeThread` returns the count it
  ## found, which turns "did the hook keep its hands off?" into a number.
  var pi: PROCESS_INFORMATION
  if not spawnSelfAsChild(CreateSuspended, pi):
    return 20
  sleep(SuspendedSettleMs)
  if waitForSingleObject(pi.hProcess, 0'i32) != WAIT_TIMEOUT:
    closeBoth(pi)
    return 21
  let previousSuspendCount = resumeThread(pi.hThread)
  if previousSuspendCount != 1:
    discard terminateProcess(pi.hProcess, 1)
    discard waitForSingleObject(pi.hProcess, 5000'i32)
    closeBoth(pi)
    # 30 = the hook resumed a suspension it did not own (count found 0);
    # 32+ = something suspended it more than once; negative = query failed.
    return (if previousSuspendCount < 0: 22
            else: 30 + int(previousSuspendCount))
  if waitForSingleObject(pi.hProcess, ChildWaitMs) != WAIT_OBJECT_0:
    discard terminateProcess(pi.hProcess, 1)
    discard waitForSingleObject(pi.hProcess, 5000'i32)
    closeBoth(pi)
    return 23
  var exitCode: int32 = -1
  discard getExitCodeProcess(pi.hProcess, exitCode)
  closeBoth(pi)
  if int(exitCode) != ChildExitCode:
    return 24
  0

# --- The monitored probe ----------------------------------------------------

proc runSpawnerUnderMonitor(spawnerArg, escapeMode, shimPath: string): int =
  ## Run one spawner as a monitored root child, so its `CreateProcessW` goes
  ## through the shim's hook. The spawner's exit code IS the verdict; this
  ## proc only forwards it.
  if not fileExists(shimPath):
    return 78
  let work = createTempDir("io-mon-", "-spawn-resume")
  defer:
    try: removeDir(work)
    except OSError: discard
  putEnv("REPRO_MONITOR_SHIM_LIB", shimPath)
  if escapeMode.len > 0:
    putEnv(EscapeEnvVar, escapeMode)
  else:
    delEnv(EscapeEnvVar)
  let stdioPath = work / "stdio.log"
  let monitored = runMonitored(FsSnoopRequest(
    command: @[getAppFilename(), spawnerArg],
    depFilePath: work / "evidence.rdep",
    captureChildStdio: true,
    captureStdioPath: stdioPath))
  if monitored.exitCode != 0 and fileExists(stdioPath):
    try: stderr.writeLine(readFile(stdioPath))
    except CatchableError: discard
  monitored.exitCode

if paramCount() == 1:
  case paramStr(1)
  of ChildArg:
    quit(ChildExitCode)
  of PlainSpawnerArg:
    quit(runPlainSpawner())
  of SuspendedSpawnerArg:
    quit(runSuspendedSpawner())
  of PlainProbeArg:
    quit(runSpawnerUnderMonitor(PlainSpawnerArg, "", BuiltShim))
  of EscapeReturnProbeArg:
    quit(runSpawnerUnderMonitor(PlainSpawnerArg, "return", EscapeShim))
  of EscapeRaiseProbeArg:
    quit(runSpawnerUnderMonitor(PlainSpawnerArg, "raise", EscapeShim))
  of SuspendedProbeArg:
    quit(runSpawnerUnderMonitor(SuspendedSpawnerArg, "", BuiltShim))
  else:
    discard

# --- Building the fault-injection shim --------------------------------------
#
# Everything below here runs ONLY in the outer suite process: the four inner
# roles above `quit` before reaching it.

proc buildEscapeShim(): bool =
  ## Compile the shim a second time with `-d:ioMonShimSpawnEscapeTest`, which
  ## is the only build in which `REPRO_MONITOR_SHIM_TEST_SPAWN_ESCAPE` means
  ## anything. Same source, same flags as `scripts/build_shim.sh`'s Windows
  ## arm plus the define, so the code the escape cases exercise is the code
  ## that ships, minus nothing.
  ##
  ## Rebuilt every run rather than reused. A stale copy would let these two
  ## cases pass against a shim that no longer matches the source -- exactly
  ## the trap a stale `build/lib` sets for anyone mutation-testing this file.
  ## The build is a couple of seconds with a warm nimcache.
  ##
  ## `-static-libgcc` is not optional even here: this DLL is LoadLibraryW'd
  ## into a child whose PATH need not contain the mingw bin directory, and a
  ## missing `libgcc_s_seh-1.dll` there surfaces as the child simply not
  ## being monitored.
  let hooksSrc = getEnv("STACKABLE_HOOKS_SRC",
    RepoRoot.parentDir / "nim-stackable-hooks" / "src")
  let queueSrc = getEnv("SHM_QUEUE_SRC",
    RepoRoot.parentDir / "nim-shm-queue" / "src")
  let gsetSrc = getEnv("SHM_GSET_SRC",
    RepoRoot.parentDir / "nim-shm-gset" / "src")
  try:
    createDir(EscapeShim.parentDir)
  except OSError, IOError:
    return false
  let p = startProcess("nim", args = @[
      "c", "--app:lib", "--threads:on", "--mm:orc", "--cc:gcc",
      "--passL:-static-libgcc", "-d:ioMonShimSpawnEscapeTest",
      "--hints:off", "--warnings:off",
      "--path:" & RepoRoot / "src",
      "--path:" & hooksSrc,
      "--path:" & queueSrc,
      "--path:" & gsetSrc,
      "--nimcache:" & RepoRoot / "build" / "nimcache" /
        "io-mon-shim-spawnescape",
      "--out:" & EscapeShim,
      RepoRoot / "src" / "io_mon" / "shim" / "windows_interpose.nim"],
    options = {poUsePath, poParentStreams})
    # poParentStreams: the compiler's diagnostics go straight to this
    # suite's stderr, where a failure is readable, and no pipe can fill up
    # while we wait.
  let code = waitForExit(p)
  close(p)
  code == 0 and fileExists(EscapeShim)

let escapeShimReady = buildEscapeShim()

proc runProbeWithTimeout(probeArg: string): int =
  ## Outer bound so a regression that DOES hang -- the spawner's own bound
  ## should prevent it, but a hang inside the hook itself would not be
  ## caught by that -- fails the suite instead of stalling it.
  let probe = startProcess(getAppFilename(), args = @[probeArg],
    options = {poUsePath, poParentStreams})
  result = -1
  for _ in 0 ..< 1200:
    result = peekExitCode(probe)
    if result != -1:
      break
    sleep(50)
  if result == -1:
    terminate(probe)
    discard waitForExit(probe, 5000)
  close(probe)

suite "Windows forced-suspension resume invariant":
  test "a monitored spawn's child runs to completion":
    require fileExists(BuiltShim)
    # The control. It passes with or without the fix, and it is here so that
    # a failure in the two escape cases below is attributable to the escape
    # and not to the fixture.
    check runProbeWithTimeout(PlainProbeArg) == 0

  test "the post-CreateProcess early return still resumes the child":
    # A hard `require`, never a skip: if the fault-injection shim did not
    # build, this case has not run, and a suite that reports green for two
    # cases it never executed is worse than one that fails.
    require escapeShimReady
    check runProbeWithTimeout(EscapeReturnProbeArg) == 0

  test "a raise swallowed by the hook still resumes the child":
    require escapeShimReady
    check runProbeWithTimeout(EscapeRaiseProbeArg) == 0

  test "a child the caller suspended is left suspended, exactly once":
    require fileExists(BuiltShim)
    check runProbeWithTimeout(SuspendedProbeArg) == 0
