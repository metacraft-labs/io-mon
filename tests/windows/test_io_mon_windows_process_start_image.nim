## Every Windows process-start names the file that ran: its `path` is the
## image `CreateProcessW` resolved.
##
## WHY. The spawn record carries what the caller passed to `CreateProcessW`.
## With no application name that is the COMMAND LINE, whose first token the
## loader searches for: the application's directory, the caller's current
## directory, the system directories, then the CALLER's `PATH` (which the
## caller may have changed). A relative first token resolves against the
## caller's current directory, which no record carries. A consumer judging
## which file ran could not locate it from the capture. The child's own
## `mrProcessStart` now carries `QueryFullProcessImageNameW` of itself, as the
## Linux and macOS shims carry `/proc/self/exe` and `proc_pidpath`
## (docs/usage.md, "The process-start image").
## https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
##
## What is graded, live through `runMonitored` and the real shim, for a copy
## of this program (`tgt.exe`) started by a monitored root:
##   * by bare name, through a `PATH` the root set itself, with a decoy
##     `tgt.exe` (which exits 7) on the `PATH` it inherited;
##   * by a path relative to a current directory the root changed to;
##   * through a symbolic link, when this host may create one (the image is
##     recorded as the link's TARGET, as on Linux and macOS);
## a process-start from a pid other than the root's names the target, none
## names the decoy, the root's names this program, and the capture is
## complete.
##
## No mocks: the real CLI library entry point, the real injected shim, real
## child processes.

when not defined(windows):
  {.error: "windows-only test".}

import descendant_guard_expectations
import std/[os, sequtils, strutils, tempfiles, unittest, widestrs]
import std/winlean

import io_mon
import io_mon/fs_snoop

const
  ChildFlag = "--io-mon-image-child"
  ByNameFlag = "--io-mon-image-by-name"
  RelativeFlag = "--io-mon-image-relative"
  ExactFlag = "--io-mon-image-exact"

proc launch(commandLine: string): int =
  ## CreateProcessW with NO application name, so the loader resolves the
  ## command line's first token itself, then wait and return its exit code.
  var si: STARTUPINFO
  si.cb = int32(sizeof(si))
  var pi: PROCESS_INFORMATION
  var cmd = newWideCString(commandLine)
  if createProcessW(nil, cmd, nil, nil, 0, 0, nil, nil, si, pi) == 0:
    return 3
  discard waitForSingleObject(pi.hProcess, INFINITE)
  var code: int32
  discard getExitCodeProcess(pi.hProcess, code)
  discard closeHandle(pi.hThread)
  discard closeHandle(pi.hProcess)
  int(code)

if paramCount() == 1 and paramStr(1) == ChildFlag:
  # The decoy is the same program in a directory named `decoy`.
  quit(if getAppFilename().parentDir.extractFilename == "decoy": 7 else: 0)

if paramCount() == 2 and paramStr(1) == ByNameFlag:
  # The root: put <bindir> first on its OWN PATH, then start `tgt.exe` by
  # name.
  discard setEnvironmentVariableW(newWideCString("PATH"),
    newWideCString(paramStr(2) & ";" & getEnv("PATH")))
  quit(launch("tgt.exe " & ChildFlag))

if paramCount() == 3 and paramStr(1) == RelativeFlag:
  # The root: change to <dir>, then start <relative path>.
  if setCurrentDirectoryW(newWideCString(paramStr(2))) == 0: quit(2)
  quit(launch(paramStr(3) & " " & ChildFlag))

if paramCount() == 2 and paramStr(1) == ExactFlag:
  # The root: start <path> as given.
  quit(launch("\"" & paramStr(2) & "\" " & ChildFlag))

proc samePath(a, b: string): bool =
  ## Windows paths compare case-insensitively, either separator.
  cmpIgnoreCase(a.replace('/', '\\'), b.replace('/', '\\')) == 0

suite "Windows process-start names the resolved image":
  let dir = expandFilename(createTempDir("io_mon_start_image_", ""))
  createDir(dir / "bin")
  createDir(dir / "decoy")
  createDir(dir / "link")
  let target = dir / "bin" / "tgt.exe"
  let decoy = dir / "decoy" / "tgt.exe"
  copyFile(getAppFilename(), target)
  copyFile(getAppFilename(), decoy)

  proc capture(args: seq[string]): MonitorResult =
    let saved = getEnv("PATH")
    # The decoy is what the INHERITED PATH would find.
    putEnv("PATH", (dir / "decoy") & ";" & saved)
    try:
      result = runMonitored(FsSnoopRequest(
        command: @[getAppFilename()] & args,
        depFilePath: dir / "run.iomon",
        cwd: dir,
        passthroughChildStdout: false,
        passthroughChildStderr: false,
        captureChildStdio: true))
    finally:
      putEnv("PATH", saved)

  # A template, not a proc: a `check` must expand inside the test body to
  # fail that test (in a proc it only sets the exit code).
  template checkResolved(captured: MonitorResult; expectedPath: string) =
    let res = captured
    let expected = expectedPath
    let starts = res.records.filterIt(it.kind == mrProcessStart)
    checkpoint("process-starts: " &
      starts.mapIt($it.osPid & ":" & it.path & " [" & it.detail & "]").join("; "))
    check res.exitCode == 0          # the target ran; the decoy exits 7
    let roots = starts.filterIt(samePath(it.path, getAppFilename()))
    check roots.len >= 1
    let hits = starts.filterIt(samePath(it.path, expected))
    check hits.len >= 1
    if roots.len >= 1:
      check hits.allIt(it.osPid != roots[0].osPid)
    check starts.allIt(not samePath(it.path, decoy))
    check starts.allIt(it.path.len > 0 and it.path.isAbsolute)
    check starts.allIt("image=unresolved" notin it.detail)
    check subsystemEvidence(res).completeness == mcComplete

  test "a bare name found through a PATH the root set":
    checkResolved(capture(@[ByNameFlag, dir / "bin"]), target)

  test "a relative path after the root changed directory":
    checkResolved(capture(@[RelativeFlag, dir, "bin\\tgt.exe"]), target)

  test "a symbolic link records the link's target":
    # SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE (2): succeeds without the
    # privilege only in Developer Mode.
    let link = dir / "link" / "tgt.exe"
    if createSymbolicLinkW(newWideCString(link), newWideCString(target),
        2) == 0:
      skip()
    else:
      let viaLink = capture(@[ExactFlag, link])
      checkResolved(viaLink, target)
      check viaLink.records.allIt(it.kind != mrProcessStart or
        not samePath(it.path, link))

  try: removeDir(dir)
  except CatchableError: discard
