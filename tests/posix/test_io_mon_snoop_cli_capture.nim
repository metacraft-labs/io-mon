## test_io_mon_snoop_cli_capture — POSIX LIVE half of the standalone `io-mon` CLI
## (M8): EMPIRICALLY run a freshly-built USER binary (a tiny C program that
## `fopen()`s + reads a known file) UNDER the snoop CLI with the shim injected,
## then assert the captured depfile CONTAINS the input read.
##
## This is POSIX-shared behavior (macOS DYLD_INSERT + body-patch; Linux
## LD_PRELOAD): the snoop CLI sets up the platform injection itself, so the same
## test exercises both shims. The platform-INDEPENDENT build + `inspect` smoke
## lives in `tests/portable/test_io_mon_snoop_cli_smoke.nim`.
##
## # macOS: the interpose internal-call gap is now CLOSED
##
## The fixture reads its input via `fopen`, whose `open` happens
## shared-cache-internally (inside libsystem_c, via `open$NOCANCEL`). The legacy
## `__DATA,__interpose` mechanism alone does NOT intercept that internal open. The
## body-patch mechanism (always on by default) closes that gap by replacing the
## libsystem open-family entry points themselves (`mach_vm_remap` overwrite), so
## the snoop CLI captures the input read on macOS too. This test therefore asserts
## the POSITIVE capture on every supported POSIX platform. (The focused
## interpose-vs-body-patch contrast lives in
## `tests/macos/test_io_mon_macos_bodypatch.nim`.)

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon  # readMonitorDepFile, MonitorObservationKind, findShimLibrary

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  fixtureC = repoRoot / "tests" / "fixtures" / "fs_snoop_tool" / "fs_snoop_tool.c"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon CLI (M8) — POSIX live capture":
  let work = getTempDir() / ("io-mon-cli-cap-" & $getCurrentProcessId())
  createDir(work)
  let snoopBin = work / "io-mon"

  test "a freshly-built user binary's read is captured under the snoop CLI":
    # Build the snoop CLI (the out-of-process driver the runner uses).
    check fileExists(snoopSrc)
    let (cliOut, cliCode) = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"),
      "--path:" & hooksSrc,
      "--out:" & snoopBin,
      snoopSrc])
    checkpoint(cliOut)
    check cliCode == 0
    check fileExists(snoopBin)

    # Build the interpose shim shared library (the live-capture half).
    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint("build_shim: " & buildShim.output)
    check buildShim.code == 0
    let shimLib = findShimLibrary()
    checkpoint("shim: " & shimLib)
    check shimLib.len > 0

    # Compile a freshly-built USER binary that open()+read()s a known file.
    check fileExists(fixtureC)
    let userBin = work / "fs-snoop-tool"
    let cc = getEnv("CC", "cc")
    let ccRes = run(cc, @[fixtureC, "-o", userBin])
    checkpoint("cc: " & ccRes.output)
    check ccRes.code == 0
    check fileExists(userBin)

    let inputPath = work / "input.txt"
    writeFile(inputPath, "io-mon snoop CLI capture fixture\n")
    let outputPath = work / "output.txt"
    let depfile = work / "cap.rdep"

    # Drive the live capture OUT OF PROCESS through the snoop CLI, pinning the
    # shim so it resolves without an install. This is the exact topology the
    # runner uses: the shim injected around the USER binary, not the runner.
    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @[
      "run", "--depfile", depfile, "--",
      userBin, inputPath, outputPath], childEnv)
    checkpoint("snoop run: " & cap.output)
    # WIRING assertions (must always hold): the CLI runs, the monitored command
    # succeeds (exit forwarded), and a well-formed depfile is produced + readable.
    check cap.code == 0
    check fileExists(depfile)
    check fileExists(outputPath)  # the user binary actually ran + wrote output

    let dep = readMonitorDepFile(depfile)
    check dep.records.len > 0  # at minimum the backend-profile + capability-gap

    # EMPIRICAL read-capture outcome: did the injection fire for the user binary?
    var capturedInputRead = false
    for rec in dep.records:
      if rec.path.len > 0 and inputPath in rec.path and
          (rec.observationKind == moFileOpen or
           rec.observationKind == moFileRead):
        capturedInputRead = true
        break

    when defined(macosx):
      # macOS: the __DATA,__interpose mechanism alone does NOT intercept the
      # fopen-internal (shared-cache-internal) open the fixture performs. That gap
      # is now CLOSED by the body-patch mechanism, which the shim always runs by
      # default (both mechanisms on). The user-binary read MUST now be captured.
      checkpoint("macOS host: capturedInputRead=" & $capturedInputRead &
        " (body-patch closes the interpose internal-call gap)")
      check capturedInputRead
    else:
      # Linux / *BSD: LD_PRELOAD is expected to capture the read of a freshly-built
      # user binary. If it does not on this host, surface it loudly (a real gap to
      # validate), don't silently pass.
      checkpoint("non-macOS POSIX host: capturedInputRead=" & $capturedInputRead)
      check capturedInputRead

    # `inspect` decodes + renders the depfile the live capture just produced.
    let (insOut, insCode) = run(snoopBin,
      @["inspect", depfile, "--format", "text"])
    checkpoint(insOut)
    check insCode == 0
    check "RMDF" in insOut

  removeDir(work)
