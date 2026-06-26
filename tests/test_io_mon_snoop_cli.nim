## test_io_mon_snoop_cli — the standalone `io-mon` CLI (M8) BUILDS, is
## RESOLVABLE, and drives a live capture over a freshly-built USER binary.
##
## # What this proves
##
## The Incremental-Test-Runner M8 relocated reprobuild's `repro internal
## io monitor` snoop surface into io-mon as a standalone binary
## (`cmd/io_mon_snoop.nim`, built by `nimble buildSnoop` → `build/bin/io-mon`).
## This test:
##
##   1. BUILDS the snoop CLI from source with ONLY io-mon's modules +
##      nim-stackable-hooks (no reprobuild path) — the standalone contract.
##   2. Confirms `inspect` round-trips a depfile (the platform-independent arm).
##   3. EMPIRICALLY runs a freshly-built USER binary (a tiny C program that
##      `fopen()`s + reads a known file) UNDER the snoop CLI with the shim
##      injected, then checks the captured depfile CONTAINS the input read.
##
## # macOS: the interpose internal-call gap is now CLOSED
##
## The fixture reads its input via `fopen`, whose `open` happens
## shared-cache-internally (inside libsystem_c, via `open$NOCANCEL`). The
## legacy `__DATA,__interpose` mechanism alone does NOT intercept that internal
## open — interpose only rewrites the binary's own import bindings. The
## body-patch mechanism (always on by default) closes that gap by
## replacing the libsystem open-family entry points themselves
## (`mach_vm_remap` overwrite technique), so the snoop CLI now captures the
## input read on macOS too. This test therefore asserts the POSITIVE capture on
## every supported platform. (The focused interpose-vs-body-patch contrast lives
## in `tests/test_io_mon_macos_bodypatch.nim`.)

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon  # readMonitorDepFile, MonitorObservationKind, findShimLibrary

const
  repoRoot = currentSourcePath().parentDir().parentDir()
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

suite "io-mon CLI (M8)":
  let work = getTempDir() / ("io-mon-cli-" & $getCurrentProcessId())
  createDir(work)
  let snoopBin = work / "io-mon"

  test "the snoop CLI builds standalone (io-mon + nim-stackable-hooks only)":
    check fileExists(snoopSrc)
    check dirExists(hooksSrc)
    let (output, code) = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"),
      "--path:" & hooksSrc,
      "--out:" & snoopBin,
      snoopSrc])
    checkpoint(output)
    check code == 0
    check fileExists(snoopBin)

  test "a freshly-built user binary's read is captured under the snoop CLI":
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

    # EMPIRICAL read-capture outcome: did the interpose fire for the user binary?
    var capturedInputRead = false
    for rec in dep.records:
      if rec.path.len > 0 and inputPath in rec.path and
          (rec.observationKind == moFileOpen or
           rec.observationKind == moFileRead):
        capturedInputRead = true
        break

    when defined(macosx):
      # macOS: the __DATA,__interpose mechanism alone does NOT intercept the
      # fopen-internal (shared-cache-internal) open the fixture performs. That
      # gap is now CLOSED by the body-patch mechanism, which the shim always runs
      # by default (both mechanisms on): it replaces the libsystem
      # open/open$NOCANCEL/__open_nocancel entry points themselves and so sees
      # the internal open regardless of caller. The user-binary read MUST now be
      # captured. (See tests/test_io_mon_macos_bodypatch.nim for the focused
      # interpose-vs-body-patch contrast.)
      checkpoint("macOS host: capturedInputRead=" & $capturedInputRead &
        " (body-patch closes the interpose internal-call gap)")
      check capturedInputRead
    else:
      # Linux / Windows: LD_PRELOAD / CreateRemoteThread are expected to capture
      # the read of a freshly-built user binary. If they do not on this host,
      # surface it loudly (it is a real gap to validate), don't silently pass.
      checkpoint("non-macOS host: capturedInputRead=" & $capturedInputRead)
      check capturedInputRead

  test "inspect round-trips a captured depfile":
    # The platform-independent arm: `inspect` decodes + renders a real depfile.
    let depfile = work / "cap.rdep"
    if fileExists(depfile):
      let (output, code) = run(snoopBin,
        @["inspect", depfile, "--format", "text"])
      checkpoint(output)
      check code == 0
      check "RMDF" in output

  removeDir(work)
