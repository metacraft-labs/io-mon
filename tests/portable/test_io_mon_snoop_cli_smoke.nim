## test_io_mon_snoop_cli_smoke — PORTABLE half of the standalone `io-mon` CLI (M8)
## coverage: the CLI BUILDS from source with ONLY io-mon's modules +
## nim-stackable-hooks (the standalone, no-reprobuild contract), and its
## `inspect` subcommand round-trips a depfile. Neither arm needs the live shim,
## a C probe, or any platform injection, so both run on EVERY OS — a build break
## or an `inspect`/codec regression is caught on Linux / *BSD / Windows too.
##
## The macOS / POSIX LIVE capture (build the shim, compile a C probe, inject it
## around the probe, assert the read is captured) lives in
## `tests/posix/test_io_mon_snoop_cli_capture.nim`.

import std/[os, osproc, streams, strutils, tempfiles, unittest]

import io_mon  # writeCanonical, MonitorRecord, observation kinds

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon CLI (M8) — portable build + inspect":
  let work = createTempDir("io-mon-cli-smoke", "")
  let snoopBin = work / "io-mon"

  test "the snoop CLI builds standalone (io-mon + nim-stackable-hooks only)":
    # The compile is the primary proof: a lingering reprobuild import would fail
    # to resolve with only io-mon's src + nim-stackable-hooks on the path.
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

  test "inspect round-trips a captured depfile":
    # Build a real RMDF depfile through the public writer, then `inspect` it. This
    # exercises the CLI's decode + render path with no live capture — fully
    # portable. (The live-capture-produced depfile is inspected in the posix test.)
    let depfile = work / "smoke.rdep"
    let records = @[
      MonitorRecord(kind: mrFileRead, observationKind: moFileRead,
        seq: 1, osPid: 100, path: work / "input.txt"),
      MonitorRecord(kind: mrFileWrite, observationKind: moFileWrite,
        seq: 2, osPid: 100, path: work / "output.txt")]
    writeCanonical(depfile, records)
    check fileExists(depfile)
    let (output, code) = run(snoopBin,
      @["inspect", depfile, "--format", "text"])
    checkpoint(output)
    check code == 0
    check "RMDF" in output

  removeDir(work)
