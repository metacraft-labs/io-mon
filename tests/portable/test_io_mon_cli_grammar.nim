## test_io_mon_cli_grammar — the `io-mon` command line is clispec's: parsed by
## the parser generated from `io_mon/cli_description`, with generated help and
## clispec's usage errors.
##
## Two halves, both portable (no shim is loaded and nothing is monitored):
##
## * the real binary, built from this checkout: `--help`, `run --help` and
##   `inspect --help` print the help generated from the description (each
##   compared with `IoMonCommandLine.helpText` of the same path, which is
##   rendered from the model, so a hand-written page would differ); an unknown
##   flag, a missing value, a missing command after `--` and a stray word
##   before it are usage errors with exit 2 and clispec's error block;
## * the parse itself (`parseFsSnoopArgs`, what `runFsSnoopCli` runs): `run`
##   and the bare form (`[flags] -- <command>`) give the same request, every
##   flag lands in its `FsSnoopRequest` field, and `--format`/`--events` are
##   one flag.
##
## No mocks: the binary is the real CLI and the parser the generated one.

import foreign_preload_isolation

import std/[os, osproc, strutils, tempfiles, unittest]

import clispec/errors
import io_mon/types
import io_mon/cli
import fixture_cleanup

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc run(cmd: string; args: seq[string]):
    tuple[stdout, stderr: string; code: int] =
  ## `cmd args` with stdout and stderr apart, piped (so help is plain), and
  ## `TERM=dumb` for good measure.
  let work = createTempDir("io-mon-cli-grammar-run", "")
  defer: removeFixtureTree(work)
  let outPath = work / "out"
  let errPath = work / "err"
  let line = "TERM=dumb " & quoteShellCommand(@[cmd] & args) & " >" &
    quoteShell(outPath) & " 2>" & quoteShell(errPath) & " </dev/null"
  let code = when defined(windows): execCmd(quoteShellCommand(@[cmd] & args))
             else: execCmd(line)
  let o = if fileExists(outPath): readFile(outPath) else: ""
  let e = if fileExists(errPath): readFile(errPath) else: ""
  (o, e, code)

suite "io-mon's command line is clispec's":
  let work = createTempDir("io-mon-cli-grammar", "")
  let cli = work / ("io-mon" & ExeExt)
  let build = execCmdEx(quoteShellCommand(@[findExe("nim"), "c",
    "--hints:off", "--warnings:off", "--threads:on",
    "--nimcache:" & work / "nimcache", "--out:" & cli,
    repoRoot / "cmd" / "io_mon_snoop.nim"]))

  test "the binary builds":
    checkpoint(build.output)
    check build.exitCode == 0
    check fileExists(cli)

  when not defined(windows):
    test "help is generated from the description":
      for (args, path) in [(@["--help"], newSeq[string]()),
                           (@["-h"], newSeq[string]()),
                           (@["run", "--help"], @["run"]),
                           (@["inspect", "--help"], @["inspect"])]:
        checkpoint("argv: " & $args)
        let r = run(cli, args)
        check r.code == 0
        check r.stderr == ""
        let long = "--help" in args
        check r.stdout == IoMonCommandLine.helpText(path, long = long)
      # The pages name what they should, and the bare form stays out of them.
      let root = run(cli, @["--help"]).stdout
      check "run" in root and "inspect" in root
      check "--depfile" notin root
      let runPage = run(cli, @["run", "--help"]).stdout
      for flag in ["--depfile", "--events", "--format", "--event-stream",
                   "--interest", "--evidence", "--inline-site-tables",
                   "--capture-stdio", "--capture-stdio-path"]:
        checkpoint("flag: " & flag)
        check flag in runPage

    test "a command line the parser rejects is a usage error, exit 2":
      for args in [@["--bogus"],
                   @["run", "--bogus", "--", "true"],
                   @["run", "--depfile"],
                   @["run", "--depfile", "x"],          # no command
                   @["run", "--depfile", "x", "--"],    # an empty command
                   @["--depfile", "x"],                 # bare, no command
                   @["--depfile", "x", "echo", "hi"],   # bare, no `--`
                   @["run", "--events", "loud", "--", "true"],
                   @["inspect"],
                   @["inspect", "--format", "yaml", "f.iomon"]]:
        checkpoint("argv: " & $args)
        let r = run(cli, args)
        checkpoint(r.stderr)
        check r.code == 2
        check r.stdout == ""
        check r.stderr.startsWith("error: ")
        check "Usage: io-mon" in r.stderr

    test "a value the parser cannot judge is still the driver's error, exit 1":
      let r = run(cli, @["run", "--evidence=", "--", "true"])
      check r.code == 1
      check r.stderr.startsWith("io-mon: error: --evidence names no evidence scope")

  test "run and the bare form ask for the same run":
    let flags = @["--depfile", "d.iomon", "--events", "jsonl",
                  "--event-stream", "e.jsonl", "--interest", "file-reads,proc",
                  "--evidence", "reads-only", "--inline-site-tables", "t.bin",
                  "--capture-stdio-path", "s.txt"]
    let command = @["--", "cc", "-c", "--", "x.c"]
    let viaRun = parseFsSnoopArgs(@["run"] & flags & command)
    let bare = parseFsSnoopArgs(flags & command)
    for parsed in [viaRun, bare]:
      check not parsed.inspectMode
      check parsed.depfileWasExplicit
      check parsed.request.depFilePath == "d.iomon"
      check parsed.request.streamMode == fsoJsonl
      check parsed.request.eventStreamPath == "e.jsonl"
      check parsed.request.interest == {ecFileReads, ecProcessTree}
      check parsed.request.evidenceScope == esReadsOnly
      check parsed.request.inlineSiteTables == "t.bin"
      check parsed.request.captureChildStdio
      check parsed.request.captureStdioPath == "s.txt"
      # Every word after the first `--`, a later `--` included.
      check parsed.request.command == @["cc", "-c", "--", "x.c"]
      check parsed.request.passthroughChildStdout
      check parsed.request.passthroughChildStderr
    check viaRun.request == bare.request

  test "absent flags keep today's defaults":
    let parsed = parseFsSnoopArgs(@["run", "--", "true"])
    check not parsed.depfileWasExplicit
    check parsed.request.depFilePath == ""
    check parsed.request.streamMode == fsoNone
    check parsed.request.interest == {}  # normalised to every category
    check parsed.request.evidenceScope == esFull
    check not parsed.request.captureChildStdio
    check parsed.request.command == @["true"]

  test "--format and --events are one flag, on run and on inspect":
    check parseFsSnoopArgs(@["run", "--format=text", "--", "true"]).
      request.streamMode == fsoText
    check parseFsSnoopArgs(@["run", "--events", "binary-stream", "--",
      "true"]).request.streamMode == fsoBinaryStream
    for args in [@["inspect", "f.iomon", "--format", "json"],
                 @["inspect", "--events=json", "f.iomon"]]:
      let parsed = parseFsSnoopArgs(args)
      check parsed.inspectMode
      check parsed.inspectPath == "f.iomon"
      check parsed.inspectFormat == "json"
    check parseFsSnoopArgs(@["inspect", "f.iomon"]).inspectFormat == "text"

  test "a missing command is a usage error, not a run of nothing":
    expect CliUsageError:
      discard parseFsSnoopArgs(@["run", "--depfile", "d.iomon"])
    expect CliUsageError:
      discard parseFsSnoopArgs(@["--depfile", "d.iomon"])

  removeFixtureTree(work)
