## The `io-mon` command line as a program: the parser, help and completion
## clispec generates from `io_mon/cli_description`, and the driver that runs
## what they parse.
##
## Not re-exported by `io_mon`: the library API (`runMonitored`,
## `startMonitor`, ...) carries no command-line dependency. A program that
## runs io-mon's command line (`cmd/io_mon_snoop.nim`, or a tool that mounts
## the description under a command of its own) imports this module.
##
## Help, completion and usage errors are clispec's (the error block and the
## usage exit code 2); there is no hand-written usage text. A command line
## that parses but cannot run (no shim, an unreadable dependency file, an
## `--interest` value naming no category) is reported as
## `<program>: error: <message>` with exit 1, as before the description.

import std/[macros, options, os]

import clispec

import ./types
import ./fs_snoop
import ./render
import ./cli_description

export options

macro ioMonCommandLineProgram() =
  ## `IoMonCommandLine`: the configuration object, `load`, `printHelp`,
  ## `printError`, `helpText`, `completionScript`, ... of `io-mon`.
  #
  # The root's statements (`help`, and the command line's naming convention,
  # kebab-case: `eventStream` is `--event-stream`) are the program's, not the
  # description's: a program that splices the description under a command
  # of its own states them at its own root.
  var body = parseStmt("""
help "Run a command under io-mon's filesystem monitor and write the files it read and wrote to a dependency file, or print one"
convention cli = kebabCase
""")
  for statement in ioMonCommandLineDescription():
    body.add(statement)
  let model = parseCliModel[NoCliExtension, NoCliExtension](body,
    NoCliExtension())
  cliProgramCode(model, "IoMonCommandLine", "io-mon", exported = true)

ioMonCommandLineProgram()

type
  ParsedFsSnoopCommand* = object
    ## What a command line asks io-mon to do: print the dependency file
    ## `inspectPath` in `inspectFormat` (`inspectMode`), or run `request`.
    inspectMode*: bool
    inspectPath*: string
    inspectFormat*: string
    request*: FsSnoopRequest
    depfileWasExplicit*: bool
      ## `--depfile` was given: the run keeps the dependency file. Without
      ## it the file lives in a temporary directory removed after the run.

proc requestOf[T](c: T): ParsedFsSnoopCommand =
  ## The run the parameters of `run`, or of the bare form, ask for. `T` is
  ## the configuration object of either; both declare the same parameters
  ## (`cli_description.runParams`). Raises `ValueError` for a value the
  ## description cannot refuse by itself (`--interest`, `--evidence`).
  result.request.streamMode = parseOutputMode(c.events)
  result.request.passthroughChildStdout = true
  result.request.passthroughChildStderr = true
  result.request.depFilePath = c.depfile
  result.depfileWasExplicit = c.depfile.len > 0
  result.request.eventStreamPath = c.eventStream
  result.request.inlineSiteTables = c.inlineSiteTables
  # Absent: the request's zero value `{}`, which `normalizeInterest` reads
  # as every category. Given empty: `parseInterestFlag("")`, every category
  # spelt out. Both mean the same to the child (`childEnv`).
  if c.interest.isSome:
    result.request.interest = parseInterestFlag(c.interest.get())
  # Absent: full scope (the request's zero value). Given, even empty: the
  # flag's own decoding, which refuses an empty or unknown scope.
  if c.evidence.isSome:
    result.request.evidenceScope = parseEvidenceScopeFlag(c.evidence.get())
  result.request.captureChildStdio = c.captureStdio
  if c.captureStdioPath.isSome:
    result.request.captureStdioPath = c.captureStdioPath.get()
    result.request.captureChildStdio = true
  result.request.command = c.command

proc fsSnoopCommandOf*(conf: IoMonCommandLine): ParsedFsSnoopCommand =
  ## The command a parsed command line asks for. Raises `ValueError` as
  ## `requestOf` does.
  case conf.command
  of IoMonCommandLineCommand.inspect:
    result.inspectMode = true
    result.inspectPath = conf.inspect.path
    result.inspectFormat = conf.inspect.format
  of IoMonCommandLineCommand.run:
    result = requestOf(conf.run)
  of IoMonCommandLineCommand.call:
    result = requestOf(conf.call)

proc parseFsSnoopArgs*(args: seq[string]): ParsedFsSnoopCommand =
  ## `args` (io-mon's arguments, without the program name) parsed by the
  ## generated parser. Raises clispec's `CliHelpRequest` / `CliUsageError`
  ## for a help request or a command line it rejects, and `ValueError` as
  ## `fsSnoopCommandOf` does.
  fsSnoopCommandOf(IoMonCommandLine.load(args))

proc runFsSnoopCli*(programName: string; args: seq[string]): int =
  ## Runs io-mon's command line `args` (without the program name). Never
  ## raises:
  ##
  ## * a help or completion request is printed on stdout (exit 0);
  ## * a command line the parser rejects is clispec's error block on stderr
  ##   (exit 2);
  ## * `inspect` prints the dependency file (exit 0);
  ## * a run returns the monitored command's exit status;
  ## * any other failure is `<programName>: error: <message>` (exit 1).
  ##
  ## `programName` names the program in that last message only: help and
  ## usage errors name `io-mon`, whose command line this is. A program that
  ## mounts the description under its own command answers help and usage
  ## errors with its own parser before calling this.
  var parsed: ParsedFsSnoopCommand
  try:
    parsed = parseFsSnoopArgs(args)
  except CliHelpRequest as e:
    IoMonCommandLine.printHelp(e)
    return 0
  except CliUsageError as e:
    IoMonCommandLine.printError(e)
    return e.exitCode
  except CatchableError as err:
    stderr.writeLine(programName & ": error: " & err.msg)
    return 1
  try:
    if parsed.inspectMode:
      echo renderMonitorDepFile(parsed.inspectPath, parsed.inspectFormat)
      return 0

    var tempRoot = ""
    if parsed.request.depFilePath.len == 0:
      tempRoot = createLocalTempDir("repro-fs-snoop")
      parsed.request.depFilePath = tempRoot / "evidence.iomon"
    try:
      # The CLI is a thin wrapper over the public batch host API — no
      # duplicated lifecycle. `runMonitored` owns the shm/consumer setup; we
      # only surface its exit code (the depfile it wrote is inspected
      # out-of-band).
      result = runMonitored(parsed.request).exitCode
    finally:
      if tempRoot.len > 0:
        # Best-effort cleanup. On Windows the monitor shim's lingering
        # handles (file-handle reuse, deferred delete on close) can leave
        # directory entries that the regular ``removeDir`` cannot
        # immediately unlink. Surfacing that as an action failure would mask
        # the monitored command's actual exit status, so the diagnostic is
        # suppressed and the OS reaps the temp tree on the next scratch
        # sweep. The temp directory's contents are evidence-only and never
        # cross-process consumed.
        try:
          removeLocalTempDir(tempRoot)
        except OSError:
          discard
  except CatchableError as err:
    stderr.writeLine(programName & ": error: " & err.msg)
    result = 1
