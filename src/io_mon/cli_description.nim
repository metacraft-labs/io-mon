## The `io-mon` command line, described once in the clispec `cli:` language.
##
## io-mon's own binary (`cmd/io_mon_snoop.nim`, through `io_mon/cli`) parses
## its arguments with the parser clispec generates from this description, and
## prints the help clispec renders from it. A program that offers io-mon's
## command line under one of its own commands (a build tool's "run this under
## the monitor" command) splices the same description there, so both accept
## exactly the same words and describe them the same way:
##
## .. code-block:: nim
##   import io_mon/cli_description
##
##   proc myDescription(): NimNode {.compileTime.} =
##     let monitor = ioMonCommandLineDescription()
##     quote do:
##       subcmd "monitor", help = "Run a command under io-mon":
##         `monitor`
##
## and then hands the words after its own command to `io_mon/cli.
## runFsSnoopCli`, which parses them with io-mon's generated parser.
##
## The description is a compile-time proc returning the `cli:` BODY of the
## command (no root `help` statement: the program that holds it gives its
## command one) rather than a macro call, so a consumer can place it anywhere
## in its own tree. It imports only `std/macros` and clispec's
## `clispec/splice` (which itself imports only `std/macros`), so splicing it
## costs the consumer no dependency on the parser; the rest of the clispec
## library is needed only where a program is generated from it (`io_mon/cli`).
##
## The body is built with `quote`, which binds every name to a symbol of this
## module's scope; `cliUnbound` turns it back into the tree the `cli:`
## language reads (`afterSeparator = true` names the literal `true`,
## `seq[string]` is a bracket expression, the spliced `runParams` groups are
## flattened into the command that holds them).
##
## The grammar (clispec: https://github.com/metacraft-labs/nim-cli-spec):
##
## * `run [flags] -- <command> [args...]`: run a command under the monitor and
##   write its dependency file;
## * `inspect <depfile> [--format text|json]`: print a dependency file;
## * `[flags] -- <command> [args...]`, the same as `run` without the word: the
##   form io-mon's CLI accepted before `run` existed, which callers still
##   write. Its flags are `internal` (accepted, listed in no help screen), so
##   help offers `run` and `inspect` only.

import std/macros

import clispec/splice

proc runParams(visibility: string): NimNode {.compileTime.} =
  ## The parameters of a monitored run, shared by `run` and by the bare form
  ## (the `call:` of the command), which differ only in their `visibility`.
  ## Each flag's meaning is `FsSnoopRequest`'s field of the same purpose
  ## (`io_mon/types`); docs/usage.md describes them at length.
  let vis = ident(visibility)
  quote do:
    flag depfile is string, visibility = `vis`,
      help = "Where to write the dependency file (default: a temporary file, removed after the run)"
    flag events is string, alias = "--format", default = "none",
      values = ["none", "text", "jsonl", "binary", "binary-stream"],
      visibility = `vis`,
      help = "Also render the captured events: none, text, jsonl, or binary (also spelt binary-stream, which needs --event-stream)"
    flag eventStream is string, visibility = `vis`,
      help = "The file the rendered events go to (default: standard error)"
    flag interest is Option[string], visibility = `vis`,
      help = "The event categories to capture, comma-separated (file-reads, path-probes, file-writes, proc, lib, env, entropy, ambient); absent or empty: all of them"
    flag evidence is Option[string], visibility = `vis`,
      help = "How much of what is observed is recorded: full (the default) or reads-only, which keeps only lookups that found something"
    flag inlineSiteTables is string, visibility = `vis`,
      help = "Linux x86-64: a sealed table of inline syscall sites, produced by an unmonitored caller, that spares the monitored processes the scan of the images it covers"
    boolFlag captureStdio is bool, visibility = `vis`,
      help = "Capture the command's merged standard output and error instead of passing them through"
    flag captureStdioPath is Option[string], visibility = `vis`,
      help = "Capture them as --capture-stdio does, and write the captured bytes to this file"
    pos command is seq[string], afterSeparator = true, visibility = `vis`,
      help = "The command to run and its arguments, after --"

proc ioMonCommandLineDescription*(): NimNode {.compileTime.} =
  ## The `cli:` body of io-mon's command line (see the module
  ## documentation): the subcommands `run` and `inspect`, and a `call:` that
  ## takes `run`'s parameters without the word. Every symbol in it is an
  ## identifier, as a macro's untyped argument is, so it can be spliced into
  ## any `cli:` description.
  let bare = runParams("internal")
  let run = runParams("shown")
  result = cliUnbound(quote do:
    subcmd "run", help = "Run a command under the monitor and write the dependency file it read and wrote":
      `run`
    subcmd "inspect", help = "Print a dependency file":
      flag format is string, alias = "--events", default = "text",
        values = ["text", "json"],
        help = "The output format: text or json"
      pos path is string, help = "The dependency file"
    call:
      `bare`)
