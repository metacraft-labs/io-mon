## io-mon — the standalone snoop CLI binary for io-mon.
##
## # What this is (relocation of reprobuild's `repro internal io monitor`)
##
## reprobuild never shipped a *standalone* fs-snoop binary: its snoop surface
## was the `repro internal io monitor` / `repro debug io monitor` subcommand,
## a thin
## dispatcher that calls `runFsSnoopCli` (the in-process driver that injects the
## interpose shim around a command and writes the captured RMDF depfile — see
## reprobuild's `repro_cli_support.nim`). io-mon already relocated that driver
## into `io_mon/fs_snoop.nim` (`runFsSnoopCli` / `findShimLibrary`); this module
## is the missing *binary entry point* that exposes it on PATH so out-of-process
## consumers (the CodeTracer incremental test runner's live read-file capture,
## `codetracer/src/ct_test/incremental/io_mon_capture.nim`) can drive a live
## capture in a clean subprocess instead of in-process.
##
## It is a faithful relocation: the dispatch + argument grammar is `fs_snoop`'s
## own (`run [--depfile PATH] [--events MODE] [--event-stream PATH] -- <command>`,
## plus `inspect <depfile> [--format text|jsonl|json]`), reusing io-mon's
## modules with NO new vendoring and NO reprobuild import.
##
## # Usage
##
##   io-mon run --depfile <out.rdep> -- <command> [args...]
##   io-mon inspect <depfile> [--format text|jsonl|json]
##
## On `run`, the shim shared library (`librepro_monitor_shim.{dylib,so,dll}`) is
## injected around `<command>` via `DYLD_INSERT_LIBRARIES` (macOS) /
## `LD_PRELOAD` (Linux) / `CreateRemoteThread`+`LoadLibraryW` (Windows), the
## command runs, and the captured read/written file observations are written to
## `<out.rdep>`. The shim is located by `io_mon/fs_snoop.findShimLibrary`
## (honouring `$REPRO_MONITOR_SHIM_LIB` first, then the canonical build layout).
##
## # Platform reality (honest gaps — see also the runner's io_mon_capture.nim)
##
## - macOS SIP: `DYLD_INSERT_LIBRARIES` injects into freshly-BUILT user binaries
##   but is stripped for SIP-protected / hardened system binaries. Snooping a
##   user binary works here; snooping a system tool yields an empty record set.
##   The runner treats an empty / failed capture as fail-safe → re-run, never a
##   false skip.
##   TODO(io-mon live interpose, macOS SIP): system-process interpose needs a
##   non-DYLD path (e.g. an ES/endpoint-security backend); user binaries are OK.
## - Linux `LD_PRELOAD`: needs full validation on a Linux host.
##   TODO(io-mon live interpose, Linux): validate LD_PRELOAD capture end-to-end.
## - Windows: the injector path needs validation under the DIY toolchain.
##   TODO(io-mon live interpose, Windows): validate the CreateRemoteThread path.

import std/os

import io_mon  # re-exports fs_snoop.runFsSnoopCli + findShimLibrary

const ProgramName = "io-mon"

when isMainModule:
  # Delegate the entire command grammar to the relocated driver. `runFsSnoopCli`
  # never raises (it converts every error into a non-zero exit + a stderr
  # diagnostic), so the binary's exit code mirrors the monitored command's exit
  # status on success and a non-zero failure code otherwise — exactly what an
  # out-of-process caller (the runner) needs to fail-safe on.
  let args = commandLineParams()
  quit(runFsSnoopCli(ProgramName, args))
