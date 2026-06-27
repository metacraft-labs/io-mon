# Package

version       = "0.1.0"
author        = "Metacraft Labs"
description   = "Cross-platform filesystem I/O monitoring for Nim (relocation of reprobuild's fs-snoop stack) on nim-stackable-hooks."
license       = "MIT"
srcDir        = "src"
skipDirs      = @["tests"]

# Dependencies
#
# io-mon builds on nim-stackable-hooks (the interpose framework, package name
# `stackable_hooks`). In this `repo`-managed multi-repo workspace, sibling
# checkouts are resolved by path — consistent with the other Metacraft Nim
# siblings (nim-acp, nim-agents, codetracer-trace-format-nim), which likewise
# do NOT pin workspace siblings as Nimble git deps. The `--path` switch is
# supplied by the test task below (and by the documented `nim c -r --path:...`
# invocations), so no published `stackable_hooks` package is required.
#
# Deliberately NOT a git dependency: a `requires "https://…/nim-stackable-hooks"`
# would fight the sibling checkout the workspace already provides (pulling a
# second, divergent copy into ~/.nimble). CI runs from the workspace and uses
# the same sibling path.
requires "nim >= 2.0.0"

import std/[strutils, algorithm]

# ---------------------------------------------------------------------------
# Per-OS test selection by DIRECTORY DISCOVERY.
#
# The test tree is organised by portability (see tests/README.md):
#
#   tests/portable/  — pure-logic tests; run on EVERY OS (no live shim, no
#                      platform-specific API/import).
#   tests/posix/     — behaviour shared across POSIX shims (macOS, Linux, *BSD,
#                      Solaris); run when the host is POSIX.
#   tests/macos/     — macOS-only (DYLD interpose + body-patch live).
#   tests/linux/     — Linux-only (LD_PRELOAD shim live).
#   tests/windows/   — Windows-only (injected hooks).
#
# Selection is driven by the HOST OS (this NimScript runs on the host, so
# `defined(...)` reflects it). Adding a `test_*.nim` file to a selected
# directory makes it run with NO change to this task; adding support for a new
# OS (e.g. FreeBSD/Solaris) is a `tests/<os>/` dir plus a `when defined(<os>)`
# arm below. The shared `--path` flags resolve identically from the repo root
# regardless of how deep a test file lives (config.nims supplies `--path:src`).
# ---------------------------------------------------------------------------

# The directories whose `test_*.nim` files the host should run.
proc selectedTestDirs(): seq[string] =
  result = @["tests/portable"]          # ALWAYS — pure logic, every OS.
  when defined(posix):                  # macOS, Linux, *BSD, Solaris.
    result.add "tests/posix"
  when defined(macosx):
    result.add "tests/macos"
  when defined(linux):
    result.add "tests/linux"
  when defined(windows):
    result.add "tests/windows"

# Compile + run every `test_*.nim` in the selected directories.
proc runTestDirs(dirs: seq[string]) =
  # `--path:../nim-stackable-hooks/src` resolves the `stackable_hooks/...` imports
  # (the sibling checkout, not a published package); `--path:tests/helpers` makes
  # the shared test helpers (e.g. `macos_backend_toggle`) importable from any
  # per-OS directory; `--path:src` comes from config.nims.
  let flags = "--path:../nim-stackable-hooks/src --path:tests/helpers"
  for dir in dirs:
    if not dirExists(dir): continue
    var files: seq[string]
    for f in listFiles(dir):
      # Basename, separator-agnostic (NimScript lacks os.splitPath; listFiles may
      # return `\`-separated paths on Windows).
      let name = f.replace("\\", "/").rsplit('/', 1)[^1]
      if name.startsWith("test_") and name.endsWith(".nim"):
        files.add f
    sort(files)                         # deterministic, reproducible order.
    for f in files:
      exec "nim c -r " & flags & " " & f

task test, "Run the io-mon test suite (auto-selecting tests for the host OS)":
  runTestDirs(selectedTestDirs())

task testPortable, "Run ONLY the portable (every-OS) io-mon tests":
  runTestDirs(@["tests/portable"])

task testPlatform, "Run ONLY the host-OS platform-specific io-mon tests":
  var dirs = selectedTestDirs()
  dirs.delete(dirs.find("tests/portable"))
  runTestDirs(dirs)

task buildShim, "Build the io-mon interpose shim shared library":
  # Produces build/lib/librepro_monitor_shim.{dylib,so,dll} — the drop-in
  # shared-library name reprobuild's M7 swap and io-mon's own fs_snoop locate.
  exec "scripts/build_shim.sh"

task buildSnoop, "Build the io-mon standalone CLI binary":
  # Produces build/bin/io-mon — the standalone snoop entry point on PATH
  # (a relocation of reprobuild's `repro internal io monitor` subcommand). It
  # runs a command under the interpose shim and writes the captured RMDF
  # depfile, so out-of-process consumers (the CodeTracer incremental test
  # runner's live read-file capture) can drive a live capture in a clean
  # subprocess.
  #
  # The snoop CLI depends only on io-mon's own modules + nim-stackable-hooks
  # (fs_snoop's interpose driver imports it); the sibling checkout is added to
  # the path the same way the test task does, so no published package is needed.
  let hooksPath = "--path:../nim-stackable-hooks/src"
  exec "nim c " & hooksPath & " --path:src --threads:on " &
    "--out:build/bin/io-mon cmd/io_mon_snoop.nim"
