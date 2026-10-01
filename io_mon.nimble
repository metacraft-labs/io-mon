# Package
import std/strutils
version       = readFile("version.txt").strip()
author        = "Metacraft Labs"
description   = "Cross-platform filesystem I/O monitoring for Nim (relocation of reprobuild's fs-snoop stack) on nim-stackable-hooks."
license       = "Apache-2.0"
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

include "scripts/test_catalog.nims"

proc reproWithNixDynlibs(command: string): string =
  ## Some local Nix shells expose `repro` before its dlopen/runtime libraries are
  ## on dyld's search path. Keep the default `nimble test` task self-contained by
  ## discovering already-realized clingo/zstd store outputs when the caller has
  ## not supplied explicit library paths.
  "CLINGO_LIB=\"${CLINGO_LIB:-$(find /nix/store -maxdepth 1 -type d -name '*clingo-5.*' -print -quit 2>/dev/null)/lib}\"; " &
    "ZSTD_LIB=\"${ZSTD_LIB:-$(find /nix/store -maxdepth 1 -type d -name '*zstd-1.*' -print -quit 2>/dev/null)/lib}\"; " &
    "DYLD_LIBRARY_PATH=\"$CLINGO_LIB:$ZSTD_LIB:${DYLD_LIBRARY_PATH:-}\" " &
    "DYLD_FALLBACK_LIBRARY_PATH=\"$CLINGO_LIB:$ZSTD_LIB:${DYLD_FALLBACK_LIBRARY_PATH:-}\" " &
    "LD_LIBRARY_PATH=\"$CLINGO_LIB:$ZSTD_LIB:${LD_LIBRARY_PATH:-}\" " &
    command

task test, "Run the io-mon test suite via reprobuild":
  runTestDirs(selectedTestDirs())

task testPortable, "Run only the portable io-mon tests":
  runTestDirs(@["tests/portable"])

task testPlatform, "Run only the host-platform io-mon tests":
  var dirs: seq[string]
  when defined(posix):
    dirs.add "tests/posix"
  when defined(macosx):
    dirs.add "tests/macos"
  when defined(linux):
    dirs.add "tests/linux"
  when defined(windows):
    dirs.add "tests/windows"
  runTestDirs(dirs)

task buildShim, "Build the io-mon interpose shim via reprobuild":
  exec reproWithNixDynlibs("repro build io-mon:shim")

task buildSnoop, "Build the io-mon standalone CLI via reprobuild":
  exec reproWithNixDynlibs("repro build io-mon")
