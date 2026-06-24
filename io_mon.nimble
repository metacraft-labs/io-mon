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

task test, "Run the io-mon test suite":
  # The sibling nim-stackable-hooks checkout is added to the path so the
  # `stackable_hooks/...` imports resolve without a published package.
  let hooksPath = "--path:../nim-stackable-hooks/src"
  exec "nim c -r " & hooksPath & " tests/test_io_mon_parity_with_fs_snoop.nim"
  exec "nim c -r " & hooksPath & " tests/test_io_mon_builds_standalone.nim"
  # The relocated interpose shim (io_mon/shim, io_mon/hooks) must build as a
  # drop-in `librepro_monitor_shim` shared library on nim-stackable-hooks with
  # no reprobuild path (this test invokes `nim c --app:lib` internally).
  exec "nim c -r " & hooksPath & " tests/test_io_mon_shim_builds_standalone.nim"
  # M8: the standalone io-mon CLI builds, is resolvable, and drives a live
  # capture over a freshly-built user binary (honestly documenting the macOS
  # chained-fixups interpose gap rather than faking a capture).
  exec "nim c -r " & hooksPath & " tests/test_io_mon_snoop_cli.nim"

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
