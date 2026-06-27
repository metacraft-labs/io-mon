## test_io_mon_builds_standalone — io-mon builds and runs with ONLY
## nim-stackable-hooks on the path, and has NO dependency on reprobuild.
##
## The fact that this module COMPILES AT ALL is the primary proof: it pulls in
## the entire io-mon public surface (`import io_mon` re-exports every submodule,
## including `fs_snoop`, which is the one that referenced `repro_core/paths` and
## `stackable_hooks/propagation`). It is built with `--path:../nim-stackable-hooks/src`
## and WITHOUT any reprobuild path on the search path (see the nimble `test`
## task / the M5 build instructions), so a lingering `repro_*` import would fail
## to resolve and break the build.
##
## On top of that compile-time proof, the runtime checks below exercise the
## public API end-to-end so "builds" also means "works".

import std/[os, tempfiles, unittest]

import io_mon

# Prove the intended dependency IS present and reachable: io-mon builds ON
# nim-stackable-hooks. If the sibling checkout were missing from the path, this
# import would fail — which is exactly the standalone contract (stackable_hooks
# yes, reprobuild no).
import stackable_hooks/propagation

suite "io-mon standalone build":

  test "the io-mon public API is importable and usable":
    # Touch a symbol from every public submodule re-exported by `io_mon`, so
    # the linker actually pulls each one in.
    let record = MonitorRecord(            # io_mon/types
      kind: mrFileRead,
      observationKind: moFileRead,
      seq: 1,
      path: "/some/input")
    check record.path == "/some/input"

    let frame = encodeFrame(record)        # io_mon/writer
    check frame.len > 0
    let decoded = decodeFrames(frame)      # io_mon/writer
    check decoded.len == 1
    check decoded[0].path == "/some/input"

    let dep = depFileFromRecords(@[record])  # io_mon/writer
    let text = renderMonitorDepFileText(dep) # io_mon/render
    check text.len > 0

    # io_mon/capabilities
    check capabilityId(mcapFileRead).len > 0

    # io_mon/reader — full file round-trip through the public reader.
    let root = createTempDir("io-mon-standalone", "")
    defer: removeDir(root)
    let depfile = root / "rt.rdep"
    writeCanonical(depfile, @[record])
    let readBack = readMonitorDepFile(depfile)
    check readBack.records.len == 1
    check readBack.records[0].path == "/some/input"

  test "the stackable_hooks dependency is reachable":
    # `isSipProtected` is a propagation symbol the macOS fs_snoop path uses.
    # Calling it proves nim-stackable-hooks is on the path and linked. The
    # value is platform-dependent; we only assert the call succeeds.
    when defined(macosx):
      discard isSipProtected("/bin/sh")
    check true
