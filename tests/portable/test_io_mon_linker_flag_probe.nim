## test_io_mon_linker_flag_probe -- the capture-time drop of a failed open of a
## linker `-l` flag token (src/io_mon/linker_flag_probe.nim, used by
## recordOpen in src/io_mon/shim/linux_preload.nim).
##
## What it proves, on literal strings and with no shim:
##   * the four tokens a linker probes (`-lc`, `-ldl`, `-lgcc`, `-lgcc_s`) and
##     the `-l:file` form are classified as linker flags;
##   * a real path is never classified as a linker flag, so a failed open of
##     one is still recorded: an absolute or relative path with a slash, a bare
##     `libc.so`, a `-` or `-l` with nothing after it, and `-I`/`-L` flags.
##
## What it does NOT prove: that the shim drops the record at runtime. The shim
## cannot be run from a portable test; its wiring is checked by the source
## assertion below, and the depfile-level result is measured separately.

import std/[unittest, strutils]
import io_mon/linker_flag_probe

suite "failed opens of linker -l flag tokens are not inputs":
  test "the tokens a linker probes are linker flags":
    for token in ["-lc", "-ldl", "-lgcc", "-lgcc_s", "-l:libfoo.so"]:
      check isLinkerFlagProbe(token)

  test "a real path is never a linker flag, so its failed open is recorded":
    for token in ["libc.so", "./libc.so", "build/-lc", "/usr/lib/libc.so",
                  "C:\\lib\\-lc", "src/-lgcc_s", "-", "-l", "-I/usr/include",
                  "-L/usr/lib", "", "lib-lc"]:
      check not isLinkerFlagProbe(token)

  test "the shim calls the classifier only on a failed open":
    # The wiring the runtime assertion cannot reach: recordOpen must guard on
    # `fd < 0` AND the classifier, and must do so before it resolves or
    # records the path.
    let src = readFile("src/io_mon/shim/linux_preload.nim")
    let guard = "if fd < 0 and path != nil and isLinkerFlagProbe($path):"
    check src.contains(guard)
    let guardAt = src.find(guard)
    let recordAt = src.find("var record = baseRecord(mrFileOpen, observationForOpen(flags))")
    check guardAt >= 0 and recordAt > guardAt
