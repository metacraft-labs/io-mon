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
#
# A failing program does NOT stop the run: every program is compiled and run,
# and the failures are reported together at the end, then raised as ONE
# exception, so the task still fails (callers rely on the exception
# propagating; see scripts/run_tests.nims). Stopping at the first failure hid
# every program after it: one load-dependent failure in
# test_io_mon_linux_tree_ledger hid 36 Linux programs that all passed when run
# on their own.
proc runTestDirs(dirs: seq[string]) =
  # config.nims resolves source dependencies from explicit environment paths
  # or sibling checkouts. Keep that choice for tests as well as normal builds.
  # The shared helpers must be importable from every per-OS test directory.
  let flags = "--path:tests/helpers"
  var failed: seq[string]
  var ran = 0
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
      inc ran
      try:
        exec "nim c -r " & flags & " " & f
      except OSError as e:
        echo "FAILED: ", f, ": ", e.msg
        failed.add f
  if failed.len > 0:
    var report = $failed.len & " of " & $ran & " test programs failed:"
    for f in failed:
      report.add "\n  " & f
    echo report
    raise newException(OSError, report)
