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
  # config.nims resolves source dependencies from explicit environment paths
  # or sibling checkouts. Keep that choice for tests as well as normal builds.
  # The shared helpers must be importable from every per-OS test directory.
  let flags = "--path:tests/helpers"
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
