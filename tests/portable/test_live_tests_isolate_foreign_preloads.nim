## Every test that runs on Linux imports `foreign_preload_isolation` before
## anything else.
##
## That module re-execs a test without agent-harbor's self-propagating
## command-trace shim (see `tests/helpers/foreign_preload_isolation.nim` and
## `tests/linux/test_io_mon_foreign_preload_isolation.nim`). It only works
## when it is initialised first, and Nim initialises modules in import order.
## A test added without it passes everywhere except in an agent session,
## which is how eleven tests in seven files came to fail there. So the rule
## is checked here, over the source, on every OS.
##
## The directories are the ones the suite runs on Linux (`tests/README.md`):
## `portable/`, `posix/` and `linux/`.
##
## Mocks: none. The check reads the real test sources; the two inline sources
## are the negative controls showing the check can fail.
import foreign_preload_isolation

import std/[os, strutils, unittest]

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  GuardImport = "import foreign_preload_isolation"

proc firstImport(source: string): string =
  ## The first top-level `import`, `from` or `include` statement in `source`.
  for line in source.splitLines():
    let word = line.split({' ', '\t'}, 1)[0]
    if word in ["import", "from", "include"]:
      return line.strip()
  ""

suite "live tests isolate themselves from foreign preloads":
  test "t_the_check_sees_a_missing_or_late_guard":
    check firstImport("## doc\nimport std/os\n" & GuardImport & "\n") != GuardImport
    check firstImport("## doc\nconst x = 1\n") == ""
    check firstImport("## doc\n" & GuardImport & "\n\nimport std/os\n") == GuardImport

  test "t_every_linux_run_test_imports_the_guard_first":
    var checked = 0
    for dir in ["portable", "posix", "linux"]:
      for path in walkFiles(repoRoot / "tests" / dir / "test_*.nim"):
        inc checked
        let first = firstImport(readFile(path))
        if first != GuardImport:
          checkpoint(relativePath(path, repoRoot) & ": first import is `" &
            first & "`, expected `" & GuardImport & "`")
        check first == GuardImport
    checkpoint("checked " & $checked & " test files")
    check checked > 100
