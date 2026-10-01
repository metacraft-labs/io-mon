## Native test entrypoint: let Nim propagate compilation and execution failures.
## The Windows Nimble bundled with Nim 2.2.10 returns zero after task exceptions.
## Share discovery and compiler invocations with the compatibility Nimble tasks.
import std/os
include "test_catalog.nims"

withDir currentSourcePath().parentDir().parentDir():
  when defined(ioMonPortableTests):
    runTestDirs(@["tests/portable"])
  elif defined(ioMonPlatformTests):
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
  else:
    runTestDirs(selectedTestDirs())
