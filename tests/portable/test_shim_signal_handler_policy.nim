## Every injected shim is built with ``-d:noSignalHandler``.
##
## Nim's default runtime installs SIGSEGV/SIGILL/... handlers in whatever
## process loads it. For an injected shim, that is the HOST program: gcc, cc1,
## rustc. A crash in the host then prints "SIGSEGV: Illegal storage access"
## and exits 1. That hides the real fault and blames Nim in a program that
## contains none. It happened on Windows, where only macOS carried the define
## (2026-09).
##
## The define lives in ``<shim>.nim.cfg`` beside each shim's project file,
## which Nim applies to every build of that file. That covers
## ``scripts/build_shim.sh`` and reprobuild's shim edges, with nothing to
## forget at a call site. This test pins the files. It is portable because it
## only reads sources, so a Linux or macOS CI run catches a Windows
## regression. It also checks, with ``nim dump``, that Nim really applies the
## file to the project.
##
## No mocks.

import std/[os, osproc, strutils, unittest]

const shimDir = currentSourcePath().parentDir().parentDir().parentDir() /
  "src" / "io_mon" / "shim"

proc cfgDefines(cfgPath: string): seq[string] =
  for raw in readFile(cfgPath).splitLines():
    let line = raw.split('#', 1)[0].strip()
    if line.startsWith("-d:") or line.startsWith("--define:"):
      result.add line.split(':', 1)[1].strip()

suite "injected shims do not install signal handlers":
  for shim in ["windows_interpose", "macos_interpose"]:
    test shim & ".nim.cfg defines noSignalHandler":
      let cfg = shimDir / (shim & ".nim.cfg")
      require fileExists(cfg)
      check "noSignalHandler" in cfgDefines(cfg)

  test "nim applies windows_interpose.nim.cfg to the Windows shim build":
    let nim = findExe("nim")
    if nim.len == 0:
      skip()
    else:
      let (output, rc) = execCmdEx(quoteShellCommand([nim, "dump",
        "--hints:off", "--os:windows", "--cpu:amd64", "--app:lib",
        shimDir / "windows_interpose.nim"]))
      checkpoint(output)
      check rc == 0
      check "noSignalHandler" in output
