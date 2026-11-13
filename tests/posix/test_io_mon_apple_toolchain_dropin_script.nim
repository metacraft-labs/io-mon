## The Apple toolchain drop-in script applies the shim's SDK selection, and
## nothing else, before it execs its tool.
##
## On macOS, `/usr/bin/clang` is an `xcode_select` shim. Before it execs the
## real compiler it sets `SDKROOT` to the active developer directory's default
## SDK when the environment names none, and appends `/usr/local/include` and
## `/usr/local/lib` to `CPATH` and `LIBRARY_PATH` in that case only. Measured
## through `/usr/bin/xcrun env` on aarch64-darwin (Xcode 26.6, macOS 26.5):
##
##     env -i PATH=/usr/bin:/bin                 xcrun env -> SDKROOT=<sdk>
##                                                            CPATH=/usr/local/include
##                                                            LIBRARY_PATH=/usr/local/lib
##     env -i ... SDKROOT=                       xcrun env -> the same
##     env -i ... CPATH=/foo LIBRARY_PATH=/lfoo  xcrun env -> CPATH=/foo:/usr/local/include
##                                                            LIBRARY_PATH=/lfoo:/usr/local/lib
##     env -i ... SDKROOT=<sdk>                  xcrun env -> SDKROOT=<sdk>, nothing added
##
## io-mon's drop-in for that shim runs the real compiler instead, so it has to
## apply the same environment or a compile with `SDKROOT` unset cannot find
## `<stdlib.h>`. `renderAppleToolchainDropIn` produces that script. Its
## behaviour is shell semantics, so it is checked here on every POSIX host by
## running the rendered script under this host's real `sh`. The real-compiler
## half (a compile through the populated drop-in on a Mac) is
## tests/macos/test_io_mon_macos_apple_toolchain_dropins.nim.
##
## Test double, justified: the drop-in's target here is a small shell script
## that prints the environment and arguments it received, standing in for the
## compiler. The property under test is what the drop-in hands its target, and
## only a target that reports its environment can show that; no part of
## io-mon is mocked, and the macOS test runs the real compiler.

import std/[os, osproc, streams, strtabs, strutils, tempfiles, unittest]

import io_mon/fs_snoop

proc canonicalShell(): string =
  let sh = findExe("sh")
  doAssert sh.len > 0, "no sh on PATH"
  expandFilename(sh)

suite "Apple toolchain drop-in script":
  let shell = canonicalShell()
  # A directory name with a space and a single quote checks the quoting of
  # both the SDK path and the tool path the script embeds.
  let work = createTempDir("io-mon-dropin-script-", " o'q")
  defer: removeDir(work)
  let sdk = work / "SDKs" / "MacOSX it's.sdk"
  createDir(sdk)
  let tool = work / "bin dir" / "clang"
  createDir(tool.parentDir)
  writeFile(tool, "#!" & shell & "\n" &
    "printf 'SDKROOT=%s\\n' \"${SDKROOT-<unset>}\"\n" &
    "printf 'CPATH=%s\\n' \"${CPATH-<unset>}\"\n" &
    "printf 'LIBRARY_PATH=%s\\n' \"${LIBRARY_PATH-<unset>}\"\n" &
    "printf 'argc=%s\\n' \"$#\"\n" &
    "for a in \"$@\"; do printf 'arg=[%s]\\n' \"$a\"; done\n" &
    "exit \"${DROPIN_TEST_EXIT:-0}\"\n")
  setFilePermissions(tool, {fpUserRead, fpUserWrite, fpUserExec})
  let dropIn = work / "usr" / "bin" / "clang"
  createDir(dropIn.parentDir)
  writeFile(dropIn, renderAppleToolchainDropIn(shell, tool, sdk))
  setFilePermissions(dropIn, {fpUserRead, fpUserWrite, fpUserExec})

  proc run(env: openArray[(string, string)];
           args: openArray[string] = []): tuple[output: string; code: int] =
    # Only the variables named: the drop-in must not depend on anything the
    # test process happens to carry.
    var table = newStringTable(modeCaseSensitive)
    table["PATH"] = "/usr/bin:/bin"
    for (key, value) in env: table[key] = value
    let p = startProcess(dropIn, args = @args, env = table,
      options = {poStdErrToStdOut})
    defer: p.close()
    let output = p.outputStream.readAll()
    (output, p.waitForExit())

  test "the script is run by the named non-SIP shell":
    check renderAppleToolchainDropIn(shell, tool, sdk).startsWith(
      "#!" & shell & "\n")

  test "SDKROOT unset: the default SDK and the /usr/local paths, as the shim":
    let (output, code) = run([])
    check code == 0
    check ("SDKROOT=" & sdk) in output.splitLines
    check "CPATH=/usr/local/include" in output.splitLines
    check "LIBRARY_PATH=/usr/local/lib" in output.splitLines

  test "SDKROOT empty is SDKROOT unset":
    let (output, code) = run([("SDKROOT", "")])
    check code == 0
    check ("SDKROOT=" & sdk) in output.splitLines
    check "CPATH=/usr/local/include" in output.splitLines

  test "existing CPATH and LIBRARY_PATH stay in front":
    let (output, code) = run([("CPATH", "/foo"), ("LIBRARY_PATH", "/lfoo")])
    check code == 0
    check "CPATH=/foo:/usr/local/include" in output.splitLines
    check "LIBRARY_PATH=/lfoo:/usr/local/lib" in output.splitLines

  test "an empty CPATH or LIBRARY_PATH gains no empty entry":
    # A leading ':' would put an empty element, the current directory, on
    # the compiler's include and library search paths.
    let (output, code) = run([("CPATH", ""), ("LIBRARY_PATH", "")])
    check code == 0
    check "CPATH=/usr/local/include" in output.splitLines
    check "LIBRARY_PATH=/usr/local/lib" in output.splitLines

  test "SDKROOT set: kept, and nothing is added":
    let (output, code) = run([("SDKROOT", "/given/sdk")])
    check code == 0
    check "SDKROOT=/given/sdk" in output.splitLines
    check "CPATH=<unset>" in output.splitLines
    check "LIBRARY_PATH=<unset>" in output.splitLines

  test "arguments reach the tool unchanged":
    let args = @["-c", "a file.c", "", "$HOME", "it's", "-DX=\"y z\""]
    let (output, code) = run([], args)
    check code == 0
    check ("argc=" & $args.len) in output.splitLines
    for a in args:
      check ("arg=[" & a & "]") in output.splitLines

  test "no arguments stays no arguments":
    let (output, code) = run([])
    check code == 0
    check "argc=0" in output.splitLines

  test "the tool's exit status is the drop-in's":
    let (_, code) = run([("DROPIN_TEST_EXIT", "7")])
    check code == 7
