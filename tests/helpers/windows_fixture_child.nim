## No mocks: this executable is also the real child, built by the same compiler.
## A Windows ARM64 host may supply an ARM64 system shell to an x64 test process.
## These tests concern capture and termination, so their child must match the shim.
import std/[os, strutils]

const FixtureChildFlag = "--io-mon-native-fixture-child"

if paramCount() == 2 and paramStr(1) == FixtureChildFlag:
  quit(parseInt(paramStr(2)))

proc windowsFixtureCommand*(exitCode = 0): seq[string] =
  @[getAppFilename(), FixtureChildFlag, $exitCode]
