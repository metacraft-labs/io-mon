## Compile genuine child programs with the selected owning C compiler.
## Exclusive fixture storage is retained for diagnostics until the test runner
## has drained descendants, including intentionally abandoned nested captures.
import std/[os, osproc, tempfiles]
import build_test_shim

const captureRepoRoot* = currentSourcePath().parentDir.parentDir.parentDir

proc captureFixtureDirectory*(): string =
  createTempDir("io-mon-capture-control-", "")

proc compileCaptureDriver*(work, sourceName: string): string =
  let compiler = findExe("gcc")
  doAssert compiler.len > 0, "declared GCC is required"
  let source = captureRepoRoot / "tests/helpers" / sourceName
  doAssert fileExists(source), "genuine child source missing: " & source
  result = work / sourceName.changeFileExt("")
  let built = execCmdEx(quoteShell(compiler) & " -std=c11 -O2 -Wall -Wextra " &
    quoteShell(source) & " -o " & quoteShell(result))
  doAssert built.exitCode == 0, built.output

proc activateCaptureFixtureShim*() =
  putEnv("REPRO_MONITOR_SHIM_LIB", buildPrivateLinuxShim(captureRepoRoot))
