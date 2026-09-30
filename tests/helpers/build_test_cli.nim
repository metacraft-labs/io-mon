## Build the real CLI from this checkout before a test launches it. Checking
## for an existing binary alone can accept a stale build or fail a clean CI job.
import std/[os, osproc, strutils]

proc buildTestCli*(repoRoot: string): string =
  let nim = findExe("nim")
  doAssert nim.len > 0, "Nim compiler is required for the CLI fixture"
  result = repoRoot / "build" / "bin" / ("io-mon" & ExeExt)
  createDir(result.parentDir)
  let (output, code) = execCmdEx(quoteShell(nim) &
    " c --threads:on --out:" & quoteShell(result) & " " &
    quoteShell(repoRoot / "cmd" / "io_mon_snoop.nim"))
  doAssert code == 0, "CLI fixture compilation failed: " & output
  doAssert fileExists(result), "CLI fixture was not produced: " & result
