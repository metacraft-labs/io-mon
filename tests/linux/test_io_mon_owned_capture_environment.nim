## Execute the actual runtime ownership helpers against the genuine production
## shared shim. Linking the real flush callback avoids embedding a second shim
## constructor; no callback or allocation implementation is replaced.
import std/[os, osproc, strutils, unittest]
import ../helpers/[capture_control_fixtures, build_test_shim]

let work = captureFixtureDirectory()
let shim = buildPrivateLinuxShim(captureRepoRoot)
let compiler = findExe("nim")
doAssert compiler.len > 0, "declared Nim compiler is required"
let binary = work / "owned-capture-environment"
let built = execCmdEx(quoteShell(compiler) & " c --path:" &
  quoteShell(captureRepoRoot / "src") & " --nimcache:" & quoteShell(work / "nimcache") &
  " --out:" & quoteShell(binary) & " --passL:" & quoteShell(shim) &
  " --passL:" & quoteShell("-Wl,-rpath," & shim.parentDir) & " " &
  quoteShell(captureRepoRoot / "tests/helpers/owned_capture_environment_body.nim"),
  workingDir = captureRepoRoot)
doAssert built.exitCode == 0, built.output
let observed = execCmdEx(quoteShell(binary))
echo observed.output
const expected = [
  "missing child route copies actual parent values and frees only owned entries",
  "actual exec generation composes route and retains borrowed input",
  "already-loaded shim still receives missing route controls",
  "borrowed unchanged result is never interpreted as owned header"]
suite "production linked ownership regression":
  test "all four real ownership assertions execute and succeed":
    checkpoint(observed.output)
    check observed.exitCode == 0
    check "[FAILED]" notin observed.output
    for name in expected:
      check "[OK] " & name in observed.output
