## Exercise real dlopen/constructor and pthread mutex ordering, with a real
## connect through the production monitor. The child library is a trigger for
## the observed LTTng ordering; no monitor callback or resolver is substituted.
## Genuine .NET lease/monitor acceptance remains a separate integration gate.
import std/[os, osproc, sequtils, unittest]
import ../../src/io_mon/[fs_snoop, types]
import ../helpers/[capture_control_fixtures, build_test_shim]

let work = captureFixtureDirectory()
let compiler = findExe("gcc")
doAssert compiler.len > 0
let driver = work / "connect-loader-driver"
let library = work / "connect-loader-constructor.so"
let helperRoot = captureRepoRoot / "tests/helpers"
let compileDriver = execCmdEx(quoteShell(compiler) &
  " -std=c11 -O2 -Wall -Wextra -pthread -Wl,-z,now -rdynamic " &
  quoteShell(helperRoot / "connect_loader_driver.c") & " -ldl -o " & quoteShell(driver))
doAssert compileDriver.exitCode == 0, compileDriver.output
let compileLibrary = execCmdEx(quoteShell(compiler) &
  " -std=c11 -O2 -Wall -Wextra -shared -fPIC -Wl,-z,now " &
  quoteShell(helperRoot / "connect_loader_constructor.c") & " -o " & quoteShell(library))
doAssert compileLibrary.exitCode == 0, compileLibrary.output
let compiledShim = buildPrivateLinuxShim(captureRepoRoot)
# The original helper owns an exit cleanup. Retain an exact produced image in
# this control's exclusive fixture tree for execution and post-drain authority.
let shimDirectory = work / "shim"
createDir(shimDirectory)
let shim = shimDirectory / "librepro_monitor_shim.so"
copyFile(compiledShim, shim)
setFilePermissions(shim, getFilePermissions(compiledShim))
doAssert readFile(shim) == readFile(compiledShim)
putEnv("REPRO_MONITOR_SHIM_LIB", shim)
let input = work / "input.txt"
writeFile(input, "real input after loader-lock handshake\n")
echo "CONNECT_FIXTURE_WORK=" & work
echo "CONNECT_FIXTURE_DRIVER=" & driver
echo "CONNECT_FIXTURE_LIBRARY=" & library
echo "CONNECT_FIXTURE_SHIM=" & shim
suite "real connect loader constructor":
  test "worker connect completes while dlopen constructor waits on library mutex":
    var request: FsSnoopRequest
    request.command = @[driver, library, input, work / "peer.sock"]
    request.depFilePath = work / "loader.iomon"
    request.streamMode = fsoNone
    let observed = runMonitored(request)
    checkpoint("exit=" & $observed.exitCode & " completeness=" & $observed.completeness)
    check observed.exitCode == 0
    check observed.completeness == mcComplete
    check observed.records.anyIt(it.kind == mrFileRead and it.path == input)
    check not observed.records.anyIt(it.kind == mrEventLoss)
