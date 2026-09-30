## No mocks: an x64 fixture starts the actual Windows identity tool. Compare
## its native output with a monitored run, including on an ARM64 host where
## the system child cannot use the x64 shim. Missing capture must remain loss.
import std/[os, osproc, strutils, tempfiles, unittest]
import io_mon

proc getCurrentProcess(): pointer {.stdcall, dynlib: "kernel32",
  importc: "GetCurrentProcess".}
proc isWow64Process2(process: pointer; processMachine,
    nativeMachine: ptr uint16): int32 {.stdcall, dynlib: "kernel32",
  importc: "IsWow64Process2".}

let whoami = getEnv("SystemRoot", r"C:\Windows") / "System32" / "whoami.exe"
if paramCount() == 1 and paramStr(1) == "--native-system-child":
  let child = execCmdEx(quoteShellCommand(
    @[whoami, "/user", "/fo", "csv", "/nh"]), options = {poStdErrToStdOut})
  stdout.write(child.output)
  quit(child.exitCode)

suite "Windows native system children keep their execution semantics":
  test "identity child runs and unsupported architecture stays incomplete":
    let work = createTempDir("io-mon-native-system-", "")
    defer: removeDir(work)
    let command = @[getAppFilename(), "--native-system-child"]
    let native = execCmdEx(quoteShellCommand(command), options = {poStdErrToStdOut})
    checkpoint(native.output)
    require native.exitCode == 0
    require "S-1-" in native.output
    let monitored = runMonitored(FsSnoopRequest(
      command: command, depFilePath: work / "capture.iomon",
      captureChildStdio: true, captureStdioPath: work / "output.txt"))
    check monitored.exitCode == 0
    check readFile(work / "output.txt").strip() == native.output.strip()
    var processMachine, nativeMachine: uint16
    require isWow64Process2(getCurrentProcess(), addr processMachine,
      addr nativeMachine) != 0
    var unsupportedSpawn = false
    var childLoss = false
    for record in monitored.records:
      if record.kind == mrProcessSpawn and
          "inject=unsupported-process-machine:" in record.detail:
        unsupportedSpawn = true
      if record.kind == mrEventLoss and "missing process-start" in record.detail:
        childLoss = true
    if nativeMachine == 0xaa64'u16:
      check unsupportedSpawn
      check childLoss
      check monitored.completeness == mcIncomplete
    else:
      check not unsupportedSpawn
      check not childLoss
      check monitored.completeness == mcComplete
