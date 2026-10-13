## Genuine public runMonitored controls compile their own child and production
## shim with the declared tools. Every named route assertion runs without argv.
import std/[os, sequtils, strutils, unittest]
import io_mon
import ../helpers/capture_control_fixtures

# Fixture paths/modes are inputs, not test-name filters. Run every named oracle.
disableParamFiltering()

let work = captureFixtureDirectory()
let driver = compileCaptureDriver(work, "explicit_child_capture_driver.c")
activateCaptureFixtureShim()
let input = work / "actual-child-input.txt"
writeFile(input, "genuine child read\n")

suite "explicit child capture route":
  for operation in ["exec", "spawn", "spawnp", "spawnp-search"]:
    for mode in ["missing", "preloaded", "complete"]:
      test operation & " " & mode & " remains complete and captures child input":
        var request: FsSnoopRequest
        request.command = @[driver, operation, mode, driver, input]
        request.depFilePath = work / (operation & "-" & mode & ".iomon")
        request.streamMode = fsoNone
        let observed = runMonitored(request)
        checkpoint("exit=" & $observed.exitCode & " completeness=" & $observed.completeness)
        check observed.exitCode == 0
        check observed.completeness == mcComplete
        check observed.records.anyIt(it.kind == mrFileRead and it.path == input)
        check observed.records.countIt(it.kind == mrProcessStart) >= 2
  for operation in ["exec-failure", "spawn-failure", "spawnp-failure"]:
    test operation & " returns the genuine failure contract without invented loss":
      var request: FsSnoopRequest
      request.command = @[driver, operation, "missing", driver, input]
      request.depFilePath = work / (operation & ".iomon")
      request.streamMode = fsoNone
      let observed = runMonitored(request)
      check observed.exitCode == 0
      check observed.completeness == mcComplete
  for mode in ["partial", "duplicate", "malformed", "foreign-seed"]:
    test mode & " reports loss to the active parent without blocking application":
      var request: FsSnoopRequest
      request.command = @[driver, "spawn", mode, driver, input]
      request.depFilePath = work / (mode & ".iomon")
      request.streamMode = fsoNone
      let observed = runMonitored(request)
      check observed.exitCode == 0
      check observed.completeness == mcIncomplete
      check observed.records.anyIt(it.kind == mrEventLoss and
        "linux child capture route invalid code=" in it.detail)
