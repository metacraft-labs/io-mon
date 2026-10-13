## Actual Linux public monitor host inside an actual outer monitored process.
## Real nested data is published through pending/checked-close/rename handoff;
## dropping the handle must keep the parent loss marker, not forge completion.
import std/[os, sequtils, sets, strutils, unittest]
import io_mon
import ../helpers/capture_control_fixtures

# Fixture paths/modes are inputs, not test-name filters. Run every named oracle.
disableParamFiltering()

var mode, reader, routeDriver, work: string
if paramCount() == 0:
  mode = "outer"
  work = captureFixtureDirectory()
  reader = compileCaptureDriver(work, "nested_child_reader.c")
  routeDriver = compileCaptureDriver(work, "explicit_child_capture_driver.c")
  activateCaptureFixtureShim()
elif paramCount() == 4 and paramStr(1).startsWith("inner-"):
  mode = paramStr(1)
  reader = absolutePath(paramStr(2))
  routeDriver = absolutePath(paramStr(3))
  work = absolutePath(paramStr(4))
else:
  raise newException(ValueError, "only actual nested-child fixture handoff accepts arguments")
let input = work / "nested-input.txt"
let output = work / "nested-output.txt"
if mode.startsWith("inner-"):
  var request: FsSnoopRequest
  request.command = @[reader, input, output]
  if mode == "inner-loss":
    request.command = @[routeDriver, "spawn", "partial", routeDriver, input]
  request.depFilePath = work / "inner.iomon"
  request.streamMode = fsoNone
  request.interest = {ecFileReads}
  if mode == "inner-abandon":
    block:
      var handle = startMonitor(request)
      discard handle.rootPid
    quit(0)
  if mode == "inner-finish-failure":
    let parentFragments = getEnv("REPRO_MONITOR_FRAGMENT_DIR")
    doAssert parentFragments.len > 0
    var previous = initHashSet[string]()
    for kind, path in walkDir(parentFragments):
      previous.incl(path)
    var handle = startMonitor(request)
    var pending: seq[string] = @[]
    for kind, path in walkDir(parentFragments):
      if kind == pcFile and path notin previous and
          path.extractFilename.startsWith("nested-") and
          path.endsWith("-pending.iomon-frag"):
        pending.add(path)
    doAssert pending.len == 1
    doAssert not symlinkExists(pending[0])
    let pendingIdentity = getFileInfo(pending[0], followSymlink = false)
    let pendingBytes = readFile(pending[0])
    doAssert pendingIdentity.kind == pcFile and pendingBytes.len > 0
    let suffix = "-pending.iomon-frag"
    let blockedPublication = pending[0][0..<(pending[0].len - suffix.len)] & ".iomon-frag"
    createDir(blockedPublication)
    var refused = false
    try:
      discard finishMonitor(move(handle))
    except IOError, OSError:
      refused = true
    doAssert refused
    doAssert fileExists(pending[0]) and not symlinkExists(pending[0])
    let retainedIdentity = getFileInfo(pending[0], followSymlink = false)
    doAssert retainedIdentity.id == pendingIdentity.id
    doAssert retainedIdentity.permissions == pendingIdentity.permissions
    doAssert readFile(pending[0]) == pendingBytes
    quit(0)
  let observed = runMonitored(request)
  doAssert observed.exitCode == 0
  if mode == "inner-loss":
    doAssert observed.completeness == mcIncomplete
  else:
    doAssert observed.completeness == mcComplete
    doAssert observed.records.anyIt(it.kind == mrFileRead and it.path == input)
    doAssert not observed.records.anyIt(it.kind == mrFileWrite and it.path == output)
  quit(0)

if mode != "outer":
  raise newException(ValueError, "unknown mode")
writeFile(input, "genuine nested input\n")
suite "Linux actual cooperating nested capture":
  test "finished narrower inner capture supplies genuine full evidence to parent":
    var request: FsSnoopRequest
    request.command = @[getAppFilename(), "inner-finish", reader, routeDriver, work]
    request.depFilePath = work / "outer-complete.iomon"
    request.streamMode = fsoNone
    let observed = runMonitored(request)
    check observed.exitCode == 0
    check observed.completeness == mcComplete
    check observed.records.anyIt(it.kind == mrFileRead and it.path == input)
    check observed.records.anyIt(it.kind == mrFileWrite and it.path == output)
    check not observed.records.anyIt(it.kind == mrEventLoss)
  for nestedMode in ["inner-abandon", "inner-loss", "inner-finish-failure"]:
    test nestedMode & " remains incomplete in parent":
      var request: FsSnoopRequest
      request.command = @[getAppFilename(), nestedMode, reader, routeDriver, work]
      request.depFilePath = work / (nestedMode & "-parent.iomon")
      request.streamMode = fsoNone
      let observed = runMonitored(request)
      check observed.exitCode == 0
      check observed.completeness == mcIncomplete
      check observed.records.anyIt(it.kind == mrEventLoss)
      if nestedMode in ["inner-abandon", "inner-finish-failure"]:
        check observed.records.anyIt(it.kind == mrEventLoss and
          "nested monitor evidence handoff pending" in it.detail)
