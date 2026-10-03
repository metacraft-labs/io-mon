## Real nested processes and production shims; no mocks. Independent captures
## must retain their own scope, and an unfinished handoff must remain a loss.
## Every launch is supervised in its own process group with a 30-second bound.
import std/[os, osproc, sequtils, streams, strutils, tempfiles, unittest]

when defined(macosx):
  import std/posix
  import io_mon
  import io_mon/nested_capture
  import build_test_shim
  proc rawSyscall(number: cint): clong {.importc: "syscall", header: "<unistd.h>", varargs.}
  var sysOpen {.importc: "SYS_open", header: "<sys/syscall.h>".}: cint
  var sysRead {.importc: "SYS_read", header: "<sys/syscall.h>".}: cint
  var sysClose {.importc: "SYS_close", header: "<sys/syscall.h>".}: cint
  var fileSizeLimit {.importc: "RLIMIT_FSIZE", header: "<sys/resource.h>".}: cint

  if paramCount() == 2 and paramStr(1) == "--flush-failure":
    let work = paramStr(2)
    let capture = startNestedCapture(work, "parent", "child")
    # A real OS file-size limit makes the buffered close fail. The limit and
    # signal disposition live only in this supervised child, never the suite.
    var limit: RLimit
    doAssert getrlimit(fileSizeLimit, limit) == 0
    limit.rlim_cur = 1
    signal(SIGXFSZ, SIG_IGN)
    doAssert setrlimit(fileSizeLimit, limit) == 0
    var refused = false
    try:
      finishNestedCapture(capture, @[MonitorRecord(kind: mrFileRead,
        observationKind: moFileRead, path: work / "input")])
    except IOError as failure:
      doAssert "cannot flush nested monitor evidence" in failure.msg
      refused = true
    doAssert refused
    doAssert fileExists(work / "nested-child-pending.iomon-frag")
    doAssert not fileExists(work / "nested-child.iomon-frag")
    doAssert not fileExists(work / "nested-child.iomon-frag.partial")
    quit(0)

  if paramCount() >= 2 and paramStr(1) == "--reader":
    let work = paramStr(2)
    doAssert readFile(work / "inner-input") == "inner"
    doAssert not fileExists(work / "absent-input")
    if paramCount() == 3 and paramStr(3) == "incomplete":
      let fd = rawSyscall(sysOpen, (work / "inner-input").cstring, O_RDONLY, 0, 0, 0, 0, 0)
      doAssert fd >= 0
      var first: char
      doAssert rawSyscall(sysRead, fd, addr first, 1, 0, 0, 0, 0) == 1
      doAssert first == 'i'
      doAssert rawSyscall(sysClose, fd, 0, 0, 0, 0, 0, 0) == 0
    quit(0)

  if paramCount() == 4 and paramStr(1) == "--host":
    let work = paramStr(2)
    let mode = paramStr(3)
    putEnv(ShimLibOverrideEnv, paramStr(4))
    var request = FsSnoopRequest(
      command: @[getAppFilename(), "--reader", work],
      depFilePath: work / "inner.iomon")
    case mode
    of "interest": request.interest = {ecAmbientReads}
    of "evidence": request.evidenceScope = esReadsOnly
    of "incomplete": request.command.add "incomplete"
    of "three-level":
      request.command = @[getAppFilename(), "--host", work, "interest", paramStr(4)]
      request.depFilePath = work / "middle.iomon"
      request.interest = {ecFileWrites}
    else: discard
    if mode in ["abandoned", "interrupted", "failed-write"]:
      block:
        var handle = startMonitor(request)
        while not pollMonitor(handle): sleep(5)
        if mode == "failed-write":
          let parentDir = getEnv("REPRO_MONITOR_FRAGMENT_DIR")
          let permissions = getFilePermissions(parentDir)
          var refused = false
          try:
            setFilePermissions(parentDir, {fpUserRead, fpUserExec})
            try:
              discard finishMonitor(move(handle))
            except IOError, OSError:
              refused = true
          finally:
            setFilePermissions(parentDir, permissions)
          doAssert refused, "handoff into a read-only directory was accepted"
        if mode == "interrupted":
          # Abrupt termination after real child evidence exists, before handoff.
          # SIGKILL bypasses destructors, atexit and shim shutdown alike.
          discard posix.kill(getpid(), SIGKILL)
          quit(99)
        # The owning handle's destructor reaps/releases, without publishing.
    else:
      let inner = runMonitored(request)
      doAssert inner.exitCode == 0
      doAssert inner.completeness == (if mode == "incomplete": mcIncomplete else: mcComplete)
    doAssert readFile(work / "outer-input") == "outer"
    quit(0)

  if paramCount() == 5 and paramStr(1) == "--outer":
    doAssert setsid() >= 0
    putEnv(ShimLibOverrideEnv, paramStr(4))
    let outer = runMonitored(FsSnoopRequest(
      command: @[getAppFilename(), "--host", paramStr(2), paramStr(3), paramStr(5)],
      depFilePath: paramStr(2) / "outer.iomon"))
    if paramStr(3) != "interrupted": doAssert outer.exitCode == 0
    quit(0)

suite "macOS nested capture handoff":
  when defined(macosx):
    let work = createTempDir("io-mon-nested-capture-", "")
    defer: removeDir(work)
    let root = currentSourcePath().parentDir.parentDir.parentDir
    let shim = buildPrivateMacosShim(root)
    let second = work / "inner-shim.dylib"
    copyFile(shim, second)

    test "buffered write failure retains the pending loss marker":
      let nested = expandFilename(work) / "flush-failure"
      createDir(nested)
      let runner = startProcess(getAppFilename(), args = @["--flush-failure", nested],
        options = {poStdErrToStdOut})
      let code = runner.waitForExit(10_000)
      if code == -1:
        runner.kill()
        discard runner.waitForExit()
      let output = runner.outputStream.readAll()
      runner.close()
      checkpoint("exit=" & $code & " output=" & output)
      require code == 0

    for mode in ["interest", "evidence", "incomplete", "three-level", "abandoned", "interrupted", "failed-write"]:
      test mode:
        let nested = expandFilename(work) / mode
        createDir(nested)
        writeFile(nested / "inner-input", "inner")
        writeFile(nested / "outer-input", "outer")
        let runner = startProcess(getAppFilename(), args = @["--outer", nested,
          mode, shim, second], options = {poStdErrToStdOut})
        let code = runner.waitForExit(30_000)
        if code == -1:
          if getpgid(Pid(runner.processID)) == Pid(runner.processID):
            discard posix.kill(Pid(-runner.processID), SIGKILL)
          else: runner.kill()
          discard runner.waitForExit()
        let output = runner.outputStream.readAll()
        runner.close()
        checkpoint("exit=" & $code & " output=" & output)
        require code == 0
        let outer = readMonitorDepFile(nested / "outer.iomon")
        let losses = outer.records.filterIt(it.kind == mrEventLoss)
        checkpoint("outer loss=" & $losses)
        if mode in ["abandoned", "interrupted", "failed-write"]:
          check outer.completeness == mcIncomplete
          check losses.anyIt("nested monitor evidence handoff pending" in it.detail)
          if mode != "failed-write":
            check not fileExists(nested / "inner.iomon")
        elif mode == "incomplete":
          check outer.completeness == mcIncomplete
          check readMonitorDepFile(nested / "inner.iomon").completeness == mcIncomplete
          check losses.anyIt("syscall(2)" in it.detail)
          check not losses.anyIt("handoff pending" in it.detail)
        else:
          check outer.completeness == mcComplete
          check outer.records.anyIt(it.kind == mrFileRead and it.path == nested / "inner-input")
          check outer.records.anyIt(it.kind == mrFileRead and it.path == nested / "outer-input")
          let inner = readMonitorDepFile(nested / "inner.iomon")
          check inner.completeness == mcComplete
          if mode in ["interest", "three-level"]:
            check not inner.records.anyIt(it.kind == mrFileRead and it.path == nested / "inner-input")
            check inner.observedInterest == {ecAmbientReads}
          if mode == "three-level":
            let middle = readMonitorDepFile(nested / "middle.iomon")
            check middle.observedInterest == {ecFileWrites}
            check not middle.records.anyIt(it.kind == mrFileRead and it.path == nested / "inner-input")
          if mode == "evidence":
            check outer.records.anyIt(it.path == nested / "absent-input" and it.probeResult == prAbsent)
            check not inner.records.anyIt(it.path == nested / "absent-input" and it.probeResult == prAbsent)
            check inner.observedEvidenceScope == esReadsOnly
  else:
    test "macOS-only nested capture": skip()
