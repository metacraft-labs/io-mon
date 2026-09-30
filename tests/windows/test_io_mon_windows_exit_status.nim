## No mocks: the same executable reads a real file and terminates through
## Windows APIs, both natively and under the production monitor shim.
import std/[os, osproc, strutils, tempfiles, unittest]
import io_mon

proc exitProcess(code: uint32) {.stdcall, dynlib: "kernel32",
  importc: "ExitProcess", noreturn.}
proc getCurrentProcess(): pointer {.stdcall, dynlib: "kernel32",
  importc: "GetCurrentProcess".}
proc terminateProcess(process: pointer; code: uint32): int32 {.stdcall,
  dynlib: "kernel32", importc: "TerminateProcess".}

if paramCount() == 4 and paramStr(1) == "--exit-child":
  doAssert readFile(paramStr(4)) == "exit status probe\n"
  let code = uint32(parseBiggestUInt(paramStr(3)))
  if paramStr(2) == "ExitProcess":
    exitProcess(code)
  discard terminateProcess(getCurrentProcess(), code)
  quit 99

suite "Windows monitoring preserves all process exit status bits":
  test "native and monitored termination agree and retain the file read":
    let work = createTempDir("io-mon-exit-status-", "")
    defer: removeDir(work)
    let marker = work / "exit-status-marker.txt"
    writeFile(marker, "exit status probe\n")
    for api in ["ExitProcess", "TerminateProcess"]:
      for code in [0'u32, 7'u32, 0x80000000'u32, 0xc0000005'u32, 0xffffffff'u32]:
        checkpoint(api & " status=" & toHex(code))
        let command = @[getAppFilename(), "--exit-child", api, $code, marker]
        # Direct CreateProcess through osproc, without cmd.exe truncation.
        let child = startProcess(command[0], args = command[1 .. ^1],
          options = {poParentStreams})
        let native = child.waitForExit()
        child.close()
        require uint32(native) == code
        let monitored = runMonitored(FsSnoopRequest(
          command: command, depFilePath: work / (api & $code & ".iomon"),
          captureChildStdio: true,
          captureStdioPath: work / (api & $code & ".log")))
        checkpoint(readFile(work / (api & $code & ".log")))
        check uint32(monitored.exitCode) == code
        var sawRead = false
        for record in monitored.records:
          if record.kind == mrFileRead and
              record.path.toLowerAscii.endsWith("exit-status-marker.txt"):
            sawRead = true
        check sawRead
