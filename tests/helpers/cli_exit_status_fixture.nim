## No mocks: the real CLI monitors this executable reading a marker and exiting
## through the OS API. A private CLI build prevents stale or competing binaries.
import std/[os, osproc, strutils, tempfiles, unittest]
import io_mon
import fixture_cleanup

when defined(windows):
  proc nativeExit(code: uint32) {.stdcall, dynlib: "kernel32",
    importc: "ExitProcess", noreturn.}
else:
  proc nativeExit(code: cint) {.cdecl, header: "<unistd.h>",
    importc: "_exit", noreturn.}

if paramCount() == 3 and paramStr(1) == "--cli-exit-child":
  doAssert readFile(paramStr(3)) == "native exit marker\n"
  when defined(windows):
    nativeExit(uint32(parseBiggestUInt(paramStr(2))))
  else:
    nativeExit(cint(parseInt(paramStr(2))))

suite "standalone CLI preserves native exit status bits":
  test "the command status and file-read evidence survive the CLI boundary":
    let work = createTempDir("io-mon-cli-exit-", "")
    defer: removeFixtureTree(work)
    let repo = currentSourcePath.parentDir.parentDir.parentDir
    var cli = getEnv("IO_MON_EXIT_STATUS_CLI")
    if cli.len == 0:
      cli = work / "io-mon".changeFileExt(ExeExt)
      let build = execCmdEx(quoteShellCommand(@[findExe("nim"), "c",
        "--hints:off", "--threads:on", "--nimcache:" & work / "nimcache",
        "--out:" & cli, repo / "cmd" / "io_mon_snoop.nim"]))
      checkpoint(build.output)
      require build.exitCode == 0
    require fileExists(cli)
    let marker = work / "cli-exit-marker.txt"
    writeFile(marker, "native exit marker\n")
    const codes = when defined(windows):
      [0'u32, 7'u32, 0x80000000'u32, 0xc0000005'u32, 0xffffffff'u32]
    else:
      [0'u32, 7'u32, 127'u32, 128'u32, 200'u32, 255'u32]
    # The bare form (`[flags] -- <command>`, no `run`), which callers that
    # predate `run` still write, must run the same monitor: same status, same
    # evidence. Dropping the description's `call:` refuses it as a usage
    # error (exit 2) and fails this case.
    block bareForm:
      let args = @["--cli-exit-child", "7", marker]
      let depfile = work / "bare.iomon"
      let monitored = startProcess(cli, args =
        @["--depfile", depfile, "--", getAppFilename()] & args,
        options={poParentStreams})
      let monitoredCode = monitored.waitForExit()
      monitored.close()
      check monitoredCode == 7
      require fileExists(depfile)
      var sawRead = false
      for record in readMonitorDepFile(depfile).records:
        if record.kind == mrFileRead and
            record.path.toLowerAscii.endsWith("cli-exit-marker.txt"):
          sawRead = true
      check sawRead
    for code in codes:
      checkpoint("native status=" & $code)
      let args = @["--cli-exit-child", $code, marker]
      let native = startProcess(getAppFilename(), args=args, options={poParentStreams})
      let nativeCode = native.waitForExit()
      native.close()
      require uint32(nativeCode) == code
      let depfile = work / ($code & ".iomon")
      let monitored = startProcess(cli, args =
        @["run", "--depfile", depfile, "--", getAppFilename()] & args,
        options={poParentStreams})
      let monitoredCode = monitored.waitForExit()
      monitored.close()
      check uint32(monitoredCode) == code
      var sawRead = false
      for record in readMonitorDepFile(depfile).records:
        if record.kind == mrFileRead and
            record.path.toLowerAscii.endsWith("cli-exit-marker.txt"):
          sawRead = true
      check sawRead
