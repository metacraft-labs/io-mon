## No mocks: invoke all four fortified symbols in the production preload shim,
## perform real failed/read/write opens, and inspect the public host's records.
## The fixture has a CPU-time limit so a self-jump fails without a wall-clock
## cutoff that would confuse host contention with lack of forward progress.
import std/[os, posix, osproc, sequtils, strtabs, tempfiles, unittest]
import io_mon
import build_test_shim, unmonitored_env

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

suite "Linux fortified open forwarding":
  let work = createTempDir("io-mon-fortified-open-", "")
  let shim = buildPrivateLinuxShim(repoRoot)
  let priorShim = getEnv("REPRO_MONITOR_SHIM_LIB")
  putEnv("REPRO_MONITOR_SHIM_LIB", shim)
  let fixture = work / "fortified-open"
  let built = execCmdEx(quoteShell(getEnv("CC", "cc")) & " -O2 " &
    quoteShell(repoRoot / "tests/fixtures/fortified_open/fortified_open.c") &
    " -ldl -o " & quoteShell(fixture))
  doAssert built.exitCode == 0, built.output
  writeFile(work / "input", "x")

  for symbol in ["__open_2", "__open64_2", "__openat_2", "__openat64_2"]:
    test symbol & " returns, preserves errno, and records every open flag":
      var req: FsSnoopRequest
      req.command = @[fixture, symbol, work, "input"]
      req.depFilePath = work / (symbol & ".iomon")
      req.streamMode = fsoNone
      let clean = unmonitoredEnv()
      for key, value in clean.pairs: req.env.add (key, value)
      req.env.add ("REPRO_MONITOR_SHIM_LIB", shim)
      let captured = runMonitored(req)
      checkpoint(symbol & " shim=" & shim & " exit=" & $captured.exitCode)
      check captured.exitCode == 0
      let opens = captured.records.filterIt(it.kind == mrFileOpen)
      check opens.anyIt(it.path == work / "absent" and it.result == -1)
      for flags in [0'u32, 1'u32, 2'u32]:
        check opens.anyIt(it.path == work / "input" and it.result >= 0 and
          it.flags == flags)
    test symbol & " rejects creation without a mode":
      for invalid in ["invalid-create", "invalid-tmpfile"]:
        var req: FsSnoopRequest
        req.command = @[fixture, symbol, work, invalid]
        req.depFilePath = work / (symbol & "-" & invalid & ".iomon")
        req.streamMode = fsoNone
        let clean = unmonitoredEnv()
        for key, value in clean.pairs: req.env.add (key, value)
        req.env.add ("REPRO_MONITOR_SHIM_LIB", shim)
        let captured = runMonitored(req)
        checkpoint(symbol & " " & invalid & " exit=" & $captured.exitCode)
        check captured.exitCode == 128 + SIGABRT
  if priorShim.len > 0: putEnv("REPRO_MONITOR_SHIM_LIB", priorShim)
  else: delEnv("REPRO_MONITOR_SHIM_LIB")
  removeDir(work)
