## A growth failure in the shared-memory dependency set grades the capture
## incomplete.
##
## WHY. On Linux the shim publishes every record into the edge's
## shared-memory set (nim-shm-gset). When the set cannot take an element, it
## bumps shard0's growth-failure counter instead of dropping it silently: an
## OOM growth failure, or an element published with `emitNoGrow`, the shim's
## descriptor-free loss channel, that shard0 could not take. The set then
## lacks an element a producer had. io-mon's consumer used to print that to
## stderr only, so the depfile still read `mcComplete`.
##
## WHAT THIS TEST GRADES. The monitored command is a small producer that
## attaches to the set the monitor named (`REPRO_MONITOR_DEP_SHM`) and fills
## shard0 through `emitNoGrow` until it reports `emSaturated`, i.e. until the
## counter is bumped. The capture must carry a `dep-set growth failed` loss
## and must not be complete. A control producer publishes one element and
## stops: its capture has no such loss and is complete. The elements are not
## records io-mon can decode, so the merge skips them; only the counter is at
## stake.
##
## Linux only: the set is the Linux shim's transport.
##
## Mocks: none. Real CLI, real shim, real set; the producer is the real
## nim-shm-gset producer API, standing in for a shim whose loss element did
## not fit.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

const producerSource = """
import std/[os, strutils]
import shm_gset/transport

# argv[1]: "fill" publishes until shard0 is full (the counter is bumped),
# "one" publishes a single element.
let path = getEnv("REPRO_MONITOR_DEP_SHM")
var p = attachProducer(path)
if not p.available: quit(3)
let fill = paramCount() >= 1 and paramStr(1) == "fill"
var saturated = false
for i in 0 ..< (if fill: 1_000_000 else: 1):
  let s = "growth-failure-test-" & $i & "-" & repeat('x', 200)
  case p.emitNoGrow(s.toOpenArrayByte(0, s.high))
  of emSaturated:
    saturated = true
    break
  of emInserted, emExists: discard
  else: quit(4)
p.detach()
quit(if fill and not saturated: 5 else: 0)
"""

suite "io-mon Linux: dependency-set growth failure":
  test "t_dep_set_growth_failure_grades_the_capture_incomplete":
    when not defined(linux):
      skip()   # the set is the Linux shim's transport
    else:
      let work = expandFilename(getTempDir()) /
        ("io-mon-growth-failure-" & $getCurrentProcessId())
      removeDir(work)
      createDir(work)
      let shimLib = buildPrivateLinuxShim(repoRoot)
      let snoopBin = work / "io-mon"
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      check cli.code == 0
      let gsetSrc = getEnv("SHM_GSET_SRC",
        repoRoot.parentDir() / "nim-shm-gset" / "src")
      let producer = work / "producer"
      writeFile(producer & ".nim", producerSource)
      let built = run("nim", @["c", "--hints:off", "--warnings:off",
        "--threads:on", "--path:" & gsetSrc, "--nimcache:" & (work / "nc"),
        "--out:" & producer, producer & ".nim"])
      checkpoint(built.output)
      check built.code == 0

      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env.del("LD_PRELOAD")
      env.del("REPRO_MONITOR_DEP_SHM_DISABLE")
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib

      for mode in ["one", "fill"]:
        checkpoint("mode: " & mode)
        let depfile = work / (mode & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
          producer, mode], env)
        checkpoint(cap.output)
        check cap.code == 0
        let dep = readMonitorDepFile(depfile)
        let growthLoss = dep.records.anyIt(it.kind == mrEventLoss and
          it.detail.startsWith("dep-set growth failed"))
        for r in dep.records:
          if r.kind == mrEventLoss:
            checkpoint("event-loss " & r.detail)
        checkpoint("growth loss: " & $growthLoss & ", completeness: " &
          $dep.completeness)
        if mode == "fill":
          check growthLoss
          check dep.completeness != mcComplete
        else:
          check not growthLoss
          check dep.completeness == mcComplete
      removeDir(work)
