## test_io_mon_dep_set — io-mon-Lossless-Event-Capture M3 (part 1) integration
## tests (Linux).
##
## Part 1 wires nim-shm-set (the M1-winning SET transport, Candidate C) in as
## io-mon's PRIMARY Linux dependency channel, replacing the DEP-SHM ring as the
## producer→consumer fast path while the `.rmdf-frag` file fallback + DEP-FLUSH
## stay in place (their deletion is part 2). These tests drive the LIVE Linux
## LD_PRELOAD shim (rebuilt from source) and assert:
##
##   t_dep_set_publishes                 — the shim attaches the set (shard0 path
##                                         in REPRO_MONITOR_DEP_SHM) and INSERTS
##                                         each observed read; the consumer's
##                                         single-threaded snapshot carries them.
##   t_dep_set_byte_identical_to_file    — LF-6 / the DEP-SHM-3 invariant: a
##                                         fully-monitored, no-loss run yields a
##                                         BYTE-IDENTICAL canonical RMDF depfile
##                                         via the set transport vs the pure-file
##                                         baseline (REPRO_MONITOR_DEP_SHM_DISABLE).
##   t_orphan_producer_bounded           — a producer that OUTLIVES its monitor
##                                         (the ~61 GiB orphan class) cannot grow
##                                         the consumer-owned set once the consumer
##                                         marks itself gone: emit fast-fails
##                                         emConsumerGone and inserts nothing.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import io_mon/shm/dep_queue          # decodeDepRecord (element bytes → MonitorRecord)
import shm_set                        # attachSet reader / shmSetSupported
import shm_set/transport              # startHost / attachProducer / emit / snapshot

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

proc buildC(work, name, source: string; extraArgs: seq[string] = @[]): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result] & extraArgs)
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc ensureSnoop(work: string): string =
  result = work / "io-mon"
  if not fileExists(result):
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & result, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

proc ensureShim(): string =
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(buildShim.output)
  check buildShim.code == 0
  findShimLibrary()

proc childEnvWith(shimLib: string; extra: openArray[(string, string)] = @[]):
    StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result["REPRO_MONITOR_SHIM_LIB"] = shimLib
  for (k, v) in extra:
    result[k] = v

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

proc normalizedCanonical(dep: MonitorDepFile; prefix: string): seq[byte] =
  ## Keep only the marker file reads, zero every per-run launcher-noise field
  ## (pids/tid/fd/result/run-token detail), and canonically re-encode — the
  ## observed dependency identity the channel must preserve byte-for-byte.
  var norm = dep.records.filterIt(it.kind == mrFileRead and
    it.path.startsWith(prefix))
  for i in 0 ..< norm.len:
    norm[i].osPid = 0
    norm[i].parentOsPid = 0
    norm[i].threadId = 0
    norm[i].childOsPid = 0
    norm[i].flags = 0
    norm[i].result = 0
    norm[i].probeResult = prUnknown
    norm[i].detail = ""
  encodeCanonical(norm)

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len:
    result[i] = byte(s[i])

suite "io-mon dep-set (nim-shm-set primary transport, M3 part 1)":
  let work = getTempDir() / ("io-mon-dep-set-" & $getCurrentProcessId())
  createDir(work)

  test "t_dep_set_publishes":
    # The shim attaches the SET (REPRO_MONITOR_DEP_SHM = a shard0 path) and
    # INSERTS each observed read. The consumer's single-threaded snapshot,
    # decoded back to MonitorRecords, carries every marker read.
    check shmSetSupported
    let shimLib = ensureShim()

    const N = 6
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("setpub-" & $i & ".txt")
      writeFile(m, "set publish marker " & $i & "\n")
      markers.add m

    let reader = buildC(work, "setpub_reader", """
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  for (int i = 1; i < argc; i++) {
    int fd = open(argv[i], O_RDONLY);
    if (fd < 0) exit(2);
    read(fd, buf, sizeof(buf));
    close(fd);
  }
  exit(0);
}
""")

    let fragDir = work / "setpub-frags"
    createDir(fragDir)
    var host = startHost(fragDir, "setpub-run")
    check host.available
    check host.path0.endsWith(".shard0")

    let env = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": fragDir,
      "REPRO_MONITOR_DEP_SHM": host.path0,
      "REPRO_MONITOR_SESSION": "setpub-run",
    })
    let cap = run(reader, markers, env)
    checkpoint(cap.output)
    check cap.code == 0

    var found: seq[MonitorRecord]
    for elem in host.snapshot():
      var ok = false
      let rec = decodeDepRecord(elem, ok)
      if ok:
        found.add rec
    host.finish()

    check found.len > 0
    # Every marker read arrived over the SET (no growth-failure saturation).
    for m in markers:
      check found.anyIt(it.kind == mrFileRead and m in it.path)

  test "t_dep_set_byte_identical_to_file":
    # LF-6 / DEP-SHM-3 — HARD invariant. Run the SAME fully-monitored, no-loss
    # workload through the full `io-mon run` consumer twice: once with the SET
    # transport active (default), once with it disabled (pure-file baseline). The
    # normalised canonical merged depfile MUST be byte-identical.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    const N = 24
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("bi-set-marker-" & $i & ".txt")
      writeFile(m, "byte-identical set marker " & $i & "\n")
      markers.add m

    let reader = buildC(work, "bi_set_reader", """
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  for (int i = 1; i < argc; i++) {
    int fd = open(argv[i], O_RDONLY);
    if (fd < 0) exit(2);
    read(fd, buf, sizeof(buf));
    close(fd);
  }
  exit(0);
}
""")

    proc capture(tag: string; extra: openArray[(string, string)]): seq[byte] =
      let depfile = work / ("bi-set-" & tag & ".rdep")
      let env = childEnvWith(shimLib, extra)
      let cap = run(snoopBin,
        @["run", "--depfile", depfile, "--", reader] & markers, env)
      checkpoint(tag & ": " & cap.output)
      check cap.code == 0
      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcComplete
      for m in markers:
        check hasFileRead(dep, m)
      normalizedCanonical(dep, work / "bi-set-marker-")

    # SET transport active (default).
    let setBytes = capture("set", @[])
    # Pure-file baseline.
    let fileBytes = capture("file", @[("REPRO_MONITOR_DEP_SHM_DISABLE", "1")])
    check setBytes == fileBytes

  test "t_orphan_producer_bounded":
    # Orphan-safe / LF-4: a monitored descendant that OUTLIVES its monitor (the
    # ~61 GiB fragment-leak class) cannot cause unbounded growth on the SET path.
    # The set is consumer-owned; once the consumer marks itself gone (as
    # `SetHost.finish` does at run teardown), a producer's `emit` fast-fails
    # `emConsumerGone` and inserts NOTHING — the distinct set stays bounded.
    check shmSetSupported
    let dir = work / "orphan"
    createDir(dir)

    var host = startHost(dir, "orphan-run")
    check host.available
    let p0 = host.path0

    var prod = attachProducer(p0)
    check prod.available

    # Pre-teardown: 100 distinct inserts land in the consumer-owned set.
    for i in 0 ..< 100:
      check prod.emit(toBytes("orphan-dep-" & $i)) in {emInserted, emExists}
    let before = host.snapshot().len
    check before == 100

    # The monitor tears down: mark the consumer gone + detach (what fs_snoop's
    # deferred `finish` does at the end of a run).
    host.finish()

    # The orphan keeps emitting far past the monitor's lifetime.
    var goneCount = 0
    var grewCount = 0
    for i in 100 ..< 10_100:
      case prod.emit(toBytes("orphan-dep-" & $i))
      of emConsumerGone: inc goneCount
      of emInserted, emExists: inc grewCount
      else: discard
    prod.detach()

    # EVERY post-teardown emit fast-failed against the gone consumer; none grew
    # the set.
    check goneCount == 10_000
    check grewCount == 0

    # Re-attach a fresh reader to the on-disk shards and confirm the distinct set
    # never grew past the pre-teardown 100 — bounded, honest, no orphan spill.
    var reader = attachSet(p0)
    check reader.available
    check reader.snapshot().len == before
    reader.detach()
