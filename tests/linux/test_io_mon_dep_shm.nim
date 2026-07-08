## test_io_mon_dep_shm — milestone io-mon-DEP-SHM integration tests (Linux).
##
## Drives the LIVE Linux LD_PRELOAD shim (rebuilt from source) against C children
## and asserts the shared-memory dependency queue behaves per the spec
## (reprobuild-specs/io-mon-Dependency-Shm-Queue.md):
##
##   DEP-SHM-2  t_shim_publishes_to_dep_ring
##   DEP-SHM-3  t_dep_ring_and_fragment_fallback_merge_byte_identical
##   DEP-SHM-4  t_dep_ring_full_falls_back_loud
##   DEP-SHM-5  t_dep_ring_survives_producer_sigkill
##
## (DEP-SHM-1 — the pure ring/codec unit test — is
## tests/portable/test_io_mon_dep_ring_mpsc_roundtrip.nim.)

import std/[os, osproc, posix, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import io_mon/shm/dep_queue

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

proc fileReadCount(dep: MonitorDepFile; path: string): int =
  dep.records.countIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  fileReadCount(dep, path) > 0

proc normalizedCanonical(dep: MonitorDepFile; prefix: string): seq[byte] =
  ## Same normalisation as the DEP-FLUSH determinism test: keep only the marker
  ## file reads, zero every per-run launcher-noise field (pids/tid/fd/result/
  ## run-token detail), and canonically re-encode. What remains is the observed
  ## dependency identity — the byte-identity contract the channel must preserve.
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

suite "io-mon DEP-SHM shared-memory dependency queue":
  let work = getTempDir() / ("io-mon-dep-shm-" & $getCurrentProcessId())
  createDir(work)

  test "t_shim_publishes_to_dep_ring":
    # DEP-SHM-2 — a CONSUMER-owned dep-queue segment; launch a monitored child
    # via the live shim with REPRO_MONITOR_DEP_SHM pointed at that segment; drain
    # the ring afterwards and assert the child's reads arrived over the RING (not
    # the file path). Proves the producer arm attaches + publishes.
    let shimLib = ensureShim()

    const N = 6
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("ringpub-" & $i & ".txt")
      writeFile(m, "ring publish marker " & $i & "\n")
      markers.add m

    let reader = buildC(work, "ringpub_reader", """
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

    let fragDir = work / "ringpub-frags"
    createDir(fragDir)
    let segPath = fragDir / "repro-dep-queue.ringpub"
    var cons = createDepQueueAtPath(segPath)
    check cons.available

    let env = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": fragDir,
      "REPRO_MONITOR_DEP_SHM": segPath,
      "REPRO_MONITOR_SESSION": "ringpub-run",
    })
    let cap = run(reader, markers, env)
    checkpoint(cap.output)
    check cap.code == 0

    var drained: seq[MonitorRecord]
    var rec: MonitorRecord
    while cons.tryDrainOne(rec):
      drained.add rec
    cons.detach()

    # Every marker read arrived over the RING.
    check drained.len > 0
    for m in markers:
      check drained.anyIt(it.kind == mrFileRead and m in it.path)
    # No signalled drops for this small below-capacity workload.
    check cons.droppedCount() == 0'u64

  test "t_dep_ring_and_fragment_fallback_merge_byte_identical":
    # DEP-SHM-3 — HARD invariant. Run the SAME workload twice through the full
    # `io-mon run` consumer: once with the ring active (some records ride the
    # ring, some — forced by a tiny ring cap env — fall back to files), once with
    # the ring disabled (pure file baseline). The normalised canonical merged
    # depfile MUST be byte-identical.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    const N = 24
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("bi-marker-" & $i & ".txt")
      writeFile(m, "byte-identical marker " & $i & "\n")
      markers.add m

    let reader = buildC(work, "bi_reader", """
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
      let depfile = work / ("bi-" & tag & ".rdep")
      let env = childEnvWith(shimLib, extra)
      let cap = run(snoopBin,
        @["run", "--depfile", depfile, "--", reader] & markers, env)
      checkpoint(tag & ": " & cap.output)
      check cap.code == 0
      let dep = readMonitorDepFile(depfile)
      check dep.completeness == mcComplete
      for m in markers:
        check hasFileRead(dep, m)
      normalizedCanonical(dep, work / "bi-marker-")

    # Ring active (default). Some records ride the ring; any it cannot hold fall
    # back to files — the merge folds both.
    let ringBytes = capture("ring", @[])
    # Pure file baseline.
    let fileBytes = capture("file", @[("REPRO_MONITOR_DEP_SHM_DISABLE", "1")])
    check ringBytes == fileBytes

  test "t_dep_ring_full_falls_back_loud":
    # DEP-SHM-4 — force the ring to overflow (many records, consumer NOT draining
    # until the end so the ring saturates) and assert (a) the drop was SIGNALLED
    # in the `dropped` counter (loud, never silent) and (b) NO dependency was
    # lost — the dropped records fell back to file fragments so the merged
    # depfile still carries every read.
    let shimLib = ensureShim()

    # Enough distinct reads to overflow the ring capacity when the consumer does
    # not drain concurrently.
    let count = DepRingCap + 500
    var markers: seq[string]
    let big = work / "loud-shared.txt"
    writeFile(big, "shared\n")

    let reader = buildC(work, "loud_reader", """
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  long n = strtol(argv[1], NULL, 10);
  const char *path = argv[2];
  char buf[16];
  for (long i = 0; i < n; i++) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) exit(2);
    read(fd, buf, sizeof(buf));
    close(fd);
  }
  exit(0);
}
""")

    let fragDir = work / "loud-frags"
    createDir(fragDir)
    let segPath = fragDir / "repro-dep-queue.loud"
    var cons = createDepQueueAtPath(segPath)
    check cons.available

    let env = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": fragDir,
      "REPRO_MONITOR_DEP_SHM": segPath,
      "REPRO_MONITOR_SESSION": "loud-run",
    })
    # Do NOT drain while the child runs, so the ring saturates and signals drops.
    let cap = run(reader, @[$count, big], env)
    checkpoint(cap.output)
    check cap.code == 0

    # The drop was SIGNALLED (loud), not silent.
    check cons.droppedCount() > 0'u64

    # No dependency lost: the dropped records fell back to file fragments. Merge
    # (ring drain + fragments) and confirm the shared file read is present.
    var drained: seq[MonitorRecord]
    var rec: MonitorRecord
    while cons.tryDrainOne(rec):
      drained.add rec
    cons.detach()
    let depfile = work / "loud.rdep"
    let dep = mergeFragments(fragDir, depfile, currentRunId = "loud-run",
      ringRecords = drained)
    check hasFileRead(dep, big)
    # Some records must have come from the FILE fallback (ring couldn't hold all).
    var fragReads = 0
    for k, p in walkDir(fragDir):
      if k == pcFile and p.endsWith(".rmdf-frag"):
        for r in readFragmentRecordsTolerant(p):
          if r.kind == mrFileRead and big in r.path:
            inc fragReads
    check fragReads > 0

  test "t_dep_ring_survives_producer_sigkill":
    # DEP-SHM-5 — a producer that publishes reads to the ring then is SIGKILLed
    # (uncatchable — no destructor, no signal handler, no batch flush) loses ZERO
    # records, because each was published into consumer-owned memory the instant
    # it was observed. Contrast the file path, where a kill before the 100 ms /
    # 64 KiB batch flush would lose the buffered tail.
    let shimLib = ensureShim()

    const N = 8
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("sigkill-marker-" & $i & ".txt")
      writeFile(m, "sigkill marker " & $i & "\n")
      markers.add m

    # Read every marker, write a sentinel to signal "all reads published", then
    # spin forever so the parent can SIGKILL it AFTER the reads are in the ring
    # but BEFORE any batch-flush window could have elapsed.
    let reader = buildC(work, "sigkill_reader", """
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  const char *sentinel = argv[1];
  for (int i = 2; i < argc; i++) {
    int fd = open(argv[i], O_RDONLY);
    if (fd < 0) exit(2);
    read(fd, buf, sizeof(buf));
    close(fd);
  }
  int sfd = open(sentinel, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (sfd >= 0) { write(sfd, "1", 1); close(sfd); }
  for (;;) pause();
  return 0;
}
""")

    let fragDir = work / "sigkill-frags"
    createDir(fragDir)
    let segPath = fragDir / "repro-dep-queue.sigkill"
    var cons = createDepQueueAtPath(segPath)
    check cons.available

    let sentinel = work / "sigkill-sentinel"
    removeFile(sentinel)
    let env = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": fragDir,
      "REPRO_MONITOR_DEP_SHM": segPath,
      "REPRO_MONITOR_SESSION": "sigkill-run",
    })
    let p = startProcess(reader, args = @[sentinel] & markers, env = env,
      options = {poStdErrToStdOut, poUsePath})
    # Wait until the child signals every read is published (sentinel appears),
    # then SIGKILL it before any flush window could matter.
    var waited = 0
    while not fileExists(sentinel) and waited < 5000:
      sleep(2); inc waited, 2
    check fileExists(sentinel)
    discard kill(Pid(p.processID), SIGKILL)
    discard p.waitForExit()
    p.close()

    # Drain the ring — the reads are ALL there despite the uncatchable kill.
    var drained: seq[MonitorRecord]
    var rec: MonitorRecord
    while cons.tryDrainOne(rec):
      drained.add rec
    cons.detach()
    for m in markers:
      check drained.anyIt(it.kind == mrFileRead and m in it.path)
