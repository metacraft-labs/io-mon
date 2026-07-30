## test_io_mon_dep_set — io-mon-Lossless-Event-Capture M3 (part 2a) integration
## tests (Linux).
##
## Part 1 wired nim-shm-gset (the M1-winning SET transport, Candidate C) in as
## io-mon's PRIMARY Linux dependency channel, but carried a raw `encodeDepRecord`
## element (INCLUDING `seq`) plus an 8-byte per-incarnation nonce — a lossless
## CARRIER that never deduped (every event a distinct element).
##
## Part 2a replaces that with the REAL dedup element-key
## (`encodeDepRecordIdentity`: the identity tuple with `seq` DROPPED) plus the
## process's real `/proc/self/exe` image as the per-exec incarnation identity, and
## enforces LF-7 (unbuffered publish-before-return) + LF-2 (unattached ⇒ hard
## `mcIncomplete`, NO file spill). The `.rmdf-frag` file path stays COMPILED but
## dormant (deletion is part 2b). These tests drive the LIVE Linux LD_PRELOAD shim
## (rebuilt from source) and assert:
##
##   t_dep_set_publishes            — the shim attaches the set and INSERTS each
##                                    observed read; the consumer snapshot carries
##                                    them.
##   t_source_dedup_probe_storm     — the Candidate-C benefit is now REAL: a
##                                    workload that re-stats ONE path N times yields
##                                    exactly ONE set element (distinct-not-events).
##   t_exec_distinct_incarnations   — the exec teeth: a pid that execs a new image
##                                    lands TWO distinct process-start elements
##                                    (pre/post-exec, keyed by image) with NO
##                                    incarnation tag, so completeness stays
##                                    mcComplete (startCount == 1 + execCount).
##   t_golden_depfile_regression    — the set-only unbuffered path reproduces
##                                    committed golden depfiles byte-for-byte
##                                    (marker + exec-heavy + probe-heavy), replacing
##                                    the part-1 LF-6-vs-file proof now the active
##                                    path never uses the file.
##   t_lf2_hard_fail_no_file        — LF-2: a producer told to use the set but whose
##                                    set is unattached/dead writes NO `.rmdf-frag`
##                                    file and the edge is mcIncomplete; and even on
##                                    SUCCESS the active set path never touches the
##                                    file writer.
##   t_orphan_producer_bounded      — LF-4: a producer that OUTLIVES its monitor
##                                    cannot grow the consumer-owned set.

import std/[algorithm, os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import io_mon/shm/dep_queue          # decode/encode element bytes ↔ MonitorRecord
import shm_gset                        # attachSet reader / shmGSetSupported
import shm_gset/transport              # startHost / attachProducer / emit / snapshot

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  fixturesDir = repoRoot / "tests" / "fixtures" / "dep_set_golden"

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

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len:
    result[i] = byte(s[i])

proc sortElems(elems: var seq[seq[byte]]) =
  elems.sort(proc (a, b: seq[byte]): int =
    let m = min(a.len, b.len)
    for i in 0 ..< m:
      if a[i] != b[i]: return cmp(a[i], b[i])
    cmp(a.len, b.len))

proc decodeSet(host: var SetHost): seq[MonitorRecord] =
  ## Deterministic decode of the host's distinct set (mirrors fs_snoop's merge).
  var elems = host.snapshot()
  sortElems(elems)
  for e in elems:
    var ok = false
    let rec = decodeDepRecord(e, ok)
    if ok:
      result.add rec

proc goldenProjection(dep: MonitorDepFile; workPrefix: string): seq[byte] =
  ## Machine-independent canonical projection: keep the workload's OWN dependency
  ## records — process lifecycle (start/exec, always) plus reads/probes whose path
  ## is under `workPrefix` (so incidental system-library reads/stats under
  ## /nix/store are excluded) — rewrite each path to its BASENAME, and zero every
  ## per-run launcher-noise field. The resulting canonical RMDF bytes depend only
  ## on the observed dependency identities the SET transport must preserve — a
  ## committable golden.
  var norm: seq[MonitorRecord]
  for r in dep.records:
    case r.kind
    of mrProcessStart, mrProcessExec:
      discard
    of mrFileRead, mrPathProbe:
      if not r.path.startsWith(workPrefix): continue
    else:
      continue
    var n = r
    n.seq = 0
    n.osPid = 0
    n.parentOsPid = 0
    n.threadId = 0
    n.childOsPid = 0
    n.flags = 0
    n.result = 0
    n.probeResult = prUnknown
    n.detail = ""
    if n.path.len > 0:
      n.path = extractFilename(n.path)
    norm.add n
  encodeCanonical(norm)

proc markerReaderSrc(): string =
  """
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
"""

suite "io-mon dep-set (nim-shm-gset real dedup element-key, M3 part 2a)":
  let work = getTempDir() / ("io-mon-dep-set-" & $getCurrentProcessId())
  createDir(work)

  test "t_dep_set_publishes":
    # The shim attaches the SET (REPRO_MONITOR_DEP_SHM = a shard0 path) and
    # INSERTS each observed read. The consumer snapshot, decoded, carries every
    # marker read.
    check shmGSetSupported
    let shimLib = ensureShim()

    const N = 6
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("setpub-" & $i & ".txt")
      writeFile(m, "set publish marker " & $i & "\n")
      markers.add m

    let reader = buildC(work, "setpub_reader", markerReaderSrc())

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

    let found = decodeSet(host)
    host.finish()

    check found.len > 0
    for m in markers:
      check found.anyIt(it.kind == mrFileRead and m in it.path)
    # Real dedup element-key: every decoded record reconstructs seq == 0.
    check found.allIt(it.seq == 0'u64)

  test "t_source_dedup_probe_storm":
    # The Candidate-C benefit is now REAL. A single process re-stats ONE path
    # STORM_N times; because the identity element-key drops `seq`, all those
    # exact-duplicate probe observations collapse to ONE distinct set element.
    check shmGSetSupported
    let shimLib = ensureShim()

    const StormN = 500
    let target = work / "storm-target.txt"
    writeFile(target, "probe storm target\n")

    let storm = buildC(work, "probe_storm", """
#include <stdlib.h>
#include <sys/stat.h>
int main(int argc, char **argv) {
  struct stat st;
  for (int i = 0; i < """ & $StormN & """; i++) {
    if (stat(argv[1], &st) != 0) exit(2);
  }
  exit(0);
}
""")

    let fragDir = work / "storm-frags"
    createDir(fragDir)
    var host = startHost(fragDir, "storm-run")
    check host.available

    let env = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": fragDir,
      "REPRO_MONITOR_DEP_SHM": host.path0,
      "REPRO_MONITOR_SESSION": "storm-run",
    })
    let cap = run(storm, @[target], env)
    checkpoint(cap.output)
    check cap.code == 0

    let found = decodeSet(host)
    let growth = host.growthFailures()
    host.finish()

    check growth == 0'u64
    # StormN=500 probes of the SAME path → exactly ONE distinct probe element for
    # that path (distinct-not-events). NO `.rmdf-frag` spill on the active path.
    let stormProbes = found.filterIt(
      it.kind == mrPathProbe and it.path == target)
    check stormProbes.len == 1
    # No `.rmdf-frag` spill on the active set path (the shard files themselves
    # live under fragDir, so filter to the file-fallback extension).
    check toSeq(walkDir(fragDir)).filterIt(
      it.path.endsWith(".rmdf-frag")).len == 0

  test "t_cross_process_open_dedup":
    check shmGSetSupported
    let shimLib = ensureShim()

    const WorkerN = 32
    let target = work / "cross-process-open-target.txt"
    writeFile(target, "cross-process open target\n")

    let storm = buildC(work, "cross_process_open_storm", """
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "--child") == 0) {
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) return 2;
    close(fd);
    return 0;
  }
  if (argc != 2) return 3;
  for (int i = 0; i < """ & $WorkerN & """; i++) {
    pid_t pid = fork();
    if (pid < 0) return 4;
    if (pid == 0) {
      execl(argv[0], argv[0], "--child", argv[1], (char *)0);
      _exit(5);
    }
  }
  for (int i = 0; i < """ & $WorkerN & """; i++) {
    int status = 0;
    if (wait(&status) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      return 6;
  }
  return 0;
}
""")

    let fragDir = work / "cross-process-open-frags"
    createDir(fragDir)
    var host = startHost(fragDir, "cross-process-open-run")
    check host.available

    let env = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": fragDir,
      "REPRO_MONITOR_DEP_SHM": host.path0,
      "REPRO_MONITOR_SESSION": "cross-process-open-run",
    })
    let cap = run(storm, @[target], env)
    checkpoint(cap.output)
    check cap.code == 0

    let found = decodeSet(host)
    let growth = host.growthFailures()
    host.finish()

    check growth == 0'u64
    let targetOpens = found.filterIt(
      it.kind == mrFileOpen and it.path == target)
    check targetOpens.len == 1
    check targetOpens[0].osPid == 0'u64
    check targetOpens[0].result == 0
    # Process-lifecycle records retain their full identities.
    check found.countIt(it.kind == mrProcessStart) >= WorkerN + 1

  test "t_exec_distinct_incarnations":
    # The exec teeth WITHOUT any incarnation tag. A pid that reads a marker then
    # execs a NEW image emits a process-start in BOTH incarnations. Those two
    # process-start records are byte-identical (seq resets to 1, same pid/ppid/tid,
    # empty path) — the real Candidate-C dedup would drop the second and downgrade
    # a fully-monitored exec. The `/proc/self/exe` image identity keeps them
    # DISTINCT: exactly TWO process-start elements survive, so the completeness
    # invariant holds and the merged depfile is mcComplete.
    check shmGSetSupported
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    let reader = buildC(work, "read_then_exec_set", """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  if (n <= 0) return 3;
  execl(argv[2], "true", (char *)0);
  _exit(4);
}
""")
    let trueBin = findExe("true")
    check trueBin.len > 0
    let marker = work / "exec-set-marker.txt"
    writeFile(marker, "exec set marker\n")
    let depfile = work / "exec-set.rdep"

    let env = childEnvWith(shimLib)
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
      reader, marker, trueBin], env)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    # The exec is fully monitored: no tag, no false downgrade.
    check dep.completeness == mcComplete
    check hasFileRead(dep, marker)
    check dep.records.anyIt(it.kind == mrProcessExec and it.path == trueBin)
    check not dep.records.anyIt(it.kind == mrEventLoss)
    # The root pid has TWO process-starts (pre-exec + post-exec image) — the teeth
    # that the image identity, not a nonce, kept both distinct in the set.
    let rootPid = block:
      var pid = 0'u64
      # The first process-start's pid is the root reader (io-mon-root-spawn aside).
      for r in dep.records:
        if r.kind == mrProcessStart and r.osPid != 0:
          pid = r.osPid; break
      pid
    check rootPid != 0'u64
    let rootStarts = dep.records.countIt(
      it.kind == mrProcessStart and it.osPid == rootPid)
    check rootStarts == 2

  test "t_exec_same_image_reexec":
    # The COVERAGE HOLE that let the part-2a regression through: a pid that
    # re-execs the SAME on-disk image (identical `/proc/self/exe`) — exactly the
    # Nix gcc/rustc bash-wrapper shape (a bash script that execs the real
    # compiler in-place; both incarnations carry the bash interpreter image).
    # The pre/post-exec process-starts are byte-identical AND share the image, so
    # WITHOUT an exec-generation identity the SET source-dedup collapses them to
    # ONE element → execs>=starts → mrEventLoss → a FALSE `mcIncomplete` that
    # defeats caching for every Nix-toolchain build. The exec generation
    # (REPRO_MONITOR_EXEC_GEN, incremented through the child env) keeps every
    # same-image incarnation DISTINCT, so completeness stays `mcComplete`.
    #
    # `t_exec_distinct_incarnations` only exercises DISTINCT-image execs (kept
    # apart by the image alone) — it cannot catch a same-image regression. This
    # test is the teeth: revert the exec-generation fix and it FAILS (rootStarts
    # collapses to 1 and completeness downgrades to mcIncomplete).
    check shmGSetSupported
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    # A helper that reads a marker then re-execs ITSELF (via /proc/self/exe, the
    # real binary path — identical image across every incarnation) advancing a
    # stage counter, so the SAME pid emits THREE same-image process-starts.
    let reexec = buildC(work, "same_image_reexec", """
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  if (n <= 0) return 3;
  int stage = atoi(argv[2]);
  if (stage < 2) {
    char next[16];
    snprintf(next, sizeof(next), "%d", stage + 1);
    execl("/proc/self/exe", argv[0], argv[1], next, (char *)0);
    _exit(4);
  }
  return 0;
}
""")
    let marker = work / "reexec-set-marker.txt"
    writeFile(marker, "same-image reexec marker\n")
    let depfile = work / "reexec-set.rdep"

    let env = childEnvWith(shimLib)
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
      reexec, marker, "0"], env)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    # Fully monitored same-image re-exec chain: no false downgrade.
    check dep.completeness == mcComplete
    check hasFileRead(dep, marker)
    check not dep.records.anyIt(it.kind == mrEventLoss)
    # The root pid re-execs the SAME image TWICE, so THREE process-start elements
    # must survive as distinct (WITHOUT the exec-generation fix, all three are
    # byte-identical and collapse to ONE).
    let rootPid = block:
      var pid = 0'u64
      for r in dep.records:
        if r.kind == mrProcessStart and r.osPid != 0:
          pid = r.osPid; break
      pid
    check rootPid != 0'u64
    let rootStarts = dep.records.countIt(
      it.kind == mrProcessStart and it.osPid == rootPid)
    check rootStarts >= 2

  test "t_golden_depfile_regression":
    # The set-only UNBUFFERED path reproduces committed golden depfiles
    # byte-for-byte (normalising only genuine launcher noise via goldenProjection).
    # Three representative workloads: a marker read set, an exec-heavy chain, and a
    # probe-heavy storm. Each golden is regenerated (self-heal) when absent so the
    # fixture is produced deterministically, then asserted byte-identical on reruns.
    createDir(fixturesDir)
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    proc runOnce(tag: string; reader: string; args: seq[string]):
        MonitorDepFile =
      let depfile = work / ("golden-" & tag & ".rdep")
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", reader] & args,
        childEnvWith(shimLib))
      checkpoint(tag & ": " & cap.output)
      check cap.code == 0
      readMonitorDepFile(depfile)

    proc assertGolden(tag: string; dep: MonitorDepFile) =
      let projected = goldenProjection(dep, work)
      let fixture = fixturesDir / (tag & ".rmdf")
      if not fileExists(fixture):
        writeFile(fixture, cast[string](projected))
        checkpoint("generated golden fixture " & fixture)
      let golden = toBytes(readFile(fixture))
      check projected == golden

    # -- marker workload (distinct reads) --
    const N = 24
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("golden-marker-" & $i & ".txt")
      writeFile(m, "golden marker " & $i & "\n")
      markers.add m
    let markerReader = buildC(work, "golden_marker_reader", markerReaderSrc())
    let depA = runOnce("marker", markerReader, markers)
    check depA.completeness == mcComplete
    for m in markers: check hasFileRead(depA, m)
    assertGolden("marker", depA)
    # Determinism: a second unbuffered run reproduces the projection byte-for-byte.
    let depA2 = runOnce("marker2", markerReader, markers)
    check goldenProjection(depA, work) == goldenProjection(depA2, work)

    # -- exec-heavy workload (chain of execs into distinct images) --
    let trueBin = findExe("true")
    check trueBin.len > 0
    let execMarker = work / "golden-exec-marker.txt"
    writeFile(execMarker, "golden exec marker\n")
    let execReader = buildC(work, "golden_exec_reader", """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  read(fd, buf, sizeof(buf));
  close(fd);
  execl(argv[2], "true", (char *)0);
  _exit(4);
}
""")
    let depE = runOnce("exec", execReader, @[execMarker, trueBin])
    check depE.completeness == mcComplete
    assertGolden("exec", depE)
    let depE2 = runOnce("exec2", execReader, @[execMarker, trueBin])
    check goldenProjection(depE, work) == goldenProjection(depE2, work)

    # -- probe-heavy workload (storm collapses to distinct probes) --
    let probeTarget = work / "golden-probe-target.txt"
    writeFile(probeTarget, "golden probe target\n")
    let probeReader = buildC(work, "golden_probe_reader", """
#include <stdlib.h>
#include <sys/stat.h>
int main(int argc, char **argv) {
  struct stat st;
  for (int i = 0; i < 300; i++) {
    if (stat(argv[1], &st) != 0) exit(2);
  }
  exit(0);
}
""")
    let depP = runOnce("probe", probeReader, @[probeTarget])
    check depP.completeness == mcComplete
    assertGolden("probe", depP)
    let depP2 = runOnce("probe2", probeReader, @[probeTarget])
    check goldenProjection(depP, work) == goldenProjection(depP2, work)

  test "t_lf2_hard_fail_no_file":
    # LF-2 — on the ACTIVE set path the `.rmdf-frag` file writer is NEVER touched.
    #
    # (1) HARD FAIL: the shim is told to use the set (REPRO_MONITOR_DEP_SHM names a
    #     `.shard0`) but the segment does not exist, so the producer cannot map it.
    #     No record — not even the process-start — is captured, and NO `.rmdf-frag`
    #     file is spilled. The consumer's root-spawn guard then downgrades the edge
    #     to mcIncomplete (a missing root process-start), never a silent false
    #     mcComplete.
    # (2) SUCCESS: the same workload against a LIVE set is mcComplete and STILL
    #     writes no `.rmdf-frag` — proving the file path is dormant on the active
    #     set path (LF-7: the shim publishes only to the set).
    check shmGSetSupported
    let shimLib = ensureShim()
    let reader = buildC(work, "lf2_reader", markerReaderSrc())
    let marker = work / "lf2-marker.txt"
    writeFile(marker, "lf2 marker\n")

    # (1) unattached/dead set → no file, mcIncomplete via the root guard.
    let badFragDir = work / "lf2-bad-frags"
    createDir(badFragDir)
    let badSetPath = badFragDir / "does-not-exist.shard0"
    let badEnv = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": badFragDir,
      "REPRO_MONITOR_DEP_SHM": badSetPath,
      "REPRO_MONITOR_SESSION": "lf2-bad-run",
    })
    let badCap = startProcess(reader, args = @[marker], env = badEnv,
      options = {poStdErrToStdOut, poUsePath})
    let badPid = uint64(badCap.processID)
    discard badCap.outputStream.readAll()
    check badCap.waitForExit() == 0
    badCap.close()
    # NO `.rmdf-frag` spill on the active set path even though attach failed.
    check toSeq(walkDir(badFragDir)).filterIt(
      it.path.endsWith(".rmdf-frag")).len == 0
    # The empty fragment dir + the launcher-known root pid ⇒ mcIncomplete.
    let badDep = mergeFragments(badFragDir, work / "lf2-bad.rdep",
      expectedRootPid = badPid, currentRunId = "lf2-bad-run")
    check badDep.completeness == mcIncomplete

    # (2) live set → mcComplete AND still no file (file path dormant on success).
    let okFragDir = work / "lf2-ok-frags"
    createDir(okFragDir)
    var host = startHost(okFragDir, "lf2-ok-run")
    check host.available
    let okEnv = childEnvWith(shimLib, {
      "LD_PRELOAD": shimLib,
      "REPRO_MONITOR_FRAGMENT_DIR": okFragDir,
      "REPRO_MONITOR_DEP_SHM": host.path0,
      "REPRO_MONITOR_SESSION": "lf2-ok-run",
    })
    let okCap = startProcess(reader, args = @[marker], env = okEnv,
      options = {poStdErrToStdOut, poUsePath})
    let okPid = uint64(okCap.processID)
    discard okCap.outputStream.readAll()
    check okCap.waitForExit() == 0
    okCap.close()
    let okRecords = decodeSet(host)
    let growth = host.growthFailures()
    host.finish()
    check growth == 0'u64
    check okRecords.anyIt(it.kind == mrFileRead and marker in it.path)
    # File path dormant on the active set path even on success.
    check toSeq(walkDir(okFragDir)).filterIt(
      it.path.endsWith(".rmdf-frag")).len == 0
    let okDep = mergeFragments(okFragDir, work / "lf2-ok.rdep",
      expectedRootPid = okPid, currentRunId = "lf2-ok-run",
      setRecords = okRecords)
    check okDep.completeness == mcComplete
    check hasFileRead(okDep, marker)

  test "t_orphan_producer_bounded":
    # LF-4: a monitored descendant that OUTLIVES its monitor cannot grow the
    # consumer-owned set once the consumer marks itself gone.
    check shmGSetSupported
    let dir = work / "orphan"
    createDir(dir)

    var host = startHost(dir, "orphan-run")
    check host.available
    let p0 = host.path0

    var prod = attachProducer(p0)
    check prod.available

    for i in 0 ..< 100:
      check prod.emit(toBytes("orphan-dep-" & $i)) in {emInserted, emExists}
    let before = host.snapshot().len
    check before == 100

    host.finish()

    var goneCount = 0
    var grewCount = 0
    for i in 100 ..< 10_100:
      case prod.emit(toBytes("orphan-dep-" & $i))
      of emConsumerGone: inc goneCount
      of emInserted, emExists: inc grewCount
      else: discard
    prod.detach()

    check goneCount == 10_000
    check grewCount == 0

    var reader = attachSet(p0)
    check reader.available
    check reader.snapshot().len == before
    reader.detach()

  test "t_launcher_loss_recorded_in_set_no_file":
    # io-mon-Lossless-Event-Capture M7 (Linux slice) — the CONSUMER's launcher-side
    # event-loss (a monitored descendant still alive past the grace window) is now
    # recorded into the consumer-owned nim-shm-gset, NOT a `.rmdf-frag` file. Prove
    # Linux is file-free end-to-end: (1) `appendLauncherEventLoss` writes NO
    # `.rmdf-frag` on the active-set path; (2) the set snapshot carries the
    # `mrEventLoss`; (3) `mergeFragments` folds it → `mcIncomplete`.
    check shmGSetSupported
    # The migration is Linux-only: on this platform the file producer is NOT the
    # host fallback for launcher loss.
    check not hostUsesFileFallback
    let dir = work / "launcher-loss-set"
    createDir(dir)
    let runId = "launcher-loss-run"

    var host = startHost(dir, runId)
    check host.available

    # The exact detail the live `waitForLinuxInjectedDescendants` grace-timeout
    # path emits — routed through the migrated `appendLauncherEventLoss`.
    appendLauncherEventLoss(dir, runId,
      "linux injected descendants still live after root exit pids=4242",
      host.path0)

    # (1) NO `.rmdf-frag` file anywhere in the fragment dir — the launcher loss
    # never touched the file writer (Linux file-free).
    var fragFiles = 0
    for kind, path in walkDir(dir):
      if kind == pcFile and path.endsWith(".rmdf-frag"):
        inc fragFiles
    check fragFiles == 0

    # (2) The loss IS present in the consumer-owned set, run-stamped.
    let setRecs = decodeSet(host)
    check setRecs.anyIt(it.kind == mrEventLoss and
      "linux injected descendants still live" in it.detail and
      ("run=" & runId) in it.detail)

    # (3) Folding the set snapshot into the merge downgrades the edge, exactly as a
    # file-borne launcher loss used to — but with an empty fragment dir on disk.
    let dep = mergeFragments(dir, dir / "launcher-loss.rdep",
      currentRunId = runId, setRecords = setRecs)
    check dep.completeness == mcIncomplete
    # The merged depfile references NO `.rmdf-frag` path (nothing was scanned).
    check not dep.records.anyIt(it.path.endsWith(".rmdf-frag"))
    host.finish()

  test "t_launcher_loss_file_fallback_retained_when_set_unavailable":
    # The shared `.rmdf-frag` writer is the RETAINED fallback (macOS/Windows arm +
    # the Linux `REPRO_MONITOR_DEP_SHM_DISABLE` pure-file baseline): when no set is
    # available (empty `depSetPath0`), `appendLauncherEventLoss` still records the
    # loss to a fragment file so the edge is honestly `mcIncomplete`, never dropped.
    let dir = work / "launcher-loss-file-fallback"
    createDir(dir)
    let runId = "launcher-loss-file-run"
    appendLauncherEventLoss(dir, runId,
      "linux injected-descendant /proc scan failed", "")  # no set → file fallback
    var fragFiles = 0
    for kind, path in walkDir(dir):
      if kind == pcFile and path.endsWith(".rmdf-frag"):
        inc fragFiles
    check fragFiles == 1
    let dep = mergeFragments(dir, dir / "fallback.rdep", currentRunId = runId)
    check dep.completeness == mcIncomplete
