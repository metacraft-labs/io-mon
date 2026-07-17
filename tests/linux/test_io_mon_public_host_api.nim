## test_io_mon_public_host_api — io-mon-Lossless-Event-Capture M6 (part A).
##
## Proves the BLESSED PUBLIC parent-host API (`runMonitored`, exported from
## `io_mon` — the §5 consumer-side batch entry point) actually works end-to-end,
## driving the LIVE Linux LD_PRELOAD shim. Unlike `test_io_mon_dep_set`, which
## hand-rolls the `startHost` → `attachProducer` → `snapshot` lifecycle, this
## test uses ONLY the public surface — the whole point of M6 is that a parent no
## longer has to hand-roll the shm/consumer setup, so a well-formed host cannot
## end up with a producer and no consumer (LF-2) and consumer liveness holds by
## construction (LF-4).
##
##   t_run_monitored_end_to_end — `runMonitored(req)` on a real marker-reading
##       command returns `mcComplete`, captures every expected input path, and
##       the consumer-owned run leaves NO `.rmdf-frag` spill (LF-2) and no
##       orphaned fragment directory behind (the host owns + tears down the
##       whole lifecycle). The depfile it wrote on disk decodes to the same.

import std/[os, osproc, sequtils, streams, strutils, unittest]

import io_mon                            # runMonitored / MonitorResult (PUBLIC)
import shm_set                           # shmSetSupported

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

proc run(cmd: string; args: seq[string]):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc buildC(work, name, source: string): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result])
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc ensureShim(): string =
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(buildShim.output)
  check buildShim.code == 0
  findShimLibrary()

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

proc hasFileRead(recs: seq[MonitorRecord]; path: string): bool =
  recs.anyIt(it.kind == mrFileRead and it.observationKind == moFileRead and
    path in it.path)

proc fragFilesUnder(dir: string): seq[string] =
  ## Any `.rmdf-frag` spill anywhere under `dir` — the file-fallback the active
  ## set path must NEVER touch.
  for path in walkDirRec(dir):
    if path.endsWith(".rmdf-frag"):
      result.add path

proc fragmentDirsUnder(dir: string): seq[string] =
  ## Any leftover `repro-fs-snoop-fragments-*` dir the host failed to reap.
  for kind, path in walkDir(dir):
    if kind == pcDir and path.extractFilename.startsWith(
        "repro-fs-snoop-fragments-"):
      result.add path

suite "io-mon public parent-host API (runMonitored, M6 part A)":
  test "t_run_monitored_end_to_end":
    check shmSetSupported
    let shimLib = ensureShim()
    check shimLib.len > 0

    # Isolate ALL of runMonitored's own scratch (it creates + tears down its
    # fragment dir under getTempDir()) into a dir we can scan afterwards, so the
    # LF-2 "no spill / no orphaned fragment dir" assertions have real teeth.
    let work = getTempDir() / ("io-mon-public-api-" & $getCurrentProcessId())
    createDir(work)
    let scratch = work / "scratch"
    createDir(scratch)

    const N = 8
    var markers: seq[string]
    for i in 0 ..< N:
      let m = work / ("public-marker-" & $i & ".txt")
      writeFile(m, "public host api marker " & $i & "\n")
      markers.add m
    let reader = buildC(work, "public_marker_reader", markerReaderSrc())
    let depfile = work / "public.rdep"

    # Redirect getTempDir() at runMonitored's scratch into `scratch`, and pin the
    # shim so findShimLibrary() (called INSIDE runMonitored) resolves it.
    let oldTmp = getEnv("TMPDIR")
    let hadTmp = existsEnv("TMPDIR")
    putEnv("TMPDIR", scratch)
    putEnv("REPRO_MONITOR_SHIM_LIB", shimLib)

    # THE PUBLIC SURFACE: one call owns create-set → export env → spawn →
    # snapshot → depfile write → markConsumerGone + detach.
    var req: FsSnoopRequest
    req.command = @[reader] & markers
    req.depFilePath = depfile
    req.streamMode = fsoNone
    let res = runMonitored(req)

    if hadTmp: putEnv("TMPDIR", oldTmp) else: delEnv("TMPDIR")

    checkpoint("exit=" & $res.exitCode &
      " completeness=" & $res.completeness &
      " records=" & $res.records.len)

    # (1) The monitored command ran and the capture is HONESTLY complete.
    check res.exitCode == 0
    check res.completeness == mcComplete
    check res.records.len > 0

    # (2) Every expected input path is in the captured set (via the PUBLIC
    #     accessors, not by re-reading the file).
    for m in markers:
      check hasFileRead(res.records, m)

    # (3) The canonical depfile the host wrote decodes to the same result.
    check res.depFilePath == depfile
    check fileExists(depfile)
    let onDisk = readMonitorDepFile(depfile)
    check onDisk.completeness == mcComplete
    for m in markers:
      check hasFileRead(onDisk.records, m)

    # (4) LF-2: the consumer-owned run left NO `.rmdf-frag` spill anywhere, and
    #     NO orphaned fragment directory — the host owned + reaped the whole
    #     lifecycle. (The active set path never writes the file fallback, and
    #     runMonitored's `defer removeDir` cleans its scratch.)
    check fragFilesUnder(scratch) == newSeq[string]()
    check fragmentDirsUnder(scratch) == newSeq[string]()

    removeDir(work)
