## Linux: closing a stdio stream must forget the path of the descriptor under it.
##
## A write must be attributed to the file that was written, never to a file the
## process merely read earlier. This test pins that for the one sequence where it
## went wrong: a descriptor number reused across a `fclose` / `fopen` pair.
##
## The Linux shim keeps an fd -> path table. `close(2)` removes an entry, but
## `fclose` closes its descriptor INSIDE glibc, where the `close` hook does not
## see it, and the `fclose` hook only dropped the FILE* -> path entry. The fd
## entry lived on whenever something had filled it in, which a raw `read(2)` on
## a stream's descriptor does (the named-fd recovery reads `/proc/self/fd`).
## The next `fopen` reuses the descriptor number, and a raw `write(2)` on the
## new stream was then recorded as a write to the OLD path.
##
## That is exactly libstdc++'s `std::ifstream` / `std::ofstream` pattern: the
## file buffer opens through `fopen` and then moves bytes with `read`/`write`
## on `fileno(stream)`. It is not hypothetical. `cmake --install` reads each
## source file with an ifstream, then writes `install_manifest.txt` with an
## ofstream, and the monitor recorded a 242-byte write to the last INSTALLED
## SOURCE file (a read-only input). A consumer that rejects writes into its
## source tree, as reprobuild does, then failed a correct build.
##
## The workload below is plain C reproducing that call sequence, so the test
## pins the shim's behaviour rather than one C++ runtime's buffering choices.
##
## MOCKS: none. A real program under the real shim and the real `io-mon run`,
## with records read back from the real depfile.

import std/[os, osproc, streams, strtabs, unittest]

import io_mon

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

proc canonical(path: string): string =
  try: expandFilename(path)
  except OSError, IOError: path

suite "io-mon Linux stream close forgets the descriptor's path":
  let work = getTempDir() / ("io-mon-stream-close-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)

  let cc = getEnv("CC", "cc")
  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()

  let snoopBin = work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0

  # argv[1] = source to read, argv[2] = output to write, argv[3] = "1" to close
  # the input stream before opening the output (descriptor reuse) or "0" to keep
  # it open (distinct descriptors: the control).
  const appSource = """
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[256];
  FILE *in = fopen(argv[1], "rb");
  if (in == NULL) { perror("fopen in"); return 1; }
  if (read(fileno(in), buf, sizeof buf) < 0) { perror("read"); return 2; }
  int reuse = strcmp(argv[3], "1") == 0;
  int inFd = fileno(in);
  if (reuse) fclose(in);
  FILE *out = fopen(argv[2], "w");
  if (out == NULL) { perror("fopen out"); return 3; }
  /* The case under test needs the descriptor number to be reused. */
  if (reuse && fileno(out) != inFd) { fprintf(stderr, "fd not reused\n"); return 5; }
  const char *text = "written-to-the-output-file\n";
  if (write(fileno(out), text, strlen(text)) < 0) { perror("write"); return 4; }
  fclose(out);
  if (!reuse) fclose(in);
  return 0;
}
"""
  let app = work / "stream_reuse_app"
  writeFile(work / "stream_reuse_app.c", appSource)
  let built = run(cc, @[work / "stream_reuse_app.c", "-o", app])
  checkpoint(built.output)
  require built.code == 0

  proc monitored(tag, reuse: string): tuple[source, output: string;
                                            records: seq[MonitorRecord]] =
    let source = work / ("source-" & tag & ".txt")
    let output = work / ("output-" & tag & ".txt")
    writeFile(source, "the input the program only reads\n")
    removeFile(output)
    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / ("stream-close-" & tag & ".iomon")
    let res = run(snoopBin,
      @["run", "--depfile", depfile, "--", app, source, output, reuse],
      childEnv)
    checkpoint(tag & ": " & res.output)
    require res.code == 0
    require fileExists(depfile)
    require readFile(output) == "written-to-the-output-file\n"
    (canonical(source), canonical(output), readMonitorDepFile(depfile).records)

  proc writesTo(records: seq[MonitorRecord]; path: string): seq[MonitorRecord] =
    for r in records:
      if r.kind == mrFileWrite and r.path.len > 0 and canonical(r.path) == path:
        result.add r

  test "a reused descriptor's write is not charged to the file closed before":
    let got = monitored("reuse", "1")
    let misattributed = writesTo(got.records, got.source)
    checkpoint("writes recorded against the read-only source: " &
      $misattributed)
    check misattributed.len == 0
    # The write itself is still on record, against the file actually written.
    check writesTo(got.records, got.output).len > 0

  test "control: with distinct descriptors the source is never written":
    # Without reuse there is nothing stale to consult. This arm shows the
    # program and the filter are sound, so a failure in the case above is the
    # shim's attribution and not the workload.
    let got = monitored("distinct", "0")
    check writesTo(got.records, got.source).len == 0
    check writesTo(got.records, got.output).len > 0

  test "control: the source read is observed, so the stale entry was live":
    # The misattribution needs the fd -> path entry to have been filled in by
    # the raw read. If the read stopped being recorded, the first case would
    # pass vacuously; this makes that visible.
    let got = monitored("readseen", "1")
    var sawRead = false
    for r in got.records:
      if r.kind == mrFileRead and r.path.len > 0 and
          canonical(r.path) == got.source:
        sawRead = true
    check sawRead
