## test_io_mon_channel_create — IoMon-Pipeline-Capture IM-3 (Linux) integration
## tests: `chan=localfd role=create` for channels a monitored process makes
## itself (`pipe`/`pipe2`/`socketpair`).
##
## THE FAILURE THESE PIN. `externalContentLossCount` (writer.nim) downgrades an
## UNPAIRED `chan=opaque role=read` — content that entered a process with no
## `read(2)` of a named file behind it — to a Level-2 loss, which sets
## `disableCacheHits`. The pairing key is the fd's kernel `dev:ino` identity, and
## the only thing that can produce the matching `chan=localfd role=create` is a
## hook on the call that made the channel. Before IM-3 the Linux shim had no such
## hook (macOS did), so a pipe the MONITORED SHELL created itself had nothing to
## pair against and `sh -c 'echo hi | cat'` was graded `mcIncomplete` — measured
## on `1474c8a`: one `chan=opaque role=read localfd:14:173347522` with no create
## anywhere in the evidence.
##
## The two tests are deliberately opposed, and the second is the one that stops a
## "fix" that merely disables the check:
##
##   self_created_pipe_does_not_downgrade
##       The in-tree pipeline must NOT downgrade. Asserting only the ABSENCE of
##       the loss record would pass vacuously if the shell's pipe were never
##       observed at all, so the test also asserts the POSITIVE shape: an opaque
##       read really happened, and a create with the SAME `dev:ino` key exists.
##       That is the pairing, not just its consequence.
##
##   genuinely_external_pipe_still_downgrades
##       One monitored run consumes TWO channels: a pipe created by an
##       OUT-OF-TREE launcher (inherited across `exec` into the monitored tree)
##       and a second pipe created entirely IN-TREE. Exactly one loss must be
##       reported. Counting rather than merely requiring "at least one" is what
##       gives this test teeth in both directions: delete the IM-3 hooks and the
##       count becomes 2; delete the downgrade wholesale and it becomes 0.
##
## The out-of-tree launcher shape is lifted from the round-4 IP1 residual probe
## (`research/adversarial-2026-06-round4/r4_residual/pipe_launcher.c`), which is
## the adversary this pairing was built against: a launcher feeds a build-relevant
## marker into a pipe, clears `FD_CLOEXEC` on the read end, and `exec`s the monitor
## so the monitored client inherits a channel whose producer io-mon never saw.
##
## No mocks: the live `LD_PRELOAD` shim is rebuilt from source and the assertions
## read the canonical depfile the monitor writes.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

  ExternalLossMarker = "out-of-tree content channel"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
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

proc monitorEnv(shimLib: string): StringTableRef =
  ## The env the MONITOR is started under. `LD_PRELOAD` is explicitly dropped so
  ## the launcher process of the second test is unambiguously out-of-tree: only
  ## the snoop root and its descendants are monitored.
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result.del("LD_PRELOAD")
  result["REPRO_MONITOR_SHIM_LIB"] = shimLib

proc externalLosses(dep: MonitorDepFile): seq[MonitorRecord] =
  dep.records.filterIt(it.kind == mrEventLoss and ExternalLossMarker in it.detail)

proc channelKeys(dep: MonitorDepFile; chan, role: string): seq[string] =
  ## The distinct channel-identity keys of every `mrExternalContent` record with
  ## this `chan`/`role` pair.
  let want = "chan=" & chan & " role=" & role
  dep.records
    .filterIt(it.kind == mrExternalContent and want in it.detail)
    .mapIt(it.path)
    .deduplicate()

## The MONITORED client of the second test. It consumes TWO channels:
##   1. `argv[1]` — an fd inherited from the OUT-OF-TREE launcher (unpaired).
##   2. an entirely IN-TREE `sh -c 'echo … | cat'` pipeline (paired by IM-3).
## Both are opaque reads; only the first may downgrade.
const dualConsumerSrc = """
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int rfd = atoi(argv[1]);
  const char *out = argv[2];
  char buf[256];
  ssize_t n = read(rfd, buf, sizeof buf - 1);
  if (n <= 0) { fprintf(stderr, "read inherited fd %d failed\n", rfd); return 1; }
  buf[n] = 0;
  /* Bake the invisible input into the output, as the r4 residual probe does. */
  int ofd = open(out, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (ofd < 0) return 2;
  dprintf(ofd, "from-inherited-pipe: %s", buf);
  close(ofd);
  /* …and consume a SECOND channel that this tree creates itself. */
  if (system("echo in-tree-payload | cat > /dev/null") != 0) return 3;
  return 0;
}
"""

## The OUT-OF-TREE launcher: it creates the pipe, feeds it, keeps the read end
## across `exec`, and only THEN starts the monitor. Nothing in the monitored tree
## ever calls `pipe` for this channel, so no `localfd` create can exist for it.
const externalLauncherSrc = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
int main(int argc, char **argv) {
  /* argv: 1=io-mon 2=depfile 3=client 4=out 5=marker */
  int p[2];
  if (pipe(p) != 0) { perror("pipe"); return 2; }
  const char *marker = argv[5];
  if (write(p[1], marker, strlen(marker)) < 0) { perror("write"); return 2; }
  close(p[1]);
  fcntl(p[0], F_SETFD, fcntl(p[0], F_GETFD) & ~FD_CLOEXEC);
  char rfd[16];
  snprintf(rfd, sizeof rfd, "%d", p[0]);
  execl(argv[1], "io-mon", "run", "--depfile", argv[2], "--",
        argv[3], rfd, argv[4], (char *)NULL);
  perror("execl");
  return 3;
}
"""

suite "io-mon Linux channel-create records (IoMon-Pipeline-Capture IM-3)":
  let work = getTempDir() / ("io-mon-chan-create-" & $getCurrentProcessId())
  createDir(work)

  test "self_created_pipe_does_not_downgrade":
    # The milestone's exact repro: a monitored shell that builds its own pipeline.
    # Both ends belong to the monitored tree, so the evidence is closed under
    # monitoring and nothing is invisible.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()
    let depfile = work / "self-pipe.iomon"

    let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
      "/bin/sh", "-c", "echo hi | cat"], monitorEnv(shimLib))
    checkpoint(cap.output)
    check cap.code == 0
    check "hi" in cap.output

    let dep = readMonitorDepFile(depfile)

    # PRIMARY: the milestone's required assertion.
    check externalLosses(dep).len == 0
    check dep.completeness == mcComplete

    # The pipe was genuinely consumed as an opaque channel — without this the
    # assertion above could pass merely because nothing was observed at all.
    let consumed = channelKeys(dep, "opaque", "read")
    check consumed.len >= 1

    # …and every consumed channel has an in-tree create with the SAME dev:ino
    # key. This is the pairing itself, which is what IM-3 adds.
    let created = channelKeys(dep, "localfd", "create")
    check created.len >= 1
    for key in consumed:
      check key.startsWith("localfd:")
      check key in created

  test "genuinely_external_pipe_still_downgrades":
    # One monitored run, two consumed channels: one whose producer is out of the
    # tree, one the tree made itself. EXACTLY ONE must downgrade.
    #
    # The count is load-bearing in both directions. Without the IM-3 hooks the
    # in-tree channel is unpaired too and the count is 2; with the downgrade
    # removed wholesale the count is 0. Only the correct behaviour gives 1.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    let client = buildC(work, "external_pipe_client", dualConsumerSrc)
    let launcher = buildC(work, "external_pipe_launcher", externalLauncherSrc)
    let depfile = work / "external-pipe.iomon"
    let outFile = work / "external-pipe.out"
    const marker = "OUT_OF_TREE_PIPE_SECRET"

    # The launcher runs OUT-OF-TREE (no LD_PRELOAD, no shim) and only becomes the
    # monitor by exec'ing it, so the pipe predates all monitoring.
    let cap = run(launcher, @[snoopBin, depfile, client, outFile, marker],
      monitorEnv(shimLib))
    checkpoint(cap.output)
    check cap.code == 0
    # The secret really did become a build input, which is why losing it matters.
    check marker in readFile(outFile)

    let dep = readMonitorDepFile(depfile)

    # PRIMARY: the out-of-tree channel downgrades, and only it.
    check externalLosses(dep).len == 1
    check dep.completeness == mcIncomplete

    # Both channels were really consumed (otherwise "exactly one loss" would be
    # satisfiable by observing only one of them).
    let consumed = channelKeys(dep, "opaque", "read")
    check consumed.len >= 2

    # …and exactly the in-tree ones are paired: at least one consumed key has a
    # matching create, and at least one does not.
    let created = channelKeys(dep, "localfd", "create")
    check consumed.anyIt(it in created)
    check consumed.anyIt(it notin created)
