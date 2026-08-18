## test_io_mon_channel_tree_membership — IoMon-Pipeline-Capture IM-4 (Linux)
## integration tests: the content-channel guard consults PROCESS-TREE MEMBERSHIP,
## not only fd-identity pairing.
##
## WHY THIS EXISTS BEYOND IM-3. IM-3 taught `externalContentLossCount` to pair an
## inherited `chan=opaque role=read` against a `chan=localfd role=create` emitted by
## the monitored process that made the channel. That pairing is a PROXY for the
## question that actually decides the grade — "was the producer one of us?" — and it
## is only as good as the set of channel-creating calls somebody has interposed.
## IM-3 hooked `pipe`/`pipe2`/`socketpair`; Linux still records NO create for
## `socket`/`accept` (macOS does), so a monitored process that hands an accepted
## unix socket to a monitored child re-broke the exact failure IM-3 had just fixed,
## and the next uninterposed channel class would break it again.
##
## MEASURED, not argued: on the pre-IM-4 tree the in-tree socket scenario below was
## graded `mcIncomplete` with one `out-of-tree content channel consumed` loss and a
## lone `chan=opaque role=read localfd:9:594279` — ZERO `chan=localfd role=create`
## records anywhere in the evidence, because nothing hooks `socket`/`accept`. The
## pairing had nothing to work with; only asking who the producer WAS can save it.
##
## HOW THE PRODUCER IS NAMED. The shim stamps the channel's peer pid into
## `childOsPid` (and `peer=` in the detail) from `SO_PEERCRED`, which the KERNEL
## fills in at connection-establishment time. Neither userspace end can forge it,
## and it survives the peer's exit. A pipe, a FIFO or an AF_INET socket cannot name
## a peer, yields 0, and falls through to the unchanged IM-3 pairing.
##
## The two tests are deliberately opposed, and both were run on the pre-change tree
## to confirm they are not green both ways:
##
##   in_tree_producer_via_uninterposed_channel_does_not_downgrade
##       PRE-CHANGE: 1 loss, `mcIncomplete`. Asserting only the absence of the loss
##       would pass vacuously if the socket were never observed as a channel at all,
##       so the test also asserts the POSITIVE shape: the opaque read happened, it
##       has NO matching `localfd` create (i.e. IM-3's pairing demonstrably did not
##       save it), and its recorded producer pid IS one of the run's monitored
##       process-start pids. That is the class fix, not merely its consequence.
##
##   genuinely_external_socket_still_downgrades
##       One monitored run consumes TWO uninterposed-class channels: a unix socket
##       created by an OUT-OF-TREE launcher (inherited across `exec` into the tree)
##       and one created entirely IN-TREE. EXACTLY ONE loss must be reported.
##       Counting gives teeth in both directions: drop the membership guard and the
##       count becomes 2 (PRE-CHANGE measurement), drop the downgrade wholesale and
##       it becomes 0. It is also the guard against "fix the symptom by trusting
##       every peer": the launcher's pid is a real pid that the merge must still
##       classify as out-of-tree.
##
## No mocks: the live `LD_PRELOAD` shim is rebuilt from source, the scenarios are
## real C programs making real `socket`/`accept` calls, and every assertion reads
## the canonical depfile the monitor writes.

import std/[os, osproc, sequtils, sets, streams, strtabs, strutils, unittest]

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

proc opaqueReads(dep: MonitorDepFile): seq[MonitorRecord] =
  dep.records.filterIt(
    it.kind == mrExternalContent and "chan=opaque role=read" in it.detail)

proc localFdCreateKeys(dep: MonitorDepFile): seq[string] =
  dep.records
    .filterIt(it.kind == mrExternalContent and
              "chan=localfd role=create" in it.detail)
    .mapIt(it.path)
    .deduplicate()

## The MONITORED root of both tests. It builds a content channel of a class the
## Linux shim does NOT interpose — `socket`/`bind`/`listen`/`accept`, none of which
## has a hook — and routes bytes through it from one monitored process to another:
##
##   1. listen on an AF_UNIX socket;
##   2. `fork` a monitored PRODUCER child that `socket`+`connect`s and writes the
##      marker (its `connect` is hooked, so its peer is checked by the existing
##      IPC-connect machinery and is in-tree — no subtree loss);
##   3. `accept`, then `fork`+`exec` a CONSUMER with the accepted fd on fd 3. The
##      `exec` is what makes fd 3 an INHERITED fd in the consumer, which is the
##      precondition for the shim to classify the read as an opaque channel read at
##      all.
##
## When `argv[5]` is not "-" it FIRST drains that inherited fd (the out-of-tree
## channel of the second test) into `argv[6]`, so one monitored run consumes both
## an external and an in-tree channel of the same uninterposed class.
const treeProducerSrc = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

static int drain(int fd, const char *out, const char *tag) {
  char buf[256];
  ssize_t n = read(fd, buf, sizeof buf - 1);
  if (n <= 0) { fprintf(stderr, "read fd %d failed\n", fd); return 1; }
  buf[n] = 0;
  int ofd = open(out, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (ofd < 0) return 2;
  dprintf(ofd, "%s: %s", tag, buf);
  close(ofd);
  return 0;
}

int main(int argc, char **argv) {
  /* 1=sock-path 2=consumer 3=out 4=marker 5=external-fd|- 6=external-out */
  const char *sockPath = argv[1];
  const char *consumer = argv[2];
  const char *out = argv[3];
  const char *marker = argv[4];

  if (strcmp(argv[5], "-") != 0) {
    /* The OUT-OF-TREE channel, inherited across the launcher's exec. */
    int rc = drain(atoi(argv[5]), argv[6], "from-external-socket");
    if (rc != 0) return rc;
  }

  struct sockaddr_un a;
  memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  snprintf(a.sun_path, sizeof a.sun_path, "%s", sockPath);
  unlink(sockPath);

  int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (lfd < 0) { perror("socket"); return 3; }
  if (bind(lfd, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 3; }
  if (listen(lfd, 1) != 0) { perror("listen"); return 3; }

  pid_t producer = fork();
  if (producer == 0) {
    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) _exit(4);
    if (connect(cfd, (struct sockaddr *)&a, sizeof a) != 0) _exit(5);
    if (write(cfd, marker, strlen(marker)) < 0) _exit(6);
    close(cfd);
    _exit(0);
  }
  int afd = accept(lfd, NULL, NULL);
  if (afd < 0) { perror("accept"); return 3; }

  pid_t consumerPid = fork();
  if (consumerPid == 0) {
    if (dup2(afd, 3) < 0) _exit(7);
    fcntl(3, F_SETFD, fcntl(3, F_GETFD) & ~FD_CLOEXEC);
    execl(consumer, "consumer", "3", out, (char *)NULL);
    _exit(127);
  }
  int ps = 0, cs = 0;
  waitpid(producer, &ps, 0);
  waitpid(consumerPid, &cs, 0);
  if (ps != 0 || cs != 0) {
    fprintf(stderr, "producer status %d consumer status %d\n", ps, cs);
    return 8;
  }
  return 0;
}
"""

## Reads an INHERITED fd and bakes the bytes into a build output, so the consumed
## content demonstrably becomes an input of the action — which is why grading it
## matters at all.
const inheritedFdConsumerSrc = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv) {
  int rfd = atoi(argv[1]);
  const char *out = argv[2];
  char buf[256];
  ssize_t n = read(rfd, buf, sizeof buf - 1);
  if (n <= 0) { fprintf(stderr, "read inherited fd %d failed\n", rfd); return 1; }
  buf[n] = 0;
  int ofd = open(out, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (ofd < 0) return 2;
  dprintf(ofd, "from-in-tree-socket: %s", buf);
  close(ofd);
  return 0;
}
"""

## The OUT-OF-TREE launcher of the second test: it creates the unix socket pair,
## feeds it, clears `FD_CLOEXEC` and only THEN becomes the monitor by `exec`ing it,
## so the channel's producer is a process io-mon never saw. `SO_PEERCRED` on the
## surviving end names that launcher pid — a REAL pid the merge must still classify
## as out-of-tree, which is what stops the membership guard from degenerating into
## "trust every named peer".
const externalSocketLauncherSrc = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
  /* argv: 1=io-mon 2=depfile 3=root 4=sock-path 5=consumer 6=out 7=marker
           8=external-out 9=external-marker */
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 2; }
  if (write(sv[1], argv[9], strlen(argv[9])) < 0) { perror("write"); return 2; }
  close(sv[1]);
  fcntl(sv[0], F_SETFD, fcntl(sv[0], F_GETFD) & ~FD_CLOEXEC);
  char rfd[16];
  snprintf(rfd, sizeof rfd, "%d", sv[0]);
  execl(argv[1], "io-mon", "run", "--depfile", argv[2], "--",
        argv[3], argv[4], argv[5], argv[6], argv[7], rfd, argv[8],
        (char *)NULL);
  perror("execl");
  return 3;
}
"""

suite "io-mon Linux content-channel tree membership (IoMon-Pipeline-Capture IM-4)":
  let work = getTempDir() / ("io-mon-chan-tree-" & $getCurrentProcessId())
  createDir(work)

  test "in_tree_producer_via_uninterposed_channel_does_not_downgrade":
    # The whole tree is closed under monitoring, but over a channel class NOTHING
    # interposes: no `chan=localfd role=create` can exist for it, so IM-3's pairing
    # cannot possibly be what saves this run.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()
    let root = buildC(work, "tree_socket_root", treeProducerSrc)
    let consumer = buildC(work, "inherited_fd_consumer", inheritedFdConsumerSrc)
    let depfile = work / "in-tree-socket.rdep"
    let outFile = work / "in-tree-socket.out"
    const marker = "IN_TREE_SOCKET_PAYLOAD"

    let monitored = run(snoopBin, @["run", "--depfile", depfile, "--",
      root, work / "m.sock", consumer, outFile, marker, "-", ""],
      monitorEnv(shimLib))
    checkpoint(monitored.output)
    check monitored.code == 0
    # The bytes really crossed the channel and became a build output.
    check marker in readFile(outFile)

    let dep = readMonitorDepFile(depfile)

    # PRIMARY: the milestone's required assertion. Measured as 1 / mcIncomplete on
    # the pre-IM-4 tree.
    check externalLosses(dep).len == 0
    check dep.completeness == mcComplete

    # The socket was genuinely consumed as an opaque content channel — otherwise
    # the assertion above would be vacuous.
    let consumed = opaqueReads(dep)
    check consumed.len >= 1

    # …and NOT via IM-3's pairing: no create exists for the consumed key, so the
    # only thing that can have suppressed the downgrade is tree membership.
    let created = localFdCreateKeys(dep)
    let started = monitoredStartPids(dep.records)
    var attributedInTree = 0
    for r in consumed:
      check r.path notin created
      if r.childOsPid != 0 and r.childOsPid in started:
        inc attributedInTree
        # The detail carries the same pid, so `io-mon inspect` shows the reason.
        check ("peer=" & $r.childOsPid) in r.detail
    check attributedInTree >= 1

  test "genuinely_external_socket_still_downgrades":
    # One monitored run, two channels of the SAME uninterposed class: one produced
    # out of the tree, one inside it. EXACTLY ONE must downgrade.
    #
    # The count is load-bearing in both directions. Without the IM-4 membership
    # guard the in-tree channel is unpaired too and the count is 2 (measured on the
    # pre-change tree); with the downgrade removed wholesale it is 0.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()
    let root = buildC(work, "tree_socket_root", treeProducerSrc)
    let consumer = buildC(work, "inherited_fd_consumer", inheritedFdConsumerSrc)
    let launcher = buildC(work, "external_socket_launcher",
      externalSocketLauncherSrc)
    let depfile = work / "external-socket.rdep"
    let outFile = work / "external-socket-intree.out"
    let extOut = work / "external-socket-external.out"
    const
      marker = "IN_TREE_SOCKET_PAYLOAD"
      extMarker = "OUT_OF_TREE_SOCKET_SECRET"

    let cap = run(launcher, @[snoopBin, depfile, root, work / "x.sock",
      consumer, outFile, marker, extOut, extMarker], monitorEnv(shimLib))
    checkpoint(cap.output)
    check cap.code == 0
    # Both channels really delivered content into build outputs.
    check extMarker in readFile(extOut)
    check marker in readFile(outFile)

    let dep = readMonitorDepFile(depfile)

    # PRIMARY: the out-of-tree channel downgrades, and only it.
    check externalLosses(dep).len == 1
    check dep.completeness == mcIncomplete

    # Both channels were really consumed (otherwise "exactly one loss" would be
    # satisfiable by observing only one of them).
    let consumed = opaqueReads(dep)
    check consumed.len >= 2

    # Neither is paired — this whole class has no create hook — so the ONLY thing
    # separating them is who produced them.
    let created = localFdCreateKeys(dep)
    let started = monitoredStartPids(dep.records)
    for r in consumed:
      check r.path notin created
    check consumed.anyIt(it.childOsPid != 0 and it.childOsPid in started)
    check consumed.anyIt(it.childOsPid == 0 or it.childOsPid notin started)
