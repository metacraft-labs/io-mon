## test_io_mon_inet_connect_attempt — a FAILED AF_INET/AF_INET6 connect is an
## observation (`mrConnectAttempt`), and a made one names its destination.
##
## WHY. A sandbox that DENIES undeclared egress (for example a network
## namespace with no route) leaves every attempt at an
## undeclared destination failing in the kernel. Before this kind existed the
## shims recorded a connect only when it reached a peer, so an action that
## tried to reach the network left no trace at all, and a consumer judging the
## capture had nothing to report. The attempt is recorded as its OWN kind
## because it means the opposite of an `mrIpcConnect` to the completeness
## machinery: it reached nobody, so it must never become an out-of-tree-peer
## loss (a refused localhost probe costing a cache hit is the false re-run each
## backend's connect hook was written to avoid).
##
## What is graded, end to end through the real CLI and the real shim:
##   * a refused AF_INET connect -> one `mrConnectAttempt` naming
##     "127.0.0.1:<port>", no `mrIpcConnect`, and the capture stays COMPLETE;
##   * a refused AF_INET6 connect -> "[::1]:<port>" (skipped where the host has
##     no IPv6 loopback at all);
##   * a made AF_INET connect to a listener outside the tree -> an
##     `mrIpcConnect` whose path is "127.0.0.1:<port>" (the Linux shim used to
##     leave it empty), and the out-of-tree-peer loss names that destination;
##   * a failed AF_UNIX connect -> neither kind (daemon-discovery noise);
##   * a connect whose address pointer the kernel cannot read still fails with
##     EFAULT, and records nothing: the shim must not read an address the
##     kernel rejected as unreadable (it would crash the program);
##   * which failures count as an attempt at all (`connectFailureReadAddress`);
##   * a BLOCKING AF_INET connect interrupted by a caught signal (EINTR) -> an
##     `mrIpcConnect`, as an in-flight non-blocking one is: POSIX leaves the
##     connection to be established asynchronously, so it may reach its peer,
##     and recording nothing for it made an undeclared connection invisible to
##     any handler installed without SA_RESTART.
##
## NO MOCKS: a freshly compiled CLI, the production `LD_PRELOAD` / `DYLD` shim
## built from this checkout, a compiled C client doing real connect(2) calls
## against real sockets owned by this test process. POSIX (Linux + macOS); the
## Windows shim's arm is `tests/windows/test_io_mon_windows_ipc_connect.nim`.

import std/[net, os, osproc, sequtils, streams, strtabs, strutils, unittest]
from std/posix import ECONNREFUSED, ENETUNREACH, EHOSTUNREACH, ETIMEDOUT,
  EACCES, EPERM, EADDRNOTAVAIL, EFAULT, EINVAL, EBADF, ENOTSOCK

import io_mon
import io_mon/posix_connect
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

  ClientC = """
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>
static void on_alarm(int sig) { (void)sig; }
/* client eintr <address> <port> <fdfile>: blocking AF_INET connects to a
   listener that never accepts, each under a 300 ms one-shot SIGALRM whose
   handler is installed WITHOUT SA_RESTART. The early ones fill the backlog and
   are made (their sockets stay open, so every fd is distinct); once it is full
   the kernel drops the SYN, the next connect blocks, and the alarm interrupts
   it with EINTR. Writes that connect's fd to <fdfile>; exit 0 on EINTR, 3 when
   no connect was interrupted, 4 on another failure, 2 on a setup error. */
static int eintr_mode(const char *addr, int port, const char *fdfile) {
  struct sigaction sa; memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_alarm;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;                       /* no SA_RESTART: connect returns EINTR */
  if (sigaction(SIGALRM, &sa, NULL) != 0) return 2;
  struct sockaddr_in a; memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons((unsigned short)port);
  if (inet_pton(AF_INET, addr, &a.sin_addr) != 1) return 2;
  for (int i = 0; i < 64; i++) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    struct itimerval arm; memset(&arm, 0, sizeof arm);
    arm.it_value.tv_usec = 300000;
    struct itimerval off; memset(&off, 0, sizeof off);
    setitimer(ITIMER_REAL, &arm, NULL);
    int rc = connect(fd, (struct sockaddr *)&a, sizeof a);
    int e = errno;
    setitimer(ITIMER_REAL, &off, NULL);
    if (rc == 0) continue;               /* made: keep it open, fill the queue */
    if (e != EINTR) return 4;
    FILE *f = fopen(fdfile, "w");
    if (f == NULL) return 2;
    fprintf(f, "%d", fd);
    fclose(f);
    return 0;
  }
  return 3;
}
/* client <inet|inet6|unix> <address> <port>: one blocking connect(2); exit 0
   when it was made, 10 + (errno % 100) when it failed, 2 on a setup error. */
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  int fd, rc;
  if (strcmp(argv[1], "badaddr") == 0) {
    /* An address pointer the kernel cannot read: exit 0 only when connect
       fails with EFAULT, as it does unmonitored. */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    rc = connect(fd, (struct sockaddr *)8, sizeof(struct sockaddr_in));
    int e = errno;
    close(fd);
    return rc == -1 && e == EFAULT ? 0 : 10 + (e % 100);
  }
  if (strcmp(argv[1], "eintr") == 0) {
    if (argc < 5) return 2;
    return eintr_mode(argv[2], atoi(argv[3]), argv[4]);
  }
  if (strcmp(argv[1], "unix") == 0) {
    struct sockaddr_un a; memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, argv[2], sizeof(a.sun_path) - 1);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    rc = connect(fd, (struct sockaddr *)&a, sizeof a);
  } else if (strcmp(argv[1], "inet6") == 0) {
    struct sockaddr_in6 a; memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_port = htons((unsigned short)atoi(argv[3]));
    if (inet_pton(AF_INET6, argv[2], &a.sin6_addr) != 1) return 2;
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    rc = connect(fd, (struct sockaddr *)&a, sizeof a);
  } else {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)atoi(argv[3]));
    if (inet_pton(AF_INET, argv[2], &a.sin_addr) != 1) return 2;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    rc = connect(fd, (struct sockaddr *)&a, sizeof a);
  }
  int e = errno;
  close(fd);
  return rc == 0 ? 0 : 10 + (e % 100);
}
"""

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc closedPort(domain: Domain; address: string): int =
  ## A loopback port nothing listens on: bind an ephemeral one, read its
  ## number, close it. The kernel refuses a connect to it (ECONNREFUSED).
  let s = newSocket(domain, SOCK_STREAM, IPPROTO_TCP)
  s.bindAddr(Port(0), address)
  result = int(s.getLocalAddr()[1])
  s.close()

suite "io-mon: a failed AF_INET connect is an observation":
  let work = getTempDir() / ("io-mon-connect-attempt-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let snoopBin = work / "io-mon"
  let cli = run("nim", @["c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--nimcache:" & (work / "nimcache"), "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0
  let shimLib =
    when defined(macosx): buildPrivateMacosShim(repoRoot)
    else: buildPrivateLinuxShim(repoRoot)
  let client = work / "client"
  writeFile(work / "client.c", ClientC)
  let cc = run(getEnv("CC", "cc"), @[work / "client.c", "-o", client])
  checkpoint(cc.output)
  require cc.code == 0

  proc capture(tag: string; args: seq[string]):
      tuple[dep: MonitorDepFile; code: int] =
    let depfile = work / (tag & ".iomon")
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let r = run(snoopBin, @["run", "--depfile", depfile, "--", client] & args,
      env)
    checkpoint(tag & ": " & r.output)
    (readMonitorDepFile(depfile), r.code)

  test "a refused AF_INET connect is one attempt naming its destination, and the capture stays complete":
    let port = closedPort(AF_INET, "127.0.0.1")
    let (dep, code) = capture("refused4", @["inet", "127.0.0.1", $port])
    check code != 0                      # the connect really failed
    let attempts = dep.records.filterIt(it.kind == mrConnectAttempt)
    check attempts.len == 1
    if attempts.len == 1:
      check attempts[0].path == "127.0.0.1:" & $port
      check attempts[0].observationKind == moConnectAttempt
      check attempts[0].detail.startsWith("connect-attempt af_inet errno=")
      check attempts[0].result < 0
      check attempts[0].osPid != 0
    check dep.records.allIt(it.kind != mrIpcConnect)
    # It reached nobody: no out-of-tree-peer loss, no downgrade.
    check unmonitoredSubtreeLossDetails(dep.records).len == 0
    check dep.completeness == mcComplete

  test "a refused AF_INET6 connect names [v6]:port":
    var port = 0
    try:
      port = closedPort(AF_INET6, "::1")
    except OSError:
      skip()                             # no IPv6 loopback on this host
    if port != 0:
      let (dep, code) = capture("refused6", @["inet6", "::1", $port])
      check code != 0
      let attempts = dep.records.filterIt(it.kind == mrConnectAttempt)
      check attempts.len == 1
      if attempts.len == 1:
        check attempts[0].path == "[::1]:" & $port
      check dep.completeness == mcComplete

  test "a made AF_INET connect names its destination and its out-of-tree peer is a loss":
    let server = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    server.setSockOpt(OptReuseAddr, true)
    server.bindAddr(Port(0), "127.0.0.1")
    server.listen()
    defer: server.close()
    let port = int(server.getLocalAddr()[1])
    let (dep, code) = capture("made4", @["inet", "127.0.0.1", $port])
    check code == 0
    let connects = dep.records.filterIt(it.kind == mrIpcConnect)
    check connects.len == 1
    if connects.len == 1:
      check connects[0].path == "127.0.0.1:" & $port
      check connects[0].detail.startsWith("connect af_inet")
    check dep.records.allIt(it.kind != mrConnectAttempt)
    # The listener is this test process, outside the tree: one loss, keyed on
    # the destination.
    check dep.completeness != mcComplete
    check unmonitoredSubtreeLossDetails(dep.records).anyIt(
      it.endsWith(" path=127.0.0.1:" & $port))

  test "a failed AF_UNIX connect records neither kind":
    let missing = work / "no-such.sock"
    let (dep, code) = capture("unix", @["unix", missing, "0"])
    check code != 0
    check dep.records.allIt(it.kind notin {mrConnectAttempt, mrIpcConnect})
    check dep.completeness == mcComplete

  test "a blocking AF_INET connect interrupted by a signal (EINTR) is a connection, not nothing":
    # A listener that never accepts, with the smallest backlog: once the
    # client has filled it the kernel drops further SYNs, so the next
    # blocking connect waits until the client's alarm interrupts it.
    let server = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    server.setSockOpt(OptReuseAddr, true)
    server.bindAddr(Port(0), "127.0.0.1")
    server.listen(1)
    defer: server.close()
    let port = int(server.getLocalAddr()[1])
    let fdFile = work / "eintr.fd"
    removeFile(fdFile)
    let (dep, code) = capture("eintr4",
      @["eintr", "127.0.0.1", $port, fdFile])
    require code == 0                    # a connect really returned EINTR
    let eintrFd = parseInt(readFile(fdFile).strip())
    let dest = "127.0.0.1:" & $port
    # THE PROPERTY: the interrupted connect is recorded as a connection to its
    # destination, exactly as an in-flight non-blocking one is, and not as an
    # attempt that reached nobody. The made connects before it are
    # `mrIpcConnect`s too, so it is told from them by `result`: the Linux shim
    # stores the socket's fd there, the macOS shim the call's return value
    # (-1 for the interrupted call, 0 for every made one).
    let interruptedResult =
      when defined(linux): int64(eintrFd)
      else: -1'i64
    let interrupted = dep.records.filterIt(it.kind == mrIpcConnect and
      it.result == interruptedResult)
    check interrupted.len == 1
    if interrupted.len == 1:
      check interrupted[0].path == dest
      check interrupted[0].detail.startsWith("connect af_inet")
    check dep.records.allIt(it.kind != mrConnectAttempt)
    # The peer may be reached and is outside the tree, so the capture is not
    # complete: an interrupted connect fails closed, like every other one.
    check dep.completeness != mcComplete
    check unmonitoredSubtreeLossDetails(dep.records).anyIt(
      it.endsWith(" path=" & dest))

  test "a connect through an unreadable address still fails with EFAULT and records nothing":
    let (dep, code) = capture("badaddr", @["badaddr", "0", "0"])
    check code == 0                      # EFAULT, and no crash (139 / 138)
    check dep.records.allIt(it.kind notin {mrConnectAttempt, mrIpcConnect})
    check dep.completeness == mcComplete

  test "only a failure the protocol returned is an attempt":
    for err in [ECONNREFUSED, ENETUNREACH, EHOSTUNREACH, ETIMEDOUT, EACCES,
                EPERM, EADDRNOTAVAIL]:
      check connectFailureReadAddress(err)
    for err in [EFAULT, EINVAL, EBADF, ENOTSOCK]:
      check not connectFailureReadAddress(err)

  removeDir(work)
