## `mcapIpcConnect` on Windows: a peer must be identifiable, or the capture
## must say it could not be.
##
## The gap M4 declared was specific: the shim had no socket hooks, so a
## named-pipe or socket peer could not be distinguished from an in-tree
## process. That is the shape of failure that DEFEATS the un-monitored-subtree
## fail-safe, because there is no spawn to anchor it on: a build tool talks to
## a persistent daemon started outside the invocation -- an sccache server, a
## language server, a build daemon -- the daemon opens and reads files on its
## behalf, and the capture contains neither those reads nor any evidence that
## they happened. It grades `mcComplete` over a dependency set with a hole in
## it, and the next build gets a cache hit it has not earned.
##
## So the tests here are live, and they are paired. One half proves the record
## flows at all. The other half proves it flows with the RIGHT peer, because a
## record that always says "unknown peer" would downgrade every capture and a
## record that always says "in-tree" would downgrade none -- and either one
## would pass a test that only counted records.
##
## The out-of-tree peer is the TEST PROCESS itself. It is not monitored (only
## the child `runMonitored` spawns is), it is a real process with a real pid,
## and it serves a real pipe -- so it is a faithful stand-in for the breakaway
## daemon without needing one installed on the host.

when not defined(windows):
  {.error: "windows-only test".}

import std/[nativesockets, net, os, strutils, tempfiles, unittest]

import io_mon
import io_mon/fs_snoop
import io_mon/types
import io_mon/writer

import windows_channel_fixture

runChannelFixtureIfRequested()

proc runFixture(dir: string; mode: string; arg = ""): MonitorResult =
  var command = @[getAppFilename(), ChannelFixtureFlag, mode]
  if arg.len > 0:
    command.add arg
  var request = FsSnoopRequest(
    command: command,
    depFilePath: dir / (mode & ".rdep"),
    captureChildStdio: true)
  runMonitored(request)

proc ipcRecords(res: MonitorResult): seq[MonitorRecord] =
  result = @[]
  for r in res.records:
    if r.kind == mrIpcConnect:
      result.add r

proc withTempDir(body: proc(dir: string)) =
  let dir = createTempDir("io_mon_m5_ipc_", "")
  try:
    body(dir)
  finally:
    try: removeDir(dir)
    except CatchableError: discard

suite "Windows ipc-connect: named pipes":

  test "an in-tree named-pipe peer is recorded WITH its pid and does not downgrade":
    ## The cardinal-sin guard. Two monitored processes -- here, one process
    ## serving and opening its own pipe -- are legitimately talking, everything
    ## they read was captured with them, and the capture must stay complete. A
    ## downgrade here would make every build that uses a pipe uncacheable.
    withTempDir(proc(dir: string) =
      let name = r"\\.\pipe\io-mon-m5-intree-" & $getCurrentProcessId()
      let res = runFixture(dir, "inproc-named-pipe", name)
      check res.exitCode == 0          # the channel really was exercised
      let ipc = ipcRecords(res)
      check ipc.len > 0
      var sawSelfPeer = false
      for r in ipc:
        check r.observationKind == moIpcConnect
        check r.path.toLowerAscii.contains("pipe")
        # The peer is the monitored process itself, so the pid must be there:
        # an "unknown peer" here is exactly the over-conservative answer that
        # would turn every in-tree pipe into a false re-run.
        if r.childOsPid != 0'u64 and r.childOsPid == r.osPid:
          sawSelfPeer = true
      check sawSelfPeer
      check res.completeness == mcComplete
      check res.depFile.summary.eventLossCount == 0'u64
      check unmonitoredSubtreeLossCount(res.records) == 0)

  test "an OUT-OF-TREE named-pipe peer downgrades the capture":
    ## The breakaway daemon. The server is this test process, which is not in
    ## the monitored tree, so its pid has no `mrProcessStart` and the merge
    ## must conclude that content could have reached the monitored program
    ## from somewhere the capture never saw.
    withTempDir(proc(dir: string) =
      let name = r"\\.\pipe\io-mon-m5-outtree-" & $getCurrentProcessId()
      let server = namedPipeServer(name)
      check server != cast[H](cast[uint](0'i64 - 1'i64))
      defer: closeH(server)
      let res = runFixture(dir, "pipe-client", name)
      check res.exitCode == 0
      let ipc = ipcRecords(res)
      check ipc.len > 0
      var sawOutOfTreePeer = false
      for r in ipc:
        if r.childOsPid == uint64(getCurrentProcessId()):
          sawOutOfTreePeer = true
      check sawOutOfTreePeer
      # And the consequence, which is the whole point of recording it.
      let details = unmonitoredSubtreeLossDetails(res.records)
      var sawIpcLoss = false
      for d in details:
        if d.startsWith("ipc peer outside monitored tree"):
          sawIpcLoss = true
      check sawIpcLoss
      check res.completeness == mcIncomplete)

  test "a client calling NtCreateFile DIRECTLY on a pipe is still seen":
    ## The NT-layer arm, exercised the only way that isolates it.
    ##
    ## `CreateFileW` lowers to `NtCreateFile`, so every other pipe case in this
    ## file fires the kernel32 arm FIRST and would pass with the NT arm removed
    ## entirely. A client that calls the ntdll export directly -- a CRT or
    ## runtime that bypasses kernel32, or any process whose kernel32 detour did
    ## not land -- reaches only this arm.
    ##
    ## What it pins is the SPELLING the classifier is given. The path the NT
    ## snoop records has had its `\??\` prefix stripped, leaving `pipe\<name>`,
    ## which `isNamedPipePath` must REJECT (it is byte-for-byte an ordinary
    ## relative open into a directory called `pipe`, the false-downgrade case
    ## the suite below covers). So the classification has to run against
    ## `objectAttributesRawName` -- the ObjectName exactly as the caller
    ## supplied it. Pass the stripped path instead and this pipe becomes
    ## invisible: the peer is an out-of-tree process, nothing records it, and
    ## the capture grades `mcComplete` over a channel it never saw. That is the
    ## cardinal sin, and no CreateFileW-based fixture can detect it.
    withTempDir(proc(dir: string) =
      let name = r"\\.\pipe\io-mon-m5-nt-" & $getCurrentProcessId()
      let server = namedPipeServer(name)
      check server != cast[H](cast[uint](0'i64 - 1'i64))
      defer: closeH(server)
      let res = runFixture(dir, "nt-pipe-client", name)
      check res.exitCode == 0          # NtCreateFile really opened the pipe
      let ipc = ipcRecords(res)
      check ipc.len > 0
      var sawOutOfTreePeer = false
      for r in ipc:
        if r.childOsPid == uint64(getCurrentProcessId()):
          sawOutOfTreePeer = true
      check sawOutOfTreePeer
      var sawIpcLoss = false
      for d in unmonitoredSubtreeLossDetails(res.records):
        if d.startsWith("ipc peer outside monitored tree"):
          sawIpcLoss = true
      check sawIpcLoss
      check res.completeness == mcIncomplete)

  test "a FAILED open of a non-existent pipe must not be recorded":
    ## The pipe-arm counterpart of the refused-socket case below, and the rule
    ## `classifyOpenedPath` already states in prose: only SUCCESSFUL opens are
    ## classified. A failed open consumed nothing and reached no peer, so
    ## recording it as a connection to an unknown peer would downgrade the
    ## capture over a connection that never happened. Probing for a pipe that
    ## may or may not be there is how a Windows client discovers a daemon.
    withTempDir(proc(dir: string) =
      let name = r"\\.\pipe\io-mon-m5-absent-" & $getCurrentProcessId()
      let res = runFixture(dir, "pipe-client-missing", name)
      check res.exitCode == 0          # the pipe really was absent
      for r in ipcRecords(res):
        checkpoint("a failed pipe open was recorded as an IPC peer: " &
          r.path & " " & r.detail)
      check ipcRecords(res).len == 0
      check unmonitoredSubtreeLossCount(res.records) == 0
      check res.completeness == mcComplete)

suite "Windows ipc-connect: sockets":

  test "a socket connect to an out-of-tree listener is recorded and downgrades":
    ## Windows offers no in-process way to name a socket peer (there is no
    ## SO_PEERCRED / LOCAL_PEERPID), so the peer is reported as unknown and the
    ## merge treats it conservatively -- the same stance the macOS arm takes
    ## for an AF_INET peer. A conservative re-run is the correct answer here;
    ## silence is not.
    withTempDir(proc(dir: string) =
      let listener = newSocket()
      defer: listener.close()
      listener.bindAddr(Port(0), "127.0.0.1")
      listener.listen()
      let port = int(listener.getLocalAddr()[1])
      let res = runFixture(dir, "socket-connect", $port)
      check res.exitCode == 0
      let ipc = ipcRecords(res)
      var sawSocketPeer = false
      for r in ipc:
        if r.path == "127.0.0.1:" & $port:
          sawSocketPeer = true
          check r.flags == 2'u32           # AF_INET
          check r.childOsPid == 0'u64      # unknown peer, stated as such
      check sawSocketPeer
      check res.completeness == mcIncomplete)

  test "an IN-FLIGHT non-blocking connect IS recorded":
    ## The other side of the same guard, and the reason it is not simply
    ## `rc == 0`.
    ##
    ## A non-blocking `connect` returns SOCKET_ERROR with WSAEWOULDBLOCK (the
    ## Winsock spelling of EINPROGRESS) and then completes asynchronously. The
    ## peer IS reached; the call merely has not finished saying so. Accepting
    ## only `rc == 0` would make every async client's connection invisible, so
    ## a monitored program taking its inputs from an out-of-tree daemon over a
    ## non-blocking socket would grade `mcComplete` -- a false complete, which
    ## is strictly worse than the false re-run the refused case is about. The
    ## macOS arm keeps exactly this case via `EInProgress`.
    withTempDir(proc(dir: string) =
      let listener = newSocket()
      defer: listener.close()
      listener.bindAddr(Port(0), "127.0.0.1")
      listener.listen()
      let port = int(listener.getLocalAddr()[1])
      let res = runFixture(dir, "socket-connect-nonblocking", $port)
      # Non-zero means the connect did NOT land in-flight, so the assertion
      # below would be passing for the `rc == 0` reason instead.
      check res.exitCode == 0
      var sawSocketPeer = false
      for r in ipcRecords(res):
        if r.path == "127.0.0.1:" & $port:
          sawSocketPeer = true
          check r.childOsPid == 0'u64      # unknown peer, stated as such
      check sawSocketPeer
      check res.completeness == mcIncomplete)

  test "a REFUSED socket connect reaches no peer and must not be recorded":
    ## The case the live-listener test above cannot see, and the one a build
    ## host actually runs thousands of times: a probe to a port with nothing
    ## behind it.
    ##
    ## `connect` returning SOCKET_ERROR/WSAECONNREFUSED consumed nothing and
    ## reached nobody. An `mrIpcConnect` for it names an UNKNOWN peer, which the
    ## merge cannot prove is in-tree, so the whole capture grades `mcIncomplete`
    ## and the action loses its cache publication -- a FALSE RE-RUN over a
    ## connection that never happened, which is the failure direction this
    ## machinery exists to prevent. `classifyOpenedPath` states exactly this
    ## rule for the pipe arm ("Only SUCCESSFUL opens are classified"); the
    ## socket arm has to honour it too, and the macOS arm's
    ## `result == 0 or EINPROGRESS` guard is the same rule again.
    ##
    ## Daemon discovery, sccache and language-server probes, and every
    ## "is the server already up?" retry loop end here by design. Each one
    ## costing its action a cache hit is not a rounding error.
    withTempDir(proc(dir: string) =
      # A port that was bound and then released: nothing is listening on it,
      # and the fixture ASSERTS the refusal rather than assuming it.
      var port = 0
      block:
        let probe = newSocket()
        probe.bindAddr(Port(0), "127.0.0.1")
        probe.listen()
        port = int(probe.getLocalAddr()[1])
        probe.close()
      let res = runFixture(dir, "socket-connect-refused", $port)
      check res.exitCode == 0          # the connect really was refused
      for r in ipcRecords(res):
        checkpoint("a refused connect was recorded as an IPC peer: " &
          r.path & " " & r.detail)
      check ipcRecords(res).len == 0
      check unmonitoredSubtreeLossCount(res.records) == 0
      check res.depFile.summary.eventLossCount == 0'u64
      check res.completeness == mcComplete)

suite "Windows ipc-connect: what must NOT be recorded":

  test "an absolute path through a directory called `pipe` is not an IPC peer":
    ## `isNamedPipePath` anchors its match instead of searching for `\pipe\`
    ## anywhere in the path. It has to: an unknown-peer IPC record downgrades
    ## the capture, so a substring match would make every project with a
    ## `src\pipe\` directory permanently uncacheable -- a false re-run caused
    ## by the machinery that exists to prevent false completes.
    withTempDir(proc(dir: string) =
      let decoy = dir / "pipe"
      createDir(decoy)
      let file = decoy / "notapipe.txt"
      writeFile(file, "ordinary bytes")
      let res = runFixture(dir, "map-file", file)
      check res.exitCode == 0
      check ipcRecords(res).len == 0
      check res.completeness == mcComplete)

  test "a RELATIVE path into a `pipe` directory is not an IPC peer":
    ## The absolute case above is caught by the cheap prefix pre-filter before
    ## the classifier is even consulted, so on its own it pins nothing about
    ## the classifier. This is the spelling that reaches it: `pipe\x.txt` is
    ## byte-for-byte the NT object form `pipe\<name>` that
    ## `objectAttributesToString` produces once it has stripped `\??\`, and the
    ## shim records the path as the CALLER spelled it. Accepting the bare form
    ## from the Win32 layer would report an ordinary file open as a connection
    ## to an unknown peer, and downgrade the capture over it.
    withTempDir(proc(dir: string) =
      let decoy = dir / "pipe"
      createDir(decoy)
      writeFile(decoy / "notapipe.txt", "ordinary bytes")
      let previous = getCurrentDir()
      setCurrentDir(dir)          # the child inherits this
      defer: setCurrentDir(previous)
      let res = runFixture(dir, "open-as-spelled", "pipe\\notapipe.txt")
      check res.exitCode == 0
      check ipcRecords(res).len == 0
      check unmonitoredSubtreeLossCount(res.records) == 0
      check res.completeness == mcComplete)

  test "an EXTENDED-LENGTH path through a `pipe` directory is not an IPC peer":
    ## `\\?\C:\...\pipe\x.txt` is the other spelling that gets past a cheap
    ## first-character filter, and it is not exotic -- it is what any tool that
    ## handles long paths emits, io-mon's own `extendedPath` included. It looks
    ## like a UNC path and it contains `\pipe\`, so it is the case that
    ## separates an anchored match from a substring search.
    withTempDir(proc(dir: string) =
      let decoy = dir / "pipe"
      createDir(decoy)
      let file = decoy / "notapipe.txt"
      writeFile(file, "ordinary bytes")
      let res = runFixture(dir, "open-as-spelled", "\\\\?\\" & file)
      check res.exitCode == 0
      check ipcRecords(res).len == 0
      check unmonitoredSubtreeLossCount(res.records) == 0
      check res.completeness == mcComplete)
