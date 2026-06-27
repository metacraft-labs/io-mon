## test_io_mon_macos_ipc_breakaway — T3a: close the DAEMON-OVER-SOCKET /
## out-of-tree breakaway escape (findings-doc break #1), the CRITICAL break that
## DEFEATS the subtree fail-safe. See
## reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org §T3a.
##
## # The escape (research/adversarial-2026-06/adv_proctree/)
##
## A persistent daemon (daemon.c) is started OUTSIDE the monitored invocation; a
## monitored client (client.c, run UNDER the shim) sends it a path over an
## AF_UNIX socket; the DAEMON opens+reads the file and returns the bytes, which
## the client folds into its output (a real data dependency). Before T3a io-mon
## recorded the client's socket send/recv as PATH-LESS file-write/file-read but
## NOT the file, saw NO process-start for the daemon (it predates the tree), and
## stamped the depfile `mcComplete` — a PROVEN false cache hit (two different
## daemon-side inputs produced byte-identical "complete" depfiles).
##
## T3a hooks connect(2): a successful connect records an `mrIpcConnect` carrying
## the destination and the PEER PID (AF_UNIX via LOCAL_PEERPID). At merge time a
## peer with NO matching `mrProcessStart` (or an unknown peer) is an out-of-tree
## breakaway ⇒ event-loss ⇒ `mcIncomplete` (a conservative re-run).
##
## This suite proves three things on the REAL shim:
##   1. REGRESSION: the adv_proctree escape now yields `mcIncomplete` (was
##      `mcComplete`), and two different daemon inputs no longer both publish as
##      complete — the false cache hit is closed.
##   2. CARDINAL SIN: a build where a monitored parent talks to a monitored child
##      over a socket STAYS `mcComplete` (no false downgrade on intra-tree IPC).
##   3. TRUSTED DAEMON: a cooperating daemon that reports its reads keeps the
##      build `mcComplete` AND the daemon-read file appears in the depfile.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  corpus = repoRoot / "research" / "adversarial-2026-06" / "adv_proctree"
  # ROUND-2 R8 — a fixed run id shared between the shim env and the cooperating
  # trusted daemon so its run-scoped breakaway report authenticates.
  testRunId = "io-mon-ipc-test-run"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(src, bin: string) =
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(bin))
    doAssert code == 0, "cc failed (" & src & "): " & output

  proc waitForFile(path: string; timeoutMs = 5000): bool =
    ## Poll until `path` exists (a daemon writes its ready file after listen()).
    var waited = 0
    while waited < timeoutMs:
      if fileExists(path):
        return true
      sleep(25)
      waited += 25
    fileExists(path)

  proc shimEnv(shim, fragmentDir: string): StringTableRef =
    ## Environment that runs a child UNDER the shim with direct DYLD injection and
    ## NO sandbox-tools rewrite (mirrors the build engine launching an action).
    result = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): result[k] = v
    result.del("CT_SANDBOX_TOOLS_DIR")
    result["DYLD_INSERT_LIBRARIES"] = shim
    result["REPRO_MONITOR_SHIM_LIB"] = shim
    result["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    # ROUND-2 R8 — give the invocation a run id so the shim stamps `run=` on its
    # records and the trusted-daemon report (run-scoped) authenticates.
    result["REPRO_MONITOR_SESSION"] = testRunId
    applyMacosBackendToggle(result, "both")

  proc runUnderShim(shim, prog: string; args: seq[string];
      fragmentDir: string; extraEnv: seq[(string, string)] = @[]): string =
    ## Run `prog args` under the shim; return its merged-into-nothing stdout. The
    ## caller merges `fragmentDir` itself (so it can pass a report dir).
    let env = shimEnv(shim, fragmentDir)
    for (k, v) in extraEnv: env[k] = v
    let p = startProcess(prog, args = args, env = env,
      options = {poStdErrToStdOut})
    let outText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    doAssert code == 0, "child should exit 0 (out=" & outText & ")"
    outText

suite "io-mon macOS IPC / daemon-over-socket breakaway (T3a, break #1)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-ipc-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    let daemonBin = work / "daemon"
    let clientBin = work / "client"
    let pairBin = work / "ipc_pair"
    let trustedBin = work / "trusted_daemon"
    cc(corpus / "daemon.c", daemonBin)
    cc(corpus / "client.c", clientBin)
    cc(corpus / "ipc_pair.c", pairBin)
    cc(corpus / "trusted_daemon.c", trustedBin)

    proc startPlainDaemon(sock, ready: string): Process =
      ## Start daemon.c OUTSIDE the shim (the test process carries no DYLD inject).
      ## daemon.c writes its readiness to the fixed /tmp/adv_proctree/daemon.ready.
      createDir("/tmp/adv_proctree")
      removeFile(ready)
      result = startProcess(daemonBin, args = @[sock],
        options = {poStdErrToStdOut})
      doAssert waitForFile(ready), "daemon did not become ready"

    proc quitDaemon(sock: string; daemon: Process) =
      ## Graceful shutdown: a __QUIT__ request is processed only AFTER the daemon
      ## has finished (and reported) the preceding connection — so by the time the
      ## daemon exits, any breakaway report is flushed to disk.
      discard execCmdEx(quoteShell(clientBin) & " " & quoteShell(sock) &
        " __QUIT__")
      discard daemon.waitForExit()
      daemon.close()

    test "REGRESSION: adv_proctree escape now downgrades to mcIncomplete":
      let ready = "/tmp/adv_proctree/daemon.ready"
      let sock = work / "regress.sock"
      let inputA = work / "inputA.txt"
      writeFile(inputA, "secret-input-A-distinct-bytes\n")
      let daemon = startPlainDaemon(sock, ready)
      let fragA = work / "fragA"
      createDir(fragA)
      let outA = runUnderShim(shim, clientBin, @[sock, inputA], fragA)
      checkpoint("client A: " & outA)
      quitDaemon(sock, daemon)

      let depA = mergeFragments(fragA, work / "A.rdep")
      # An mrIpcConnect to the out-of-tree daemon was captured (peer pid known)…
      var sawConnect = false
      for r in depA.records:
        if r.kind == mrIpcConnect:
          sawConnect = true
      check sawConnect
      # …and it downgrades completeness — the false cache hit is closed.
      check depA.completeness == mcIncomplete

    test "false-cache-hit demo closed: two different daemon inputs both re-run":
      let ready = "/tmp/adv_proctree/daemon.ready"
      let inputA = work / "inA.txt"
      let inputB = work / "inB.txt"
      writeFile(inputA, "AAAA-distinct\n")
      writeFile(inputB, "BBBB-totally-different-and-longer\n")

      proc captureFor(input, sock, frag: string): MonitorCompleteness =
        let daemon = startPlainDaemon(sock, ready)
        createDir(frag)
        discard runUnderShim(shim, clientBin, @[sock, input], frag)
        quitDaemon(sock, daemon)
        mergeFragments(frag, frag / "out.rdep").completeness

      let cA = captureFor(inputA, work / "demoA.sock", work / "demoFragA")
      let cB = captureFor(inputB, work / "demoB.sock", work / "demoFragB")
      # Before T3a both were mcComplete with byte-identical depfiles (a false
      # cache hit). Now at least one is mcIncomplete ⇒ a re-run, so a stale cache
      # entry can never be served. (Both are in fact mcIncomplete.)
      check cA == mcIncomplete
      check cB == mcIncomplete

    test "CARDINAL SIN: intra-tree socket IPC stays mcComplete (no false re-run)":
      # A monitored parent posix_spawns a monitored child; the child connects back
      # over an AF_UNIX socket. Both load the shim and emit process-start, so the
      # connect's peer pid (the parent) IS in the injected set ⇒ NO downgrade.
      let sock = work / "pair.sock"
      let frag = work / "pairFrag"
      createDir(frag)
      let outP = runUnderShim(shim, pairBin, @[sock], frag)
      checkpoint("ipc_pair: " & outP)
      let dep = mergeFragments(frag, work / "pair.rdep")
      # The intra-tree connect was recorded…
      var sawConnect = false
      for r in dep.records:
        if r.kind == mrIpcConnect:
          sawConnect = true
      check sawConnect
      # …but it must NOT downgrade — the whole point of the peer-set guard.
      check dep.completeness == mcComplete

    test "TRUSTED DAEMON: reported reads keep mcComplete + add the dependency":
      let sock = work / "trusted.sock"
      let ready = work / "trusted.ready"
      let reportDir = work / "reports"
      createDir(reportDir)
      let served = work / "served-header.h"
      writeFile(served, "// served by the trusted daemon\n")
      removeFile(ready)
      let daemon = startProcess(trustedBin, args = @[sock, ready],
        env = (block:
          var e = newStringTable(modeCaseSensitive)
          for k, v in envPairs(): e[k] = v
          e["IO_MON_BREAKAWAY_REPORT_DIR"] = reportDir
          # ROUND-2 R8 — the daemon echoes this run id so its report is
          # scoped to (and authenticates against) THIS invocation.
          e["REPRO_MONITOR_SESSION"] = testRunId
          e),
        options = {poStdErrToStdOut})
      doAssert waitForFile(ready), "trusted daemon did not become ready"

      let frag = work / "trustedFrag"
      createDir(frag)
      discard runUnderShim(shim, clientBin, @[sock, served], frag)
      # Graceful quit so the served connection's report is flushed before merge.
      discard execCmdEx(quoteShell(clientBin) & " " & quoteShell(sock) &
        " __QUIT__")
      discard daemon.waitForExit()
      daemon.close()

      # WITHOUT the report dir the out-of-tree daemon would downgrade…
      check mergeFragments(frag, work / "tNo.rdep").completeness == mcIncomplete
      # …but WITH the report folded in, the daemon accounted for its read, so the
      # build stays mcComplete and the served file is a recorded dependency.
      let dep = mergeFragments(frag, work / "tYes.rdep", reportDir)
      check dep.completeness == mcComplete
      var sawServed = false
      for r in dep.records:
        if r.path == served and r.observationKind == moFileRead:
          sawServed = true
      check sawServed

    removeDir(work)
  else:
    test "IPC-breakaway detection is macOS-only (no-op on this platform)":
      check true
