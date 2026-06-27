## test_io_mon_macos_xpc_mach_breakaway — ROUND-2 phase R-C: close the
## XPC / Mach-port breakaway false negative (round-2 break R2), the CRITICAL
## escape that DEFEATS the connect(2) breakaway fail-safe. See
## reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org §R-C.
##
## # The escape (research/adversarial-2026-06-round2/r2_xpc/)
##
## XPC and raw Mach RPC NEVER issue connect(2): a client resolves a service name
## to a Mach send port via `bootstrap_look_up` (raw Mach) or
## `xpc_connection_create_mach_service` (XPC) + `mach_msg` to launchd's bootstrap
## port. A monitored client (mach_client.c / xpc_client.c, run UNDER the shim)
## delegates a file read to an OUT-OF-TREE service (mach_server.c, started OUTSIDE
## the invocation) that opens+reads the marker on the client's behalf and returns
## the bytes. Before R-C io-mon saw NO `mrIpcConnect` (the connect hook is blind
## to Mach), NO spawn, NO event-loss — so it stamped the depfile `mcComplete`: a
## PROVEN false cache hit (two different server-side inputs → byte-identical
## "complete" depfiles).
##
## R-C hooks the connection-establishment boundary: `bootstrap_look_up` (raw-Mach
## clients) and `xpc_connection_create_mach_service` (the XPC client entry). A
## resolution of a NON-`com.apple.*` service records an `mrIpcConnect` with an
## UNKNOWN (launchd-brokered) peer pid; at merge time an unknown/out-of-tree peer
## is an event-loss ⇒ `mcIncomplete` (a conservative re-run), reusing the EXACT
## T3a merge machinery (`writer.unmonitoredSubtreeLossCount` case (c)).
##
## This suite proves, on the REAL shim:
##   1. REGRESSION (raw Mach, end-to-end): the r2_xpc escape now yields
##      `mcIncomplete` (was `mcComplete`) with a mach-service `mrIpcConnect`
##      record. Best-effort: honestly skips if this host/CI forbids raw Mach
##      bootstrap registration (no launchd bootstrap access).
##   2. XPC (create-entry, environment-independent): a connection to a non-system
##      mach service downgrades to `mcIncomplete` even when the service is not
##      running — the create entry is recorded at create time. This exercises the
##      XPC client path, which does NOT funnel through the interposed
##      `bootstrap_look_up` (modern libxpc resolves internally).
##   3. CARDINAL SIN (the critical no-false-downgrade guard): a trivial
##      file-reading program with NO XPC/Mach IPC, and a program that does ONLY
##      `com.apple.*` system-service traffic (the pervasive lookups every build —
##      and the shim's own startup — perform), BOTH stay `mcComplete`. A shim that
##      self-downgraded every capture would be catastrophic; this locks that out.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir()
  corpus = repoRoot / "research" / "adversarial-2026-06-round2" / "r2_xpc"
  testRunId = "io-mon-xpc-test-run"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(src, bin: string; extra: seq[string] = @[]) =
    ## Compile a C probe for arm64. `extra` carries per-probe flags (e.g. the
    ## corpus include dir for the shared mach_msg.h, or -fblocks for xpc_client).
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " &
      extra.mapIt(quoteShell(it)).join(" ") & " " &
      quoteShell(src) & " -o " & quoteShell(bin))
    doAssert code == 0, "cc failed (" & src & "): " & output

  proc writeProbe(path, body: string) =
    writeFile(path, body)

  proc shimEnv(shim, fragmentDir: string): StringTableRef =
    result = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): result[k] = v
    result.del("CT_SANDBOX_TOOLS_DIR")
    result["DYLD_INSERT_LIBRARIES"] = shim
    result["REPRO_MONITOR_SHIM_LIB"] = shim
    result["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    result["REPRO_MONITOR_SESSION"] = testRunId
    applyMacosBackendToggle(result, "both")

  proc runUnderShim(shim, prog: string; args: seq[string];
      fragmentDir: string): tuple[output: string, code: int] =
    ## Run `prog args` under the shim; return its stdout+stderr and exit code.
    ## The caller asserts on the code (some probes intentionally fail, e.g. an
    ## XPC send to a service that is not running — the create is still recorded).
    let env = shimEnv(shim, fragmentDir)
    let p = startProcess(prog, args = args, env = env,
      options = {poStdErrToStdOut})
    let outText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    (outText, code)

  proc machServiceRecords(dep: MonitorDepFile): seq[MonitorRecord] =
    ## The mach-service `mrIpcConnect` records R-C emits (distinguished from the
    ## T3a socket connect records by the "mach-service" detail tag).
    for r in dep.records:
      if r.kind == mrIpcConnect and "mach-service" in r.detail:
        result.add r

suite "io-mon macOS XPC / Mach-port breakaway (R-C, round-2 break R2)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-xpc-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # --- CARDINAL SIN (the critical no-false-downgrade guard) ---------------
    # These run FIRST and are environment-INDEPENDENT: they must hold on every
    # host. A shim whose own startup bootstrap_look_up calls (or libsystem's
    # pervasive com.apple.* lookups) self-downgraded a capture would be
    # catastrophic — every build would falsely re-run.

    test "CARDINAL SIN: trivial program with NO IPC stays mcComplete":
      let trivial = work / "trivial"
      let trivialSrc = work / "trivial.c"
      writeProbe(trivialSrc, """
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  FILE *f = fopen(argv[1], "r");
  if (!f) return 1;
  char b[256];
  size_t n = fread(b, 1, sizeof b, f);
  fclose(f);
  printf("read %zu bytes\n", n);
  return 0;
}
""")
      cc(trivialSrc, trivial)
      let input = work / "trivial-in.txt"
      writeFile(input, "trivial-marker\n")
      let frag = work / "trivialFrag"
      createDir(frag)
      let (outT, codeT) = runUnderShim(shim, trivial, @[input], frag)
      check codeT == 0
      checkpoint("trivial: " & outT)
      let dep = mergeFragments(frag, work / "trivial.rdep")
      # No Mach/XPC service was touched, so no mach-service record exists…
      check machServiceRecords(dep).len == 0
      # …and the build stays complete — the shim's OWN startup bootstrap calls
      # (com.apple.* baseline) must NOT self-downgrade. This is the keystone.
      check dep.completeness == mcComplete

    test "CARDINAL SIN: only com.apple.* service traffic stays mcComplete":
      # A program that does ONLY system-service traffic — an XPC connection to a
      # com.apple.* mach service and a com.apple.* bootstrap_look_up — the kind of
      # lookups a normal compile/link/make performs pervasively. The com.apple.*
      # baseline filter (the bootstrap analog of the /usr/lib + /System
      # library-load filter) must keep this mcComplete.
      let apple = work / "apple"
      let appleSrc = work / "apple.c"
      writeProbe(appleSrc, """
#include <xpc/xpc.h>
#include <servers/bootstrap.h>
#include <stdio.h>
int main(void) {
  xpc_connection_t c =
    xpc_connection_create_mach_service("com.apple.cfprefsd.daemon", NULL, 0);
  xpc_connection_set_event_handler(c, ^(xpc_object_t e){ (void)e; });
  xpc_connection_resume(c);
  mach_port_t sp = 0;
  (void)bootstrap_look_up(bootstrap_port,
                          "com.apple.system.notification_center", &sp);
  printf("did apple lookups\n");
  return 0;
}
""")
      cc(appleSrc, apple, @["-fblocks"])
      let frag = work / "appleFrag"
      createDir(frag)
      let (outA, codeA) = runUnderShim(shim, apple, @[], frag)
      check codeA == 0
      checkpoint("apple: " & outA)
      let dep = mergeFragments(frag, work / "apple.rdep")
      # com.apple.* lookups are the system baseline — NEVER recorded…
      check machServiceRecords(dep).len == 0
      # …so a build doing only system-service traffic stays complete.
      check dep.completeness == mcComplete

    # --- XPC (create-entry, environment-independent) ------------------------

    test "XPC: non-system mach-service connection downgrades to mcIncomplete":
      # xpc_connection_create_mach_service to a NON-system service. The service is
      # not launchd-registered here (launchd service load is unavailable in a
      # non-GUI/CI session), so the send fails — but the R-C hook records the
      # connection at CREATE time, so the gap is closed regardless of whether the
      # round-trip completes. This exercises the XPC client path, which does NOT
      # funnel through the interposed bootstrap_look_up.
      let xpcClient = work / "xpc_client"
      cc(corpus / "xpc_client.c", xpcClient, @["-fblocks"])
      let frag = work / "xpcFrag"
      createDir(frag)
      let marker = work / "xpc-secret.txt"
      writeFile(marker, "xpc-marker\n")
      # The probe may exit non-zero (the service is not running) — that is fine;
      # the create-entry record is what matters.
      let (outX, _) = runUnderShim(shim, xpcClient, @[marker], frag)
      checkpoint("xpc_client: " & outX)
      let dep = mergeFragments(frag, work / "xpc.rdep")
      let recs = machServiceRecords(dep)
      # The XPC client entry to the non-system service was recorded…
      check recs.len >= 1
      var sawService = false
      for r in recs:
        if "com.example.r2xpc" in r.path:
          sawService = true
      check sawService
      # …and it downgrades completeness — the XPC breakaway gap is closed.
      check dep.completeness == mcIncomplete

    # --- REGRESSION (raw Mach, end-to-end) ----------------------------------

    test "REGRESSION: raw-Mach r2_xpc escape now downgrades to mcIncomplete":
      # Faithful end-to-end reproduction of the confirmed break: an out-of-tree
      # mach_server (started OUTSIDE the shim) reads the marker on the monitored
      # mach_client's behalf over raw Mach RPC (bootstrap_look_up + mach_msg).
      # Best-effort: if this host/CI forbids raw Mach bootstrap registration, the
      # server never becomes ready and we skip honestly (the create-entry XPC test
      # above is the environment-independent proof that the gap is closed).
      let server = work / "mach_server"
      let client = work / "mach_client"
      cc(corpus / "mach_server.c", server, @["-I", corpus])
      cc(corpus / "mach_client.c", client, @["-I", corpus])

      let svc = "com.example.r2xpc.regress." & $getCurrentProcessId()
      # Start the out-of-tree server (NOT under the shim) and let bootstrap_register
      # settle. The definitive proof of a working raw-Mach environment is the
      # marker round-trip below (the server serving the client the file bytes), so
      # we keep readiness detection simple: give the server time to register, and
      # if it crashed early (no bootstrap access) we skip honestly.
      let srv = startProcess(server, args = @[svc],
        options = {poStdErrToStdOut})
      sleep(1000)                          # let bootstrap_register settle
      let serverAlive = srv.peekExitCode() < 0

      proc stopServer() =
        try: srv.terminate() except CatchableError: discard
        try: discard srv.waitForExit() except CatchableError: discard
        srv.close()

      if not serverAlive:
        checkpoint("mach_server exited early (no raw Mach bootstrap here) — skip")
        stopServer()
        check true
      else:
        let marker = work / "secret-mach.txt"
        let markText = "MACH-FNEG-" & $getCurrentProcessId()
        writeFile(marker, markText & "\n")
        let frag = work / "machFrag"
        createDir(frag)
        let (outM, _) = runUnderShim(shim, client, @[marker, svc], frag)
        checkpoint("mach_client: " & outM)
        stopServer()

        if markText in outM:
          # The breakaway DID happen (the out-of-tree server served the marker)…
          let dep = mergeFragments(frag, work / "mach.rdep")
          let recs = machServiceRecords(dep)
          check recs.len >= 1            # the bootstrap_look_up was recorded
          var sawSvc = false
          for r in recs:
            if svc in r.path: sawSvc = true
          check sawSvc
          # …and the false cache hit is now closed: mcIncomplete (was mcComplete).
          check dep.completeness == mcIncomplete
        else:
          checkpoint("client did not complete the Mach round-trip — skip")
          check true

    removeDir(work)
  else:
    test "XPC/Mach-breakaway detection is macOS-only (no-op on this platform)":
      check true
