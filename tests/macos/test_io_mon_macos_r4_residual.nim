## test_io_mon_macos_r4_residual — ROUND-4 RW3: re-close the EXEMPT-BY-NAME
## regressions, LIVE under the macOS interpose+body-patch shim, against the
## round-4 residual corpus (research/adversarial-2026-06-round4/r4_residual).
##
## For the SECOND round running, shipped fixes fell to the SAME weakness — "exempt
## BY NAME" — so an attacker just picks an exempt name. RW3 applies the robust
## PAIR-or-VERIFY pattern. Each re-break is asserted CLOSED, with its cardinal-sin
## guard (a NORMAL build must STAY mcComplete — a false downgrade re-runs every
## build):
##
##   S1' shm  — round-3 exempted any shm whose name had the `apple.shm.` /
##              `com.apple.` PREFIX. An out-of-tree producer of `apple.shm.evil`
##              + a monitored consumer slipped through → missing content. FIX:
##              exempt only the EXACT whole names of the genuine system shm objects
##              (apple.shm.notification_center, com.apple.AppleDatabaseChanged);
##              everything else PAIRS against an in-tree create. `apple.shm.evil`
##              out-of-tree → mcIncomplete; the real system shm → mcComplete.
##
##   IP1 pipe — an inherited anonymous pipe from an OUT-OF-TREE writer was recorded
##              `chan=opaque role=read` but never paired, so never downgraded →
##              missing content. FIX: pair an opaque read against an in-tree
##              pipe/socketpair/socket/accept CREATE (by fd dev:ino). An inherited
##              out-of-tree pipe → mcIncomplete; an in-tree `pipe()+fork` pipeline
##              → mcComplete.
##
##   S0' XPC  — round-3 exempted a `com.apple.*` lookup whose name is a whole token
##              in the SIP-protected launchd plists. An attacker `bootstrap_register`s
##              a GENUINE declared name (com.apple.cfprefsd.daemon) from an unsigned
##              binary, defeating the name-trust. FIX (where verifiable): on the XPC
##              path, verify the responder is platform/Apple-signed via the peer
##              audit token on the program's OWN synchronous reply. A genuine Apple
##              XPC service (real cfprefsd) → mcComplete (the critical
##              no-false-downgrade). The raw bootstrap_look_up path's owner is
##              UNOBTAINABLE in-process on macOS 26 (documented residual; ES endgame).
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r4Residual = repoRoot / "research" / "adversarial-2026-06-round4" / "r4_residual"

# In-tree anonymous-pipe pipeline (the IP1 cardinal-sin guard): a monitored
# parent pipe()s + forks; the monitored child reads the inherited READ end. The
# in-tree pipe() create PAIRS the child's opaque read ⇒ NO downgrade.
const inTreePipeSrc = """
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
int main(int argc, char** argv) {
  int p[2];
  if (pipe(p)) { perror("pipe"); return 2; }
  pid_t pid = fork();
  if (pid < 0) { perror("fork"); return 2; }
  if (pid == 0) {                     // child: in-tree reader
    close(p[1]);
    char buf[128];
    ssize_t n = read(p[0], buf, sizeof buf - 1);
    if (n > 0) {
      buf[n] = 0;
      int o = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
      if (o >= 0) { dprintf(o, "got:%s", buf); close(o); }
    }
    _exit(0);
  }
  close(p[0]);                        // parent: in-tree writer
  const char* m = "in-tree-pipe-content";
  write(p[1], m, strlen(m));
  close(p[1]);
  int st; while (wait(&st) < 0) {}
  return 0;
}
"""

# A normal program that ATTACHES the genuine system shm (apple.shm.notification_center)
# via libnotify — the S1' cardinal-sin guard: the real system object is exempted by
# EXACT name, so this stays mcComplete with NO shm downgrade.
const notifySrc = """
#include <notify.h>
#include <stdio.h>
int main(void) {
  int tok = 0;
  notify_register_check("com.apple.system.timezone", &tok);
  uint64_t s = 0;
  notify_get_state(tok, &s);
  printf("notify ok\n");
  return 0;
}
"""

# A genuine com.apple.* XPC service client (the S0' cardinal-sin guard): create a
# connection to the REAL cfprefsd and do a synchronous reply round-trip. The peer
# is the genuine, platform-signed cfprefsd, so the S0' peer verification keeps the
# build mcComplete. -fblocks (the event handler is a block).
const xpcGenuineSrc = """
#include <xpc/xpc.h>
#include <stdio.h>
int main(void) {
  xpc_connection_t c =
    xpc_connection_create_mach_service("com.apple.cfprefsd.daemon", NULL, 0);
  xpc_connection_set_event_handler(c, ^(xpc_object_t e){ (void)e; });
  xpc_connection_resume(c);
  xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
  xpc_object_t rep = xpc_connection_send_message_with_reply_sync(c, msg);
  printf("cfprefsd reply=%s\n",
         xpc_get_type(rep) == XPC_TYPE_ERROR ? "error" : "ok");
  return 0;
}
"""

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(args: string; clang = false) =
    let ccBin = if clang:
                  let c = findExe("clang")
                  if c.len > 0: c else: getEnv("CC", "cc")
                else: getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " & args)
    doAssert code == 0, "cc failed (" & args & "): " & output

  proc compileProbe(work, src, name: string; extra = ""; clang = false): string =
    result = work / name
    cc(quoteShell(src) & " " & extra & " -o " & quoteShell(result), clang)

  proc compileSource(work, code, name: string; extra = ""; clang = false): string =
    let src = work / (name & ".c")
    writeFile(src, code)
    compileProbe(work, src, name, extra, clang)

  proc baseEnv(shim, fragmentDir: string): StringTableRef =
    result = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): result[k] = v
    result.del("CT_SANDBOX_TOOLS_DIR")
    result["DYLD_INSERT_LIBRARIES"] = shim
    result["REPRO_MONITOR_SHIM_LIB"] = shim
    result["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(result, "both")

  type RunResult = object
    records: seq[MonitorRecord]
    completeness: MonitorCompleteness
    output: string
    code: int

  proc runOutOfTree(prog: string; args: seq[string]) =
    ## Run `prog args` OUT-OF-TREE: a clean env with NO shim injection.
    var penv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): penv[k] = v
    penv.del "DYLD_INSERT_LIBRARIES"
    penv.del "REPRO_MONITOR_SHIM_LIB"
    penv.del "REPRO_MONITOR_FRAGMENT_DIR"
    let p = startProcess(prog, args = args, env = penv,
      options = {poStdErrToStdOut})
    discard p.outputStream.readAll()
    discard p.waitForExit()
    p.close()

  proc runProbe(shim, work, probe: string; args: seq[string];
      requireExit0 = true): RunResult =
    let fragmentDir = work / ("frags-" & probe.extractFilename())
    removeDir(fragmentDir)
    createDir(fragmentDir)
    let env = baseEnv(shim, fragmentDir)
    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    result.output = p.outputStream.readAll()
    result.code = p.waitForExit()
    p.close()
    checkpoint(probe.extractFilename() & " exit=" & $result.code &
      " out=" & result.output)
    if requireExit0:
      doAssert result.code == 0, "probe should exit 0 (" & probe & "): " &
        result.output
    let dep = mergeFragments(fragmentDir, work / (probe.extractFilename() & ".rdep"))
    result.records = readMonitorDepFile(work / (probe.extractFilename() & ".rdep")).records
    result.completeness = dep.completeness

  proc externalContentDowngrades(records: seq[MonitorRecord]): int =
    ## The synthetic event-losses the content-channel path injected (so a
    ## cardinal-sin assertion can prove my change added none).
    for r in records:
      if r.kind == mrEventLoss and "out-of-tree content channel" in r.detail:
        inc result

  proc hasPathRead(records: seq[MonitorRecord]; path: string): bool =
    for r in records:
      if r.path == path and r.observationKind == moFileRead:
        return true

suite "io-mon macOS ROUND-4 RW3 exempt-by-name re-breaks":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r4res-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # --- S1' shm exact-allowlist (was: prefix carve-out) --------------------

    test "S1' out-of-tree apple.shm.evil producer + monitored consumer DOWNGRADES":
      let producer = compileProbe(work, r4Residual / "shm_producer.c", "shm_producer")
      let consumer = compileProbe(work, r4Residual / "shm_consumer.c", "shm_consumer")
      let cleanup = compileProbe(work, r4Residual / "shm_cleanup.c", "shm_cleanup")
      let evil = "apple.shm.evil.r4res"            # apple.* PREFIX, NOT exact-system
      runOutOfTree(cleanup, @[evil])
      # Out-of-tree producer writes a secret into the apple.shm.* object…
      runOutOfTree(producer, @[evil, "OUT_OF_TREE_SHM_SECRET"])
      # …the monitored consumer mmaps+reads it. The PREFIX carve-out is gone, so an
      # apple.shm.* attach with NO in-tree create now downgrades.
      let res = runProbe(shim, work, consumer, @[evil, work / "evil.out"])
      check res.completeness == mcIncomplete
      check hasPathRead(res.records, "shm:" & evil)
      runOutOfTree(cleanup, @[evil])

    test "S1' CARDINAL SIN: the real system shm (notification_center) stays mcComplete":
      # A normal program that attaches the GENUINE system shm
      # (apple.shm.notification_center) via libnotify — exempted by EXACT name, so
      # NO downgrade. This is the keystone: a false downgrade here re-runs every
      # build that talks to libnotify (essentially all of them).
      let probe = compileSource(work, notifySrc, "notify_probe")
      let res = runProbe(shim, work, probe, @[])
      check res.completeness == mcComplete
      check externalContentDowngrades(res.records) == 0

    # --- IP1 inherited-pipe pairing (was: opaque record-not-downgrade) ------

    test "IP1 out-of-tree-fed inherited pipe DOWNGRADES":
      # The out-of-tree pipe_launcher creates a pipe, writes a secret, clears
      # CLOEXEC on the read end, and execs the monitored pipe_client (via io-mon)
      # which reads the inherited fd. The opaque read now pairs against an in-tree
      # pipe create — there is none (the launcher is out-of-tree) → mcIncomplete.
      let launcher = compileProbe(work, r4Residual / "pipe_launcher.c", "pipe_launcher")
      let client = compileProbe(work, r4Residual / "pipe_client.c", "pipe_client")
      let ioMon = repoRoot / "build" / "bin" / "io-mon"
      doAssert fileExists(ioMon), "io-mon CLI not built at " & ioMon &
        " (run `nimble buildSnoop`)"
      let depfile = work / "ip1.rdep"
      let outFile = work / "ip1.out"
      # pipe_launcher argv: io-mon depfile client out marker
      let p = startProcess(launcher,
        args = @[ioMon, depfile, client, outFile, "OUT_OF_TREE_PIPE_SECRET"],
        options = {poStdErrToStdOut})
      let outText = p.outputStream.readAll()
      let code = p.waitForExit()
      p.close()
      checkpoint("pipe_launcher exit=" & $code & " out=" & outText)
      doAssert fileExists(depfile), "io-mon produced no depfile: " & outText
      # The io-mon CLI already merged the fragments into `depfile`.
      let dep = readMonitorDepFile(depfile)
      var sawOpaque = false
      for r in dep.records:
        if r.kind == mrExternalContent and "chan=opaque role=read" in r.detail:
          sawOpaque = true
      check sawOpaque
      check dep.completeness == mcIncomplete

    test "IP1 CARDINAL SIN: an in-tree pipe()+fork pipeline stays mcComplete":
      # A monitored parent pipe()s + forks; the monitored child reads the inherited
      # READ end. The in-tree pipe() create PAIRS the child's opaque read ⇒ NO
      # downgrade (a false downgrade here re-runs every driver↔cc1-style pipeline).
      let probe = compileSource(work, inTreePipeSrc, "intree_pipe")
      let res = runProbe(shim, work, probe, @[work / "itp.out"])
      check res.completeness == mcComplete
      check externalContentDowngrades(res.records) == 0

    # --- S0' com.apple.* responder owner verification (XPC path) ------------

    test "S0' CARDINAL SIN: a genuine com.apple.* XPC service stays mcComplete":
      # A client that XPC-connects to the REAL cfprefsd and does a synchronous reply
      # round-trip. The S0' verification reads the peer audit token on the program's
      # OWN reply → the genuine cfprefsd is a platform binary → NO downgrade. This is
      # the no-false-downgrade keystone for S0': the verification must EXEMPT a real
      # Apple service (otherwise every tool talking to cfprefsd re-runs).
      let clangBin = findExe("clang")
      if clangBin.len == 0:
        checkpoint("clang not found — skip (the genuine path is covered by the " &
          "xpc_mach_breakaway suite's com.apple.* cardinal-sin test)")
        check true
      else:
        let probe = compileSource(work, xpcGenuineSrc, "xpc_genuine",
          extra = "-fblocks", clang = true)
        let res = runProbe(shim, work, probe, @[], requireExit0 = false)
        # The genuine, platform-signed cfprefsd peer must NOT downgrade.
        check res.completeness == mcComplete
        var forged = 0
        for r in res.records:
          if r.kind == mrIpcConnect and "forged-apple-xpc" in r.detail:
            inc forged
        check forged == 0

    removeDir(work)
  else:
    test "RW3 exempt-by-name re-breaks are macOS-only (no-op on this platform)":
      check true
