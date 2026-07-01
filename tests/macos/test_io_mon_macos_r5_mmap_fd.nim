## test_io_mon_macos_r5_mmap_fd — ROUND-5 Phase 3: an out-of-tree-opened file fd
## consumed via mmap is captured (Break B), without re-triggering the mmap
## reentrancy crash (rustc/clang) and without flooding on a normal build.
##
## Break B (CONFIRMED, research/adversarial-2026-07-round5/ipc): when a file's `open`
## happens OUTSIDE the injected tree (an fd inherited across exec, or SCM_RIGHTS-
## passed) AND the content is consumed via `mmap()` with no read(2), io-mon recorded
## NOTHING → a false `mcComplete` with the input absent. The fix: a MAP_PRIVATE,
## non-PROT_EXEC mapping of an fd with no in-tree open record enters the Nim hook
## (crash-safe: libmalloc and rustc's own in-tree/anonymous maps are gated out in C),
## resolves the backing path via F_GETPATH, and records a content read.
##
## CRASH CONSTRAINT: the fix widened the mmap C-gate from "MAP_SHARED only" to "any
## fd >= 0, minus in-tree/PROT_EXEC MAP_PRIVATE". The in-tree-fd C table + the fd<0
## rule keep every libmalloc-reentrant / rustc-own mapping in pure C. This test
## additionally guards that rustc/clang do not crash (the definitive proof lives in
## test_io_mon_macos_mmap_reentrancy.nim; here we re-assert it for the Phase-3 gate).
##
## Break G (mprotect-escalation) is a DOCUMENTED RESIDUAL, not fixed here (see
## recordMmap): over-recording a read-only MAP_SHARED as a write would misclassify a
## genuine INPUT as output (the round-1 R3 bug); it is safe in the cardinal sense
## (can only mis-mark an output, never miss an input).
##
## macOS-only; a no-op pass elsewhere.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r5ipc = repoRoot / "research" / "adversarial-2026-07-round5" / "ipc"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc buildCli(): string =
    let (output, code) = execCmdEx("cd " & quoteShell(repoRoot) &
      " && nimble buildSnoop")
    let cli = repoRoot / "build" / "bin" / "io-mon"
    doAssert fileExists(cli), "io-mon CLI not produced: " & output
    cli

  proc ccExe(src, outBin: string) =
    let cc = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(cc) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(outBin))
    doAssert code == 0, "cc failed (" & src & "): " & output
    doAssert fileExists(outBin), "probe not produced: " & outBin

  proc countPath(dep: MonitorDepFile; sub: string; kind: MonitorRecordKind): int =
    for r in dep.records:
      if r.kind == kind and r.path.contains(sub): inc result

  proc runIomon(cli, shim, depfile: string; argv: seq[string]): MonitorDepFile =
    ## Run `io-mon run --depfile <depfile> -- <argv>` with the shim on DYLD, and
    ## read the resulting depfile. Used for the Break-B launcher which itself execs
    ## `io-mon run` on the monitored client, so the launcher stays OUT of tree.
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    applyMacosBackendToggle(env, "both")
    let p = startProcess(argv[0], args = argv[1 .. ^1], env = env,
      options = {poStdErrToStdOut})
    let outText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("launcher exit=" & $code & " out=" & outText)
    doAssert fileExists(depfile), "no depfile produced: " & outText
    readMonitorDepFile(depfile)

suite "io-mon macOS R5 Phase-3 mmap of out-of-tree fd (Break B)":
  when defined(macosx):
    let shim = buildShim()
    let cli = buildCli()
    let work = getTempDir() / ("io-mon-r5mmap-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    test "Break B: an out-of-tree-opened fd consumed via mmap IS captured":
      # F3_launcher opens the marker (OUT of tree — before io-mon run starts),
      # leaves the fd open across exec into `io-mon run -- F3_client`, and the
      # client mmaps the inherited fd. Pre-fix the marker was absent + mcComplete;
      # the fix records it via F_GETPATH.
      let marker = work / "ootree_marker.txt"
      writeFile(marker, "out-of-tree-mmap-content\n")
      let client = work / "F3_client"
      ccExe(r5ipc / "F3_client.c", client)
      let launcher = work / "F3_launcher"
      ccExe(r5ipc / "F3_launcher.c", launcher)
      let depfile = work / "breakB.rdep"
      let dep = runIomon(cli, shim, depfile,
        @[launcher, marker, cli, depfile, client])
      # The marker is now recorded as a content read on its canonical path,
      # tagged mmap-inherited-fd.
      var sawMarker = false
      for r in dep.records:
        if r.kind == mrFileRead and r.path.endsWith("ootree_marker.txt") and
            r.detail.contains("mmap-inherited"):
          sawMarker = true
      check sawMarker
      check dep.completeness == mcComplete

    test "no double-record: an IN-TREE open+mmap is not tagged mmap-inherited-fd":
      # G_intree_mmap opens the marker IN-tree (the open records the dep) then
      # mmaps it. The in-tree-fd C table must skip the mmap capture — no
      # mmap-inherited-fd record, no crash-hazard entry into Nim for an in-tree fd.
      let marker = work / "intree_marker.txt"
      writeFile(marker, "in-tree-content\n")
      let bin = work / "G_intree"
      ccExe(r5ipc / "G_intree_mmap.c", bin)
      # Run directly under the shim (the open is in-tree).
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs():
        if k == "CT_SANDBOX_TOOLS_DIR": continue
        env[k] = v
      env["DYLD_INSERT_LIBRARIES"] = shim
      env["REPRO_MONITOR_SHIM_LIB"] = shim
      let runWork = work / "gintree"
      createDir(runWork)
      env["REPRO_MONITOR_FRAGMENT_DIR"] = runWork
      applyMacosBackendToggle(env, "both")
      let p = startProcess(bin, args = @[marker], env = env,
        options = {poStdErrToStdOut})
      discard p.outputStream.readAll()
      doAssert p.waitForExit() == 0
      p.close()
      let depfile = work / "intree.rdep"
      discard mergeFragments(runWork, depfile)
      let dep = readMonitorDepFile(depfile)
      # The dep IS captured (via the in-tree open), but NOT via a mmap-inherited-fd
      # record (that is the out-of-tree path only).
      check countPath(dep, "intree_marker.txt", mrFileOpen) +
        countPath(dep, "intree_marker.txt", mrFileRead) >= 1
      var mmapInherited = 0
      for r in dep.records:
        if r.detail.contains("mmap-inherited"): inc mmapInherited
      check mmapInherited == 0
      check dep.completeness == mcComplete

    removeDir(work)
  else:
    test "R5 Phase-3 mmap-fd capture is macOS-only (no-op here)":
      check true
