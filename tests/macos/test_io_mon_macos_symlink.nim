## test_io_mon_macos_symlink — a hooked open of a SYMLINK (or a /.vol/<dev>/<inode>
## firmlink) ALSO records the resolved REAL target path, closing findings-doc
## break #7 (mcapSymlink moves to supported).
##
## # The gap this proves
##
## `open()` of a symlink records only the LINK path; the real dependency is the
## TARGET, so editing the target (while the link is unchanged) would be invisible.
## And a `/.vol/<dev>/<inode>` inode-path open records an OPAQUE path that an
## incremental engine keying on real paths can never match. The shim now resolves
## the opened fd's canonical path via `fcntl(F_GETPATH)` and records it as an
## additional dependency, so the real file behind a link / inode path is visible.
##
## # What this test asserts
##
## * Symlink: a probe `fopen`s a symlink; the merged depfile contains a read/open
##   record for the RESOLVED TARGET (not just the link).
## * /.vol: a probe resolves a file's (fsid, fileid) and opens it via
##   `/.vol/<dev>/<inode>`; the depfile contains BOTH the raw /.vol open AND a
##   resolved record naming the canonical real path.
##
## Probes are the adversarial corpus at research/adversarial-2026-06/.
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  corpus = repoRoot / "research" / "adversarial-2026-06"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc cc(args: string) =
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " & args)
    doAssert code == 0, "cc failed (" & args & "): " & output

  proc runProbe(shim, probe: string; args: seq[string]): seq[MonitorRecord] =
    let runWork = probe.parentDir() / ("run-" & probe.extractFilename())
    removeDir(runWork)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, "both")
    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(probe.extractFilename() & " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe should exit 0 (" & probe & ", out=" & stdoutText & ")"
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    readMonitorDepFile(depfile).records

  proc hasReadOpenEndingWith(records: seq[MonitorRecord]; suffix: string;
      excludeVol = true): bool =
    for rec in records:
      if rec.observationKind in {moFileOpen, moFileRead} and
          rec.path.endsWith(suffix) and
          (not excludeVol or not rec.path.startsWith("/.vol/")):
        return true

suite "io-mon macOS symlink + /.vol target resolution (break #7, mcapSymlink)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-symlink-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    proc compileProbe(src, name: string): string =
      let bin = work / name
      cc(quoteShell(src) & " -o " & quoteShell(bin))
      bin

    test "mcapSymlink is now an advertised macOS capability":
      check mcapSymlink in MacosInterposeSupportedCapabilities

    test "a symlink open also records the resolved TARGET path":
      let targetPath = work / "real-source.txt"
      writeFile(targetPath, "target-bytes\n")
      let linkPath = work / "config-link"
      removeFile(linkPath)
      createSymlink(targetPath, linkPath)
      let symBin = compileProbe(corpus / "adv_clone" / "probe_symlink_read.c",
        "symlink_read")
      let recs = runProbe(shim, symBin, @[linkPath])
      # The resolved target (basename real-source.txt) must be present as a
      # read/open dependency — not just the link path.
      check hasReadOpenEndingWith(recs, "real-source.txt")

    test "a /.vol/<dev>/<inode> open records the canonical real path":
      let secretPath = work / "secret-volpath.txt"
      writeFile(secretPath, "vol-secret\n")
      let volBin = compileProbe(corpus / "adv_syscall" / "volpath_probe.c",
        "volpath")
      let recs = runProbe(shim, volBin, @[secretPath])
      # The raw inode-path open is recorded ...
      var sawVol = false
      for rec in recs:
        if rec.path.startsWith("/.vol/"):
          sawVol = true
      check sawVol
      # ... AND the canonical real path (basename secret-volpath.txt, NOT a
      # /.vol path) is recovered via F_GETPATH.
      check hasReadOpenEndingWith(recs, "secret-volpath.txt")

    removeDir(work)
  else:
    test "symlink/.vol resolution is macOS-only (no-op on this platform)":
      check true
