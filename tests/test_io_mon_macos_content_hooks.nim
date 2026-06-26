## test_io_mon_macos_content_hooks — the macOS shim records the SOURCE of an
## APFS clone / hardlink / copyfile-CLONE as a content (read) dependency, and a
## getattrlist existence probe as a path-probe, closing findings-doc breaks
## #3 and #5 (MacOS-Monitoring-Adversarial-Hardening.milestones.org).
##
## # The gap this proves
##
## An APFS `clonefile` copy-on-write clone reads ZERO source bytes, and a
## hardlink `link` merely aliases the inode — so NO hooked open/read ever fires
## on the source. A `copyfile` in a CLONE mode bottoms out in the same CoW path.
## And `getattrlist` is an existence/mtime probe with NO stat record. Before this
## change a build tool that consumed an input via any of these left the
## dependency INVISIBLE — a silent false cache hit. The probes are the adversarial
## corpus at research/adversarial-2026-06/.
##
## # What this test asserts
##
## For each probe, run a freshly-built copy under the shim (both mechanisms on,
## the default) and assert the SOURCE marker path appears as a read (clone/link/
## copyfile) or a path-probe (getattrlist) in the merged depfile. A baseline
## `fopen` of the same source is used as the harness control (it MUST be
## captured, proving any "absent" elsewhere is a real evasion, not a broken
## harness). The interpose-only A/B arm is also exercised to lock in that the
## interpose tuple hooks them too.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, unittest]

when defined(macosx):
  import io_mon          # readMonitorDepFile, mergeFragments, observation kinds
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir()
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

  proc compileProbe(work, src, name: string): string =
    let bin = work / name
    cc(quoteShell(src) & " -o " & quoteShell(bin))
    bin

  proc runProbe(shim, probe: string; args: seq[string]; backend: string):
      seq[MonitorRecord] =
    ## Run `probe args` under the shim (direct DYLD, no fs-snoop sandbox tools)
    ## and return the merged depfile records. Mirrors the existing macOS tests'
    ## direct-injection capture path.
    let runWork = probe.parentDir() / ("run-" & probe.extractFilename() &
      "-" & backend)
    removeDir(runWork)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)

    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)

    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] " & probe.extractFilename() &
      " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe should exit 0 (" & probe & ", backend=" &
      backend & ", out=" & stdoutText & ")"

    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    readMonitorDepFile(depfile).records

  proc hasReadOrProbe(records: seq[MonitorRecord]; path: string): bool =
    for rec in records:
      if rec.path == path and rec.observationKind in
          {moFileRead, moFileOpen, moPathProbe}:
        return true

suite "io-mon macOS content/metadata hooks (clonefile/link/copyfile/getattrlist)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-content-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let srcPath = work / "source-input.txt"
    writeFile(srcPath, "the-source-content\n")

    let baseBin = compileProbe(work, corpus / "adv_syscall" / "baseline_fopen.c",
      "baseline")
    let cloneBin = compileProbe(work, corpus / "adv_clone" / "probe_clonefile.c",
      "clonefile")
    let linkBin = compileProbe(work, corpus / "adv_clone" / "probe_link.c", "link")
    let copyCloneBin = compileProbe(work,
      corpus / "adv_clone" / "probe_copyfile_clone.c", "copyfile_clone")
    let getattrBin = compileProbe(work,
      corpus / "adv_syscall" / "getattrlist_probe.c", "getattrlist")

    test "harness control: a plain fopen of the source IS captured":
      let recs = runProbe(shim, baseBin, @[srcPath], "both")
      check hasReadOrProbe(recs, srcPath)

    test "clonefile records the SOURCE as a read dependency (break #3)":
      let recs = runProbe(shim, cloneBin, @[srcPath, work / "clone-dst"], "both")
      check hasReadOrProbe(recs, srcPath)

    test "link (hardlink) records the SOURCE as a read dependency (break #3)":
      let recs = runProbe(shim, linkBin, @[srcPath, work / "link-dst"], "both")
      check hasReadOrProbe(recs, srcPath)

    test "copyfile(COPYFILE_CLONE_FORCE) records the SOURCE as a read (break #3)":
      let recs = runProbe(shim, copyCloneBin,
        @[srcPath, work / "copyclone-dst"], "both")
      check hasReadOrProbe(recs, srcPath)

    test "getattrlist existence probe yields a path-probe record (break #5)":
      let recs = runProbe(shim, getattrBin, @[srcPath], "both")
      var sawProbe = false
      for rec in recs:
        if rec.path == srcPath and rec.observationKind == moPathProbe:
          sawProbe = true
      check sawProbe

    test "interpose-only arm also hooks clonefile + getattrlist (the tuple)":
      check hasReadOrProbe(
        runProbe(shim, cloneBin, @[srcPath, work / "clone-dst2"], "interpose"),
        srcPath)
      check hasReadOrProbe(
        runProbe(shim, getattrBin, @[srcPath], "interpose"), srcPath)

    removeDir(work)
  else:
    test "content/metadata hooks are macOS-only (no-op on this platform)":
      check true
