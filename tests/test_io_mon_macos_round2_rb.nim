## test_io_mon_macos_round2_rb — ROUND 2 phase R-B: four content/metadata
## hook-coverage false-negatives, each closed and proven against the round-2
## adversarial corpora (research/adversarial-2026-06-round2/). See
## reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org (R-B).
##
## R3 — O_RDWR-opened INPUT classification. Round 1 classified ANY O_RDWR open as
##   a WRITE, so a file opened O_RDWR but only READ (SQLite db, lockfile, editor;
##   the lock-then-read idiom) was recorded purely as an OUTPUT and a downstream
##   "inputs = read AND NOT written" fold dropped it (a false cache hit). A pure
##   O_RDWR is now an INPUT (moFileOpen); an actual write/mmap-write marks it
##   written. Probes: r2_mmap/probeA (O_RDWR + mmap-read) and probeB (O_RDWR +
##   read()).
##
## R4 — path-probe-family canonicalisation. Round 1 canonicalised OPENS but the
##   stat/lstat/fstatat/access family recorded the RAW path, so a metadata-only
##   dependency keyed on a canonical path (a `/./` segment, a mid-path symlink, a
##   relative-after-chdir path) was missed. The probe family now ALSO records the
##   realpath-canonical companion, and stamps (dev, ino) for hardlink identity.
##   Probes: r2_path/sprobe (stat/lstat/access) and relprobe (chdir + stat).
##
## R6 — library-load filter EXACT identity (a round-1 BUG). The shim self-exclusion
##   was a SUBSTRING match (`strstr(path,"librepro_monitor_shim")`), so a genuine
##   dependency dylib whose path merely CONTAINED that substring was silently
##   dropped — and a dyld-mmap'd dylib has no open backstop, so the code dependency
##   vanished (a false cache hit). The shim is now excluded by mach_header / exact
##   realpath identity; a substring-named dep is recorded. Probe: r2_implicit.
##
## R9 — mmap/MAP_SHARED write-back. A file modified through a MAP_SHARED|PROT_WRITE
##   mapping changes content with NO write() syscall (ld64 writes its output this
##   way), so round 1 saw only the open. The mmap hook now records the content
##   write. Probe: r2_mmap/probeC.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir()
  r2mmap = repoRoot / "research" / "adversarial-2026-06-round2" / "r2_mmap"
  r2path = repoRoot / "research" / "adversarial-2026-06-round2" / "r2_path"
  r2impl = repoRoot / "research" / "adversarial-2026-06-round2" / "r2_implicit"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc run(cmd: string) =
    let (output, code) = execCmdEx(cmd)
    doAssert code == 0, "command failed (" & cmd & "): " & output

  proc ccExe(src, outBin: string; extra = "") =
    let ccBin = getEnv("CC", "cc")
    run(quoteShell(ccBin) & " -arch arm64 " & extra & " " & quoteShell(src) &
      " -o " & quoteShell(outBin))

  proc ccDylib(src, outDylib: string) =
    ## A NON-SYSTEM dylib whose install_name is its own absolute path, so dladdr
    ## reports that path to the library-load filter.
    let ccBin = getEnv("CC", "cc")
    run(quoteShell(ccBin) & " -arch arm64 -dynamiclib " & quoteShell(src) &
      " -install_name " & quoteShell(outDylib) & " -o " & quoteShell(outDylib))

  proc runProbe(shim, probe: string; args: seq[string];
      backend = "both"; workingDir = ""): seq[MonitorRecord] =
    ## Run `probe args` under the shim (direct DYLD injection, no sandbox-tools)
    ## and return the merged depfile records. Mirrors the existing macOS tests.
    let runWork = probe.parentDir() / ("run-" & probe.extractFilename() &
      "-" & backend)
    removeDir(runWork)
    createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)
    let opts = {poStdErrToStdOut}
    let p =
      if workingDir.len > 0:
        startProcess(probe, workingDir = workingDir, args = args, env = env,
          options = opts)
      else:
        startProcess(probe, args = args, env = env, options = opts)
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] " & probe.extractFilename() &
      " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe should exit 0 (" & probe & ", out=" &
      stdoutText & ")"
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    readMonitorDepFile(depfile).records

  proc hasObs(records: seq[MonitorRecord]; suffix: string;
      kinds: set[MonitorObservationKind]): bool =
    for rec in records:
      if rec.path.endsWith(suffix) and rec.observationKind in kinds:
        return true

  proc hasProbeForPath(records: seq[MonitorRecord]; path: string): bool =
    ## A path-probe (or open/read — any input-shaped observation) for the EXACT
    ## canonical path. Used to assert the R4 canonical companion is present.
    for rec in records:
      if rec.path == path and rec.observationKind in
          {moPathProbe, moFileOpen, moFileRead}:
        return true

  proc detailToken(detail, key: string): string =
    ## Local copy of the writer's `key=value` token reader (avoids depending on a
    ## non-exported symbol): extract `key`'s value from a record's detail.
    let needle = key & "="
    for tok in detail.splitWhitespace():
      if tok.len > needle.len and tok.startsWith(needle):
        return tok[needle.len .. ^1]
    ""

  proc devInoFor(records: seq[MonitorRecord]; suffix: string):
      tuple[dev, ino: string] =
    ## The (dev, ino) tokens stamped on the first path-probe/open record whose
    ## path ends with `suffix` (ROUND-2 R4 hardlink identity).
    for rec in records:
      if rec.path.endsWith(suffix) and rec.observationKind in
          {moPathProbe, moFileOpen, moFileRead}:
        let dev = detailToken(rec.detail, "dev")
        let ino = detailToken(rec.detail, "ino")
        if dev.len > 0 and ino.len > 0:
          return (dev, ino)
    ("", "")

suite "io-mon macOS ROUND-2 R-B (R3 O_RDWR / R4 path-canon / R6 lib-id / R9 mmap)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r2rb-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # The r2_mmap probes use FIXED /tmp/r2_mmap input/output paths; create them.
    let mmapDir = "/tmp/r2_mmap"
    createDir(mmapDir)

    # --- R3: O_RDWR-opened input must NOT be dropped from the input set -------
    test "R3: an O_RDWR-opened-then-mmap-READ input is captured as INPUT (probeA)":
      writeFile(mmapDir / "config_input.txt", "the-config-bytes\n")
      let bin = work / "probeA"
      ccExe(r2mmap / "probeA_rdwr_mmap_read.c", bin)
      let recs = runProbe(shim, bin, @[])
      # The O_RDWR open of the config is now an INPUT observation (moFileOpen),
      # so a "read AND NOT written" fold keeps it…
      check hasObs(recs, "config_input.txt", {moFileOpen, moFileRead})
      # …and it is NOT misrecorded as a WRITE/output (the round-1 bug): the file
      # is only read (via mmap), so no write observation may name it.
      check not hasObs(recs, "config_input.txt", {moFileWrite})
      # Sanity: the genuine output IS recorded as a write.
      check hasObs(recs, "derived_out.txt", {moFileWrite})

    test "R3: an O_RDWR-opened-then-read() input is captured as INPUT (probeB)":
      writeFile(mmapDir / "rdwr_config.txt", "rdwr-config-bytes\n")
      let bin = work / "probeB"
      ccExe(r2mmap / "probeB_rdwr_read.c", bin)
      let recs = runProbe(shim, bin, @[])
      check hasObs(recs, "rdwr_config.txt", {moFileOpen, moFileRead})
      check not hasObs(recs, "rdwr_config.txt", {moFileWrite})

    # --- R9: a MAP_SHARED|PROT_WRITE write-back is recorded as an output ------
    test "R9: a MAP_SHARED write-back produces a content WRITE record (probeC)":
      # Pre-create the output with content so the probe's fstat-sized mmap works.
      writeFile(mmapDir / "mmap_output.bin", repeat("X", 64))
      let bin = work / "probeC"
      ccExe(r2mmap / "probeC_mmap_writeback.c", bin)
      let recs = runProbe(shim, bin, @["B"])
      # The bytes are changed through the mapping with NO write() syscall; the
      # mmap hook records the content write beyond the bare open.
      check hasObs(recs, "mmap_output.bin", {moFileWrite})

    # --- R4: non-canonical stat/access ALSO records the canonical path -------
    let r4dir = work / "realdir"
    createDir(r4dir)
    let r4file = r4dir / "file.txt"
    writeFile(r4file, "metadata-target\n")
    let r4canonFile = expandFilename(r4file)   # the realpath the consumer keys on
    let sprobe = work / "sprobe"
    ccExe(r2path / "sprobe.c", sprobe)

    test "R4: stat of a /./-laden path records the canonical companion":
      let dotted = r4dir / "." / "file.txt"   # realdir/./file.txt
      let recs = runProbe(shim, sprobe, @["stat", dotted])
      check hasProbeForPath(recs, r4canonFile)

    test "R4: access of a /./-laden path records the canonical companion":
      let dotted = r4dir / "." / "file.txt"
      let recs = runProbe(shim, sprobe, @["access", dotted])
      check hasProbeForPath(recs, r4canonFile)

    test "R4: stat through a mid-path SYMLINK records the canonical target":
      let symdir = work / "symdir"
      removeFile(symdir)
      createSymlink(r4dir, symdir)
      let viaSym = symdir / "file.txt"
      let recs = runProbe(shim, sprobe, @["stat", viaSym])
      check hasProbeForPath(recs, r4canonFile)

    test "R4: a RELATIVE stat after chdir records the canonical companion":
      let relprobe = work / "relprobe"
      ccExe(r2path / "relprobe.c", relprobe)
      # relprobe chdir()s to argv[1] then stat()s argv[2] (relative).
      let recs = runProbe(shim, relprobe, @[r4dir, "file.txt"])
      check hasProbeForPath(recs, r4canonFile)

    test "R4: a probe records (dev, ino) and a HARDLINK shares the inode":
      let hard = r4dir / "hard.txt"
      removeFile(hard)
      createHardlink(r4file, hard)
      let recsA = runProbe(shim, sprobe, @["stat", r4file])
      let recsB = runProbe(shim, sprobe, @["stat", hard])
      let a = devInoFor(recsA, "file.txt")
      let b = devInoFor(recsB, "hard.txt")
      check a.dev.len > 0 and a.ino.len > 0       # (dev, ino) is stamped
      check b.dev.len > 0 and b.ino.len > 0
      # The hardlink names the SAME inode on the SAME device → matchable by
      # identity even though realpath cannot collapse the two names.
      check a.dev == b.dev
      check a.ino == b.ino

    # --- R6: a dep dylib whose path CONTAINS the shim substring is recorded ---
    test "R6: a substring-named dependency dylib is recorded; the shim is NOT":
      # The dylib's basename CONTAINS "librepro_monitor_shim" — the exact case the
      # round-1 substring self-exclusion silently DROPPED. It is now recorded
      # (excluded only by mach_header / exact-realpath identity).
      let depDylib = work / "x_librepro_monitor_shim_dep.dylib"
      ccDylib(r2impl / "libdep.c", depDylib)
      let main = work / "impl_main"
      # Link a tiny main against the dep so dyld kernel-maps it at launch.
      writeFile(work / "impl_main.c",
        "int dep_value(void); int main(void){ return dep_value() & 0; }\n")
      ccExe(work / "impl_main.c", main, quoteShell(depDylib))
      let recs = runProbe(shim, main, @[], workingDir = work)
      var sawDep = false
      var sawShim = false
      for rec in recs:
        if rec.kind == mrLibraryLoad:
          if rec.path.endsWith("x_librepro_monitor_shim_dep.dylib"):
            sawDep = true
          # The REAL shim must still be excluded by identity (no flood, no self).
          if rec.path.endsWith("/librepro_monitor_shim.dylib"):
            sawShim = true
          # The system baseline stays filtered.
          check not rec.path.startsWith("/usr/lib/")
          check not rec.path.startsWith("/System/")
      check sawDep           # the substring-named dep is RECORDED (was dropped)
      check not sawShim      # our own shim is still excluded (exact identity)

    removeDir(work)
    removeDir(mmapDir)
  else:
    test "ROUND-2 R-B hooks are macOS-only (no-op on this platform)":
      check true
