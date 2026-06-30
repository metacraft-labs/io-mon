## test_io_mon_macos_s2_fd_fidelity — ROUND-3 S2 fd→path / PATH-FIDELITY holes,
## LIVE under the macOS interpose+body-patch shim, against the round-3 adversarial
## corpus (research/adversarial-2026-06-round3/r3_fd). See
## reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org (ROUND 3,
## S2). Each break is a dependency captured under a path that would NOT match a
## consumer's canonical cache key, or attributed to the wrong file via fd
## duplication — a false cache hit / stale artifact.
##
## S2a dirfd-relative stat — `fstatat(dirfd, "rel", …)` / `getattrlistat` with a
##   REAL dirfd recorded only the BARE relative component (the round-2 residual).
##   The dirfd is now resolved via F_GETPATH, joined, and realpath'd, so a canonical
##   ABSOLUTE companion is recorded (r3_fd p_fstat).
##
## S2b canonicalise ALL opens (writes too) — round-2 F_GETPATH canonicalisation ran
##   only for READ opens, so a dirfd-relative or symlink/firmlink-traversing WRITE
##   output was recorded under an unmatchable path. F_GETPATH now runs for every
##   successful open; the canonical write target is recorded and the fd→path map
##   re-pointed (r3_fd p_oat read, p_oatw dirfd write, p_normw absolute write).
##
## S2c execve / posix_spawn symlink resolution — the launched binary was recorded
##   verbatim, so `execve("/dir/tool_link", …)` (tool_link→tool) named only the
##   link; swapping the real binary's bytes was invisible. The realpath-resolved
##   target's BYTES are now recorded as a content read (r3_fd p_symexec).
##
## S2d dup/dup2/fcntl(F_DUPFD*) tracking — a read via a dup'd fd had no path, and a
##   dup2(A,B) onto an open B (whose internal close bypasses the hooked close) left
##   a STALE B entry that MISATTRIBUTED a read of A to B. The duplication now mirrors
##   the source path onto the new fd and clears the stale destination (r3_fd p_dup,
##   p_dup2, p_fdupfd, p_dup2swap).
##
## CARDINAL SIN — the new canonicalisation/fd-tracking is ADDITIVE: a trivial
##   program, a normal file reader, and a real injectable `cc` compile all stay
##   mcComplete with no new event-loss, and existing path attribution does not
##   regress.
##
## macOS-only; a no-op pass elsewhere.

import std/[os, osproc, streams, strtabs, strutils, unittest]

when defined(macosx):
  import io_mon
  import macos_backend_toggle

  proc c_realpath(path: cstring; resolved: cstring): cstring
    {.importc: "realpath", header: "<stdlib.h>".}

  proc realPathOf(p: string): string =
    ## The realpath a canonical-keyed consumer would use (e.g. /tmp → /private/tmp
    ## on macOS). Falls back to the input when realpath fails.
    var buf: array[4096, char]
    let r = c_realpath(cstring(p), cast[cstring](addr buf[0]))
    if r != nil: $r else: p

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  fdCorpus = repoRoot / "research" / "adversarial-2026-06-round3" / "r3_fd"
  # The r3_fd probes use FIXED /tmp/r3_fd input/output paths (matching the corpus).
  fdDir = "/tmp/r3_fd"

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

  proc compileSource(work, code, name: string): string =
    let src = work / (name & ".c")
    writeFile(src, code)
    compileProbe(work, src, name)

  type RunResult = object
    records: seq[MonitorRecord]
    completeness: MonitorCompleteness

  proc runProbe(shim, probe: string; args: seq[string] = @[];
      backend = "both"; requireExit0 = true): RunResult =
    ## Run `probe args` under the shim (direct DYLD injection) and return the merged
    ## records + completeness. Mirrors the existing round-2/round-3 macOS tests, but
    ## places its work dir under a WRITABLE temp root (NOT probe.parentDir(), which is
    ## read-only when the probe is a system compiler in /nix/store — the cc test).
    let work = getTempDir() / ("io-mon-s2run-" & probe.extractFilename() & "-" &
      backend & "-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let fragmentDir = work / "frags"
    createDir(fragmentDir)
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, backend)
    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    let outText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint("[" & backend & "] " & probe.extractFilename() & " exit=" &
      $code & " out=" & outText)
    if requireExit0:
      doAssert code == 0, "probe should exit 0 (" & probe & "): " & outText
    let depfile = work / "cap.rdep"
    let dep = mergeFragments(fragmentDir, depfile)
    result.records = readMonitorDepFile(depfile).records
    result.completeness = dep.completeness

  proc hasObs(records: seq[MonitorRecord]; path: string;
      kinds: set[MonitorObservationKind]): bool =
    ## An observation of one of `kinds` on the EXACT path.
    for r in records:
      if r.path == path and r.observationKind in kinds:
        return true

  proc readPathFor(records: seq[MonitorRecord]; path: string): bool =
    ## A file-READ (content) observation on the EXACT path.
    hasObs(records, path, {moFileRead})

  proc eventLossCount(records: seq[MonitorRecord]): int =
    for r in records:
      if r.kind == mrEventLoss:
        inc result

  proc resolvesThroughBoth(bin: string): bool =
    ## True if `bin` or ANY hop of its symlink chain is one of the repo's `run-*-both`
    ## A/B compiler wrappers (which startProcess cannot exec). Bounded loop.
    var cur = bin
    for _ in 0 ..< 16:
      if "both" in cur.extractFilename:
        return true
      var nxt = cur
      try:
        if symlinkExists(cur):
          let target = expandSymlink(cur)
          nxt = (if target.isAbsolute: target else: cur.parentDir / target)
      except CatchableError:
        break
      if nxt == cur:
        break
      cur = nxt
    false

  proc canSpawn(bin: string): bool =
    ## True if `bin` can actually be exec'd by startProcess (a real Mach-O / a script
    ## with a valid shebang). Probes with `--version`; any failure ⇒ false.
    try:
      let p = startProcess(bin, args = @["--version"],
        options = {poStdErrToStdOut})
      discard p.outputStream.readAll()
      discard p.waitForExit()
      p.close()
      true
    except OSError, Exception:
      false

  proc findSpawnableCc(): string =
    ## A real, directly-spawnable, INJECTABLE toolchain driver (a nix-store clang/gcc
    ## — NOT SIP-protected). Rejects the repo's non-exec `run-*-both` A/B wrappers
    ## (whether named directly or reached via a symlink hop) and /usr SIP binaries
    ## (which would strip the shim), then confirms spawnability by exec-ing the
    ## candidate. Returns "" if none works (the caller then skips the test).
    for cand in ["clang", "cc", "gcc"]:
      let p = findExe(cand)
      if p.len == 0 or p.startsWith("/usr/"):
        continue
      if resolvesThroughBoth(p):
        continue
      if canSpawn(p):
        return p
    ""

suite "io-mon macOS ROUND-3 S2 fd/path fidelity":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-s2-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)

    # Fixed input markers the r3_fd probes open (matching the corpus paths).
    createDir(fdDir)
    writeFile(fdDir / "marker_fstat.txt", "fstat-marker\n")
    writeFile(fdDir / "marker_oat.txt", "oat-marker\n")
    writeFile(fdDir / "marker_dup.txt", "dup-marker\n")
    writeFile(fdDir / "marker_dup2.txt", "dup2-marker\n")
    writeFile(fdDir / "marker_fdupfd.txt", "fdupfd-marker\n")
    writeFile(fdDir / "marker_A.txt", "AAAA-content\n")
    writeFile(fdDir / "marker_B.txt", "BBBB-content\n")

    # Canonical (realpath) forms a consumer keys on — /tmp → /private/tmp.
    let canonFstat = realPathOf(fdDir / "marker_fstat.txt")
    let canonOat = realPathOf(fdDir / "marker_oat.txt")
    let canonOatw = realPathOf(fdDir) / "out_oatw.txt"
    let canonNormw = realPathOf(fdDir) / "out_normw.txt"
    let canonDup = realPathOf(fdDir / "marker_dup.txt")
    let canonDup2 = realPathOf(fdDir / "marker_dup2.txt")
    let canonFdupfd = realPathOf(fdDir / "marker_fdupfd.txt")
    let canonA = realPathOf(fdDir / "marker_A.txt")
    let canonB = realPathOf(fdDir / "marker_B.txt")

    # --- S2a — dirfd-relative fstatat records the canonical ABSOLUTE companion --
    test "S2a fstatat(dirfd, rel) records the canonical absolute path (p_fstat)":
      let bin = compileProbe(work, fdCorpus / "p_fstat.c", "p_fstat")
      let res = runProbe(shim, bin)
      # The bare relative component is still recorded (additive)…
      check hasObs(res.records, "marker_fstat.txt", {moPathProbe})
      # …AND the canonical absolute companion is now present (the round-2 residual).
      check hasObs(res.records, canonFstat, {moPathProbe})

    # --- S2b — every open canonicalised (reads AND writes) ---------------------
    test "S2b openat(dirfd) READ records the canonical absolute path (p_oat)":
      let bin = compileProbe(work, fdCorpus / "p_oat.c", "p_oat")
      let res = runProbe(shim, bin)
      # The dirfd-relative read is recorded under, and read via, the canonical path.
      check hasObs(res.records, canonOat, {moFileOpen, moFileRead})
      check readPathFor(res.records, canonOat)

    test "S2b openat(dirfd) WRITE output records the canonical absolute path (p_oatw)":
      let bin = compileProbe(work, fdCorpus / "p_oatw.c", "p_oatw")
      let res = runProbe(shim, bin)
      # The output write is now recorded under the canonical absolute path (it was
      # the bare relative "out_oatw.txt" before — an unmatchable output key).
      check hasObs(res.records, canonOatw, {moFileWrite})

    test "S2b absolute-but-firmlink WRITE output is canonicalised (p_normw)":
      let bin = compileProbe(work, fdCorpus / "p_normw.c", "p_normw")
      let res = runProbe(shim, bin)
      # /tmp/... opens traverse the /private firmlink; the write target is now
      # recorded under its canonical /private/tmp/... form (round-2 did this for
      # READ opens only).
      check hasObs(res.records, canonNormw, {moFileWrite})

    # --- S2c — execve via a symlink records the resolved binary's bytes --------
    test "S2c execve via a symlink records the resolved-target binary (p_symexec)":
      # tgt_link -> tgt; the launched-binary dependency must name the REAL binary.
      let tgt = fdDir / "tgt"
      cc(quoteShell(fdCorpus / "tgt.c") & " -o " & quoteShell(tgt))
      let link = fdDir / "tgt_link"
      removeFile(link)
      createSymlink(tgt, link)
      let canonTgt = realPathOf(tgt)
      let bin = compileProbe(work, fdCorpus / "p_symexec.c", "p_symexec")
      let res = runProbe(shim, bin, requireExit0 = false)  # tgt exits 7
      # The real binary's BYTES are recorded as a content read (cache-busts on a
      # content swap behind the stable link). It was the link path only before.
      check readPathFor(res.records, canonTgt)

    # --- S2d — dup / dup2 / fcntl(F_DUPFD) reads attribute to the source -------
    test "S2d a read via a dup'd fd is attributed to the source file (p_dup)":
      let bin = compileProbe(work, fdCorpus / "p_dup.c", "p_dup")
      let res = runProbe(shim, bin)
      check readPathFor(res.records, canonDup)

    test "S2d a read via a dup2'd fd is attributed to the source file (p_dup2)":
      let bin = compileProbe(work, fdCorpus / "p_dup2.c", "p_dup2")
      let res = runProbe(shim, bin)
      check readPathFor(res.records, canonDup2)

    test "S2d a read via a fcntl(F_DUPFD) fd is attributed to the source (p_fdupfd)":
      let bin = compileProbe(work, fdCorpus / "p_fdupfd.c", "p_fdupfd")
      let res = runProbe(shim, bin)
      check readPathFor(res.records, canonFdupfd)

    test "S2d dup2-swap attributes the read to A (not the stale B) (p_dup2swap)":
      let bin = compileProbe(work, fdCorpus / "p_dup2swap.c", "p_dup2swap")
      let res = runProbe(shim, bin)
      # dup2(A, B) makes B refer to A and closes the old B INTERNALLY (bypassing the
      # hooked close). The read of A via B must be attributed to A…
      check readPathFor(res.records, canonA)
      # …and NOT to B's stale entry (the misattribution the round-2 table left open).
      check not readPathFor(res.records, canonB)

    # --- CARDINAL SIN — additive only; no false downgrade, no path regression ---
    test "CARDINAL SIN: a trivial program stays mcComplete with no event-loss":
      let bin = compileSource(work, "int main(void){return 0;}\n", "trivial")
      let res = runProbe(shim, bin)
      check res.completeness == mcComplete
      check eventLossCount(res.records) == 0

    test "CARDINAL SIN: a normal file reader stays mcComplete + correct attribution":
      # base.c reads /tmp/r3_fd/marker_base.txt; the read names the canonical file.
      writeFile(fdDir / "marker_base.txt", "base-content\n")
      let canonBase = realPathOf(fdDir / "marker_base.txt")
      let bin = compileProbe(work, fdCorpus / "base.c", "reader")
      let res = runProbe(shim, bin)
      check res.completeness == mcComplete
      check eventLossCount(res.records) == 0
      check readPathFor(res.records, canonBase)

    test "CARDINAL SIN: a real injectable cc compile stays mcComplete":
      # A genuine toolchain compile posix_spawns + execs its subprocesses; the S2c
      # resolved-target must be recorded as CONTENT (not a duplicate process record),
      # so the merge's process-tree/exec-coverage accounting is unchanged and the
      # compile is NOT falsely downgraded.
      let srcC = work / "hello.c"
      writeFile(srcC, "#include <stdio.h>\nint main(void){printf(\"hi\\n\");return 0;}\n")
      let outO = work / "hello.o"
      let ccBin = findSpawnableCc()
      if ccBin.len == 0:
        skip()   # no injectable toolchain driver available in this environment
      else:
        let res = runProbe(shim, ccBin,
          @["-arch", "arm64", srcC, "-c", "-o", outO])
        check res.completeness == mcComplete
        check fileExists(outO)

    removeDir(work)
  else:
    test "ROUND-3 S2 fd/path-fidelity hooks are macOS-only (no-op here)":
      check true
