## test_io_mon_macos_r4_dir — ROUND 4 phase RW2: directory structure / metadata
## granularity dependency gaps.
##
## # The breaks (round-4 r4_dir corpus)
##
## D1 (directory-enumerate has NO content fingerprint): a directory enumeration
##    recorded only `directory-enumerate detail=readdir` per readdir() return — an
##    entry-COUNT signal, no name-set / mtime / hash. A net-zero add+remove (remove
##    b.c, add x.c — same count) produced byte-identical depfiles, mcComplete, while
##    a glob-based build (CMake GLOB / Make $(wildcard)) compiles a DIFFERENT file
##    set (r4_dir/glob_probe.c).
##
## D2 (stat-only probes record dev/ino but NOT mtime/size): stat/lstat/fstatat/
##    access recorded `path-probe ... dev=N ino=N` — but dev/ino are STABLE across
##    content/mtime changes. A directory's mtime bump (a file was added) or a
##    regular file's content change (when only stat'd, not read) produced IDENTICAL
##    records → any make/ninja-style mtime ("source newer than target") dependency
##    was INVISIBLE (r4_dir/{mtime_probe,scope_probe}.c).
##
## D3 (mkdir/rmdir/unlink/unlinkat unrecorded): these output-directory mutations
##    took real effect but produced NO record; the depfile self-declared a
##    `path-mutation` capability gap marked required=false, so completeness stayed
##    mcComplete despite the unhooked mutations (r4_dir/misc_probe.c).
##
## # The fix
##
## D2: statDetail now folds the full-resolution (nanosecond) mtime + size into the
##     path-probe detail (`mtime=N size=N`), for stat/lstat/fstatat from the stat
##     buffer and for access via a bounded raw stat on success.
## D1: the directory-enumerate record now carries the enumerated directory's
##     mtime+size — captured ONCE per enumeration (at opendir, or once per
##     getdirentries batch), NOT per readdir() entry. A dir's mtime bumps on any
##     add/remove, so a net-zero swap changes the recorded dependency.
## D3: mkdir/mkdirat/rmdir/unlink/unlinkat are hooked (interpose + body-patch) and
##     emit an `mrPathMutation` output record on the canonical path; the
##     `path-mutation` capability is now ADVERTISED (no gap).
##
## # The CARDINAL-SIN GUARD
##
## A NORMAL build must STAY mcComplete and must not be slowed or flooded. The new
## mtime/size + dir-mtime stats fire on already-stat-ish paths via raw syscalls
## (no extra records); the mkdir/unlink hooks record OUTPUTS and never downgrade.
## This file proves each break is CLOSED, the round-4 caught negative-dependency
## case is PRESERVED, and a real cc compile + a stat-storm stay mcComplete + fast.
##
## See reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org
## (ROUND 4, RW2) and research/adversarial-2026-06-round4/r4_dir/.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs, times]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r4dir = repoRoot / "research" / "adversarial-2026-06-round4" / "r4_dir"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc ccExe(src, outBin: string) =
    let ccBin = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(ccBin) & " -arch arm64 " &
      quoteShell(src) & " -o " & quoteShell(outBin))
    doAssert code == 0, "cc failed (" & src & "): " & output

  proc runProbe(shim, probe: string; args: seq[string];
      workingDir: string): MonitorDepFile =
    ## Run `probe args` under the shim ("both" backend — interpose + body-patch,
    ## the production default) from `workingDir` (the corpus probes use RELATIVE
    ## paths, so cwd must be the prepared state dir) and return the merged depfile
    ## (records + completeness). The run/fragment dir lives under a separate
    ## WRITABLE temp dir so it never pollutes the probe's state dir.
    let runWork = getTempDir() / ("io-mon-r4d-run-" & probe.extractFilename() &
      "-" & $getCurrentProcessId() & "-" & $epochTime())
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
    applyMacosBackendToggle(env, "both")
    let p = startProcess(probe, workingDir = workingDir, args = args, env = env,
      options = {poStdErrToStdOut})
    let stdoutText = p.outputStream.readAll()
    let code = p.waitForExit()
    p.close()
    checkpoint(probe.extractFilename() & " exit=" & $code & " out=" & stdoutText)
    doAssert code == 0, "probe should exit 0 (" & probe & ", out=" &
      stdoutText & ")"
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    result = readMonitorDepFile(depfile)
    removeDir(runWork)

  proc probeMetaFor(dep: MonitorDepFile; suffix: string): string =
    ## The `mtime=N size=N` token pair of a path-probe record whose path ends with
    ## `suffix` (the raw or canonical companion — both carry the same detail). ""
    ## when no such record carries an mtime token.
    for r in dep.records:
      if r.observationKind == moPathProbe and r.path.endsWith(suffix):
        let mt = detailToken(r.detail, "mtime")
        if mt.len > 0:
          return "mtime=" & mt & " size=" & detailToken(r.detail, "size")

  proc dirEnumMetaFor(dep: MonitorDepFile; suffix: string): string =
    ## The `mtime=N size=N` token pair of a directory-enumerate record whose path
    ## ends with `suffix`. "" when none carries an mtime token.
    for r in dep.records:
      if r.observationKind == moDirectoryEnumerate and r.path.endsWith(suffix):
        let mt = detailToken(r.detail, "mtime")
        if mt.len > 0:
          return "mtime=" & mt & " size=" & detailToken(r.detail, "size")

  proc hasMutation(dep: MonitorDepFile; suffix, verb: string): bool =
    ## A successful `mrPathMutation` output record for `suffix` tagged `verb`.
    for r in dep.records:
      if r.kind == mrPathMutation and r.path.endsWith(suffix) and
          r.detail.startsWith(verb):
        return true

  proc hasAbsentProbe(dep: MonitorDepFile; suffix: string): bool =
    ## A recorded probe/open for an ABSENT path (the round-4 caught negative
    ## dependency): a path-probe with prAbsent, or a failed file-open, for `suffix`.
    for r in dep.records:
      if r.path.endsWith(suffix):
        if r.observationKind == moPathProbe and r.probeResult == prAbsent:
          return true
        if r.observationKind in {moFileOpen, moFileRead} and r.result < 0:
          return true

  proc freshDir(tag: string): string =
    result = getTempDir() / ("io-mon-r4d-state-" & tag & "-" &
      $getCurrentProcessId() & "-" & $epochTime())
    removeDir(result)
    createDir(result)

suite "io-mon macOS RW2 directory structure / metadata granularity (live, r4_dir)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r4d-bins-" & $getCurrentProcessId())
    removeDir(work); createDir(work)

    proc probeBin(name: string): string =
      result = work / name
      ccExe(r4dir / (name & ".c"), result)

    let
      mtimeProbe = probeBin("mtime_probe")
      scopeProbe = probeBin("scope_probe")
      globProbe = probeBin("glob_probe")
      miscProbe = probeBin("misc_probe")
      negProbe = probeBin("neg_probe")

    # --- D2: stat/access now carry mtime+size (was dev/ino only) ---------------

    test "D2: a directory mtime bump changes the recorded stat probe":
      # A make/ninja "is the dir newer than my target" check stats a directory.
      # Adding a file BUMPS the dir mtime; round-3 recorded only (dev, ino) — stable
      # — so the bump was invisible. mtime_probe stats "watchdir".
      let stateA = freshDir("d2dirA")
      createDir(stateA / "watchdir")
      let depA = runProbe(shim, mtimeProbe, @[], stateA)
      let metaA = probeMetaFor(depA, "watchdir")
      check metaA.len > 0                        # mtime/size is now recorded

      let stateB = freshDir("d2dirB")
      createDir(stateB / "watchdir")
      writeFile(stateB / "watchdir" / "added.c", "x")  # add a file -> mtime bumps
      let depB = runProbe(shim, mtimeProbe, @[], stateB)
      let metaB = probeMetaFor(depB, "watchdir")
      check metaB.len > 0
      check metaA != metaB                       # the dir mtime change is DETECTABLE
      removeDir(stateA); removeDir(stateB)

    test "D2: a stat-only file content change changes the recorded probe":
      # scope_probe stats data.txt (a regular file, stat-only — never read) then
      # renames old.o. A content change alters mtime AND size; round-3 recorded
      # neither, so a stat-only metadata dependency was invisible.
      let stateA = freshDir("d2fileA")
      writeFile(stateA / "data.txt", "SHORT")
      writeFile(stateA / "old.o", "o")
      let depA = runProbe(shim, scopeProbe, @[], stateA)
      let metaA = probeMetaFor(depA, "data.txt")
      check metaA.len > 0

      let stateB = freshDir("d2fileB")
      writeFile(stateB / "data.txt", "A MUCH LONGER REPLACEMENT CONTENT BODY")
      writeFile(stateB / "old.o", "o")
      let depB = runProbe(shim, scopeProbe, @[], stateB)
      let metaB = probeMetaFor(depB, "data.txt")
      check metaB.len > 0
      check metaA != metaB                       # mtime+size change is DETECTABLE
      removeDir(stateA); removeDir(stateB)

    # --- D1: directory-enumerate now carries the dir mtime fingerprint ---------

    test "D1: a net-zero directory swap changes the directory-enumerate dependency":
      # glob_probe globs *.c in srcdir. A net-zero swap (remove b.c, add x.c — SAME
      # entry count) left a byte-identical depfile under round-3 (the bare count
      # signal), so a glob build silently compiled a different file set. The dir's
      # mtime bumps on any add/remove, so the recorded directory dependency now
      # differs.
      let stateA = freshDir("d1A")
      createDir(stateA / "srcdir")
      writeFile(stateA / "srcdir" / "a.c", "a")
      writeFile(stateA / "srcdir" / "b.c", "b")
      let depA = runProbe(shim, globProbe, @[], stateA)
      let metaA = dirEnumMetaFor(depA, "srcdir")
      check metaA.len > 0                         # the dir mtime is now recorded

      let stateB = freshDir("d1B")
      createDir(stateB / "srcdir")
      writeFile(stateB / "srcdir" / "a.c", "a")
      writeFile(stateB / "srcdir" / "x.c", "x")   # removed b.c, added x.c — count==2
      let depB = runProbe(shim, globProbe, @[], stateB)
      let metaB = dirEnumMetaFor(depB, "srcdir")
      check metaB.len > 0
      check metaA != metaB                        # the net-zero swap is DETECTABLE
      removeDir(stateA); removeDir(stateB)

    # --- D3: mkdir/unlink/rmdir now produce records ----------------------------

    test "D3: mkdir / unlink / rmdir produce path-mutation records":
      let state = freshDir("d3")
      createDir(state / "watchdir")               # misc_probe stats this
      writeFile(state / "stale.o", "stale")       # unlinked
      createDir(state / "emptydir")               # rmdir'd
      # outdir must NOT exist (misc_probe mkdir's it).
      let dep = runProbe(shim, miscProbe, @[], state)
      check hasMutation(dep, "outdir", "mkdir")
      check hasMutation(dep, "stale.o", "unlink")
      check hasMutation(dep, "emptydir", "rmdir")
      removeDir(state)

    test "D3: symlink / symlinkat produce path-mutation records":
      # symlink ADDS a directory entry exactly as unlink REMOVES one, so it is part
      # of the same mutation surface the advertised mcapPathMutation claims to
      # cover. A build laying down a versioned-library symlink (libfoo.dylib ->
      # libfoo.N.dylib) or an `ln -s` install step mutates the output namespace; if
      # it went unrecorded, advertising the capability as supported would overclaim.
      let state = freshDir("d3sym")
      let src = state / "symprobe.c"
      writeFile(src, """
#include <unistd.h>
#include <fcntl.h>
int main(void){
  symlink("libfoo.1.dylib", "libfoo.dylib");          /* path form, arg2 = link */
  symlinkat("target.txt", AT_FDCWD, "at_link.txt");   /* *at form, arg3 = link  */
  return 0;
}
""")
      let bin = state / "symprobe"
      ccExe(src, bin)
      let dep = runProbe(shim, bin, @[], state)
      check hasMutation(dep, "libfoo.dylib", "symlink")
      check hasMutation(dep, "at_link.txt", "symlinkat")
      removeDir(state)

    test "D3: path-mutation is an advertised capability (no required=false gap)":
      check mcapPathMutation in MacosInterposeSupportedCapabilities
      check mcapPathMutation in MacosMonitorShimTaxonomyCapabilities
      check mcapPathMutation notin MacosInterposeKnownUnsupportedCapabilities

    # --- Round-4 caught negative-dependency case stays caught (no regression) --

    test "PRESERVED: failed open/stat ENOENT are still recorded":
      let state = freshDir("neg1")
      createDir(state / "watchdir")
      writeFile(state / "stale.o", "stale")
      createDir(state / "emptydir")
      let dep = runProbe(shim, miscProbe, @[], state)
      check hasAbsentProbe(dep, "absent_stat.h")  # stat() ENOENT recorded
      check hasAbsentProbe(dep, "absent_open.h")  # open() ENOENT recorded
      removeDir(state)

    test "PRESERVED: a failed access() ENOENT is still recorded":
      let state = freshDir("neg2")                # maybe.h ABSENT
      let dep = runProbe(shim, negProbe, @[], state)
      check hasAbsentProbe(dep, "maybe.h")
      removeDir(state)

    # --- CARDINAL-SIN GUARD: a normal build stays mcComplete + fast ------------

    test "CARDINAL SIN GUARD: a real cc compile stays mcComplete":
      # cc spawns clang/ld, stats/opens hundreds of headers + toolchain dylibs,
      # and creates/unlinks temp objects — the new mtime/dir-mtime stats and the
      # mkdir/unlink mutation records must NOT downgrade it.
      let state = freshDir("ccin")
      let src = state / "hello.c"
      writeFile(src, "#include <stdio.h>\nint main(void){printf(\"hi\\n\");return 0;}\n")
      let outBin = state / "hello"
      let ccPath = findExe(getEnv("CC", "cc"))
      doAssert ccPath.len > 0, "could not resolve a C compiler on PATH"
      let dep = runProbe(shim, ccPath,
        @["-arch", "arm64", src, "-o", outBin], state)
      check dep.completeness == mcComplete        # NO false downgrade
      removeDir(state)

    test "CARDINAL SIN GUARD: a stat-storm stays mcComplete and does not flood":
      # A configure-style stat storm (thousands of stat/access, mostly ENOENT) plus
      # a directory enumerated many times. The new mtime/dir-mtime stats are RAW
      # syscalls that emit NO records, and the dir-mtime is captured once per
      # enumeration (NOT per readdir entry), so this must stay mcComplete and the
      # record count must stay bounded.
      let state = freshDir("storm")
      createDir(state / "manydir")
      for i in 0 ..< 64:
        writeFile(state / "manydir" / ("e" & $i & ".c"), "x")
      let src = state / "storm.c"
      writeFile(src, """
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
int main(void){
  struct stat st;
  for (int i = 0; i < 4000; i++) {
    char p[64]; snprintf(p, sizeof(p), "missing_%d.h", i);
    stat(p, &st); access(p, F_OK);          /* mostly ENOENT */
  }
  for (int r = 0; r < 16; r++) {            /* enumerate manydir repeatedly */
    DIR *d = opendir("manydir");
    if (d) { while (readdir(d)) {} closedir(d); }
  }
  printf("storm done\n");
  return 0;
}
""")
      let bin = state / "storm"
      ccExe(src, bin)
      let started = epochTime()
      let dep = runProbe(shim, bin, @[], state)
      let elapsed = epochTime() - started
      check dep.completeness == mcComplete        # NO false downgrade
      # The dir-mtime stat is once per enumeration: 16 enumerations of a 64-entry
      # dir would flood to >1000 directory-enumerate records ONLY if it re-stat'd
      # per entry. The per-readdir count signal is unchanged (≈ entries*rounds), but
      # there must be NO explosion of path-probe records beyond the storm's own
      # ~8000 stat/access calls (each records once + a canonical companion).
      check dep.records.len < 60000               # bounded — no flood
      check elapsed < 60.0                         # not pathologically slowed
      removeDir(state)

    removeDir(work)
  else:
    test "RW2 directory/metadata hooks are macOS-only (no-op on this platform)":
      check true
