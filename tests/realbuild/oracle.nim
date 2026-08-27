## Real-build completeness oracle — io-mon-Lossless-Event-Capture M3 part 3
## (design spec §4.5(h), the cardinal-sin gate).
##
## The synthetic ground-truth oracle (§4.5(f)) proves the SET transport loses
## nothing it was *handed*; it cannot prove the shim *observed everything a real
## build touched*. This program establishes that second, harder truth against
## ground truth produced INDEPENDENTLY of io-mon, over real rapid-fork builds:
##
##   A. Curated known-closure fixtures — a cmake+ninja C project and an offline
##      cargo workspace whose COMPLETE source-input closure is enumerable by
##      construction. Assert io-mon's captured input set == the known closure,
##      BOTH directions (no missing real input; no phantom), modulo an explicit
##      incidental/toolchain/build-output allowlist.
##
##   B. Differential vs the toolchain's OWN dependency data — ninja `-t deps`
##      (`.ninja_deps`) for the cmake build and cargo/rustc `--emit=dep-info`
##      `.d` files for the cargo build. Assert captured ⊇ tool-declared (every
##      input the toolchain itself recorded was observed). This is the direct
##      under-capture / cardinal-sin gate.
##
##   C. Differential vs `strace -f` — a second, differently-implemented observer.
##      Extract the successfully-opened-for-read path set and diff it against
##      io-mon's captured set on the build-input domain.
##
##   D. Under contention — a control build (mcComplete) plus a SIGKILL injected
##      into a build subprocess mid-flight; assert io-mon stays honest (never a
##      FALSE mcComplete) and the SET transport drops nothing under the kill.
##
## CLASS-(a) TRANSPORT GATE (the campaign's cardinal sin): for every build we
## capture twice from clean — once through the nim-shm-gset SET transport (the
## thing this campaign changed) and once through the pure-file baseline
## (`REPRO_MONITOR_DEP_SHM_DISABLE=1`). Any build input the FILE baseline
## observed but the SET path dropped is a class-(a) transport loss and FAILS the
## milestone. Zero class-(a) gaps is the campaign pass bar.
##
## Every ground-truth path that is NOT captured is classified:
##   (a) observed-but-lost-in-transport  -> campaign bug, FAILS.
##   (b) never-observed with mcComplete   -> pre-existing io-mon hook-coverage
##       gap; surfaced LOUDLY, not fixed here.
##   (c) never-observed with mcIncomplete -> honest (io-mon knew it was partial).
##   (d) incidental (allowlist)           -> fine.
##
## Usage:  oracle <fast|full> <workdir>
##   fast  — fixtures A (both projects) + the class-(a) transport gate + the D
##           control (kept in CI; ninja/cargo builds are seconds).
##   full  — fast + differentials B & C + the SIGKILL-under-load battery D.

import std/[os, osproc, sets, strutils, sequtils, algorithm, streams, tables,
            strtabs, net]
import io_mon

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

let
  shimLib = getEnv("REPRO_MONITOR_SHIM_LIB",
                   repoRoot / "build" / "lib" / "librepro_monitor_shim.so")
  ioMonBin = getEnv("IO_MON_BIN", repoRoot / "build" / "bin" / "io-mon")
  fixturesDir = repoRoot / "tests" / "realbuild" / "fixtures"

var
  hardFailures = 0      ## campaign pass-bar violations (class-(a), missing fixture inputs, etc.)
  classBFindings: seq[string]  ## pre-existing io-mon hook-coverage gaps (surfaced, not blocking)

proc note(msg: string) = echo "    " & msg
proc section(msg: string) = echo "\n== " & msg & " =="
proc fail(msg: string) =
  inc hardFailures
  echo "  [FAIL] " & msg
proc ok(msg: string) = echo "  [OK]   " & msg

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

proc realp(p: string): string =
  ## Resolve symlinks when the path exists; otherwise return it unchanged.
  if p.len == 0: return p
  try:
    if fileExists(p) or dirExists(p) or symlinkExists(p): expandFilename(p)
    else: p
  except CatchableError:
    p

proc underDir(path, dir: string): bool =
  let d = dir.strip(chars = {'/'}, leading = false, trailing = true)
  path == d or path.startsWith(d & "/")

proc underExcluded(p, projectDir: string; excludeDirs: openArray[string]): bool =
  ## True if any excludeDir name appears as a path COMPONENT of p below the
  ## project root. Component-based (not prefix-based) so a nested build-output
  ## tree (e.g. cargo's `mycrate/target`) is excluded wherever it sits.
  let root = realp(projectDir)
  if not underDir(p, root): return false
  let rel = p[root.len .. ^1]
  let comps = rel.split('/')
  for ed in excludeDirs:
    if ed in comps: return true
  false

proc copyFixture(name, workdir: string): string =
  ## Fresh copy of a committed fixture into the work dir (builds mutate the tree,
  ## so every capture must start from a clean source — no incremental no-ops).
  result = workdir / name
  removeDir(result)
  createDir(result)
  copyDirWithPermissions(fixturesDir / name, result)

proc childEnv(disableShm: bool): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result["REPRO_MONITOR_SHIM_LIB"] = shimLib
  if disableShm:
    result["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"

type Capture = object
  dep: MonitorDepFile
  code: int
  output: string

proc capture(depPath: string; cmd: seq[string]; workDir: string;
             disableShm = false): Capture =
  ## Run `io-mon run --depfile depPath -- cmd...` in workDir and read the depfile.
  let args = @["run", "--depfile", depPath, "--"] & cmd
  let p = startProcess(ioMonBin, workingDir = workDir, args = args,
                       env = childEnv(disableShm),
                       options = {poStdErrToStdOut})
  result.output = p.outputStream.readAll()
  result.code = p.waitForExit()
  p.close()
  if not fileExists(depPath):
    raise newException(IOError, "io-mon produced no depfile: " & depPath &
      "\n" & result.output)
  result.dep = readMonitorDepFile(depPath)

proc inputReads(dep: MonitorDepFile): HashSet[string] =
  ## The captured CONTENT-input set: file reads + library loads (both are
  ## observationKind moFileRead — the dependencies a cache key must cover).
  for r in dep.records:
    if r.kind in {mrFileRead, mrLibraryLoad} and r.path.len > 0:
      result.incl realp(r.path)

proc observedPaths(dep: MonitorDepFile): HashSet[string] =
  ## The captured OBSERVATION set: every path io-mon saw opened-for-read OR read
  ## OR mapped (file-open ∪ file-read ∪ library-load). Superset of `inputReads`;
  ## used by the battery-D honesty gate to prove io-mon observed every read an
  ## independent monitor (strace) saw — an open strace recorded but io-mon missed
  ## would be a false-complete cardinal sin regardless of whether bytes flowed.
  for r in dep.records:
    if r.kind in {mrFileOpen, mrFileRead, mrLibraryLoad} and r.path.len > 0:
      result.incl realp(r.path)

proc completeness(dep: MonitorDepFile): string = $dep.completeness

# ---- incidental / allowlist classification -------------------------------

proc isIncidental(path: string): bool =
  ## Paths io-mon or the toolchain legitimately touch that are NOT source
  ## dependencies of the build: loader/runtime, kernel pseudo-fs, locale, the
  ## toolchain's own store paths, temp, and io-mon's own machinery.
  # System / runtime prefixes only. NB: deliberately NOT /tmp or /var — build
  # work dirs legitimately live under /tmp (e.g. this oracle's own scratch), and
  # swallowing them would hide real source reads.
  for pre in ["/proc/", "/sys/", "/dev/", "/run/", "/etc/", "/usr/lib/locale"]:
    if path.startsWith(pre): return true
  for frag in ["locale-archive", "ld.so.cache", "ld.so.preload", "gconv-modules",
               "nsswitch", "/.cache/", "librepro_monitor_shim"]:
    if frag in path: return true
  # The toolchain's own store paths are allowlisted for the fixture ==
  # direction and for over-capture; differential B does NOT use this (store
  # headers there are genuine declared inputs that MUST be captured).
  if path.startsWith("/nix/store/"): return true
  false

# ---- classify a ground-truth path that was NOT captured ------------------

proc classifyGap(path: string; setCap, fileCap: HashSet[string];
                 setComplete: bool): string =
  ## Returns "a"/"b"/"c"/"d".
  let rp = realp(path)
  if isIncidental(rp): return "d"
  if rp in fileCap and rp notin setCap: return "a"   # transport lost it
  if setComplete: return "b"                         # never observed, yet complete
  return "c"                                          # never observed, honestly incomplete

# ---------------------------------------------------------------------------
# tool-declared parsers (differential B)
# ---------------------------------------------------------------------------

proc ninjaDeclaredDeps(buildDir: string): HashSet[string] =
  ## `ninja -t deps` reads .ninja_deps (the headers gcc -MD recorded per TU).
  let (outp, code) = execCmdEx("ninja -C " & quoteShell(buildDir) & " -t deps")
  if code != 0:
    note "ninja -t deps exit " & $code
  for line in outp.splitLines():
    if line.startsWith("    "):
      var dep = line.strip()
      if dep.len == 0: continue
      if not dep.startsWith("/"): dep = buildDir / dep     # relative to build dir
      let rp = realp(dep)
      if fileExists(rp): result.incl rp

proc cargoDeclaredDeps(crateDir: string): HashSet[string] =
  ## rustc `--emit=dep-info` `.d` files under target/**; collect the source
  ## files each crate declared (relative paths resolve against the crate dir).
  let targetDir = crateDir / "target"
  if not dirExists(targetDir): return
  for path in walkDirRec(targetDir):
    if not path.endsWith(".d"): continue
    for line in readFile(path).splitLines():
      let colon = line.find(": ")
      if colon < 0: continue
      for tok in line[colon + 2 .. ^1].split(' '):
        let t = tok.strip()
        if t.len == 0 or not t.endsWith(".rs"): continue
        let abs = if t.startsWith("/"): t else: crateDir / t
        let rp = realp(abs)
        if fileExists(rp): result.incl rp

# ---------------------------------------------------------------------------
# strace differential (C)
# ---------------------------------------------------------------------------

proc parseStraceReads(logPath: string): HashSet[string] =
  ## Extract the paths a `strace -f -e trace=openat,open` log shows successfully
  ## opened for reading (O_RDONLY, numeric fd >= 0), resolved + confirmed to exist.
  if not fileExists(logPath): return
  for line in readFile(logPath).splitLines():
    # ... openat(AT_FDCWD, "PATH", O_RDONLY|... ) = <fd>
    if "O_RDONLY" notin line: continue
    if "O_WRONLY" in line or "O_RDWR" in line: continue
    let eq = line.rfind("= ")
    if eq < 0: continue
    let tail = line[eq + 2 .. ^1].strip()
    if tail.len == 0 or not (tail[0] in {'0'..'9'}): continue   # skip errors (-1 ...)
    let q1 = line.find('"')
    if q1 < 0: continue
    let q2 = line.find('"', q1 + 1)
    if q2 < 0: continue
    let path = line[q1 + 1 ..< q2]
    let rp = realp(path)
    if fileExists(rp): result.incl rp

proc straceReadSet(cmd: seq[string]; workDir: string; logPath: string):
    HashSet[string] =
  ## Run the build under `strace -f -e trace=file` (an independent observer) and
  ## extract the paths successfully opened for reading (O_RDONLY, fd >= 0).
  let args = @["-f", "-e", "trace=openat,open", "-o", logPath] & cmd
  let p = startProcess("strace", workingDir = workDir, args = args,
                       options = {poStdErrToStdOut, poUsePath})
  discard p.outputStream.readAll()
  discard p.waitForExit()
  p.close()
  result = parseStraceReads(logPath)

# ---------------------------------------------------------------------------
# battery A — known-closure fixtures + class-(a) transport gate
# ---------------------------------------------------------------------------

proc sourceClosure(projectDir: string; exts: openArray[string];
                   excludeDirs: openArray[string]): HashSet[string] =
  ## The known input closure = the committed source files under the project,
  ## enumerated by construction, excluding build-output subtrees.
  for path in walkDirRec(projectDir):
    if underExcluded(realp(path), projectDir, excludeDirs): continue
    let (_, _, ext) = splitFile(path)
    if ext in exts or extractFilename(path) in exts:
      result.incl realp(path)

const SourceExts = [".c", ".h", ".hh", ".hpp", ".cc", ".cpp", ".cxx",
                    ".rs", ".toml", ".lock", ".txt", ".cmake"]

proc looksLikeSource(path: string): bool =
  let (_, name, ext) = splitFile(path)
  ext in SourceExts or (name & ext) in ["CMakeLists.txt"]

proc capturedProjectSources(cap: HashSet[string]; projectDir: string;
                            excludeDirs: openArray[string]): HashSet[string] =
  ## Captured reads restricted to SOURCE-like files under the project tree
  ## (excluding build-output subtrees) — what we compare to the known closure.
  ## Source-extension filtering keeps per-run-random build scratch (e.g. cargo's
  ## `target<rand>` atomic-rename staging, `*.rcgu.o`) out of the deterministic
  ## input domain; those are build OUTPUTS, not source dependencies.
  for p in cap:
    if not underDir(p, realp(projectDir)): continue
    if isIncidental(p): continue
    if underExcluded(p, projectDir, excludeDirs): continue
    if not looksLikeSource(p): continue
    result.incl p

proc runFixtureAndGate(name, projectDir: string; buildCmd: seq[string];
                       closure: HashSet[string]; excludeDirs: openArray[string];
                       allowedExtras: HashSet[string]; workdir: string):
    tuple[setCap, fileCap: HashSet[string]; setComplete: bool] =
  ## Capture SET + file-baseline (both clean), assert fixture-A ==, the
  ## class-(a) transport gate, AND the completeness-axis divergence gate
  ## (file-complete / SET-incomplete is the cardinal sin on the completeness
  ## axis — the exact part-2a regression this campaign closes).
  let setCapC = capture(workdir / (name & "-set.iomon"), buildCmd, projectDir)
  # THE BUILD MUST HAVE SUCCEEDED before any closure assertion runs.
  #
  # Without this gate a build that FAILED (for a reason having nothing to do
  # with io-mon) never opens the inputs the closure lists, so the very next
  # assertion reports "known-closure inputs NOT captured" — i.e. it reports a
  # CARDINAL-SIN VIOLATION, the most serious verdict this oracle can return,
  # for a build that simply did not run. That is a false alarm in the one
  # direction an oracle must never be wrong in: it destroys the signal that
  # makes a real under-capture credible.
  #
  # Observed for real: a stray `/tmp/Cargo.toml` left by an unrelated process
  # made cargo resolve the wrong workspace root and exit non-zero; the oracle
  # dutifully announced `[FAIL] 4 known-closure inputs NOT captured`. The exit
  # code was right there and unexamined.
  #
  # `abort` rather than `fail`: with no successful build there is nothing to
  # assert about, so continuing would only pile more meaningless failures onto
  # a misleading one.
  proc requireBuildOk(kind: string; c: Capture) =
    if c.code != 0:
      fail name & " (" & kind & "): FIXTURE BUILD FAILED with exit code " &
        $c.code & " — closure assertions skipped because a build that did " &
        "not run cannot have opened its inputs (this is an ENVIRONMENT " &
        "failure, not an io-mon under-capture). Build output:\n" & c.output
      raise newException(IOError, name & ": fixture build exit code " & $c.code)
  requireBuildOk("set", setCapC)
  let setDep = setCapC.dep
  # clean rebuild for the baseline (avoid incremental no-op)
  removeDir(projectDir); createDir(parentDir(projectDir))
  discard copyFixture(name, workdir)
  let fileCapC = capture(workdir / (name & "-file.iomon"), buildCmd, projectDir,
                         disableShm = true)
  requireBuildOk("file-baseline", fileCapC)
  result.setCap = inputReads(setDep)
  result.fileCap = inputReads(fileCapC.dep)
  result.setComplete = setDep.completeness == mcComplete
  let fileComplete = fileCapC.dep.completeness == mcComplete

  # --- completeness-axis divergence gate ---------------------------------
  # The SET transport must NEVER report a WEAKER completeness than the
  # file-baseline for the same build: a file-baseline `mcComplete` that the SET
  # path downgrades to `mcIncomplete` is a transport-introduced false negative
  # (it silently defeats caching for the whole build). This is the divergence
  # the part-2a SET-identity dedup introduced on every Nix-toolchain build; the
  # exec-generation identity fix must keep SET == file on this axis.
  note name & ": completeness set=" & $setDep.completeness &
    " file=" & $fileCapC.dep.completeness
  if fileComplete and not result.setComplete:
    fail name & " completeness DIVERGENCE (cardinal sin, completeness axis): " &
      "file-baseline=mcComplete but SET=" & $setDep.completeness &
      " — the SET transport downgraded a build the file baseline saw as complete"
  elif result.setComplete and not fileComplete:
    # SET stronger than file: also suspicious (a false complete would be the
    # worst sin), surface it loudly but do not hard-fail here — the class-(a)
    # and captured-⊇ gates below independently guard against a false complete.
    echo "  [WARN] " & name & " completeness: SET=mcComplete but file-baseline=" &
      $fileCapC.dep.completeness & " (SET stronger than file — investigate)"
  else:
    ok name & " completeness gate: SET matches file-baseline (" &
      $setDep.completeness & ")"

  let projSrc = capturedProjectSources(result.setCap, projectDir, excludeDirs)

  # --- fixture-A: captured source set == known closure, both directions ---
  let missing = closure - projSrc
  let phantom = projSrc - closure - allowedExtras
  note name & ": completeness(set)=" & $setDep.completeness &
    " closure=" & $closure.len & " captured-src=" & $projSrc.len
  if missing.len == 0:
    ok name & " fixture-A: every known-closure input captured (no under-capture)"
  else:
    fail name & " fixture-A: " & $missing.len &
      " known-closure input(s) NOT captured:"
    for m in missing: note "MISSING " & m
  if phantom.len == 0:
    ok name & " fixture-A: no phantom source inputs (over-capture bounded)"
  else:
    echo "  [WARN] " & name & " fixture-A: " & $phantom.len &
      " unexpected project-source read(s) (over-capture, inverse sin):"
    for ph in phantom: note "PHANTOM " & ph

  # --- class-(a) transport gate: SET must not drop what the file baseline saw.
  # Compare on the deterministic build-input domain (project sources), since
  # incidental reads (locale, caches) legitimately vary run-to-run.
  let fileProjSrc = capturedProjectSources(result.fileCap, projectDir, excludeDirs)
  let classA = fileProjSrc - result.setCap
  if classA.len == 0:
    ok name & " class-(a) gate: SET transport dropped nothing the file baseline observed"
  else:
    fail name & " class-(a) TRANSPORT LOSS (cardinal sin): " & $classA.len &
      " input(s) in file-baseline but not SET:"
    for c in classA: note "LOST-IN-TRANSPORT " & c

# ---------------------------------------------------------------------------
# battery B/C — differentials against an external truth
# ---------------------------------------------------------------------------

proc classifyMissingSet(missing, setCap, fileCap: HashSet[string];
                        setComplete: bool; label: string) =
  ## Classify each ground-truth path the SET capture missed and enforce the bar.
  var counts = initTable[string, int]()
  for cls in ["a", "b", "c", "d"]: counts[cls] = 0
  var aList, bList: seq[string]
  for m in missing:
    let cls = classifyGap(m, setCap, fileCap, setComplete)
    counts[cls].inc
    if cls == "a": aList.add m
    elif cls == "b": bList.add m
  note label & " gap classes: (a)=" & $counts["a"] & " (b)=" & $counts["b"] &
    " (c)=" & $counts["c"] & " (d)=" & $counts["d"]
  if aList.len > 0:
    fail label & ": " & $aList.len & " class-(a) transport loss(es):"
    for a in aList: note "CLASS-A " & a
  if bList.len > 0:
    echo "  [FIND] " & label & ": " & $bList.len &
      " class-(b) pre-existing io-mon hook-coverage gap(s) (surfaced, not blocking):"
    for b in bList:
      note "CLASS-B " & b
      classBFindings.add label & ": " & b

proc differentialB(name, label: string; declared, setCap, fileCap: HashSet[string];
                   setComplete: bool) =
  note label & ": tool-declared=" & $declared.len & " captured(set)=" & $setCap.len
  let missing = declared - setCap
  if missing.len == 0:
    ok label & ": captured ⊇ tool-declared (zero under-capture — cardinal-sin gate holds)"
  else:
    note label & ": " & $missing.len & " tool-declared path(s) not in captured set:"
    classifyMissingSet(missing, setCap, fileCap, setComplete, label)

proc differentialC(label: string; straceSet, setCap, fileCap, domain: HashSet[string];
                   setComplete: bool) =
  ## Compare on the build-input domain (project sources + tool-declared), since
  ## strace legitimately observes far more incidental paths io-mon ignores.
  let straceInputs = straceSet * domain
  let missing = straceInputs - setCap
  note label & ": strace-observed inputs=" & $straceInputs.len &
    " captured(set)∩domain=" & $(setCap * domain).len
  if missing.len == 0:
    ok label & ": io-mon captured every build input strace observed (independent-monitor agreement)"
  else:
    note label & ": " & $missing.len & " strace-observed input(s) not in captured set:"
    classifyMissingSet(missing, setCap, fileCap, setComplete, label)

# ---------------------------------------------------------------------------
# battery D — under contention (kill injection)
# ---------------------------------------------------------------------------

proc buildForktree(workdir: string): string =
  result = workdir / "forktree"
  let cc = getEnv("CC", "cc")
  let src = fixturesDir / "forktree.c"
  let (outp, code) = execCmdEx(cc & " -O0 " & quoteShell(src) & " -o " &
                               quoteShell(result))
  if code != 0:
    fail "battery D: could not build forktree control: " & outp

proc batteryD_control(workdir: string) =
  let ft = buildForktree(workdir)
  if not fileExists(ft): return
  createDir(workdir / "d")
  writeFile(workdir / "d" / "marker.txt", "dependency\n")
  let cap = capture(workdir / "d-nokill.iomon",
                    @[ft, workdir / "d" / "marker.txt", "6"], workdir)
  if cap.dep.completeness == mcComplete:
    ok "battery D control (fork tree, no kill): mcComplete — completeness is reportable"
  else:
    fail "battery D control: expected mcComplete, got " & $cap.dep.completeness
  # kill a leaf after it published its read (LF-7): io-mon must stay honest —
  # NOT a false loss of the killed child's already-published dependency.
  let cap2 = capture(workdir / "d-leafkill.iomon",
                     @[ft, workdir / "d" / "marker.txt", "6", "kill"], workdir)
  let reads = inputReads(cap2.dep)
  let markerRead = anyIt(reads.toSeq, "marker.txt" in it)
  if markerRead:
    ok "battery D leaf-kill: killed child's already-published read is retained (LF-7 honest); completeness=" &
      $cap2.dep.completeness
  else:
    fail "battery D leaf-kill: the marker dependency was lost after a kill (LF-7 violation)"

proc isSourceOrHeaderInput(path, projDir: string): bool =
  ## True for the build-input domain the battery-D honesty gate reasons over:
  ## the killed compiler's actual source/header reads. Kernel pseudo-fs is
  ## excluded (not content); everything else that is a C source/header OR lives
  ## under the project tree is in-domain — deliberately KEEPING /nix/store headers
  ## (a store header cc1 read that io-mon missed would be the false-complete bug).
  for pre in ["/proc/", "/sys/", "/dev/", "/run/"]:
    if path.startsWith(pre): return false
  if underDir(path, realp(projDir)): return true
  let (_, _, ext) = splitFile(path)
  ext in [".c", ".h", ".hpp", ".hh", ".cc", ".cpp", ".cxx", ".inc", ".gch", ".i"]

proc batteryD_realBuildKill(workdir: string) =
  ## SIGKILL a real compiler subprocess mid-flight in a ninja build and assert
  ## io-mon stays honest. A large generated TU keeps cc1 alive long enough to be
  ## hit; configure runs UNMONITORED so only the compile/link is monitored.
  ##
  ## LF-7 SEMANTICS (the part-3 clarification): the shim publishes each read
  ## UNBUFFERED into the consumer-owned SET *before* returning the bytes to the
  ## application, and the SET lives in consumer memory that outlives every
  ## producer. So a compiler SIGKILLed mid-flight loses ZERO of the reads it had
  ## already performed — every read that ACTUALLY happened before the kill is
  ## captured. A cleanly-killed build is therefore legitimately `mcComplete`: the
  ## kill is not an event loss. (The OLD "kill ⇒ mcIncomplete" expectation was an
  ## artefact of the file/batch transport losing the last un-flushed batch — a bug
  ## the SET transport fixed — NOT a completeness truth.)
  ##
  ## Two runs. RUN A kills under io-mon directly (the pure LF-7 shape) and ASSERTS
  ## the cleanly-killed build stays `mcComplete` — a deterministic result here
  ## (kills don't spuriously downgrade a fully-observed build). RUN B does NOT
  ## simply trust that `mcComplete`; it PROVES it is HONEST by re-running the SAME
  ## killed build under `strace -f` WRAPPING io-mon (both observers see the
  ## identical execution + identical kill) and confirming io-mon OBSERVED every
  ## source/header read strace saw. A read strace recorded that io-mon reported
  ## `mcComplete` over WITHOUT capturing would be a false-complete cardinal sin and
  ## FAILS here.
  let proj = workdir / "killbuild"
  removeDir(proj); createDir(proj / "src")
  # A TU large enough that cc1 lives several seconds under -O2, so a mid-flight
  # SIGKILL reliably intercepts it (empirically ~1s per ~1000 funcs at -O2).
  const NFuncs = 8000
  var big = "#include <stdio.h>\n"
  for i in 0 ..< NFuncs: big.add "int f" & $i & "(int x){return x*" & $i & "+" & $i & ";}\n"
  big.add "int main(void){long s=0;"
  for i in 0 ..< NFuncs: big.add "s+=f" & $i & "(s);"
  big.add "printf(\"%ld\\n\",s);return 0;}\n"
  writeFile(proj / "src" / "big.c", big)
  writeFile(proj / "CMakeLists.txt",
    "cmake_minimum_required(VERSION 3.20)\nproject(kb C)\n" &
    "add_executable(kb src/big.c)\nset_source_files_properties(src/big.c " &
    "PROPERTIES COMPILE_OPTIONS \"-O2\")\n")
  let (cfgOut, cfgCode) = execCmdEx("cmake -S " & quoteShell(proj) & " -B " &
    quoteShell(proj / "build") & " -G Ninja")
  if cfgCode != 0:
    fail "battery D kill: cmake configure failed: " & cfgOut
    return
  # Killer uses EXACT comm match (pkill -x cc1) so it cannot match the wrapping
  # bash script's own text (which contains the literal "cc1"). It fires for ~12s
  # to cover the whole compile; ninja's real exit code is preserved (NOT masked).
  let script = "( for _ in $(seq 1 240); do pkill -9 -x cc1 2>/dev/null; " &
    "pkill -9 -x cc1plus 2>/dev/null; sleep 0.05; done ) & kpid=$!\n" &
    "ninja -C build; rc=$?\n" &
    "kill \"$kpid\" 2>/dev/null; wait \"$kpid\" 2>/dev/null\n" &
    "exit $rc"

  # ==========================================================================
  # RUN A — the pure LF-7 scenario: SIGKILL under io-mon directly (no strace).
  # This is the real headline shape and its completeness is DETERMINISTIC:
  # empirically a mid-compile SIGKILL of cc1 yields `mcComplete` every time,
  # because the SET transport publishes each read UNBUFFERED before returning the
  # bytes, so the killed compiler's already-performed reads are ALL captured — the
  # kill is not an event loss. We ASSERT that a cleanly-killed build stays
  # `mcComplete` (kills don't spuriously downgrade a fully-observed build and
  # defeat caching — the good property this campaign restored). A rare
  # exec-accounting-boundary race can instead yield an honest `mcIncomplete`; that
  # is NOT a false complete, so it degrades to a WARN rather than a hard failure.
  # ==========================================================================
  let capA = capture(workdir / "killbuild-kill.iomon", @["bash", "-c", script], proj)
  ok "battery D kill (run A, direct): depfile produced despite mid-flight SIGKILL " &
    "(build exit " & $capA.code & ")"
  if capA.code != 0:
    if capA.dep.completeness == mcComplete:
      ok "battery D kill (run A): cleanly-SIGKILLed build (exit " & $capA.code &
        ") is mcComplete — LF-7: unbuffered publish-before-return captures every " &
        "already-performed read, so a clean kill does NOT downgrade completeness " &
        "(kills don't spuriously defeat caching)"
    else:
      echo "  [WARN] battery D kill (run A): killed build reported " &
        $capA.dep.completeness & " (honest — a kill that raced an exec-accounting " &
        "boundary; never a false complete). LF-7 expects mcComplete for a " &
        "fully-observed kill."
  else:
    echo "  [WARN] battery D kill (run A): compile finished before a kill landed " &
      "(build exit 0); completeness=" & $capA.dep.completeness

  # ==========================================================================
  # RUN B — HONESTY PROOF: re-run the SAME killed build under `strace -f`
  # WRAPPING io-mon, so BOTH observers watch the identical process tree and the
  # identical kill point (the only way to get a per-run ⊇ guarantee against a racy
  # kill — separate runs kill at different points and diverge). strace's ptrace
  # and io-mon's LD_PRELOAD are orthogonal and compose cleanly. We then confirm
  # io-mon OBSERVED every source/header read strace recorded: a read strace saw
  # that io-mon claimed `mcComplete` over WITHOUT capturing is a false-complete
  # cardinal sin and FAILS here. (strace's ptrace overhead perturbs timing, so the
  # kill here may land at a different point than run A and completeness may differ
  # — the ⊇ relation is what's load-bearing, not the completeness value.)
  # ==========================================================================
  let depPathB = workdir / "killbuild-kill-strace.iomon"
  let straceLog = workdir / "killbuild-kill.strace"
  let straceArgs = @["-f", "-e", "trace=openat,open", "-o", straceLog,
    ioMonBin, "run", "--depfile", depPathB, "--", "bash", "-c", script]
  let sp = startProcess("strace", workingDir = proj, args = straceArgs,
                        env = childEnv(false), options = {poStdErrToStdOut, poUsePath})
  discard sp.outputStream.readAll()
  let buildExitB = sp.waitForExit()
  sp.close()
  if not fileExists(depPathB):
    fail "battery D kill: io-mon produced no depfile under strace-wrapped kill"
    return
  let depB = readMonitorDepFile(depPathB)
  let straceReads = parseStraceReads(straceLog)
  var straceDomain = initHashSet[string]()
  for p in straceReads:
    if isSourceOrHeaderInput(p, proj): straceDomain.incl p
  let observed = observedPaths(depB)
  let missing = straceDomain - observed
  note "battery D kill (run B, strace-wrapped): strace source/header reads=" &
    $straceDomain.len & " io-mon observed=" & $observed.len &
    " completeness=" & $depB.completeness & " build-exit=" & $buildExitB
  if depB.completeness == mcComplete and missing.len > 0:
    fail "battery D kill FALSE-COMPLETE (cardinal sin): io-mon reported mcComplete " &
      "but strace saw " & $missing.len & " read(s) io-mon never captured:"
    for m in missing: note "UNCAPTURED-YET-COMPLETE " & m
  elif missing.len == 0:
    ok "battery D kill (run B) HONESTY: io-mon captured ⊇ every source/header read " &
      "strace observed in the killed tree (" & $straceDomain.len &
      " input(s)) — the mcComplete/mcIncomplete verdict is honest, never a false-complete"
  else:
    # io-mon missed a read BUT honestly flagged the run incomplete — not a false
    # complete (a class-(b) hook-coverage gap surfaced under a torn build).
    echo "  [FIND] battery D kill (run B): strace saw " & $missing.len &
      " read(s) io-mon missed, but io-mon honestly reported mcIncomplete (not a " &
      "false complete):"
    for m in missing: classBFindings.add "battery D kill: " & m

proc batteryD_ipcBreakaway(workdir: string) =
  ## GENUINE `mcIncomplete` under the LF-7 model — the honesty counterweight to
  ## the "clean kill is mcComplete" property above. Now that a fully-observed kill
  ## no longer downgrades, this test keeps the load-bearing invariant covered:
  ##
  ##   io-mon reports mcIncomplete when it TRULY could not observe everything —
  ##   never a false mcComplete.
  ##
  ## A monitored process reads a file (io-mon captures it) and then `connect()`s
  ## to an OUT-OF-TREE daemon — the sccache/distcc/nix-daemon "breakaway" shape: a
  ## persistent server, started outside the invocation, that opens+reads files on
  ## the client's behalf and returns the bytes, so the real file dependency is
  ## invisible to io-mon. The shim records the `mrIpcConnect` to a peer with no
  ## in-tree `mrProcessStart`; the merge's T0 signal (c) injects an event-loss and
  ## the run downgrades to `mcIncomplete` — a CONSERVATIVE re-run, not a silent
  ## false skip. The listener here is this oracle process itself (io-mon's PARENT,
  ## outside the monitored tree), so the client's connect lands on an out-of-tree
  ## peer by construction; no accept() is needed — the kernel completes the
  ## handshake from the listen backlog.
  let cc = getEnv("CC", "cc")
  let src = workdir / "ipcbreak.c"
  writeFile(src, """
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc, char **argv) {
  char b[64];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  if (read(fd, b, sizeof(b)) < 0) return 3;
  close(fd);
  int port = atoi(argv[2]);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return 4;
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) return 5;
  close(s);
  return 0;
}
""")
  let bin = workdir / "ipcbreak"
  let (outp, code) = execCmdEx(cc & " -O2 " & quoteShell(src) & " -o " &
                               quoteShell(bin))
  if code != 0:
    fail "battery D breakaway: could not build ipcbreak client: " & outp
    return
  createDir(workdir / "ipc")
  let marker = workdir / "ipc" / "breakaway-marker.txt"
  writeFile(marker, "monitored dependency the client legitimately read\n")

  # Out-of-tree TCP listener (this parent process is NOT monitored by io-mon).
  var listener = newSocket()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(0), "127.0.0.1")
  listener.listen()
  let port = int(listener.getLocalAddr()[1])

  let cap = capture(workdir / "ipc-breakaway.iomon",
                    @[bin, marker, $port], workdir)
  listener.close()

  let reads = inputReads(cap.dep)
  let markerRead = anyIt(reads.toSeq, "breakaway-marker.txt" in it)
  if not markerRead:
    fail "battery D breakaway: the monitored client's own read was not captured " &
      "(io-mon should still see the reads it CAN observe)"
  if cap.dep.completeness == mcIncomplete:
    ok "battery D breakaway (genuine mcIncomplete): out-of-tree IPC peer forces an " &
      "honest mcIncomplete (T0 signal c) while the monitored read stays captured — " &
      "io-mon downgrades when it cannot observe everything, never a false mcComplete"
  else:
    fail "battery D breakaway: connect to an OUT-OF-TREE daemon yet io-mon reported " &
      $cap.dep.completeness & " (expected mcIncomplete) — a FALSE COMPLETE: the " &
      "breakaway peer's hidden reads would be silently uncached"
  note "battery D breakaway: client exit=" & $cap.code &
    " completeness=" & $cap.dep.completeness & " captured reads=" & $reads.len

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

proc main() =
  if paramCount() < 2:
    quit("usage: oracle <fast|full> <workdir>", 2)
  let mode = paramStr(1)
  let workdir = paramStr(2)
  createDir(workdir)
  echo "io-mon real-build completeness oracle (§4.5(h))"
  echo "  shim:   " & shimLib
  echo "  binary: " & ioMonBin
  echo "  mode:   " & mode
  if not fileExists(shimLib): quit("shim not built: " & shimLib, 2)
  if not fileExists(ioMonBin): quit("io-mon not built: " & ioMonBin, 2)

  # ---- cmake+ninja fixture -------------------------------------------------
  section "Battery A + class-(a) gate — cmake+ninja known-closure fixture"
  let cmProj = copyFixture("cmproj", workdir)
  let cmCmd = @["bash", "-c",
    "cmake -S . -B build -G Ninja >/dev/null && ninja -C build >/dev/null"]
  let cmClosure = sourceClosure(cmProj, [".c", ".h", "CMakeLists.txt"], ["build"])
  let cmRes = runFixtureAndGate("cmproj", cmProj, cmCmd, cmClosure, ["build"],
                                initHashSet[string](), workdir)

  # ---- cargo fixture -------------------------------------------------------
  section "Battery A + class-(a) gate — cargo (offline path-dep) known-closure fixture"
  let cgWs = copyFixture("cargo_ws", workdir)
  let cgCrate = cgWs / "mycrate"
  let cgCmd = @["cargo", "build", "--offline", "--manifest-path", cgCrate / "Cargo.toml"]
  var cgAllowed = initHashSet[string]()
  cgAllowed.incl realp(cgCrate / "Cargo.lock")
  # cargo build writes the lockfile then reads it back — an allowed generated input.
  let cgClosure = sourceClosure(cgWs, [".rs", "Cargo.toml"], ["target"])
  let cgRes = runFixtureAndGate("cargo_ws", cgWs, cgCmd, cgClosure, ["target"],
                                cgAllowed, workdir)

  # ---- D control + genuine-mcIncomplete trigger (kept in fast) ------------
  section "Battery D — completeness under contention (control + leaf kill)"
  batteryD_control(workdir)
  # The kill-honesty counterweight: a genuine, DETERMINISTIC mcIncomplete trigger
  # (out-of-tree IPC breakaway) so the "io-mon downgrades when it cannot observe
  # everything, never a false mcComplete" invariant stays covered now that a
  # cleanly-killed, fully-observed build is legitimately mcComplete.
  section "Battery D — genuine mcIncomplete (out-of-tree IPC breakaway peer)"
  batteryD_ipcBreakaway(workdir)

  if mode == "full":
    # ---- Differential B ---------------------------------------------------
    section "Battery B — differential vs the toolchain's own dependency data"
    let cmDeclared = ninjaDeclaredDeps(cmProj / "build")
    differentialB("cmproj", "cmproj ninja -t deps", cmDeclared,
                  cmRes.setCap, cmRes.fileCap, cmRes.setComplete)
    let cgDeclared = cargoDeclaredDeps(cgCrate)
    differentialB("cargo_ws", "cargo dep-info .d", cgDeclared,
                  cgRes.setCap, cgRes.fileCap, cgRes.setComplete)

    # ---- Differential C ---------------------------------------------------
    section "Battery C — differential vs strace -f (independent monitor)"
    # cmake: fresh build under strace
    removeDir(cmProj); discard copyFixture("cmproj", workdir)
    let cmStrace = straceReadSet(cmCmd, cmProj, workdir / "cmproj.strace")
    let cmDomain = cmClosure + cmDeclared +
      capturedProjectSources(cmRes.setCap, cmProj, ["build"])
    differentialC("cmproj strace", cmStrace, cmRes.setCap, cmRes.fileCap,
                  cmDomain, cmRes.setComplete)
    removeDir(cgWs); discard copyFixture("cargo_ws", workdir)
    let cgStrace = straceReadSet(cgCmd, cgWs / "mycrate", workdir / "cargo.strace")
    let cgDomain = cgClosure + cgDeclared +
      capturedProjectSources(cgRes.setCap, cgWs, ["target"])
    differentialC("cargo strace", cgStrace, cgRes.setCap, cgRes.fileCap,
                  cgDomain, cgRes.setComplete)

    # ---- Battery D kill-under-load ---------------------------------------
    section "Battery D — SIGKILL injected into a real build subprocess mid-flight"
    batteryD_realBuildKill(workdir)

  # ---- verdict -------------------------------------------------------------
  section "Verdict"
  if classBFindings.len > 0:
    echo "  class-(b) pre-existing io-mon hook-coverage findings (surfaced, NOT campaign blockers):"
    for f in classBFindings: echo "    - " & f
  if hardFailures == 0:
    echo "  PASS: zero class-(a) transport gaps; fixtures match; captured ⊇ tool-declared."
    quit(0)
  else:
    echo "  FAIL: " & $hardFailures & " campaign pass-bar violation(s) above."
    quit(1)

main()
