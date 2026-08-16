## Linux: the monitor must not change how the monitored process resolves a
## `dlopen`.
##
## glibc resolves a BARE soname handed to `dlopen` against the DT_RPATH /
## DT_RUNPATH of the object that CALLED dlopen, expanding `$ORIGIN` against that
## object's directory. It identifies that object from dlopen's RETURN ADDRESS.
##
## The LD_PRELOAD shim interposes `dlopen`, so before the fix the return address
## glibc saw belonged to `librepro_monitor_shim.so`: the monitored program's own
## RUNPATH stopped governing the lookup and a `dlopen("libfoo.so")` that succeeds
## unmonitored failed under the monitor with "cannot open shared object file".
##
## That is a monitor changing the behaviour of the process it observes — the one
## thing a monitor may never do. Every dependency set captured from such a run
## describes a DIFFERENT execution than the unmonitored one, so a consumer
## (reprobuild) caching against it caches a fiction. Consumers had been papering
## over it by listing the toolchain's private libraries on the process-wide
## LD_LIBRARY_PATH, which only ever covers the libraries someone remembered to
## enumerate.
##
## NO MOCKS. Real `cc`-built shared objects, the real shim, the real `io-mon run`
## driver, and the real dynamic loader. The assertions below compare the
## MONITORED outcome against the UNMONITORED outcome measured in the same run,
## so the test states the invariant ("observation does not perturb") rather than
## a hard-coded expectation.

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc childEnvWith(extra: openArray[(string, string)]): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  for (k, v) in extra: result[k] = v

suite "io-mon Linux dlopen caller-relative resolution":
  let work = getTempDir() / ("io-mon-dlopen-runpath-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  createDir(work / "privlib")
  createDir(work / "envlib")

  let cc = getEnv("CC", "cc")

  # Two DIFFERENT `libplug.so` builds with the same soname. `plug_answer`
  # returns a different value from each, so the test can tell WHICH copy the
  # loader picked — that is what makes the LD_LIBRARY_PATH-precedence assertion
  # falsifiable rather than a smoke test.
  proc buildPlug(dir: string; answer: int) =
    let src = work / ("plug" & $answer & ".c")
    writeFile(src, "int plug_answer(void) { return " & $answer & "; }\n")
    let built = run(cc, @["-shared", "-fPIC", src, "-o", dir / "libplug.so"])
    checkpoint("plug " & $answer & ": " & built.output)
    require built.code == 0

  buildPlug(work / "privlib", 42)
  buildPlug(work / "envlib", 7)

  const appSource = """
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
  void *h = dlopen("libplug.so", RTLD_NOW);
  if (h == NULL) { fprintf(stderr, "dlopen-failed: %s\n", dlerror()); return 1; }
  int (*answer)(void) = (int (*)(void))dlsym(h, "plug_answer");
  if (answer == NULL) { fprintf(stderr, "dlsym-failed\n"); return 2; }
  printf("plug_answer=%d\n", answer());
  return 0;
}
"""

  # `--enable-new-dtags` emits DT_RUNPATH (the modern tag, searched AFTER
  # LD_LIBRARY_PATH); `--disable-new-dtags` emits legacy DT_RPATH (searched
  # BEFORE it). glibc treats the two differently, the fix reproduces both
  # orderings, so both get their own binary.
  proc buildApp(name: string; dtagFlag: string): string =
    result = work / name
    let src = work / (name & ".c")
    writeFile(src, appSource)
    let built = run(cc, @[src, "-o", result, "-ldl",
      "-Wl," & dtagFlag, "-Wl,-rpath,$ORIGIN/privlib"])
    checkpoint(name & ": " & built.output)
    require built.code == 0

  let runpathApp = buildApp("runpath_app", "--enable-new-dtags")
  let rpathApp = buildApp("rpath_app", "--disable-new-dtags")

  # Sanity: the fixtures really do carry the tag each case is about. Without
  # this a toolchain default flip would silently turn both cases into the same
  # test.
  let runpathTags = run("readelf", @["-d", runpathApp])
  check "RUNPATH" in runpathTags.output
  let rpathTags = run("readelf", @["-d", rpathApp])
  check "RPATH" in rpathTags.output
  check "RUNPATH" notin rpathTags.output

  # Build the CLI and the shim once for the whole suite.
  let snoopBin = work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0

  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()

  proc captureRun(app, depfile: string; extraEnv: openArray[(string, string)] = []):
      tuple[output: string; code: int] =
    run(snoopBin, @["run", "--depfile", depfile, "--", app],
      childEnvWith(@[("REPRO_MONITOR_SHIM_LIB", shimLib)] & @extraEnv))

  test "DT_RUNPATH soname resolves identically monitored and unmonitored":
    let bare = run(runpathApp, @[])
    checkpoint("unmonitored: " & bare.output)
    # Establishes the ground truth in this environment rather than assuming it.
    require bare.code == 0
    require "plug_answer=42" in bare.output

    let depfile = work / "runpath.rdep"
    let monitored = captureRun(runpathApp, depfile)
    checkpoint("monitored: " & monitored.output)

    # THE regression: before the fix this exited 1 with
    # "dlopen-failed: libplug.so: cannot open shared object file".
    check monitored.code == bare.code
    check "dlopen-failed" notin monitored.output
    check monitored.output.strip() == bare.output.strip()

    # And the capture itself must still be produced and honest.
    check fileExists(depfile)
    let dep = readMonitorDepFile(depfile)
    check dep.completeness == mcComplete

  test "legacy DT_RPATH soname resolves identically monitored and unmonitored":
    let bare = run(rpathApp, @[])
    checkpoint("unmonitored: " & bare.output)
    require bare.code == 0
    require "plug_answer=42" in bare.output

    let depfile = work / "rpath.rdep"
    let monitored = captureRun(rpathApp, depfile)
    checkpoint("monitored: " & monitored.output)
    check monitored.code == bare.code
    check "dlopen-failed" notin monitored.output
    check monitored.output.strip() == bare.output.strip()

  test "LD_LIBRARY_PATH still beats DT_RUNPATH under the monitor":
    # glibc searches LD_LIBRARY_PATH BEFORE DT_RUNPATH. Restoring the caller's
    # RUNPATH must not promote it over LD_LIBRARY_PATH: the monitored process
    # must load the SAME copy the unmonitored one does. `envlib` answers 7,
    # `privlib` (the RUNPATH dir) answers 42, so the two are distinguishable.
    let envDir = work / "envlib"
    let bare = run(runpathApp, @[],
      childEnvWith([("LD_LIBRARY_PATH", envDir)]))
    checkpoint("unmonitored: " & bare.output)
    require bare.code == 0
    require "plug_answer=7" in bare.output

    let depfile = work / "precedence.rdep"
    let monitored = captureRun(runpathApp, depfile,
      [("LD_LIBRARY_PATH", envDir)])
    checkpoint("monitored: " & monitored.output)
    check monitored.code == bare.code
    check monitored.output.strip() == bare.output.strip()

  test "a genuinely missing soname still fails identically under the monitor":
    # The fix must not paper over real failures: an unresolvable soname has to
    # keep failing, and with the monitored exit status matching the unmonitored
    # one. Otherwise "does not perturb" would be satisfiable by a resolver that
    # invents libraries.
    let missingApp = work / "missing_app"
    let src = work / "missing_app.c"
    writeFile(src, appSource.replace("libplug.so", "libnosuchplug.so"))
    let built = run(cc, @[src, "-o", missingApp, "-ldl",
      "-Wl,--enable-new-dtags", "-Wl,-rpath,$ORIGIN/privlib"])
    checkpoint(built.output)
    require built.code == 0

    let bare = run(missingApp, @[])
    require bare.code == 1
    require "dlopen-failed" in bare.output

    let depfile = work / "missing.rdep"
    let monitored = captureRun(missingApp, depfile)
    checkpoint("monitored: " & monitored.output)
    check monitored.code == bare.code
    check "dlopen-failed" in monitored.output
    # Comparing the whole message, not just the failure, is what makes this
    # falsifiable: a resolver that rewrote the unresolvable soname into a
    # RUNPATH-relative path would still fail, but `dlerror` would name that
    # invented path instead of the soname the program asked for.
    check monitored.output.strip() == bare.output.strip()
