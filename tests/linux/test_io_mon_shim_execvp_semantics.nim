## Under the shim, the PATH-searching exec family behaves exactly as glibc's.
##
## WHY. The shim cannot see inside glibc's PATH search, so its execvp,
## execvpe and execlp hooks record the exec themselves and then hand the
## search to glibc's execvpe with a prepared environment (LD_PRELOAD and the
## next REPRO_MONITOR_EXEC_GEN). Two earlier versions changed what the host
## observed:
##   - the exec hook called the real execve on the name it was given before
##     the PATH search; for a name without a slash that resolves against the
##     CURRENT DIRECTORY, so with an executable `./name` present the host ran
##     it instead of the PATH entry, which execvp never does;
##   - the hooks replaced the host's `environ` with an array from the shim's
##     heap, which a host that manages `environ` with its own allocator (bash)
##     later freed or realloc'd.
##
## WHAT THIS TEST GRADES — on a debug and a release shim, preloaded and under
## `io-mon run`:
##   `t_path_search_semantics_are_glibcs` — execvp of a name present both in
##   the current directory and on PATH runs the PATH entry; a missing name
##   fails with ENOENT and a non-executable one with EACCES, leaving `environ`
##   the same array; a PATH entry without a `#!` line runs through /bin/sh
##   (ENOEXEC); execlp behaves as execvp.
##   `t_path_search_children_are_monitored` — a child started through
##   execvp or execlp, or under `io-mon run` through execvpe with an
##   environment that lacks LD_PRELOAD, carries LD_PRELOAD and the same exec
##   generation as one started through execv with the full path.
##
## Mocks: none. The probe and the PATH entries are real programs.

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil;
         workingDir = ""): tuple[output: string; code: int] =
  let p = startProcess(cmd, workingDir = workingDir, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc baseEnv(): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result.del("LD_PRELOAD")

proc ensureShim(): string =
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(built.output)
  check built.code == 0
  findShimLibrary()

proc ensureReleaseShim(work: string): string =
  var env = baseEnv()
  env["IO_MON_BUILD_MODE"] = "release"
  env["IO_MON_SHIM_OUT_DIR"] = work / "release-lib"
  env["IO_MON_SHIM_NIMCACHE_DIR"] = work / "release-nimcache"
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"], env)
  checkpoint(built.output)
  check built.code == 0
  result = work / "release-lib" / "librepro_monitor_shim.so"

proc ensureSnoop(work: string): string =
  result = work / "io-mon"
  if not fileExists(result):
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & result, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

const probeSource = """
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
/* probe <mode> <name>: report how failing PATH searches behaved, then exec
 * <name> with the exec function <mode> names. */
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  const char *mode = argv[1], *name = argv[2];
  char **before = environ;
  char *missing[] = {"io-mon-no-such-program", NULL};
  execvp(missing[0], missing);
  printf("probe missing errno=%s environ-kept=%d\n",
         strerror(errno), environ == before);
  char *noexec[] = {"io-mon-not-executable", NULL};
  execvp(noexec[0], noexec);
  printf("probe noexec errno=%s environ-kept=%d\n",
         strerror(errno), environ == before);
  fflush(stdout);
  char *args[] = {(char *)name, NULL};
  if (strcmp(mode, "execvp") == 0) {
    execvp(name, args);
  } else if (strcmp(mode, "execlp") == 0) {
    execlp(name, name, (char *)NULL);
  } else if (strcmp(mode, "execvpe") == 0) {
    char path[4096];
    snprintf(path, sizeof path, "PATH=%s", getenv("PATH"));
    char *env[] = {path, "PROBE_OWN_ENV=1", NULL};
    execvpe(name, args, env);
  } else if (strcmp(mode, "execv") == 0) {
    execv(name, args);
  }
  printf("probe exec failed: %s\n", strerror(errno));
  return 1;
}
"""

proc writeScript(path, body: string) =
  writeFile(path, body)
  setFilePermissions(path, {fpUserRead, fpUserWrite, fpUserExec,
    fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})

proc field(output, key: string): string =
  ## The value after `key=` on the probe target's line, up to a space.
  for line in output.splitLines():
    if line.startsWith("RAN-PATH-COPY"):
      for word in line.splitWhitespace():
        if word.startsWith(key & "="):
          return word[key.len + 1 .. ^1]
  "<absent>"

suite "io-mon shim keeps glibc's PATH-search exec semantics":
  let work = getTempDir() / ("io-mon-execvp-" & $getCurrentProcessId())
  createDir(work)
  let shims = [("debug", ensureShim()), ("release", ensureReleaseShim(work))]
  let snoopBin = ensureSnoop(work)
  let probe = work / "probe"
  writeFile(work / "probe.c", probeSource)
  let cc = run(getEnv("CC", "cc"), @[work / "probe.c", "-o", probe])
  checkpoint(cc.output)
  check cc.code == 0
  let cwdDir = work / "cwd"
  let pathDir = work / "pathdir"
  createDir(cwdDir)
  createDir(pathDir)
  writeScript(cwdDir / "io-mon-probe-target",
    "#!/bin/sh\necho RAN-CWD-COPY\n")
  writeScript(pathDir / "io-mon-probe-target",
    "#!/bin/sh\necho RAN-PATH-COPY gen=${REPRO_MONITOR_EXEC_GEN:-none} " &
    "preload=${LD_PRELOAD:+yes} own=${PROBE_OWN_ENV:-0}\n")
  writeScript(pathDir / "io-mon-probe-noshebang", "echo RAN-VIA-BIN-SH\n")
  writeFile(pathDir / "io-mon-not-executable", "not a program\n")

  proc variants(): seq[tuple[label: string; prefix: seq[string];
                             env: StringTableRef]] =
    for (mode, shimLib) in shims:
      var env = baseEnv()
      env["PATH"] = pathDir & ":" & getEnv("PATH")
      var pre = newStringTable(modeCaseSensitive)
      for k, v in env: pre[k] = v
      pre["LD_PRELOAD"] = shimLib
      result.add((mode & " preloaded", newSeq[string](), pre))
      var mon = newStringTable(modeCaseSensitive)
      for k, v in env: mon[k] = v
      mon["REPRO_MONITOR_SHIM_LIB"] = shimLib
      result.add((mode & " monitored",
        @[snoopBin, "run", "--depfile",
          work / ("execvp-" & mode & "-" & $result.len & ".iomon"), "--"],
        mon))

  proc runProbe(prefix: seq[string]; env: StringTableRef;
                mode, name: string): tuple[output: string; code: int] =
    let argv = prefix & @[probe, mode, name]
    run("timeout", @["-s", "KILL", "60"] & argv, env, workingDir = cwdDir)

  test "t_path_search_semantics_are_glibcs":
    var bareEnv = baseEnv()
    bareEnv["PATH"] = pathDir & ":" & getEnv("PATH")
    let bare = runProbe(@[], bareEnv, "execvp", "io-mon-probe-target")
    checkpoint("without shim:\n" & bare.output)
    check "RAN-PATH-COPY" in bare.output
    for v in variants():
      for mode in ["execvp", "execlp"]:
        let r = runProbe(v.prefix, v.env, mode, "io-mon-probe-target")
        checkpoint(v.label & " " & mode & " (exit " & $r.code & "):\n" &
          r.output)
        check r.code == 0
        check "RAN-PATH-COPY" in r.output
        check "RAN-CWD-COPY" notin r.output
        check "probe missing errno=No such file or directory environ-kept=1" in
          r.output
        check "probe noexec errno=Permission denied environ-kept=1" in r.output
      let sh = runProbe(v.prefix, v.env, "execvp", "io-mon-probe-noshebang")
      checkpoint(v.label & " ENOEXEC fallback (exit " & $sh.code & "):\n" &
        sh.output)
      check sh.code == 0
      check "RAN-VIA-BIN-SH" in sh.output

  test "t_path_search_children_are_monitored":
    for v in variants():
      let direct = runProbe(v.prefix, v.env, "execv",
        pathDir / "io-mon-probe-target")
      checkpoint(v.label & " execv (exit " & $direct.code & "):\n" &
        direct.output)
      check direct.code == 0
      check field(direct.output, "preload") == "yes"
      for mode in ["execvp", "execlp", "execvpe"]:
        # Preloaded without an io-mon session, the shim has no library path
        # of its own to inject: it carries the LD_PRELOAD the environment
        # already has, so an explicit environment without one starts an
        # unmonitored child, through execve as through execvpe.
        if mode == "execvpe" and "monitored" notin v.label: continue
        let r = runProbe(v.prefix, v.env, mode, "io-mon-probe-target")
        checkpoint(v.label & " " & mode & " (exit " & $r.code & "):\n" &
          r.output)
        check r.code == 0
        check field(r.output, "preload") == "yes"
        check field(r.output, "gen") == field(direct.output, "gen")
        if mode == "execvpe":
          check field(r.output, "own") == "1"

  removeDir(work)
