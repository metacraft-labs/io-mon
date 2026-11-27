## test_io_mon_spawn_record_without_pid — a successful `posix_spawn` or
## `posix_spawnp` writes its `mrProcessSpawn` record whether or not the caller
## asked for the child's pid.
##
## WHY. POSIX lets the caller pass a NULL pid pointer
## (https://pubs.opengroup.org/onlinepubs/9799919799/functions/posix_spawn.html:
## "If pid is not a null pointer, posix_spawn() shall store the process ID of
## the child process in the variable pointed to by pid"). A fire-and-forget
## caller, or one that reaps with `wait(&status)` / `waitpid(-1, …)`, does
## exactly that. The shim knows the child either way: on Linux it lends the
## call a pid slot, because the tree ledger needs the pid; on macOS it lends
## one for the record. Until reprobuild-pm
## `issues/2026-11-22-a-posix-spawn-with-a-null-pid-pointer-writes-no-spawn-record.md`
## both shims still gated the record on the CALLER's pointer, so such a spawn
## left no `mrProcessSpawn` at all. On Linux that record is the only one naming
## the image a `posix_spawn` child runs (glibc performs the child's `execve`
## below the interposed symbol), and a consumer that keys on executed images
## lost the child's binary; the process-tree merge saw a start nothing named.
##
## What is graded, end to end through the real CLI and the real shim:
##   * `posix_spawn(NULL, <absolute path>, …)` reaped with `wait`;
##   * `posix_spawnp(NULL, <bare name>, …)` reaped with `wait`;
##   * the same two with a pid pointer, as the control that the assertions
##     below hold for the shape that always worked;
## each capture has exactly one `mrProcessSpawn` from the launcher whose
## `childOsPid` is the pid of the target's own process-start and whose path is
## the image as passed (the absolute path, or the bare name, which
## `posix_spawnp` searches for on `PATH` and the record therefore keeps as
## spelled), and the capture is complete.
##
## NO MOCKS: a freshly compiled CLI, the production shim built from this
## checkout, and a compiled C program making real spawn calls. POSIX (Linux +
## macOS).

import foreign_preload_isolation

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

  # argv[1] = "spawn" | "spawnp", argv[2] = "pid" | "nopid", argv[3] = the
  # image as handed to the call. Exits 0 when the target ran and exited 0,
  # 2 on a usage error, 3 when the spawn failed, 4 when the reap failed.
  LauncherC = """
#include <spawn.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
extern char **environ;
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  int usePath = strcmp(argv[1], "spawnp") == 0;
  int wantPid = strcmp(argv[2], "pid") == 0;
  char *child_argv[] = {argv[3], 0};
  pid_t pid = 0;
  pid_t *pidp = wantPid ? &pid : 0;
  int rc = usePath
    ? posix_spawnp(pidp, argv[3], 0, 0, child_argv, environ)
    : posix_spawn(pidp, argv[3], 0, 0, child_argv, environ);
  if (rc != 0) return 3;
  int st = 0;
  /* A caller that discarded the pid reaps whichever child exits: `wait`. */
  pid_t reaped = wait(&st);
  if (reaped <= 0 || (wantPid && reaped != pid)) return 4;
  return WIFEXITED(st) ? WEXITSTATUS(st) : 4;
}
"""

  TargetC = """
int main(void) { return 0; }
"""

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon: a posix_spawn is recorded whether or not the caller asked for the pid":
  let work = expandFilename(getTempDir()) /
    ("io-mon-spawn-nopid-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let snoopBin = work / "io-mon"
  let cli = run("nim", @["c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--nimcache:" & (work / "nimcache"), "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0
  let shimLib =
    when defined(macosx): buildPrivateMacosShim(repoRoot)
    else: buildPrivateLinuxShim(repoRoot)

  proc compile(src, name: string; outPath: string) =
    writeFile(work / (name & ".c"), src)
    let cc = run(getEnv("CC", "cc"), @[work / (name & ".c"), "-o", outPath])
    checkpoint(cc.output)
    require cc.code == 0

  createDir(work / "bin")
  let launcher = work / "launcher"
  compile(LauncherC, "launcher", launcher)
  compile(TargetC, "target", work / "bin" / "spawn_nopid_tgt")
  # `work` went through `expandFilename`, so this is physical already: the
  # path a process-start records and the path handed to `posix_spawn` agree.
  let target = work / "bin" / "spawn_nopid_tgt"
  require expandFilename(target) == target

  proc capture(tag: string; args: seq[string]):
      tuple[dep: MonitorDepFile; code: int] =
    let depfile = work / (tag & ".iomon")
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    # `posix_spawnp` finds the bare name here.
    env["PATH"] = (work / "bin") & ":" & getEnv("PATH")
    let r = run(snoopBin, @["run", "--depfile", depfile, "--", launcher] &
      args, env)
    checkpoint(tag & ": " & r.output)
    (readMonitorDepFile(depfile), r.code)

  # A template, not a proc: a `check` must expand inside the test body to
  # fail that test (in a proc it only sets the exit code).
  template checkSpawnRecorded(tag, entry, pidMode, image: string) =
    let (dep, code) = capture(tag, @[entry, pidMode, image])
    check code == 0
    let starts = dep.records.filterIt(it.kind == mrProcessStart)
    let spawns = dep.records.filterIt(it.kind == mrProcessSpawn)
    checkpoint(tag & " process-starts: " &
      starts.mapIt($it.osPid & ":" & it.path).join("; "))
    checkpoint(tag & " spawns: " & spawns.mapIt($it.osPid & "->" &
      $it.childOsPid & ":" & it.path & " [" & it.detail & "]").join("; "))
    let launcherStarts = starts.filterIt(it.path == launcher)
    let targetStarts = starts.filterIt(it.path == target)
    check launcherStarts.len == 1
    check targetStarts.len == 1
    if launcherStarts.len == 1 and targetStarts.len == 1:
      let fromLauncher = spawns.filterIt(it.osPid == launcherStarts[0].osPid)
      # One record for the one user-level spawn (macOS reaches its real
      # `posix_spawnp` through an internal `posix_spawn`; that is not a second).
      check fromLauncher.len == 1
      if fromLauncher.len == 1:
        let s = fromLauncher[0]
        check s.childOsPid == targetStarts[0].osPid
        check s.result == 0
        check s.path == image
        check ("posix_" & entry) in s.detail
    check dep.completeness == mcComplete

  test "posix_spawn with a NULL pid pointer, by absolute path":
    checkSpawnRecorded("spawn-nopid", "spawn", "nopid", target)

  test "posix_spawnp with a NULL pid pointer, by bare name":
    checkSpawnRecorded("spawnp-nopid", "spawnp", "nopid", "spawn_nopid_tgt")

  test "control: posix_spawn with a pid pointer":
    checkSpawnRecorded("spawn-pid", "spawn", "pid", target)

  test "control: posix_spawnp with a pid pointer":
    checkSpawnRecorded("spawnp-pid", "spawnp", "pid", "spawn_nopid_tgt")

  removeDir(work)
