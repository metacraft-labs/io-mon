## test_io_mon_process_start_image — every process-start names the file that
## ran: its `path` is the resolved, physical image.
##
## WHY. The exec and spawn records carry what the program PASSED. For
## `posix_spawnp` and the `execvp` family that is a bare name, which the
## program's OWN `PATH` resolves (and the program may have changed `PATH`);
## for a relative path it is resolved in the program's working directory at
## the exec, which no record carries; for `fexecve` it is a descriptor. A
## consumer judging WHICH file ran (for example, whether a process started
## from outside a declared closure) could not locate it from the capture. The
## child's own `mrProcessStart` now carries the kernel's answer: Linux reads
## `/proc/self/exe`, macOS `proc_pidpath`, both an absolute path with every
## symlink resolved (docs/usage.md, "The process-start image").
##
## What is graded, end to end through the real CLI and the real shim, for a
## target program reached by:
##   * `posix_spawnp` of a bare name, through a `PATH` the program set itself,
##     with a DIFFERENT file of the same name on the `PATH` it inherited;
##   * `execvp` of that bare name, the same way;
##   * a relative path, after the child `chdir`s;
##   * `posix_spawn` with a `chdir` file action and a relative path;
##   * a symlink to the target (the PHYSICAL path is recorded, not the link);
##   * `fexecve` of a descriptor (Linux; macOS has no `fexecve`);
## the capture has a process-start, from a pid other than the root's, whose
## path is the target's physical path; none names the decoy; the root's own
## process-start names the fixture program; and the capture is complete.
##
## NO MOCKS: a freshly compiled CLI, the production shim built from this
## checkout, and compiled C programs making real spawn/exec calls. POSIX
## (Linux + macOS); the Windows arm is
## `tests/windows/test_io_mon_windows_process_start_image.nim`.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

  # The program the capture monitors. Every mode starts the target once and
  # exits with its status (0 when the target ran and exited 0; 2 on a setup
  # error; 3 when the start itself failed).
  LauncherC = """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
static int reap(pid_t pid) {
  int st = 0;
  if (waitpid(pid, &st, 0) != pid) return 2;
  return WIFEXITED(st) ? WEXITSTATUS(st) : 3;
}
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  const char *mode = argv[1];
  char *child_argv[] = {(char *)"target", NULL};
  if (strcmp(mode, "spawnp") == 0 || strcmp(mode, "execvp") == 0) {
    /* argv[2] = name, argv[3] = the directory this program puts FIRST on its
       own PATH (the inherited PATH holds a decoy of the same name). */
    if (argc < 4) return 2;
    const char *old = getenv("PATH");
    char path[8192];
    snprintf(path, sizeof path, "%s:%s", argv[3], old ? old : "");
    if (setenv("PATH", path, 1) != 0) return 2;
    if (mode[0] == 's') {
      pid_t pid;
      if (posix_spawnp(&pid, argv[2], NULL, NULL, child_argv, environ) != 0)
        return 3;
      return reap(pid);
    }
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) { execvp(argv[2], child_argv); _exit(3); }
    return reap(pid);
  }
  if (strcmp(mode, "relative") == 0) {
    /* argv[2] = directory, argv[3] = path relative to it */
    if (argc < 4) return 2;
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
      if (chdir(argv[2]) != 0) _exit(2);
      execv(argv[3], child_argv);
      _exit(3);
    }
    return reap(pid);
  }
  if (strcmp(mode, "spawnchdir") == 0) {
    /* posix_spawn, a chdir file action, and a path relative to it */
    if (argc < 4) return 2;
    /* The target holds briefly: the Linux shim re-checks a chdir-action
       child through /proc/<child> before posix_spawn returns, and a child
       that has already exited makes that check report a loss (an open
       issue of its own, not what this test grades). */
    char *hold_argv[] = {(char *)"target", (char *)"hold", NULL};
    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa) != 0) return 2;
    if (posix_spawn_file_actions_addchdir_np(&fa, argv[2]) != 0) return 2;
    pid_t pid;
    int rc = posix_spawn(&pid, argv[3], &fa, NULL, hold_argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) return 3;
    return reap(pid);
  }
  if (strcmp(mode, "exec") == 0) {
    /* argv[2] = a path (here: a symlink to the target) */
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) { execv(argv[2], child_argv); _exit(3); }
    return reap(pid);
  }
#ifdef __linux__
  if (strcmp(mode, "fexecve") == 0) {
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
      int fd = open(argv[2], O_RDONLY);
      if (fd < 0) _exit(2);
      fexecve(fd, child_argv, environ);
      _exit(3);
    }
    return reap(pid);
  }
#endif
  return 2;
}
"""

  TargetC = """
#include <unistd.h>
int main(int argc, char **argv) {
  (void)argv;
  if (argc > 1) usleep(300000);   /* "hold" */
  return 0;
}
"""

  # The decoy exits 7, so a test that ran it instead fails on the exit status
  # as well as on the recorded path.
  DecoyC = """
int main(void) { return 7; }
"""

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

suite "io-mon: a process-start names the resolved image":
  let work = expandFilename(getTempDir()) /
    ("io-mon-start-image-" & $getCurrentProcessId())
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
    let cc = run(getEnv("CC", "cc"), @["-Wno-deprecated-declarations",
      work / (name & ".c"), "-o", outPath])
    checkpoint(cc.output)
    require cc.code == 0

  createDir(work / "bin")
  createDir(work / "decoy")
  createDir(work / "link")
  let launcher = work / "launcher"
  compile(LauncherC, "launcher", launcher)
  compile(TargetC, "target", work / "bin" / "tgt")
  compile(DecoyC, "decoy", work / "decoy" / "tgt")
  createSymlink(work / "bin" / "tgt", work / "link" / "tgt")
  # `work` went through `expandFilename`, so these are physical already
  # (macOS's temp directory lives under the /var -> /private/var link).
  let target = expandFilename(work / "bin" / "tgt")
  let decoy = expandFilename(work / "decoy" / "tgt")
  let physicalLauncher = expandFilename(launcher)
  require target == work / "bin" / "tgt"

  proc capture(tag: string; args: seq[string]):
      tuple[dep: MonitorDepFile; code: int] =
    let depfile = work / (tag & ".iomon")
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    # The decoy is what the INHERITED PATH would find.
    env["PATH"] = (work / "decoy") & ":" & getEnv("PATH")
    let r = run(snoopBin, @["run", "--depfile", depfile, "--", launcher] &
      args, env)
    checkpoint(tag & ": " & r.output)
    (readMonitorDepFile(depfile), r.code)

  proc starts(dep: MonitorDepFile): seq[MonitorRecord] =
    dep.records.filterIt(it.kind == mrProcessStart)

  proc rootPid(dep: MonitorDepFile): uint64 =
    ## The launcher's pid: the one process-start naming the launcher image
    ## whose parent did not also start (the CLI is not monitored).
    let pids = dep.starts.mapIt(it.osPid)
    for r in dep.starts:
      if r.parentOsPid notin pids: return r.osPid
    0

  # A template, not a proc: a `check` must expand inside the test body to
  # fail that test (in a proc it only sets the exit code).
  template checkResolved(tag: string; args: seq[string]) =
    let (dep, code) = capture(tag, args)
    check code == 0                  # the target ran (the decoy exits 7)
    let s = dep.starts
    checkpoint(tag & " process-starts: " &
      s.mapIt($it.osPid & ":" & it.path & " [" & it.detail & "]").join("; "))
    let root = dep.rootPid
    check root != 0
    let hits = s.filterIt(it.path == target)
    check hits.len >= 1
    check hits.allIt(it.osPid != root)
    check s.allIt(it.path != decoy)
    # The root's own start names the launcher, and no start is unresolved.
    check s.anyIt(it.osPid == root and it.path == physicalLauncher)
    check s.allIt(it.path.len > 0 and it.path.isAbsolute)
    check s.allIt("image=unresolved" notin it.detail)
    check dep.completeness == mcComplete

  test "posix_spawnp of a bare name through a PATH the program set":
    checkResolved("spawnp", @["spawnp", "tgt", work / "bin"])

  test "execvp of a bare name through a PATH the program set":
    checkResolved("execvp", @["execvp", "tgt", work / "bin"])

  test "a relative path after chdir":
    checkResolved("relative", @["relative", work / "bin", "./tgt"])

  test "posix_spawn with a chdir file action and a relative path":
    checkResolved("spawnchdir", @["spawnchdir", work / "bin", "./tgt"])

  test "a symlinked executable records the physical path, not the link":
    checkResolved("symlink", @["exec", work / "link" / "tgt"])
    let (dep, _) = capture("symlink-again", @["exec", work / "link" / "tgt"])
    check dep.starts.allIt(it.path != work / "link" / "tgt")

  when defined(linux):
    test "fexecve of a descriptor":
      checkResolved("fexecve", @["fexecve", work / "bin" / "tgt"])

  removeDir(work)
