## Entering an image the loader will not inject the shim into is event-loss.
##
## THE DEFECT THIS PINS (reprobuild-pm issue
## 2026-10-22-linux-process-whose-loader-ignores-the-shim-is-graded-complete).
## glibc's loader refuses a 64-bit `LD_PRELOAD` object in a 32-bit process
## ("wrong ELF class: ignored") and runs the program anyway, and a static
## binary has no loader at all. Either way that image runs with no shim and
## leaves no record. The merge's process-tree signals did not notice when the
## unmonitored image later exec'd a monitored one IN THE SAME PID: the
## monitored image emitted that pid's `process-start`, so "spawn child missing
## process-start" was satisfied, and the unmonitored image recorded no exec, so
## "execs >= starts" balanced. Measured at io-mon 8b6e94ae: `i686-bash -c
## '<64-bit helper> in.txt'` graded `mcComplete` with no event-loss, although
## everything bash itself did was unobserved.
##
## WHAT THIS TEST GRADES. Each way a monitored context can start an image --
## the root spawn, every exec entry point the shim hooks (execve, execvp's
## PATH search, fexecve, posix_spawn -- also with a file action that changes
## the child's directory before a relative name is resolved --, posix_spawnp),
## and the raw `execve`
## system call through syscall(2) and through an inline `syscall`
## instruction, and an execve from a raw-clone child that skips monitor
## bookkeeping and so can only report the loss unnamed -- is driven into an
## image the shim cannot enter: an i686
## dynamic shell, a static and a static-pie x86_64 binary, an execute-only
## (mode --x) static binary whose header cannot be read, and a `#!` script
## whose interpreter is the i686 shell. The uninjectable image then execs a
## monitored 64-bit helper in the same pid, the shape that defeated the
## counting signals. Each capture must be `mcIncomplete`, with an event-loss
## whose detail names the uninjectable image. The negative controls -- an
## ordinary dynamic root, a script with a 64-bit interpreter, ld.so run
## directly (it honours LD_PRELOAD), and execs that fail (a missing file, a
## file that is neither ELF nor `#!`) before a good one -- must stay
## `mcComplete`: a false loss makes an action uncacheable.
##
## The i686 shell comes from io-mon's dev shell (`IO_MON_TEST_I686_SH`,
## `pkgsi686Linux.bash`). On x86_64-linux a missing value FAILS this test
## rather than skipping it, so a CI shell that lost the variable cannot pass
## vacuously; on other hosts the i686 and x86_64-only cases report an explicit
## skip.
##
## Mocks: none. Real programs, the real shim, the real `io-mon run` driver.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  i686Applicable = defined(amd64)
    ## Where an i686 image and the freestanding x86_64 fixtures exist.

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil;
         workDir = ""): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env, workingDir = workDir,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

const helperSource = """
#include <fcntl.h>
#include <unistd.h>
/* The monitored 64-bit helper: reads the file it is given. */
int main(int argc, char **argv) {
  if (argc < 2) return 20;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 21;
  char buf[16];
  if (read(fd, buf, sizeof(buf)) <= 0) return 22;
  close(fd);
  return 0;
}
"""

const hostSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#ifdef __x86_64__
/* An inline `syscall` instruction, which the shim patches to trap. */
static long __attribute__((noinline))
raw3(long nr, long a0, long a1, long a2) {
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(nr), "D"(a0), "S"(a1), "d"(a2)
                   : "rcx", "r11", "memory");
  return ret;
}
#endif

static int spawn_and_wait(int use_path, char *target, char **argv) {
  pid_t pid;
  int rc = use_path ? posix_spawnp(&pid, target, NULL, NULL, argv, environ)
                    : posix_spawn(&pid, target, NULL, NULL, argv, environ);
  if (rc != 0) return 30;
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 31;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 32;
}

/* posix_spawn TARGET (typically relative) in DIR: a file action changes the
 * child's directory before its exec resolves the name. */
static int spawn_in_dir_and_wait(const char *dir, char *target, char **argv) {
  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) != 0) return 33;
  if (posix_spawn_file_actions_addchdir_np(&fa, dir) != 0) return 34;
  pid_t pid;
  int rc = posix_spawn(&pid, target, &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  if (rc != 0) return 30;
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 31;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 32;
}

/* A second thread that only waits, so the process is multi-threaded. */
static void *idle_thread(void *arg) {
  (void)arg;
  for (;;) pause();
  return NULL;
}

/* A child made by a raw clone of a multi-threaded process runs no atfork
 * handler, so the shim in it skips bookkeeping until exec and cannot
 * record; it execs TARGET from there. */
static int clone_child_exec(char *target, char **targv) {
  pthread_t t;
  if (pthread_create(&t, NULL, idle_thread, NULL) != 0) return 40;
  pid_t pid = (pid_t)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
  if (pid < 0) return 41;
  if (pid == 0) {
    execve(target, targv, environ);
    _exit(42);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 43;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 44;
}

/* Make this thread one the shim cannot record from, as it is inside a hook
 * (where a host signal handler can run), through the shim's own switch. */
static int disable_shim_recording(void) {
  void (*disable)(void) = (void (*)(void))dlsym(
      RTLD_DEFAULT, "repro_monitor_shim_disable_current_thread");
  if (disable == NULL) return 0;
  disable();
  return 1;
}

/* exec-host MODE TARGET ARG...: start TARGET with argv TARGET ARG... */
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  const char *mode = argv[1];
  char *target = argv[2];
  char **targv = &argv[2];
  if (strcmp(mode, "execve") == 0) {
    execve(target, targv, environ);
  } else if (strcmp(mode, "execvp") == 0) {
    execvp(target, targv);
  } else if (strcmp(mode, "fexecve") == 0) {
    int fd = open(target, O_RDONLY);
    if (fd < 0) return 4;
    fexecve(fd, targv, environ);
  } else if (strcmp(mode, "posix_spawn") == 0) {
    return spawn_and_wait(0, target, targv);
  } else if (strcmp(mode, "posix_spawnp") == 0) {
    return spawn_and_wait(1, target, targv);
  } else if (strncmp(mode, "posix_spawn-chdir=", 18) == 0) {
    return spawn_in_dir_and_wait(mode + 18, target, targv);
  } else if (strcmp(mode, "syscall-execve") == 0) {
    syscall(SYS_execve, target, targv, environ);
#ifdef __x86_64__
  } else if (strcmp(mode, "inline-execve") == 0) {
    raw3(SYS_execve, (long)target, (long)targv, (long)environ);
#endif
  } else if (strcmp(mode, "unrecorded-execve") == 0) {
    if (!disable_shim_recording()) return 5;
    execve(target, targv, environ);
  } else if (strcmp(mode, "unrecorded-posix_spawn") == 0) {
    if (!disable_shim_recording()) return 5;
    return spawn_and_wait(0, target, targv);
  } else if (strncmp(mode, "unrecorded-posix_spawn-chdir=", 29) == 0) {
    if (!disable_shim_recording()) return 5;
    return spawn_in_dir_and_wait(mode + 29, target, targv);
  } else if (strcmp(mode, "clone-child-execve") == 0) {
    return clone_child_exec(target, targv);
  } else if (strcmp(mode, "fail-then-execve") == 0) {
    /* TARGET is expected to fail to exec; then exec argv[3] ARG... */
    if (argc < 4) return 2;
    execve(target, targv, environ);
    execve(argv[3], &argv[3], environ);
  }
  return 10;
}
"""

const staticExecSource = """
/* Freestanding: no libc, no loader, so LD_PRELOAD cannot reach it. It execs
 * argv[1] with argv[1..] and its own environment through a raw system call,
 * in the same pid. */
__asm__(".text\n.global _start\n_start:\n"
        "  xor %rbp, %rbp\n  mov %rsp, %rdi\n  and $-16, %rsp\n"
        "  call cstart\n  hlt\n");
static long sys3(long n, long a, long b, long c) {
  long r;
  __asm__ volatile ("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                    : "rcx", "r11", "memory");
  return r;
}
void cstart(long *sp) {
  long argc = sp[0];
  char **argv = (char **)(sp + 1);
  char **envp = argv + argc + 1;
  if (argc < 2) sys3(60, 2, 0, 0);
  sys3(59, (long)argv[1], (long)(argv + 1), (long)envp);
  sys3(60, 3, 0, 0);
  __builtin_unreachable();
}
"""

proc elfClass(path: string): int =
  ## EI_CLASS of `path` (1: 32-bit, 2: 64-bit), 0 when it is not ELF.
  try:
    let head = readFile(path)
    if head.len >= 5 and head.startsWith("\x7FELF"):
      return ord(head[4])
  except IOError:
    discard
  0

proc lossDetails(dep: MonitorDepFile): seq[string] =
  dep.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail)

proc describe(dep: MonitorDepFile) =
  checkpoint("completeness: " & $dep.completeness)
  for r in dep.records:
    if r.kind in {mrEventLoss, mrProcessExec, mrProcessStart, mrProcessSpawn,
                  mrFileOpen}:
      checkpoint("  " & $r.kind & " pid=" & $r.osPid & " child=" &
        $r.childOsPid & " " & r.path & " " & r.detail)

suite "io-mon Linux: entry into an image the shim cannot enter":
  let work = expandFilename(getTempDir()) /
    ("io-mon-uninjectable-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let shimLib = buildPrivateLinuxShim(repoRoot)
  let snoopBin = work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0

  let cc = getEnv("CC", "cc")
  proc compile(name, source: string; flags: seq[string] = @[]): string =
    result = work / name
    writeFile(result & ".c", source)
    let built = run(cc, flags & @[result & ".c", "-o", result])
    checkpoint(built.output)
    require built.code == 0

  let helper = compile("helper64", helperSource)
  let host = compile("exec-host", hostSource, @["-O0", "-pthread"])
  let input = work / "in.txt"
  writeFile(input, "input\n")

  # The i686 shell. Applicable only on x86_64-linux, and required there.
  let i686Sh = getEnv("IO_MON_TEST_I686_SH")
  # Templates, not procs, wherever a check is made: unittest's `check`,
  # `require` and `skip` fail the enclosing `test` only when expanded in it
  # (in a suite-level proc they set the exit code and the test reads [OK]).
  template requireI686(): bool =
    ## True when the i686 cases can run. On x86_64 a missing or wrong shell
    ## FAILS (the dev shell must provide it); elsewhere the case is skipped.
    when i686Applicable:
      checkpoint("IO_MON_TEST_I686_SH=" & i686Sh)
      require i686Sh.len > 0
      require fileExists(i686Sh)
      require elfClass(i686Sh) == 1
      true
    else:
      checkpoint("skipped: an i686 image runs only on an x86_64 host")
      skip()
      false

  proc scriptFor(name, interpreter: string): string =
    ## A `#!` script run by `interpreter` that `exec`s the helper, so the
    ## helper replaces the interpreter in the same pid. Without `exec` bash
    ## forks for the command, the root pid never starts the shim, and the
    ## root-spawn signal already reported that (measured at 8b6e94ae).
    result = work / name
    writeFile(result, "#!" & interpreter & "\nexec " & helper & " " & input &
      "\n")
    setFilePermissions(result, {fpUserRead, fpUserWrite, fpUserExec})

  var spawnEnv = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): spawnEnv[k] = v
  spawnEnv.del("LD_PRELOAD")
  spawnEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib

  var captureIndex = 0
  proc runCapture(argv: seq[string]; extraPath: string):
      tuple[dep: MonitorDepFile; code: int; ok: bool] =
    inc captureIndex
    let depfile = work / ("capture-" & $captureIndex & ".iomon")
    let env = newStringTable(modeCaseSensitive)
    for k, v in spawnEnv.pairs: env[k] = v
    if extraPath.len > 0:
      env["PATH"] = extraPath & ":" & spawnEnv.getOrDefault("PATH")
    checkpoint("argv: " & argv.join(" "))
    let res = run(snoopBin, @["run", "--depfile", depfile, "--"] & argv, env)
    checkpoint(res.output)
    result.code = res.code
    result.ok = fileExists(depfile)
    if result.ok:
      result.dep = readMonitorDepFile(depfile)
      describe(result.dep)

  template capture(argv: seq[string]; extraPath = ""): MonitorDepFile =
    let captured = runCapture(argv, extraPath)
    # Every scenario ends in the helper reading its input and exiting 0, so
    # a non-zero code means the scenario did not run as designed.
    check captured.code == 0
    require captured.ok
    captured.dep

  proc helperRanMonitored(dep: MonitorDepFile): bool =
    ## The monitored helper's read is in the capture: the scenario reached a
    ## monitored image after the uninjectable one.
    dep.records.anyIt(it.kind == mrFileOpen and it.path == input)

  template checkUninjectable(depExpr: MonitorDepFile; image: string) =
    let dep = depExpr
    check helperRanMonitored(dep)
    check dep.completeness == mcIncomplete
    let named = lossDetails(dep).filterIt("uninjectable image" in it and
      ("image=" & image) in it)
    checkpoint("expected a loss naming image=" & image)
    check named.len > 0

  template checkComplete(depExpr: MonitorDepFile) =
    let dep = depExpr
    check helperRanMonitored(dep)
    check lossDetails(dep).len == 0
    check dep.completeness == mcComplete

  # --- i686 dynamic shell -------------------------------------------------

  test "root: an i686 dynamic shell that execs a monitored helper":
    if requireI686():
      checkUninjectable(capture(@[i686Sh, "-c", helper & " " & input]),
        i686Sh)

  for mode in ["execve", "fexecve", "posix_spawn", "syscall-execve",
               "inline-execve"]:
    test "descendant via " & mode & ": an i686 dynamic shell":
      if mode == "inline-execve" and not defined(amd64):
        checkpoint("skipped: the inline-syscall fixture is x86_64 assembly")
        skip()
      elif requireI686():
        checkUninjectable(capture(@[host, mode, i686Sh, "-c",
          helper & " " & input]), i686Sh)

  for mode in ["execvp", "posix_spawnp"]:
    test "descendant via " & mode & " PATH search: an i686 dynamic shell":
      if requireI686():
        # A bare name, found only through the caller's PATH.
        let dir = work / ("path-" & mode)
        createDir(dir)
        let name = "sh32-" & mode
        createSymlink(i686Sh, dir / name)
        checkUninjectable(capture(@[host, mode, name, "-c",
          helper & " " & input], extraPath = dir), dir / name)

  test "descendant via posix_spawn with a chdir file action: i686 shell":
    # The relative name exists only in the directory the file action moves
    # the child to, so classifying it in the caller's directory finds
    # nothing: the shim must resolve it where the child exec'd it.
    if requireI686():
      let dir = work / "chdir-target"
      createDir(dir)
      createSymlink(i686Sh, dir / "sh32-chdir")
      require not fileExists(getCurrentDir() / "sh32-chdir")
      checkUninjectable(capture(@[host, "posix_spawn-chdir=" & dir,
        "./sh32-chdir", "-c", helper & " " & input]), "./sh32-chdir")

  test "descendant via execve from a child that cannot record: i686 shell":
    # A raw clone of a multi-threaded host: its child skips monitor
    # bookkeeping until exec, so it cannot record the loss by name. It must
    # still report it, through the pre-encoded unnamed frame. The capture was
    # already incomplete before that frame existed (at 8b6e94ae the raw clone
    # reported "unsupported nr=56" and skipped evidence), so this case pins
    # that the frame is written, not the grade.
    if requireI686():
      let dep = capture(@[host, "clone-child-execve", i686Sh, "-c",
        helper & " " & input])
      check helperRanMonitored(dep)
      check dep.completeness == mcIncomplete
      check lossDetails(dep).anyIt("uninjectable image" in it and
        "could not record it by name" in it)

  # A thread the shim cannot record from: inside a hook, where a host signal
  # handler that execs or spawns would run, and here reached deterministically
  # through the shim's per-thread switch. The entry has to be reported anyway
  # (unnamed). At 06ee30af only a fork child skipping bookkeeping did.
  for mode in ["unrecorded-execve", "unrecorded-posix_spawn",
               "unrecorded-posix_spawn-chdir"]:
    test "descendant via " & mode & " from a thread that cannot record":
      if requireI686():
        var hostMode = mode
        var target = i686Sh
        if mode.endsWith("-chdir"):
          let dir = work / "chdir-unrecorded"
          createDir(dir)
          createSymlink(i686Sh, dir / "sh32-unrecorded")
          hostMode = mode & "=" & dir
          target = "./sh32-unrecorded"
        let dep = capture(@[host, hostMode, target, "-c",
          helper & " " & input])
        check helperRanMonitored(dep)
        check dep.completeness == mcIncomplete
        check lossDetails(dep).anyIt("uninjectable image" in it and
          "could not record it by name" in it)

  # --- #! script whose interpreter is the i686 shell ---------------------

  test "root: a #! script whose interpreter is the i686 shell":
    if requireI686():
      let script = scriptFor("script-i686", i686Sh)
      checkUninjectable(capture(@[script]), i686Sh)

  test "descendant via execve: a #! script whose interpreter is i686":
    if requireI686():
      let script = scriptFor("script-i686-exec", i686Sh)
      checkUninjectable(capture(@[host, "execve", script]), i686Sh)

  # --- static and static-pie ----------------------------------------------

  when i686Applicable:
    let staticExec = compile("static-exec", staticExecSource,
      @["-static", "-nostdlib", "-nostartfiles", "-fno-stack-protector",
        "-fno-pie", "-no-pie"])
    let staticPieExec = compile("static-pie-exec", staticExecSource,
      @["-static-pie", "-nostdlib", "-nostartfiles", "-fno-stack-protector",
        "-fPIE"])

    test "root: a static binary that execs a monitored helper":
      checkUninjectable(capture(@[staticExec, helper, input]), staticExec)

    test "root: a static-pie binary that execs a monitored helper":
      checkUninjectable(capture(@[staticPieExec, helper, input]),
        staticPieExec)

    test "descendant via execve: a static binary":
      checkUninjectable(capture(@[host, "execve", staticExec, helper, input]),
        staticExec)

    # --- execute-only (mode --x): the header cannot be read -------------
    #
    # The kernel runs it, but the classifier cannot inspect it, so the entry
    # is unverifiable and must be graded as a loss rather than assumed
    # monitored. As root (CAP_DAC_OVERRIDE) the header is readable and the
    # ordinary "statically linked" verdict names the same image, so the
    # check holds either way.
    let execOnly = work / "static-exec-xonly"
    copyFile(staticExec, execOnly)
    setFilePermissions(execOnly, {fpUserExec})

    test "root: an execute-only static binary":
      checkUninjectable(capture(@[execOnly, helper, input]), execOnly)

    test "descendant via execve: an execute-only static binary":
      checkUninjectable(capture(@[host, "execve", execOnly, helper, input]),
        execOnly)

    test "descendant via execvp PATH search: an execute-only static binary":
      let dir = work / "path-xonly"
      createDir(dir)
      copyFile(staticExec, dir / "xonly-static")
      setFilePermissions(dir / "xonly-static", {fpUserExec})
      checkUninjectable(capture(@[host, "execvp", "xonly-static", helper,
        input], extraPath = dir), dir / "xonly-static")

  # --- negative controls: no false loss ----------------------------------

  test "control: an ordinary 64-bit dynamic root":
    checkComplete(capture(@[helper, input]))

  test "control: posix_spawn of an ordinary 64-bit dynamic image":
    checkComplete(capture(@[host, "posix_spawn", helper, input]))

  test "control: a chdir file action before an ordinary 64-bit image":
    # The post-spawn re-check (the child's /proc exe and cwd) must not flag
    # an image the shim enters, whether or not the thread can record.
    let dir = work / "chdir-control"
    createDir(dir)
    createSymlink(helper, dir / "helper64-chdir")
    checkComplete(capture(@[host, "posix_spawn-chdir=" & dir,
      "./helper64-chdir", input]))
    checkComplete(capture(@[host, "unrecorded-posix_spawn-chdir=" & dir,
      "./helper64-chdir", input]))

  test "control: a #! script whose interpreter is a 64-bit shell":
    let bash64 = findExe("bash")
    checkpoint("64-bit shell: " & bash64)
    require bash64.len > 0
    require elfClass(bash64) == 2
    let script = scriptFor("script-64", bash64)
    checkComplete(capture(@[script]))
    checkComplete(capture(@[host, "execve", script]))

  test "control: ld.so run directly honours LD_PRELOAD":
    let patchelf = run("patchelf", @["--print-interpreter", helper])
    checkpoint(patchelf.output)
    require patchelf.code == 0
    let ldso = patchelf.output.strip()
    require fileExists(ldso)
    checkComplete(capture(@[ldso, helper, input]))

  test "control: execs that fail before a good one":
    checkComplete(capture(@[host, "fail-then-execve", work / "missing",
      helper, input]))
    let text = work / "not-elf-not-script"
    writeFile(text, "just some text\n")
    setFilePermissions(text, {fpUserRead, fpUserWrite, fpUserExec})
    checkComplete(capture(@[host, "fail-then-execve", text, helper, input]))

  removeDir(work)
