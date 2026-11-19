## Entering an image the loader will not inject the shim into is event-loss.
##
## THE DEFECT THIS PINS: a Linux process whose loader ignores the shim was
## graded complete.
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
## bookkeeping and so can only report the loss unnamed, and system(3) and
## popen(3), whose `/bin/sh` glibc starts through its internal posix_spawn
## that no exported hook sees -- is driven into an
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
## `mcComplete`: a false loss makes an action uncacheable. A spawn with a
## chdir file action is re-checked from the child's /proc entries; its control
## holds the child alive across that re-check, and a child whose entries
## cannot be read must be graded as a loss (the fail-closed arm).
##
## system(3) and popen(3) always run `/bin/sh` (glibc's `_PATH_BSHELL`), so
## their cases run the capture in a private user and mount namespace whose
## `/bin/sh` is the i686 shell, bind-mounted over the file it resolves to
## (`shellSwapSource`); the host's own `/bin/sh` is never touched. A control
## swaps in the 64-bit shell the same way and must stay `mcComplete`, so the
## namespace itself cannot be what grades those captures incomplete. Where
## the host refuses unprivileged user namespaces, those cases report an
## explicit skip, as test_io_mon_linux_tree_ledger does. Like the rest of
## this oracle they must run with no outer preload (repro.nim isolates the
## monitor for this test): an outer shim that exports its own `system` or
## `popen` and spawns through the public `posix_spawn` would let the
## posix_spawn hook report the shell, so these cases could not fail without
## the fix (measured with agent-harbor's command-trace shim at io-mon
## f9e8ccca5).
##
## The i686 shell comes from io-mon's dev shell (`IO_MON_TEST_I686_SH`,
## `pkgsi686Linux.bash`) or the recipe's declared `io-mon-test-i686-sh`
## executable, which provisions that same shell for isolated actions.
## On x86_64-linux a missing shell FAILS this test
## rather than skipping it, so a CI shell that lost the variable cannot pass
## vacuously; on other hosts the i686 and x86_64-only cases report an explicit
## skip.
##
## Mocks: none. Real programs, the real shim, the real `io-mon run` driver.

import foreign_preload_isolation

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]
from std/posix import geteuid

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
#ifdef HOLD_FD
  /* The held build stays alive until the host closes the pipe's write end
   * (EOF), which it does only after posix_spawn has returned. A missing
   * descriptor fails, so a pass proves the child was held. */
  char c;
  if (read(HOLD_FD, &c, 1) != 0) return 23;
#endif
  return 0;
}
"""

const hostSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wordexp.h>

extern char **environ;

/* Declared here: <spawn.h> has them only on a glibc 2.39 or later. */
int pidfd_spawn(int *, const char *, const posix_spawn_file_actions_t *,
                const posix_spawnattr_t *, char *const[], char *const[]);
int pidfd_spawnp(int *, const char *, const posix_spawn_file_actions_t *,
                 const posix_spawnattr_t *, char *const[], char *const[]);

/* pidfd_spawn{,p} TARGET and wait on the descriptor it returns. ENV is the
 * child's environment: the caller's, or (`bare`) one with no LD_PRELOAD and
 * nothing else the shim sets. NO_FD passes a NULL pidfd and waits for any
 * child. */
static int pidfd_spawn_and_wait(int use_path, int bare, int no_fd,
                                char *target, char **argv) {
  int pidfd = -1;
  char *bare_env[] = {"PATH=/run/current-system/sw/bin:/usr/bin:/bin", NULL};
  char **envp = bare ? bare_env : environ;
  int rc = use_path ? pidfd_spawnp(no_fd ? NULL : &pidfd, target, NULL, NULL,
                                   argv, envp)
                    : pidfd_spawn(no_fd ? NULL : &pidfd, target, NULL, NULL,
                                  argv, envp);
  if (rc != 0) return 30;
  int status = 0;
  if (no_fd) {
    if (waitpid(-1, &status, 0) < 0) return 31;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 32;
  }
  siginfo_t info;
  memset(&info, 0, sizeof(info));
  if (waitid(P_PIDFD, (id_t)pidfd, &info, WEXITED) != 0) return 31;
  close(pidfd);
  return info.si_code == CLD_EXITED ? info.si_status : 32;
}

static int write_file(const char *path, const char *text) {
  int fd = open(path, O_WRONLY);
  if (fd < 0) return -1;
  ssize_t n = write(fd, text, strlen(text));
  close(fd);
  return n == (ssize_t)strlen(text) ? 0 : -1;
}

/* wordexp WORDS with flags FLAGS in user and mount namespaces of its own whose
 * /bin/sh is SH, the image wordexp runs for a command substitution. Exit 5
 * when the namespaces cannot be made. */
static int wordexp_with_sh(const char *sh, const char *words, int flags) {
  if (sh != NULL) {
    char map[64];
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return 5;
    if (write_file("/proc/self/setgroups", "deny") != 0) return 5;
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)uid);
    if (write_file("/proc/self/uid_map", map) != 0) return 5;
    snprintf(map, sizeof(map), "0 %u 1", (unsigned)gid);
    if (write_file("/proc/self/gid_map", map) != 0) return 5;
    /* Slave, not private: a private copy keeps every host mount it copied
       mounted after the host unmounts it, for as long as this process
       lives. The bind below cannot reach the host either way. */
    if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL) != 0) return 5;
    if (mount(sh, "/bin/sh", NULL, MS_BIND, NULL) != 0) return 5;
  }
  wordexp_t we;
  int rc = wordexp(words, &we, flags);
  if (rc != 0) return 30;
  wordfree(&we);
  return 0;
}

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

/* As spawn_in_dir_and_wait, but the child gets the read end of a pipe as
 * descriptor HOLD_FD, and the write end is closed only once posix_spawn has
 * returned. The shim's post-spawn re-check of the child's /proc exe and cwd
 * runs inside posix_spawn, so a child that waits for EOF on HOLD_FD (the held
 * helper) is provably alive when that re-check reads them. */
#define HOLD_FD 100
static int spawn_in_dir_held_and_wait(const char *dir, char *target,
                                      char **argv) {
  int hold[2];
  if (pipe2(hold, O_CLOEXEC) != 0) return 35;
  posix_spawn_file_actions_t fa;
  if (posix_spawn_file_actions_init(&fa) != 0) return 33;
  if (posix_spawn_file_actions_addchdir_np(&fa, dir) != 0) return 34;
  if (posix_spawn_file_actions_adddup2(&fa, hold[0], HOLD_FD) != 0) return 36;
  pid_t pid;
  int rc = posix_spawn(&pid, target, &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  close(hold[1]);
  close(hold[0]);
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

/* system(3) COMMAND, which glibc runs as `/bin/sh -c COMMAND` through its
 * internal posix_spawn. The command's exit code, or 50 + how it failed. */
static int system_and_status(const char *command) {
  int status = system(command);
  if (status == -1) return 50;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 51;
}

/* popen(3) COMMAND for reading, drained to EOF, then pclose(3): glibc starts
 * `/bin/sh -c COMMAND` through the same internal posix_spawn. */
static int popen_and_status(const char *command) {
  FILE *pipe = popen(command, "r");
  if (pipe == NULL) return 52;
  char buf[256];
  while (fread(buf, 1, sizeof(buf), pipe) > 0) {
  }
  int status = pclose(pipe);
  if (status == -1) return 53;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 54;
}

/* exec-host MODE TARGET ARG...: start TARGET with argv TARGET ARG...
 * (for the system and popen modes TARGET is the shell command). */
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
  } else if (strcmp(mode, "pidfd_spawn") == 0) {
    return pidfd_spawn_and_wait(0, 0, 0, target, targv);
  } else if (strcmp(mode, "pidfd_spawnp") == 0) {
    return pidfd_spawn_and_wait(1, 0, 0, target, targv);
  } else if (strcmp(mode, "pidfd_spawn-bare-env") == 0) {
    return pidfd_spawn_and_wait(0, 1, 0, target, targv);
  } else if (strcmp(mode, "pidfd_spawn-null-fd") == 0) {
    return pidfd_spawn_and_wait(0, 0, 1, target, targv);
  } else if (strcmp(mode, "unrecorded-pidfd_spawn") == 0) {
    if (!disable_shim_recording()) return 5;
    return pidfd_spawn_and_wait(0, 0, 0, target, targv);
  } else if (strncmp(mode, "wordexp-sh=", 11) == 0) {
    /* TARGET is the words to expand; the rest of the mode names /bin/sh. */
    return wordexp_with_sh(mode + 11, target, 0);
  } else if (strncmp(mode, "wordexp-nocmd-sh=", 17) == 0) {
    return wordexp_with_sh(mode + 17, target, WRDE_NOCMD);
  } else if (strcmp(mode, "wordexp") == 0) {
    return wordexp_with_sh(NULL, target, 0);
  } else if (strncmp(mode, "unrecorded-wordexp-sh=", 22) == 0) {
    if (!disable_shim_recording()) return 5;
    return wordexp_with_sh(mode + 22, target, 0);
  } else if (strncmp(mode, "posix_spawn-chdir=", 18) == 0) {
    return spawn_in_dir_and_wait(mode + 18, target, targv);
  } else if (strncmp(mode, "posix_spawn-chdir-held=", 23) == 0) {
    return spawn_in_dir_held_and_wait(mode + 23, target, targv);
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
  } else if (strncmp(mode, "unrecorded-posix_spawn-chdir-held=", 34) == 0) {
    if (!disable_shim_recording()) return 5;
    return spawn_in_dir_held_and_wait(mode + 34, target, targv);
  } else if (strcmp(mode, "system") == 0) {
    return system_and_status(target);
  } else if (strcmp(mode, "popen") == 0) {
    return popen_and_status(target);
  } else if (strcmp(mode, "unrecorded-system") == 0) {
    if (!disable_shim_recording()) return 5;
    return system_and_status(target);
  } else if (strcmp(mode, "unrecorded-popen") == 0) {
    if (!disable_shim_recording()) return 5;
    return popen_and_status(target);
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

const ShellSwapRefused = 77
  ## shell-swap's exit code when the host refuses an unprivileged user or
  ## mount namespace: the system/popen cases then skip, explicitly.

const shellSwapSource = """
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

/* shell-swap SHELL COMMAND ARG...: run COMMAND in a new user and mount
 * namespace in which /bin/sh is SHELL. glibc's system(3) and popen(3) run
 * /bin/sh by that fixed name, so this is the only way to make them start an
 * image of the test's choosing. The bind mount covers the file /bin/sh
 * resolves to (on NixOS /bin/sh is a symlink into the store); it is private
 * to the namespace and gone when the namespace's last process exits.
 * Exits 77 when the host refuses the namespace. */
static int write_file(const char *path, const char *text) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t len = (ssize_t)strlen(text);
  ssize_t n = write(fd, text, (size_t)len);
  close(fd);
  return n == len ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc < 3) return 2;
  uid_t uid = getuid();
  gid_t gid = getgid();
  if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
    perror("shell-swap: unshare");
    return 77;
  }
  char map[64];
  snprintf(map, sizeof(map), "0 %u 1", (unsigned)uid);
  if (write_file("/proc/self/uid_map", map) != 0) {
    perror("shell-swap: uid_map");
    return 77;
  }
  if (write_file("/proc/self/setgroups", "deny") != 0) {
    perror("shell-swap: setgroups");
    return 77;
  }
  snprintf(map, sizeof(map), "0 %u 1", (unsigned)gid);
  if (write_file("/proc/self/gid_map", map) != 0) {
    perror("shell-swap: gid_map");
    return 77;
  }
  /* Slave, not private (see wordexp_with_sh): the bind below stays here
     either way, and a slave copy lets the host's unmounts through. */
  if (mount("none", "/", NULL, MS_REC | MS_SLAVE, NULL) != 0) {
    perror("shell-swap: make / a slave");
    return 77;
  }
  char target[PATH_MAX];
  if (realpath("/bin/sh", target) == NULL) {
    perror("shell-swap: realpath /bin/sh");
    return 3;
  }
  if (mount(argv[1], target, NULL, MS_BIND, NULL) != 0) {
    perror("shell-swap: bind mount");
    return 4;
  }
  execv(argv[2], &argv[2]);
  perror("shell-swap: execv");
  return 5;
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
  # The same helper, held alive on descriptor 100 until the host releases it
  # (HOLD_FD in the host's spawn_in_dir_held_and_wait).
  let heldHelper = compile("helper64-held", helperSource, @["-DHOLD_FD=100"])
  let host = compile("exec-host", hostSource, @["-O0", "-pthread"])
  let input = work / "in.txt"
  writeFile(input, "input\n")

  # The i686 shell. Applicable only on x86_64-linux, and required there.
  let i686Sh = getEnv("IO_MON_TEST_I686_SH", findExe("io-mon-test-i686-sh"))
  # Templates, not procs, wherever a check is made: unittest's `check`,
  # `require` and `skip` fail the enclosing `test` only when expanded in it
  # (in a suite-level proc they set the exit code and the test reads [OK]).
  template requireI686(): bool =
    ## True when the i686 cases can run. On x86_64 a missing or wrong shell
    ## FAILS (the dev shell or recipe must provide it); elsewhere it skips.
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
  proc runCapture(argv: seq[string]; extraPath: string;
                  wrapper: seq[string] = @[]):
      tuple[dep: MonitorDepFile; code: int; ok: bool] =
    ## `wrapper` (shell-swap and its shell) runs the capture, `io-mon run`
    ## included, in the namespace it makes.
    inc captureIndex
    let depfile = work / ("capture-" & $captureIndex & ".iomon")
    let env = newStringTable(modeCaseSensitive)
    for k, v in spawnEnv.pairs: env[k] = v
    if extraPath.len > 0:
      env["PATH"] = extraPath & ":" & spawnEnv.getOrDefault("PATH")
    checkpoint("argv: " & argv.join(" "))
    let snoopArgv = @[snoopBin, "run", "--depfile", depfile, "--"] & argv
    let res =
      if wrapper.len == 0: run(snoopArgv[0], snoopArgv[1 .. ^1], env)
      else: run(wrapper[0], wrapper[1 .. ^1] & snoopArgv, env)
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

  # --- system(3) and popen(3) of an i686 /bin/sh ------------------------
  #
  # glibc starts their `/bin/sh` through its internal posix_spawn, which no
  # exported hook sees, so before io-mon interposed system and popen the
  # shell ran unobserved and the capture was graded complete (io-mon issue
  # 2026-11-08-linux-system-popen-of-an-uninjectable-shell-is-unseen). The
  # shell `exec`s the monitored helper in its own pid, the shape the counting
  # signals cannot see.

  let shellSwap = compile("shell-swap", shellSwapSource)
  template shellSwapAvailable(): bool =
    ## True when shell-swap can make its namespace here; an explicit skip
    ## when the host refuses unprivileged user namespaces. The probe swaps
    ## the helper in as /bin/sh and runs it, so a pass also proves the bind
    ## mount works.
    let probe = run(shellSwap, @[helper, helper, input])
    checkpoint("shell-swap probe: " & $probe.code & " " & probe.output)
    if probe.code == ShellSwapRefused:
      echo "    SKIP: unprivileged user namespaces are unavailable: ",
        probe.output
      skip()
      false
    else:
      require probe.code == 0
      true

  template swappedCapture(shell: string; argv: seq[string]): MonitorDepFile =
    ## `capture`, run in a namespace whose /bin/sh is `shell`.
    let captured = runCapture(argv, "", @[shellSwap, shell])
    check captured.code == 0
    require captured.ok
    captured.dep

  let shellCommand = helper & " " & input
  for mode in ["system", "popen"]:
    test "descendant via " & mode & ": /bin/sh is an i686 dynamic shell":
      if requireI686() and shellSwapAvailable():
        checkUninjectable(swappedCapture(i686Sh,
          @[host, mode, shellCommand]), "/bin/sh")

    test "descendant via " & mode & " from a thread that cannot record":
      if requireI686() and shellSwapAvailable():
        let dep = swappedCapture(i686Sh,
          @[host, "unrecorded-" & mode, shellCommand])
        check helperRanMonitored(dep)
        check dep.completeness == mcIncomplete
        check lossDetails(dep).anyIt("uninjectable image" in it and
          "could not record it by name" in it)

    test "control: " & mode & " of a 64-bit /bin/sh":
      # The host's own /bin/sh, then the 64-bit bash swapped in through the
      # same namespace the cases above use: neither may report a loss.
      checkComplete(capture(@[host, mode, shellCommand]))
      checkComplete(capture(@[host, "unrecorded-" & mode, shellCommand]))
      if shellSwapAvailable():
        let bash64 = findExe("bash")
        require elfClass(bash64) == 2
        checkComplete(swappedCapture(bash64, @[host, mode, shellCommand]))

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

  # --- pidfd_spawn / pidfd_spawnp ------------------------------------------
  # glibc starts these through the internal __spawni, which no exported
  # posix_spawn hook reaches, so the shim interposes them itself.

  for mode in ["pidfd_spawn", "pidfd_spawn-null-fd"]:
    test "descendant via " & mode & ": an i686 dynamic shell":
      if requireI686():
        checkUninjectable(capture(@[host, mode, i686Sh, "-c",
          helper & " " & input]), i686Sh)

  template checkUninjectableUnnamed(depExpr: MonitorDepFile) =
    ## The entry could not be recorded by name (the calling thread is inside
    ## a hook), and is reported through the unnamed frame.
    let dep = depExpr
    check helperRanMonitored(dep)
    check dep.completeness == mcIncomplete
    check lossDetails(dep).anyIt("uninjectable image" in it and
      "could not record it by name" in it)

  test "descendant via unrecorded-pidfd_spawn from a thread that cannot record":
    if requireI686():
      checkUninjectableUnnamed(capture(@[host, "unrecorded-pidfd_spawn",
        i686Sh, "-c", helper & " " & input]))

  test "descendant via pidfd_spawnp PATH search: an i686 dynamic shell":
    if requireI686():
      let dir = work / "path-pidfd_spawnp"
      createDir(dir)
      createSymlink(i686Sh, dir / "sh32-pidfd_spawnp")
      checkUninjectable(capture(@[host, "pidfd_spawnp", "sh32-pidfd_spawnp",
        "-c", helper & " " & input], extraPath = dir),
        dir / "sh32-pidfd_spawnp")

  test "pidfd_spawn: a child started with an environment lacking LD_PRELOAD":
    # The shim adds the capture route to the child's environment, as it does
    # for posix_spawn, so the helper's read is recorded although the caller
    # passed an environment that names no shim.
    checkComplete(capture(@[host, "pidfd_spawn-bare-env", helper, input]))

  test "pidfd_spawn: the spawn is recorded with the child's pid":
    let dep = capture(@[host, "pidfd_spawn", helper, input])
    let spawns = dep.records.filterIt(it.kind == mrProcessSpawn and
      "pidfd_spawn" in it.detail)
    check spawns.len == 1
    if spawns.len == 1:
      check spawns[0].childOsPid > 0
      check dep.records.anyIt(it.kind == mrProcessStart and
        it.osPid == spawns[0].childOsPid)

  for mode in ["pidfd_spawn", "pidfd_spawnp", "pidfd_spawn-null-fd",
               "unrecorded-pidfd_spawn"]:
    test "control: " & mode & " of an ordinary 64-bit dynamic image":
      checkComplete(capture(@[host, mode, helper, input], extraPath =
        helper.parentDir))

  # --- wordexp --------------------------------------------------------------
  # glibc runs a command substitution as `/bin/sh -c`; the test binds the i686
  # shell over /bin/sh in private user and mount namespaces.

  for mode in ["wordexp-sh=", "unrecorded-wordexp-sh="]:
    test mode & ": a command substitution run by an i686 /bin/sh":
      if requireI686():
        let captured = runCapture(@[host, mode & i686Sh,
          "$(" & helper & " " & input & ")"], "")
        if captured.code == 5:
          checkpoint("skipped: user and mount namespaces are unavailable")
          skip()
        else:
          check captured.code == 0
          require captured.ok
          if mode.startsWith("unrecorded"):
            checkUninjectableUnnamed(captured.dep)
          else:
            checkUninjectable(captured.dep, "/bin/sh")

  test "wordexp: a backquote command substitution under an i686 /bin/sh":
    if requireI686():
      let captured = runCapture(@[host, "wordexp-sh=" & i686Sh,
        "`" & helper & " " & input & "`"], "")
      if captured.code == 5:
        checkpoint("skipped: user and mount namespaces are unavailable")
        skip()
      else:
        check captured.code == 0
        require captured.ok
        checkUninjectable(captured.dep, "/bin/sh")

  test "control: wordexp with no command substitution under an i686 /bin/sh":
    if requireI686():
      let captured = runCapture(@[host, "wordexp-sh=" & i686Sh, "~ $HOME x*"],
        "")
      if captured.code == 5:
        checkpoint("skipped: user and mount namespaces are unavailable")
        skip()
      else:
        check captured.code == 0
        require captured.ok
        check lossDetails(captured.dep).len == 0

  test "control: WRDE_NOCMD under an i686 /bin/sh starts no shell":
    if requireI686():
      let captured = runCapture(@[host, "wordexp-nocmd-sh=" & i686Sh,
        "plain"], "")
      if captured.code == 5:
        checkpoint("skipped: user and mount namespaces are unavailable")
        skip()
      else:
        check captured.code == 0
        require captured.ok
        check lossDetails(captured.dep).len == 0

  test "control: a command substitution run by the ordinary /bin/sh":
    checkComplete(capture(@[host, "wordexp",
      "$(" & helper & " " & input & ")"]))

  # --- negative controls: no false loss ----------------------------------

  test "control: an ordinary 64-bit dynamic root":
    checkComplete(capture(@[helper, input]))

  test "control: posix_spawn of an ordinary 64-bit dynamic image":
    checkComplete(capture(@[host, "posix_spawn", helper, input]))

  test "control: a chdir file action before an ordinary 64-bit image":
    # The post-spawn re-check (the child's /proc exe and cwd) must not flag
    # an image the shim enters, whether or not the thread can record.
    #
    # The child is HELD: it stays alive until the host closes a pipe after
    # posix_spawn has returned, and so after the re-check. A child that has
    # already exited by then leaves both /proc links unreadable, and the shim
    # then fails closed by contract ("spawned image unverifiable"; see
    # `ct_linux_spawn_image_uninjectable`). An unheld helper exits fast
    # enough to lose that race on a loaded host (2 of 2 full runs at
    # b60947c), which made this control flaky. That false loss is a product
    # gap recorded in issues/2026-11-04-linux-posix-spawn-chdir-reports-a-
    # false-loss-when-the-child-exits-before-the-recheck.md; this control
    # grades the re-check of a live child, which is what it is for.
    let dir = work / "chdir-control"
    createDir(dir)
    createSymlink(heldHelper, dir / "helper64-chdir")
    checkComplete(capture(@[host, "posix_spawn-chdir-held=" & dir,
      "./helper64-chdir", input]))
    checkComplete(capture(@[host, "unrecorded-posix_spawn-chdir-held=" & dir,
      "./helper64-chdir", input]))

  test "a chdir file action before a child whose /proc entries are unreadable":
    # The fail-closed arm of the post-spawn re-check, made deterministic:
    # neither /proc/<child>/exe nor /proc/<child>/cwd can be read and the
    # name depends on the directory, so the entry cannot be verified and must
    # be graded as a loss. Exiting before the re-check is not something a
    # test can force (the re-check runs inside posix_spawn, before the caller
    # can reap), so this uses the other way to make both links unreadable:
    # exec of an image the caller may not read makes the child non-dumpable,
    # and the kernel then refuses its /proc links to a same-user process
    # without CAP_SYS_PTRACE. The image itself is an ordinary dynamic one
    # the shim enters, held alive across the re-check as in the control.
    if geteuid() == 0:
      checkpoint("skipped: root reads a non-dumpable child's /proc links")
      skip()
    else:
      let dir = work / "chdir-unreadable"
      createDir(dir)
      copyFile(heldHelper, dir / "helper64-xonly-chdir")
      setFilePermissions(dir / "helper64-xonly-chdir", {fpUserExec})
      let dep = capture(@[host, "posix_spawn-chdir-held=" & dir,
        "./helper64-xonly-chdir", input])
      check helperRanMonitored(dep)
      check dep.completeness == mcIncomplete
      check lossDetails(dep).anyIt("spawned image unverifiable" in it and
        "image=./helper64-xonly-chdir" in it)
      let unrecorded = capture(@[host, "unrecorded-posix_spawn-chdir-held=" &
        dir, "./helper64-xonly-chdir", input])
      check helperRanMonitored(unrecorded)
      check unrecorded.completeness == mcIncomplete
      check lossDetails(unrecorded).anyIt("uninjectable image" in it and
        "could not record it by name" in it)

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
