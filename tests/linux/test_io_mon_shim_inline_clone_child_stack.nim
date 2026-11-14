## A program's own inline `clone` with a child stack runs as it does
## unmonitored.
##
## WHY. The x86_64 inline backend patches a program's own `syscall`
## instruction to trap and used to replay the call inside the SIGTRAP handler.
## For `clone` / `clone3` naming a child stack, the kernel starts the child at
## the instruction after the system call, which was then inside the handler,
## on the stack the program passed. The handler's frames are not on that
## stack, so the child crashed (SIGSEGV) as soon as the handler returned.
## (io-mon issue 2026-11-08-linux-inline-clone-with-a-child-stack-crashes-
## the-child.)
##
## WHAT THIS TEST GRADES. A host issues `clone` or `clone3` through ONE inline
## `syscall` instruction, with a child stack, with `SIGCHLD`, with
## `SIGCHLD | CLONE_VM` (a CLONE_VM process) and with the flags of a thread. Before the call it loads sentinels into the
## callee-saved registers and `xmm7` and blocks SIGUSR2. The child records
## what it finds and checks it is what an unmonitored `syscall` gives it: the
## sentinels, `rax` 0, `rsp` at the stack it named, `xmm7` intact, SIGUSR2
## still blocked and SIGTRAP not blocked. The parent
## checks the same of its own registers and that the pid it got is the
## child's. A fork-like child exits 7; a CLONE_VM process or a thread
## reports 7 through the memory it shares (the process is then killed and
## reaped, the thread ends with the process). Every combination runs
## unmonitored first (the control: the fixture itself is right) and then
## under `io-mon run`, which must give the same outcome.
##
## The second case grades the bookkeeping the `syscall(2)` route already does
## for a CLONE_VM process: the creator writes the child's tree-ledger entry
## and reports the CLONE_VM-process loss. A CLONE_VM child that outlives the
## root, and whose environment no longer carries the shim's needles, must be
## found through that entry (`linux recorded descendants still live`, naming
## its pid), with exactly one CLONE_VM-process loss.
##
## A clone without a child stack (`fork`'s shape) is the control that the
## unchanged path still works. A clone the kernel refuses (a thread's flags
## without CLONE_SIGHAND, EINVAL) grades the stub path's failure return: the
## program gets -EINVAL with its registers intact, as unmonitored.
##
## x86_64 only: the trap substrate this test exercises is the x86_64 one.
##
## Mocks: none. Real program, real shim, real kernel.

import std/[os, osproc, posix, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  RecordedLive = "linux recorded descendants still live after root exit"
  VmProcessLoss = "linux CLONE_VM process (not a thread or vfork child)"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

const hostSource = """
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* What each side of the clone saw right after the `syscall` instruction:
 * rbx rbp r12 r13 r14 r15 rax rcx rsp xmm7(low 64 bits). */
enum { R_RBX, R_RBP, R_R12, R_R13, R_R14, R_R15, R_RAX, R_RCX, R_RSP, R_XMM7,
       R_COUNT };
static volatile uint64_t g_child[R_COUNT];
static volatile uint64_t g_parent[R_COUNT];
static volatile int g_child_report;   /* a CLONE_VM child's verdict */

static const uint64_t sentinel[6] = {
  0x1111111111111111ull, 0x2222222222222222ull, 0x3333333333333333ull,
  0x4444444444444444ull, 0x5555555555555555ull, 0x6666666666666666ull};
static const uint64_t xmm_sentinel = 0x7777777777777777ull;

void clone_child_main(void) __attribute__((noreturn, used));

/* inline_clone(nr, a0, a1): the program's only `syscall` instruction. It
 * loads the sentinels, issues the call and, on each side, stores what it
 * sees. The parent returns rax; the child, now on its new stack, calls
 * clone_child_main and never returns. */
long inline_clone(long nr, long a0, long a1);
__asm__(
  ".text\n"
  ".globl inline_clone\n"
  ".type inline_clone, @function\n"
  "inline_clone:\n"
  "  pushq %rbx\n  pushq %rbp\n  pushq %r12\n  pushq %r13\n"
  "  pushq %r14\n  pushq %r15\n"
  "  movq %rdi, %rax\n"
  "  movq %rsi, %rdi\n"
  "  movq %rdx, %rsi\n"
  "  xorl %edx, %edx\n  xorl %r10d, %r10d\n  xorl %r8d, %r8d\n"
  "  xorl %r9d, %r9d\n"
  "  movabsq $0x7777777777777777, %rcx\n"
  "  movq %rcx, %xmm7\n"
  "  movabsq $0x1111111111111111, %rbx\n"
  "  movabsq $0x2222222222222222, %rbp\n"
  "  movabsq $0x3333333333333333, %r12\n"
  "  movabsq $0x4444444444444444, %r13\n"
  "  movabsq $0x5555555555555555, %r14\n"
  "  movabsq $0x6666666666666666, %r15\n"
  "  syscall\n"
  ".globl inline_clone_after\n"
  "inline_clone_after:\n"
  "  testq %rax, %rax\n"
  "  jz 1f\n"
  "  movq %rbx, g_parent+0(%rip)\n  movq %rbp, g_parent+8(%rip)\n"
  "  movq %r12, g_parent+16(%rip)\n  movq %r13, g_parent+24(%rip)\n"
  "  movq %r14, g_parent+32(%rip)\n  movq %r15, g_parent+40(%rip)\n"
  "  movq %rax, g_parent+48(%rip)\n  movq %rcx, g_parent+56(%rip)\n"
  "  movq %rsp, g_parent+64(%rip)\n  movq %xmm7, g_parent+72(%rip)\n"
  "  popq %r15\n  popq %r14\n  popq %r13\n  popq %r12\n"
  "  popq %rbp\n  popq %rbx\n"
  "  ret\n"
  "1:\n"
  "  movq %rbx, g_child+0(%rip)\n  movq %rbp, g_child+8(%rip)\n"
  "  movq %r12, g_child+16(%rip)\n  movq %r13, g_child+24(%rip)\n"
  "  movq %r14, g_child+32(%rip)\n  movq %r15, g_child+40(%rip)\n"
  "  movq %rax, g_child+48(%rip)\n  movq %rcx, g_child+56(%rip)\n"
  "  movq %rsp, g_child+64(%rip)\n  movq %xmm7, g_child+72(%rip)\n"
  "  andq $-16, %rsp\n"
  "  call clone_child_main\n"
  "  hlt\n"
  ".size inline_clone, .-inline_clone\n");

static uint64_t g_expected_child_rsp;
static int g_vm;

/* 0 when `seen` is what an unmonitored `syscall` gives; otherwise a bit per
 * register (or the signal mask) that differs. */
static int check_side(volatile uint64_t *seen, int child) {
  int bad = 0;
  for (int i = 0; i < 6; i++)
    if (seen[i] != sentinel[i]) bad |= 1 << i;
  if (child && seen[R_RAX] != 0) bad |= 1 << R_RAX;
  if (child && g_expected_child_rsp != 0 &&
      seen[R_RSP] != g_expected_child_rsp)
    bad |= 1 << R_RSP;
  if (seen[R_XMM7] != xmm_sentinel) bad |= 1 << R_XMM7;
  sigset_t now;
  if (sigprocmask(SIG_BLOCK, NULL, &now) != 0) bad |= 1 << 12;
  else {
    if (!sigismember(&now, SIGUSR2)) bad |= 1 << 10;
    if (sigismember(&now, SIGTRAP)) bad |= 1 << 11;
  }
  return bad;
}

void clone_child_main(void) {
  int bad = check_side(g_child, 1);
  if (bad) fprintf(stderr, "child: register/mask mismatch 0x%x\n", bad);
  if (g_vm) {
    /* Shares the parent's memory: report through it, then wait to be
     * reaped (an exit from here would run on the parent's libc state). */
    __atomic_store_n(&g_child_report, bad ? 100 : 7, __ATOMIC_SEQ_CST);
    for (;;) pause();
  }
  _exit(bad ? 100 : 7);
}

static char g_stack[256 * 1024] __attribute__((aligned(16)));

/* Overwrite this process's REPRO_MONITOR_* strings in place, so the guard's
 * environment sweep cannot see a CLONE_VM child (which shares them): only
 * the tree-ledger entry its creator wrote can find it. */
static void clobber_needles(void) {
  for (char **e = environ; e && *e; e++)
    if (!strncmp(*e, "REPRO_MONITOR_", 14)) memset(*e, 'x', strlen(*e));
}

int main(int argc, char **argv) {
  /* argv: <clone|clone3|clone-nostack> <fork|vm|thread|refused>
   *       [linger <pidfile>] */
  if (argc < 3) return 2;
  const char *call = argv[1];
  int thread = strcmp(argv[2], "thread") == 0;
  /* A thread's flags without CLONE_SIGHAND: the kernel refuses them
   * (EINVAL), so the call fails with a child stack named. */
  int refused = strcmp(argv[2], "refused") == 0;
  g_vm = thread || strcmp(argv[2], "vm") == 0;
  int linger = argc == 5 && strcmp(argv[3], "linger") == 0;
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR2);
  if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) return 3;
  unsigned long flags =
      refused ? CLONE_VM | CLONE_THREAD
      : thread ? CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FS |
                     CLONE_FILES
               : SIGCHLD | (g_vm ? CLONE_VM : 0);
  if (linger) clobber_needles();
  char *top = g_stack + sizeof(g_stack) - 64;
  long pid;
  if (strcmp(call, "clone") == 0) {
    g_expected_child_rsp = (uint64_t)(uintptr_t)top;
    pid = inline_clone(SYS_clone, (long)flags, (long)top);
  } else if (strcmp(call, "clone3") == 0) {
    static struct {
      uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack,
          stack_size, tls;
    } args;
    memset(&args, 0, sizeof(args));
    args.flags = flags & ~0xffull;
    args.exit_signal = flags & 0xff;
    args.stack = (uint64_t)(uintptr_t)g_stack;
    args.stack_size = (uint64_t)(top - g_stack);
    g_expected_child_rsp = (uint64_t)(uintptr_t)top;
    pid = inline_clone(SYS_clone3, (long)&args, (long)sizeof(args));
  } else if (strcmp(call, "clone-nostack") == 0 && !g_vm) {
    pid = inline_clone(SYS_clone, (long)flags, 0);
  } else {
    return 2;
  }
  if (refused) {
    /* The error reaches the program as it does unmonitored, with the
     * program's registers intact. */
    int bad = check_side(g_parent, 0);
    if ((long)g_parent[R_RAX] != pid) bad |= 1 << R_RAX;
    printf("clone refused %ld, mismatch 0x%x\n", pid, bad);
    return pid == -22 && bad == 0 ? 0 : 12;
  }
  if (pid < 0) { fprintf(stderr, "clone failed: %ld\n", pid); return 4; }
  int bad = check_side(g_parent, 0);
  if ((long)g_parent[R_RAX] != pid) bad |= 1 << R_RAX;
  if (bad) { fprintf(stderr, "parent: register/mask mismatch 0x%x\n", bad);
             return 5; }
  if (linger) {
    FILE *f = fopen(argv[4], "w");
    if (f == NULL) return 6;
    fprintf(f, "%ld\n", pid);
    fclose(f);
    return 0;
  }
  int status = 0;
  if (thread) {
    /* A thread of this process: it reports, then sleeps until main's
     * return ends the process. */
    for (int i = 0; i < 5000 && __atomic_load_n(&g_child_report,
                                                 __ATOMIC_SEQ_CST) == 0; i++) {
      struct timespec ts = {0, 2000000};
      nanosleep(&ts, NULL);
    }
    int report = __atomic_load_n(&g_child_report, __ATOMIC_SEQ_CST);
    printf("child reported %d\n", report);
    return report == 7 ? 0 : 8;
  }
  if (g_vm) {
    for (int i = 0; i < 5000 && __atomic_load_n(&g_child_report,
                                                 __ATOMIC_SEQ_CST) == 0; i++) {
      struct timespec ts = {0, 2000000};
      nanosleep(&ts, NULL);
      if (waitpid((pid_t)pid, &status, WNOHANG) == pid) {
        fprintf(stderr, "child died: status 0x%x\n", status);
        return 7;
      }
    }
    int report = __atomic_load_n(&g_child_report, __ATOMIC_SEQ_CST);
    kill((pid_t)pid, SIGKILL);
    waitpid((pid_t)pid, &status, 0);
    printf("child reported %d\n", report);
    return report == 7 ? 0 : 8;
  }
  if (waitpid((pid_t)pid, &status, 0) != pid) return 9;
  if (WIFSIGNALED(status)) {
    fprintf(stderr, "child killed by signal %d\n", WTERMSIG(status));
    return 10;
  }
  printf("child exited %d\n", WEXITSTATUS(status));
  return WIFEXITED(status) && WEXITSTATUS(status) == 7 ? 0 : 11;
}
"""

proc losses(dep: MonitorDepFile): seq[string] =
  for r in dep.records:
    if r.kind == mrEventLoss: result.add r.detail

proc alive(pid: Pid): bool =
  ## Alive and not a zombie.
  if posix.kill(pid, 0) != 0: return false
  try:
    let stat = readFile("/proc/" & $pid & "/stat")
    let close = stat.rfind(')')
    close < 0 or close + 2 >= stat.len or stat[close + 2] != 'Z'
  except IOError:
    false

suite "io-mon Linux shim: an inline clone with a child stack":
  when not defined(amd64):
    test "t_inline_clone_child_stack":
      skip()   # the trap substrate under test is the x86_64 one
  else:
    let work = expandFilename(getTempDir()) /
      ("io-mon-inline-clone-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    doAssert cli.code == 0, cli.output
    let host = work / "inline-clone"
    writeFile(host & ".c", hostSource)
    let hostCc = run(getEnv("CC", "cc"), @[host & ".c", "-O1", "-o", host])
    doAssert hostCc.code == 0, hostCc.output
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env.del("LD_PRELOAD")
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    putEnv("REPRO_MONITOR_SHIM_LIB", shimLib)
    putEnv("IO_MON_LINUX_DESCENDANT_GRACE_MS", "300")
    putEnv("IO_MON_LINUX_DESCENDANT_POLL_MS", "10")
    var serial = 0

    test "t_inline_clone_child_runs_as_unmonitored":
      for (call, kind) in [("clone", "fork"), ("clone", "vm"),
                           ("clone", "thread"), ("clone3", "fork"),
                           ("clone3", "vm"), ("clone3", "thread"),
                           ("clone", "refused"), ("clone3", "refused"),
                           ("clone-nostack", "fork")]:
        checkpoint(call & " " & kind)
        let plain = run(host, @[call, kind])
        checkpoint("unmonitored: " & plain.output)
        check plain.code == 0
        inc serial
        let depfile = work / ("run-" & $serial & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
          call, kind], env)
        checkpoint("monitored: " & cap.output)
        check cap.code == 0
        if kind == "refused":
          check "clone refused -22, mismatch 0x0" in cap.output
        else:
          check "child reported 7" in cap.output or
            "child exited 7" in cap.output
        let dep = readMonitorDepFile(depfile)
        checkpoint($dep.losses)
        # The site really was trapped: an unpatched `syscall` would leave
        # no trace of the clone at all.
        check dep.losses.anyIt(it.startsWith("inline raw syscall"))
        check dep.losses.filterIt(it.startsWith(VmProcessLoss)).len ==
          (if kind == "vm": 1 else: 0)

    test "t_inline_clone_vm_child_gets_its_creator_ledger_entry":
      for call in ["clone", "clone3"]:
        checkpoint(call)
        inc serial
        let pidFile = work / ("linger-" & $serial & ".pid")
        let req = FsSnoopRequest(
          command: @[host, call, "vm", "linger", pidFile],
          depFilePath: work / ("linger-" & $serial & ".iomon"))
        var child = Pid(0)
        try:
          let res = runMonitored(req)
          check res.exitCode == 0
          if fileExists(pidFile):
            child = Pid(parseInt(readFile(pidFile).strip()))
          check child != Pid(0)
          check alive(child)
          checkpoint($res.depFile.losses)
          check res.completeness == mcIncomplete
          let recorded = res.depFile.losses.filterIt(
            it.startsWith(RecordedLive))
          check recorded.len == 1
          if recorded.len == 1:
            check ("pids=" & $child) in recorded[0]
          check res.depFile.losses.filterIt(
            it.startsWith(VmProcessLoss)).len == 1
          # The needles really were gone: the environment sweep did not
          # find the child, the ledger did.
          check not res.depFile.losses.anyIt(
            it.startsWith("linux injected descendants still live"))
        finally:
          if child != Pid(0):
            discard posix.kill(child, SIGKILL)

    removeDir(work)
