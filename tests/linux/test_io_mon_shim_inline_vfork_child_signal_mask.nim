## A CLONE_VM|CLONE_VFORK child of a trapped inline `clone` gets the
## program's signal mask, and survives its own trapped `syscall`.
##
## WHY. The x86_64 inline backend patches a program's own `syscall`
## instruction to trap. When the trap handler replayed a `clone` that names a
## child stack from inside itself, the child started inside the handler and
## never went through `rt_sigreturn`, so it kept the mask the kernel set for
## the handler: SIGTRAP blocked. Its first trapped `syscall` then made the
## kernel force the default action of the blocked synchronous trap, and the
## child died by SIGTRAP with a core dump (wait status 0x85), where it exits
## normally unmonitored. The trapped clone now runs from the site's resume
## stub after the signal returns (linux_preload_runtime.nim, "A TRAPPED
## CLONE THAT NAMES A CHILD STACK RUNS OUTSIDE THE HANDLER").
##
## test_io_mon_shim_inline_clone_child_stack.nim grades a CLONE_VM process
## and a thread whose child exits through libc. This file grades the shape
## that failed: a CLONE_VM|CLONE_VFORK child on its own stack, created
## through and leaving through one hand-written `syscall; ret` entry, with
## the parent blocked in the kernel until the child exits.
##
## WHAT THIS TEST GRADES. The program that showed the defect, in three modes:
##   raw-raw   clone through the entry, child exits through the entry
##   raw-libc  clone through the entry, child exits through syscall(3)
##   libc-raw  clone through clone(3), child exits through the entry
## The child records its blocked-signal mask before it exits. Each mode runs
## unmonitored first (the control that the fixture is right: exit 7, an
## empty mask) and then under `io-mon run`, which must print the same line.
## `libc-raw` is the control that a trapped `syscall` in a CLONE_VM child
## that was not created from the trap is handled. In the `raw-*` modes the
## depfile must carry the trapped clone, so the site really was patched.
##
## x86_64 only: the trap substrate this test exercises is the x86_64 one.
##
## Mocks: none. Real program, real shim, real kernel.

import foreign_preload_isolation

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

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

## The program that showed the defect, unchanged apart from this comment's
## absence. It is compiled at -O0, as it was when the defect was found:
## `child` must really call the entry rather than have it inlined.
const hostSource = """
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

long entry6(long, long, long, long, long, long, long);
__asm__(".text\n.globl entry6\n.type entry6,@function\nentry6:\n"
        " movq %rdi,%rax\n movq %rsi,%rdi\n movq %rdx,%rsi\n movq %rcx,%rdx\n"
        " movq %r8,%r10\n movq %r9,%r8\n movq 8(%rsp),%r9\n syscall\n ret\n"
        ".size entry6,.-entry6\n");

static int child_exit_raw;
static volatile unsigned long child_mask = ~0UL;
static char stk[64 * 1024] __attribute__((aligned(16)));

__attribute__((noreturn, force_align_arg_pointer, noinline))
static void child(void) {
  unsigned long m = 0;
  syscall(SYS_rt_sigprocmask, SIG_BLOCK, NULL, &m, 8);
  child_mask = m;
  if (child_exit_raw) entry6(SYS_exit, 7, 0, 0, 0, 0, 0);
  else syscall(SYS_exit, 7);
  for (;;) {}
}

static int child_fn(void *u) { (void)u; child(); }

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "raw-raw";
  child_exit_raw = strcmp(mode, "raw-libc") != 0;
  long pid;
  if (strncmp(mode, "libc", 4) == 0) {
    pid = clone(child_fn, stk + sizeof stk, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
  } else {
    void **sp = (void **)(stk + sizeof stk) - 64;
    for (int i = 0; i < 64; i++) sp[i] = (void *)child;
    pid = entry6(SYS_clone, CLONE_VM | CLONE_VFORK | SIGCHLD, (long)sp, 0, 0, 0, 0);
  }
  if (pid <= 0) { printf("%s: clone failed %ld\n", mode, pid); return 2; }
  int st = 0;
  waitpid((pid_t)pid, &st, 0);
  printf("%s: status=0x%x exited=%d code=%d signaled=%d sig=%d core=%d "
         "child_mask=0x%lx (SIGTRAP bit %s)\n",
         mode, st, WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1,
         WIFSIGNALED(st), WIFSIGNALED(st) ? WTERMSIG(st) : 0,
         WIFSIGNALED(st) ? WCOREDUMP(st) : 0, child_mask,
         child_mask == ~0UL ? "unknown" :
         (child_mask & (1UL << (SIGTRAP - 1))) ? "BLOCKED" : "clear");
  return 0;
}
"""

proc resultLine(output, mode: string): string =
  ## The program's one verdict line; anything else in the output (the
  ## monitor's own diagnostics) is not compared.
  for line in output.splitLines():
    if line.startsWith(mode & ": "): return line
  ""

suite "io-mon Linux shim: a vfork child of a trapped inline clone":
  when not defined(amd64):
    test "t_inline_vfork_child_signal_mask":
      skip()   # the trap substrate under test is the x86_64 one
  else:
    let work = expandFilename(getTempDir()) /
      ("io-mon-inline-vfork-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    doAssert cli.code == 0, cli.output
    let host = work / "vfork_trap"
    writeFile(host & ".c", hostSource)
    let hostCc = run(getEnv("CC", "cc"), @[host & ".c", "-O0", "-g",
      "-fno-stack-protector", "-o", host])
    doAssert hostCc.code == 0, hostCc.output
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): env[k] = v
    env.del("LD_PRELOAD")
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    putEnv("REPRO_MONITOR_SHIM_LIB", shimLib)

    test "t_inline_vfork_child_runs_as_unmonitored":
      for mode in ["raw-raw", "raw-libc", "libc-raw"]:
        checkpoint(mode)
        let plain = run(host, @[mode])
        checkpoint("unmonitored: " & plain.output)
        let expected = mode & ": status=0x700 exited=1 code=7 signaled=0 " &
          "sig=0 core=0 child_mask=0x0 (SIGTRAP bit clear)"
        # The control: unmonitored, the fixture exits normally with SIGTRAP
        # unblocked in the child.
        check plain.code == 0
        check resultLine(plain.output, mode) == expected
        let depfile = work / (mode & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
          mode], env)
        checkpoint("monitored: " & cap.output)
        check cap.code == 0
        check resultLine(cap.output, mode) == expected
        if mode.startsWith("raw-"):
          # The clone's site really was trapped: an unpatched `syscall`
          # would leave no trace of the clone at all.
          let dep = readMonitorDepFile(depfile)
          let trapped = dep.records.filterIt(it.kind == mrEventLoss and
            it.detail.startsWith("inline raw syscall") and
            "nr=56" in it.detail)   # SYS_clone on x86_64
          checkpoint($dep.records.mapIt(it.detail))
          check trapped.len >= 1

    removeDir(work)
