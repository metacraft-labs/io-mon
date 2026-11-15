## An inline system call made on a small signal alternate stack is trapped
## without overflowing it.
##
## WHY. The inline-syscall backend replays each trapped call in a SIGTRAP
## handler installed without SA_ONSTACK, so the handler runs on whatever stack
## the trapped thread was on. When a program's OWN signal handler runs on a
## `sigaltstack` and makes an inline system call, that is the alternate stack,
## which a program may size as small as the kernel allows. The first trap of a
## process arms the inline loss (it creates an empty armed file in the
## fragment directory), and the helpers that build that file's path used to put
## a PATH_MAX (4 KiB) array on the stack. On a small alternate stack that
## overflowed into whatever lay below it.
##
## WHAT THIS TEST GRADES. A program raises SIGUSR1 with an SA_ONSTACK
## handler on an alternate stack painted with a known byte, and makes its
## first inline `openat` (and `close`) from that handler, so the first trap of
## the process, the one that arms, runs there. It then reports how deep the
## alternate stack was used. Run unmonitored, that is the kernel's signal
## frame plus the program's own handler; run under the shim, the trap path
## comes on top. The difference must stay within `TrapPathBudget`, the open
## must be recorded, and the capture must be complete with no loss (the exit
## drain retracts the armed file).
##
## Painting is used rather than a guard page below a small stack: a frame
## that holds a large array writes only the array's lowest bytes, so the calls
## below it can land beyond a guard page instead of in it, and the overflow
## then corrupts memory without a fault. A depth measurement has no such
## blind spot.
##
## Neutered by restoring the PATH_MAX buffers: the trap path's depth exceeds
## the budget.
##
## x86_64 only: no other architecture has the inline-syscall trap backend.
##
## Mocks: none. Real program, real shim, real files.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  TrapPathBudget = 6144
    ## Bytes of alternate stack the shim's trap path may add to an inline
    ## system call made on it. Measured on x86_64 (gcc, the default shim
    ## build): about 4.5 KiB with the bounded path buffers, about 8.0 KiB with
    ## the PATH_MAX ones. MINSIGSTKSZ is 2 KiB and glibc's SIGSTKSZ 8 KiB.

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
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The only `syscall` instruction in this program, reached only from the
 * signal handler, so the first trap of the process happens there. */
static long __attribute__((noinline))
raw6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
  register long r10 __asm__("r10") = a3;
  register long r8 __asm__("r8") = a4;
  register long r9 __asm__("r9") = a5;
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(nr), "D"(a0), "S"(a1), "d"(a2),
                     "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

static volatile sig_atomic_t opened = 0;

static void on_usr1(int sig) {
  (void)sig;
  long fd = raw6(SYS_openat, AT_FDCWD, (long)"input-a.txt", O_RDONLY, 0, 0, 0);
  if (fd >= 0) {
    opened = 1;
    raw6(SYS_close, fd, 0, 0, 0, 0, 0);
  }
}

/* host <dir>: run the handler on a 64 KiB alternate stack painted with a
 * known byte, then print how many bytes of it were used (the deepest byte
 * that changed, measured from the top), and exit 0 when the inline open
 * succeeded. */
#define ALT (64 * 1024)
int main(int argc, char **argv) {
  if (argc < 2 || chdir(argv[1]) != 0) return 2;
  char *region = mmap(NULL, ALT, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (region == MAP_FAILED) return 3;
  memset(region, 0xA5, ALT);
  stack_t ss;
  memset(&ss, 0, sizeof ss);
  ss.ss_sp = region;
  ss.ss_size = ALT;
  if (sigaltstack(&ss, NULL) != 0) return 4;
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_usr1;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_ONSTACK;
  if (sigaction(SIGUSR1, &sa, NULL) != 0) return 5;
  raise(SIGUSR1);
  size_t untouched = 0;
  while (untouched < ALT && (unsigned char)region[untouched] == 0xA5)
    untouched++;
  printf("altstack-used=%zu\n", (size_t)ALT - untouched);
  return opened ? 0 : 6;
}
"""

suite "io-mon: inline syscall trapped on a signal alternate stack":
  when not defined(amd64):
    test "x86_64 only":
      skip()
  else:
    let work = getTempDir() / ("io-mon-small-altstack-" &
      $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let snoopBin = work / "io-mon"
    let cli = run("nim", @["c", "--hints:off", "--warnings:off",
      "--threads:on", "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--nimcache:" & (work / "nimcache"), "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    require cli.code == 0
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let host = work / "host"
    writeFile(work / "host.c", hostSource)
    let cc = run(getEnv("CC", "cc"), @["-O1", work / "host.c", "-o", host])
    checkpoint(cc.output)
    require cc.code == 0
    let tree = work / "tree"
    createDir(tree)
    writeFile(tree / "input-a.txt", "a")

    proc depthOf(output: string): int =
      for line in output.splitLines():
        if line.startsWith("altstack-used="):
          return parseInt(line["altstack-used=".len .. ^1])
      -1

    test "the first trap, on an alternate stack, stays within the trap-path budget":
      # Unmonitored: the kernel's frame and the program's handler.
      let bare = run(host, @[tree])
      checkpoint("unmonitored: exit " & $bare.code & ": " & bare.output)
      require bare.code == 0
      let baseline = depthOf(bare.output)
      require baseline > 0
      let depfile = work / "trap.iomon"
      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let r = run(snoopBin, @["run", "--depfile", depfile, "--", host, tree],
        env)
      checkpoint("monitored: exit " & $r.code & ": " & r.output)
      check r.code == 0
      let depth = depthOf(r.output)
      checkpoint("baseline=" & $baseline & " monitored=" & $depth)
      check depth > baseline             # the handler really trapped there
      check depth - baseline <= TrapPathBudget
      let dep = readMonitorDepFile(depfile)
      let opens = dep.records.filterIt(it.kind == mrFileOpen and
        it.path == tree / "input-a.txt")
      check opens.len == 1
      let losses = dep.records.filterIt(it.kind == mrEventLoss)
      check losses.len == 0
      if losses.len != 0: checkpoint(losses.mapIt(it.detail).join("; "))
      check dep.completeness == mcComplete

    removeDir(work)
