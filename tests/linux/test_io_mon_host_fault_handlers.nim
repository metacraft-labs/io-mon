## The real Linux shim must preserve the host's synchronous signal handlers.
## A C host installs handlers before loading a private copy of the production
## library, then raises each fault signal in a separate process. io-mon's C
## flush handler may wrap a disposition, but must reach the original handler
## with its signal mask intact. A distinct image exercises initialization
## even under an enclosing monitor. These are controlled signals in real
## processes, with alarm deadlines; no mocks or genuine invalid memory access.
import std/[os, osproc, strutils, tempfiles, unittest]
import build_test_shim

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
const hostSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void host_fault(int signal) {
  sigset_t active;
  if (sigprocmask(SIG_SETMASK, NULL, &active) ||
      sigismember(&active, SIGUSR1) != 1 ||
      sigismember(&active, signal) != 1) _exit(69);
  const char message[] = "original host fault handler reached\n";
  if (write(STDOUT_FILENO, message, sizeof(message) - 1) != sizeof(message) - 1)
    _exit(70);
  _exit(73);
}
int main(int argc, char **argv) {
  if (argc != 3) return 10;
  int selected = atoi(argv[2]);
  if (selected < 0 || selected >= 5) return 10;
  alarm(30);
  const int signals[] = {SIGSEGV, SIGILL, SIGFPE, SIGBUS, SIGABRT};
  for (int i = 0; i < 5; ++i) {
    struct sigaction action = {0};
    action.sa_handler = host_fault;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGUSR1);
    action.sa_flags = SA_RESTART;
    if (sigaction(signals[i], &action, NULL)) return 11;
  }
  if (!dlopen(argv[1], RTLD_NOW | RTLD_LOCAL)) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 12;
  }
  raise(signals[selected]);
  return 15; /* The original handler must have exited 73. */
}
"""

suite "Linux injected shim preserves host fault handlers":
  test "fault delivery reaches the original host handler with its mask":
    let work = createTempDir("io-mon-host-faults-", "")
    defer: removeDir(work)
    let builtShim = buildPrivateLinuxShim(repoRoot)
    let shim = work / "distinct-monitor.so"
    copyFile(builtShim, shim)
    let source = work / "host.c"
    let host = work / "host"
    writeFile(source, hostSource)
    let built = execCmdEx(quoteShellCommand([getEnv("CC", "cc"), source,
      "-o", host, "-ldl"]))
    checkpoint(built.output)
    require built.exitCode == 0
    for signalIndex in 0 ..< 5:
      let observed = execCmdEx(quoteShellCommand([host, shim, $signalIndex]))
      checkpoint("signal index " & $signalIndex & ": " & observed.output)
      check observed.exitCode == 73
      check "original host fault handler reached" in observed.output
