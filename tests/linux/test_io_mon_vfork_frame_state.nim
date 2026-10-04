## Real vfork/exec must leave the suspended parent's Nim frame state unchanged.
## The production build script compiles the actual shim with one test-only
## include: a trace-free getter for Nim's frame pointer. It changes no hook or
## compiler setting. A C host queries it immediately before and after its
## child's successful exec, before libc can reuse the abandoned child stack.
## The previous trace-enabled shim returns a non-null abandoned frame (exit 71)
## on both x64 and ARM. The normal POSIX settings keep both observations null.
## This directly covers the state that a repeated-vfork workload may overwrite
## without crashing. Capture completeness is covered by the propagation suite.
## No mocks. All processes, compiler invocations and the loaded library are real.
import std/[os, osproc, strtabs, strutils, tempfiles, unittest]

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
const probeSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc == 2) return 0; /* successful exec child */
  alarm(30);
  void *(*frame)(void) = dlsym(RTLD_DEFAULT, "io_mon_test_frame_state");
  if (!frame) return 10;
  void *before = frame();
  pid_t child = vfork();
  if (child < 0) return 11;
  if (child == 0) {
    execl(argv[0], argv[0], "child", (char *)0);
    _exit(12);
  }
  void *after = frame();
  int intact = before == NULL && after == NULL;
  printf("vfork frame state: before-null=%d after-null=%d\n",
         before == NULL, after == NULL);
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return 13;
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 14;
  return intact ? 0 : 71;
}
"""

suite "Linux vfork preserves the suspended host runtime":
  test "successful child exec leaves no abandoned Nim frame in parent TLS":
    let work = createTempDir("io-mon-vfork-frame-", "")
    defer: removeDir(work)
    let getter = work / "frame_state_probe.nim"
    # --include is applied to every project module; export the getter once.
    writeFile(getter, "when isMainModule:\n" &
      "  proc io_mon_test_frame_state(): pointer " &
      "{.exportc, dynlib, stackTrace: off, raises: [].} =\n" &
      "    cast[pointer](getFrame())\n")
    var buildEnv = newStringTable(modeCaseSensitive)
    for key, value in envPairs(): buildEnv[key] = value
    buildEnv["IO_MON_SHIM_OUT_DIR"] = work / "lib"
    buildEnv["IO_MON_SHIM_NIMCACHE_DIR"] = work / "nimcache"
    let builtShim = execCmdEx(quoteShellCommand(["bash",
      repoRoot / "scripts/build_shim.sh", "--include:" & getter]), env = buildEnv)
    checkpoint(builtShim.output)
    require builtShim.exitCode == 0
    let shim = work / "lib/librepro_monitor_shim.so"
    require fileExists(shim)
    let source = work / "probe.c"
    let binary = work / "probe"
    writeFile(source, probeSource)
    let compiled = execCmdEx(quoteShellCommand([getEnv("CC", "cc"), source,
      "-ldl", "-o", binary]))
    checkpoint(compiled.output)
    require compiled.exitCode == 0
    var env = newStringTable(modeCaseSensitive)
    for key, value in envPairs(): env[key] = value
    env["LD_PRELOAD"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    let observed = execCmdEx(quoteShell(binary), env = env)
    checkpoint(observed.output)
    check observed.exitCode == 0
    check "vfork frame state: before-null=1 after-null=1" in observed.output
