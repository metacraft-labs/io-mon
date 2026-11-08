## Linux: the monitor must not change what `dlsym(RTLD_NEXT, …)` returns to
## the object that asks.
##
## glibc answers `dlsym(RTLD_NEXT, name)` with the first definition of `name`
## loaded AFTER the object that called `dlsym`, and it identifies that object
## from dlsym's RETURN ADDRESS. The shim interposes `dlsym` (for the vDSO
## replacement), so before the fix every such lookup reached glibc from inside
## `librepro_monitor_shim.so` and was answered relative to the shim.
##
## That is fatal to any other LD_PRELOAD hook library loaded after the shim:
## `io-mon run` prepends the shim to the inherited `LD_PRELOAD`, so a hook
## library already in the environment sits after it, and the "next" definition
## after the shim is the hook library's OWN export. Its hook then calls itself
## until the stack overflows. Measured 2026-11-08: Agent Harbor's command-trace
## shim resolved its "real" `fcntl` to its own `fcntl`, every monitored process
## of an agent session died of SIGSEGV, and `repro exec` failed with a bare
## `__repro_provider_compile asFailed`.
##
## The same defect has a quieter second face: an object loaded BEFORE the shim
## (the program, or a hook library preloaded ahead of it) asking for the next
## definition of a function the shim hooks got libc's, skipping the shim, so
## its calls went unobserved.
##
## NO MOCKS. A real hook library and program built with `cc`, the real shim,
## the real `io-mon run` driver and the real dynamic loader. The expected
## answers are not hard-coded loader trivia: each assertion names the first
## object after the caller that defines the symbol, and the unmonitored run is
## measured in the same test as the ground truth for the hook library.

import std/[os, osproc, streams, strtabs, strutils, tempfiles, unittest]

import io_mon
import build_test_cli
import build_test_shim
import unmonitored_env

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()

# The hook library has the shape of every LD_PRELOAD interposer: it exports
# the libc name and forwards to `dlsym(RTLD_NEXT, name)`. A hook whose "next"
# definition is itself calls itself forever: as a tail call that is a busy
# loop, otherwise a stack overflow (Agent Harbor's shim). The re-entry guard
# turns either into a named exit status, so the failure is readable.
const hookSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

const char *foreign_owner_of(void *symbol) {
  Dl_info info;
  if (symbol == NULL) return "(null)";
  if (!dladdr(symbol, &info) || info.dli_fname == NULL) return "(unknown)";
  const char *slash = strrchr(info.dli_fname, '/');
  return slash ? slash + 1 : info.dli_fname;
}

static int getppid_depth;

pid_t getppid(void) {
  static pid_t (*real)(void);
  if (getppid_depth > 0) {
    fprintf(stderr, "foreign-hook: getppid re-entered: RTLD_NEXT resolved "
                    "it to %s\n", foreign_owner_of((void *)real));
    _exit(97);
  }
  if (real == NULL) real = (pid_t (*)(void))dlsym(RTLD_NEXT, "getppid");
  if (real == NULL) _exit(98);
  getppid_depth++;
  pid_t result = real();
  getppid_depth--;
  return result;
}

/* What RTLD_NEXT answers when THIS library asks. */
const char *foreign_next_owner(const char *name) {
  return foreign_owner_of(dlsym(RTLD_NEXT, name));
}

/* The same question from this library's constructor. Constructors run in
   reverse load order, so when the shim precedes this library this runs
   BEFORE the shim's constructor has resolved anything -- the moment a real
   hook library resolves its "real" functions. */
static const char *ctor_getppid_owner = "(not run)";
__attribute__((constructor)) static void foreign_ctor(void) {
  ctor_getppid_owner = foreign_next_owner("getppid");
}
const char *foreign_ctor_getppid_owner(void) { return ctor_getppid_owner; }
"""

const programSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
  const char *(*next_owner)(const char *) =
      (const char *(*)(const char *))dlsym(RTLD_DEFAULT, "foreign_next_owner");
  const char *(*owner_of)(void *) =
      (const char *(*)(void *))dlsym(RTLD_DEFAULT, "foreign_owner_of");
  const char *(*ctor_owner)(void) =
      (const char *(*)(void))dlsym(RTLD_DEFAULT, "foreign_ctor_getppid_owner");
  if (next_owner == NULL || owner_of == NULL || ctor_owner == NULL) return 90;
  if (getppid() <= 0) return 91;
  printf("ctor-getppid=%s\n", ctor_owner());
  printf("hook-getppid=%s\n", next_owner("getppid"));
  printf("hook-getenv=%s\n", next_owner("getenv"));
  printf("main-getenv=%s\n", owner_of(dlsym(RTLD_NEXT, "getenv")));
  return 0;
}
"""

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  ## Bounded: a hook that loops instead of recursing must fail the test, not
  ## hang it. Output is read after the exit, which is safe for the few lines
  ## these programs print.
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  var code = p.waitForExit(120_000)
  if code == -1 and p.running:
    p.kill()
    discard p.waitForExit()
    code = -1
  let output = p.outputStream.readAll()
  p.close()
  (output, code)

proc envWith(extra: openArray[(string, string)]): StringTableRef =
  ## Every case states the preload list it means: the session running the
  ## suite may carry its own LD_PRELOAD hook library, and an outer monitor's
  ## settings would change the experiment (see `unmonitoredEnv`).
  result = unmonitoredEnv()
  for (key, value) in extra: result[key] = value

proc line(output, key: string): string =
  for candidate in output.splitLines():
    if candidate.startsWith(key & "="):
      return candidate[key.len + 1 .. ^1]
  "(missing)"

suite "io-mon Linux RTLD_NEXT is answered relative to the caller":
  let work = createTempDir("io-mon-rtld-next-", "")
  let cc = getEnv("CC", "cc")
  let hookLib = work / "libforeign_hook.so"
  let program = work / "rtld_next_probe"
  writeFile(work / "hook.c", hookSource)
  writeFile(work / "program.c", programSource)
  let hookBuilt = run(cc, @["-shared", "-fPIC", work / "hook.c", "-o",
    hookLib, "-ldl"])
  checkpoint(hookBuilt.output)
  require hookBuilt.code == 0
  let programBuilt = run(cc, @[work / "program.c", "-o", program, "-ldl"])
  checkpoint(programBuilt.output)
  require programBuilt.code == 0

  let shimLib = buildPrivateLinuxShim(repoRoot)
  let shimName = extractFilename(shimLib)
  let snoopBin = buildTestCli(repoRoot)

  # Ground truth: with only the hook library preloaded, its RTLD_NEXT lookups
  # reach libc.
  let bare = run(program, @[], envWith([("LD_PRELOAD", hookLib)]))
  checkpoint("unmonitored: " & bare.output)
  require bare.code == 0
  let libcName = bare.output.line("hook-getppid")
  require libcName.startsWith("libc.so")
  require bare.output.line("ctor-getppid") == libcName
  require bare.output.line("hook-getenv") == libcName
  require bare.output.line("main-getenv") == libcName

  test "a hook library inherited by io-mon run reaches libc, not itself":
    # The launch the issue took: `io-mon run` prepends its shim to the
    # inherited LD_PRELOAD, so the hook library is loaded after the shim.
    let depfile = work / "inherited.iomon"
    let monitored = run(snoopBin, @["run", "--depfile", depfile, "--",
      program], envWith([("LD_PRELOAD", hookLib),
        ("REPRO_MONITOR_SHIM_LIB", shimLib)]))
    checkpoint("monitored: " & monitored.output)
    # Before the fix (measured at e66e05c): hook-getppid=libforeign_hook.so,
    # the hook library's own export -- the recursion Agent Harbor's shim died of.
    check monitored.code == 0
    check "re-entered" notin monitored.output
    # Nothing after the hook library but libc defines either name.
    check monitored.output.line("hook-getppid") == libcName
    check monitored.output.line("ctor-getppid") == libcName
    check monitored.output.line("hook-getenv") == libcName
    # The program precedes the shim, and the shim defines getenv: the next
    # definition after the program is the shim's, so the call stays observed.
    # Before the fix: libc's.
    check monitored.output.line("main-getenv") == shimName
    require fileExists(depfile)
    check readMonitorDepFile(depfile).completeness == mcComplete

  test "both preload orders answer with the first definition after the caller":
    for (order, preload, hookGetenv) in [
        ("shim first", shimLib & ":" & hookLib, libcName),
        # The hook library precedes the shim, so the next getenv after it is
        # the shim's. Before the fix: libc's, which bypassed the monitor.
        ("hook first", hookLib & ":" & shimLib, shimName)]:
      let monitored = run(program, @[], envWith([("LD_PRELOAD", preload),
        ("REPRO_MONITOR_SHIM_LIB", shimLib)]))
      checkpoint(order & ": " & monitored.output)
      check monitored.code == 0
      check monitored.output.line("hook-getppid") == libcName
      check monitored.output.line("ctor-getppid") == libcName
      check monitored.output.line("hook-getenv") == hookGetenv
      # The hook library defines no getenv, so in either order the first
      # definition after the program is the shim's.
      check monitored.output.line("main-getenv") == shimName

  removeDir(work)
