## Linux: a live test runs without an interposer that puts itself back into
## every child, even when the test was started inside an agent session.
##
## THE DEFECT. In an agent-harbor session every process carries agent-harbor's
## command-trace shim (`libah_command_trace_shim.so`), and that shim adds
## itself to the `LD_PRELOAD` of every child again, whatever environment the
## parent passed. io-mon's `unmonitored_env` removes `LD_PRELOAD` for a bare
## control, but the shim came back, so "bare" controls were not bare and
## monitored runs had two interposers. Eleven tests in seven files failed on
## that alone in an agent session, and passed once the shim was gone: the
## shim's `close` hook re-entered the allocator host's lock, its `connect`
## hook deadlocked under the loader lock and crashed on an unreadable
## address, and its own I/O showed up as evidence that differed between
## launch paths. `tests/helpers/foreign_preload_isolation.nim` re-execs the
## test without it; this file grades that module.
##
## WHAT THIS TEST GRADES. A probe program (`tests/helpers/
## foreign_preload_probe.nim`) built with the module (as every live test is)
## and without it (the control) reports whether the foreign library is mapped
## into itself and into a child it starts with `LD_PRELOAD` removed:
##   1. `t_the_stand_in_propagates_without_isolation`: the control's child
##      still has the library mapped. This proves the stand-in recreates the
##      condition; without it the other cases would pass vacuously.
##   2. `t_isolation_removes_a_self_propagating_preload`: with the module,
##      neither the probe nor its child has it mapped, another `LD_PRELOAD`
##      entry the test chose is kept, and the module's hop counter is gone.
##   3. `t_isolation_refuses_a_preload_it_cannot_remove`: a stand-in that
##      ignores agent-harbor's switch makes the probe stop with a message
##      after the bounded number of re-execs instead of running.
##   4. `t_isolation_removes_the_real_agent_harbor_shim`: the same as (2)
##      with the real shim, when this test was started with one loaded.
##      Skipped, saying so, where agent-harbor is not installed (CI).
##
## Mocks: the stand-in in (1)-(3) imitates the one property of agent-harbor's
## shim that matters here, re-adding itself to `LD_PRELOAD` at exec and
## `posix_spawn` unless `AH_CMDTRACE_DISABLE_AUTO_PROPAGATION` was set when
## it was initialised (agent-harbor `crates/ah-command-trace-shim/src/lib.rs`,
## `compute_init_decisions`). It is justified because CI hosts do not have
## agent-harbor installed. Case (4) runs the real shim wherever it exists, so
## the stand-in cannot drift from it unnoticed on the hosts where the problem
## occurs.
import foreign_preload_isolation

import std/[os, osproc, streams, strtabs, strutils, unittest]

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  probeSrc = repoRoot / "tests" / "helpers" / "foreign_preload_probe.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

const standInSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;
static int propagate;
static char self_path[4096];

__attribute__((constructor)) static void standin_init(void) {
#ifdef IGNORE_SWITCH
  propagate = 1;
#else
  propagate = getenv("AH_CMDTRACE_DISABLE_AUTO_PROPAGATION") == NULL;
#endif
  Dl_info info;
  if (dladdr((void *)standin_init, &info) && info.dli_fname)
    strncpy(self_path, info.dli_fname, sizeof(self_path) - 1);
}

/* The environment the child gets: the caller's, with this library first in
   LD_PRELOAD. Leaked on success, like the image that made it. */
static char **with_self(char *const envp[]) {
  if (!propagate || self_path[0] == 0) return (char **)envp;
  size_t n = 0;
  const char *old = NULL;
  for (; envp[n]; n++)
    if (strncmp(envp[n], "LD_PRELOAD=", 11) == 0) old = envp[n] + 11;
  char **out = calloc(n + 2, sizeof(char *));
  size_t len = strlen(self_path) + 12 + (old ? strlen(old) + 1 : 0);
  char *preload = malloc(len);
  strcpy(preload, "LD_PRELOAD=");
  strcat(preload, self_path);
  if (old && old[0]) { strcat(preload, ":"); strcat(preload, old); }
  size_t j = 0;
  out[j++] = preload;
  for (size_t i = 0; i < n; i++)
    if (strncmp(envp[i], "LD_PRELOAD=", 11) != 0) out[j++] = envp[i];
  out[j] = NULL;
  return out;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
  int (*real)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
  return real(path, argv, with_self(envp));
}
int execv(const char *path, char *const argv[]) {
  return execve(path, argv, environ);
}
int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
  int (*real)(pid_t *, const char *, const posix_spawn_file_actions_t *,
              const posix_spawnattr_t *, char *const[], char *const[]) =
      dlsym(RTLD_NEXT, "posix_spawn");
  return real(pid, path, fa, attr, argv, with_self(envp));
}
int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
  int (*real)(pid_t *, const char *, const posix_spawn_file_actions_t *,
              const posix_spawnattr_t *, char *const[], char *const[]) =
      dlsym(RTLD_NEXT, "posix_spawnp");
  return real(pid, file, fa, attr, argv, with_self(envp));
}
"""

const keepSource = """
int foreign_preload_isolation_keep_marker(void) { return 1; }
"""

proc buildLibrary(dir, name, source: string; defines: seq[string] = @[]):
    string =
  ## Builds `source` as the shared library `<dir>/<name>`. The stand-in is
  ## named like agent-harbor's shim, the file name the module looks for.
  createDir(dir)
  result = dir / name
  let src = dir / (name & ".c")
  writeFile(src, source)
  var args = @["-shared", "-fPIC", "-O1", src, "-o", result, "-ldl"]
  for d in defines: args.add "-D" & d
  let built = run(getEnv("CC", "cc"), args)
  checkpoint(name & " cc: " & built.output)
  doAssert built.code == 0, built.output

proc buildProbe(work: string; isolate: bool): string =
  result = work / (if isolate: "probe-isolated" else: "probe-control")
  var args = @["c", "--hints:off", "--warnings:off",
    "--path:" & (repoRoot / "tests" / "helpers"),
    "--nimcache:" & (result & "-nimcache"), "--out:" & result]
  if isolate: args.add "-d:isolate"
  args.add probeSrc
  let built = run("nim", args)
  checkpoint("probe build: " & built.output)
  doAssert built.code == 0, built.output

proc probeEnv(preload: string): StringTableRef =
  ## This process's environment with `preload` as `LD_PRELOAD`, and without
  ## agent-harbor's switch: this test's own isolation set it, and a probe
  ## started with it would never propagate the library under test.
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs():
    if k notin ["LD_PRELOAD", AgentHarborDisablePropagationEnv,
                IsolationHopsEnv]:
      result[k] = v
  result["LD_PRELOAD"] = preload

proc roleLine(output, role: string): string =
  for line in output.splitLines():
    if line.startsWith(role & " "):
      return line
  ""

suite "live tests run without a self-propagating foreign preload":
  let work = getTempDir() / ("io-mon-foreign-preload-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)
  let standIn = buildLibrary(work / "standin", AgentHarborShimName,
    standInSource)
  let stubborn = buildLibrary(work / "stubborn", AgentHarborShimName,
    standInSource, @["IGNORE_SWITCH"])
  let keep = buildLibrary(work / "keep", "libkeep_preload.so", keepSource)
  let control = buildProbe(work, isolate = false)
  let isolated = buildProbe(work, isolate = true)

  test "t_the_stand_in_propagates_without_isolation":
    let r = run(control, @[AgentHarborShimName], probeEnv(standIn))
    checkpoint("control (exit " & $r.code & "):\n" & r.output)
    check r.code == 0
    check "mapped=1" in roleLine(r.output, "self")
    # The child was given an environment without LD_PRELOAD and still has
    # the library: the condition every live test met in an agent session.
    check "mapped=1" in roleLine(r.output, "child")

  test "t_isolation_removes_a_self_propagating_preload":
    let r = run(isolated, @[AgentHarborShimName, keep.extractFilename],
      probeEnv(standIn & ":" & keep))
    checkpoint("isolated (exit " & $r.code & "):\n" & r.output)
    check r.code == 0
    let self = roleLine(r.output, "self")
    let child = roleLine(r.output, "child")
    check "mapped=0" in self
    check "mapped=0" in child
    # The entry the test chose stays where it was put.
    check "keep=1" in self
    check ("preload=[" & keep & "]") in self
    check "hops=unset" in self
    check "hops=unset" in child

  test "t_isolation_refuses_a_preload_it_cannot_remove":
    let r = run(isolated, @[AgentHarborShimName], probeEnv(stubborn))
    checkpoint("stubborn (exit " & $r.code & "):\n" & r.output)
    check r.code != 0
    check "is still mapped after 2 re-execs" in r.output
    check roleLine(r.output, "self") == ""

  test "t_isolation_removes_the_real_agent_harbor_shim":
    let real = removedForeignPreload
    if real.len == 0 or not fileExists(real):
      checkpoint("this test was not started with agent-harbor's " &
        "command-trace shim loaded, so the real shim cannot be graded here")
      skip()
    else:
      let bare = run(control, @[AgentHarborShimName], probeEnv(real))
      checkpoint("real shim, control (exit " & $bare.code & "):\n" & bare.output)
      check "mapped=1" in roleLine(bare.output, "child")
      let r = run(isolated, @[AgentHarborShimName], probeEnv(real))
      checkpoint("real shim, isolated (exit " & $r.code & "):\n" & r.output)
      check r.code == 0
      check "mapped=0" in roleLine(r.output, "self")
      check "mapped=0" in roleLine(r.output, "child")

  removeDir(work)
