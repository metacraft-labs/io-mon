## A host that execs from vfork children does not grow the shim's heap.
##
## WHY. The exec hooks hand the new image an environment the shim prepares on
## its own heap (LD_PRELOAD and the next exec generation added to the
## caller's). The hook frees it when the exec fails; when the exec succeeds
## the image that held it is gone. After vfork, though, the child runs in the
## parent's memory, so a successful exec in a vfork child left the
## preparation allocated in the PARENT, once per exec. A shell or build driver
## that vforks and execs in a loop (posix_spawn-style launchers, make, ninja
## via their own vfork paths) grew without bound.
##
## WHAT THIS TEST GRADES. `t_vfork_exec_does_not_leak_prepared_env`: a host
## pads its environment (so each preparation is a few KiB), warms up, then
## runs thousands of vfork + exec children, alternating execvp of a bare name
## (the PATH-searching route) and execve of an absolute path, and reports how
## much its resident anonymous memory (its heaps) grew over the loop. Preloaded and under `io-mon run`,
## every child must exit 0 and the growth must stay under a bound far below
## what one leaked preparation per exec adds up to (measured: several MiB on
## io-mon 6453936).
##
## Mocks: none. The host is a real program, the shim the built library, and
## the children real executables.

import std/[os, osproc, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  Iterations = "4000"
  MaxGrowthKb = 1024
    ## One leaked preparation per exec is at least 2 KiB with the padded
    ## environment, i.e. about 8 MiB over the loop; a correct shim keeps the
    ## growth to allocator noise.

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc buildC(work, name, source: string): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let built = run(getEnv("CC", "cc"), @[sourcePath, "-O1", "-o", result])
  checkpoint(name & " cc: " & built.output)
  check built.code == 0

proc baseEnv(): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result.del("LD_PRELOAD")

proc countAfter(output, key: string): int =
  let at = output.find(key)
  if at < 0: return -1
  var i = at + key.len
  var digits = ""
  while i < output.len and output[i].isDigit:
    digits.add output[i]
    inc i
  if digits.len == 0: -1 else: parseInt(digits)

const vforkHostSource = """
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static const char *true_path;

/* Resident anonymous memory, in KiB: the heaps (the host's and the shim's),
 * but not the shared file mappings io-mon's capture transport fills with the
 * run's records, which grow legitimately with every exec. See proc(5),
 * /proc/pid/smaps_rollup. */
static long anon_kb(void) {
  FILE *f = fopen("/proc/self/smaps_rollup", "r");
  if (f == NULL) return -1;
  char line[256];
  long kb = -1;
  while (fgets(line, sizeof line, f) != NULL)
    if (sscanf(line, "Anonymous: %ld kB", &kb) == 1) break;
  fclose(f);
  return kb;
}

/* One vfork child that execs `true`: odd i through execvp's PATH search,
 * even i through execve of the absolute path. */
static int one(int i) {
  char *args[] = {"true", NULL};
  pid_t pid = vfork();
  if (pid == 0) {
    if (i & 1) execvp("true", args);
    else execve(true_path, args, environ);
    _exit(127);
  }
  if (pid < 0) return 0;
  int status;
  if (waitpid(pid, &status, 0) != pid) return 0;
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(int argc, char **argv) {
  if (argc < 3) return 2;
  true_path = argv[1];
  int n = atoi(argv[2]);
  char name[32];
  for (int i = 0; i < 200; ++i) {
    snprintf(name, sizeof name, "IO_MON_VFORK_PAD_%03d", i);
    setenv(name, "padding-padding-padding-padding", 1);
  }
  int failures = 0;
  for (int i = 0; i < 64; ++i) failures += !one(i);
  long before = anon_kb();
  for (int i = 0; i < n; ++i) failures += !one(i);
  long after = anon_kb();
  printf("vfork-exec n=%d failures=%d anon_growth_kb=%ld\n", n, failures,
         after - before);
  return failures == 0 && before >= 0 && after >= 0 ? 0 : 1;
}
"""

suite "io-mon shim: exec from vfork children":
  let work = getTempDir() / ("io-mon-vfork-exec-" & $getCurrentProcessId())
  createDir(work)
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(built.output)
  check built.code == 0
  let shimLib = findShimLibrary()
  let host = buildC(work, "vfork_host", vforkHostSource)
  let truePath = findExe("true")

  test "t_vfork_exec_does_not_leak_prepared_env":
    check truePath.len > 0
    let bare = run(host, @[truePath, Iterations], baseEnv())
    checkpoint("without shim (exit " & $bare.code & "):\n" & bare.output)
    check bare.code == 0

    var preloadEnv = baseEnv()
    preloadEnv["LD_PRELOAD"] = shimLib
    let pre = run(host, @[truePath, Iterations], preloadEnv)
    checkpoint("LD_PRELOAD only (exit " & $pre.code & "):\n" & pre.output)
    check pre.code == 0
    check countAfter(pre.output, "failures=") == 0
    let preGrowth = countAfter(pre.output, "anon_growth_kb=")
    check preGrowth >= 0 and preGrowth < MaxGrowthKb

    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0
    var env = baseEnv()
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / "vfork.iomon"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
      truePath, Iterations], env)
    checkpoint("monitored (exit " & $cap.code & "):\n" & cap.output)
    check cap.code == 0
    check countAfter(cap.output, "failures=") == 0
    let capGrowth = countAfter(cap.output, "anon_growth_kb=")
    check capGrowth >= 0 and capGrowth < MaxGrowthKb

  removeDir(work)
