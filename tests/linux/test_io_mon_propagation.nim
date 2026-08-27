## test_io_mon_propagation — IoMon-Pipeline-Capture IM-2 (Linux) integration tests.
##
## IM-2 asks whether every process below the monitored root is monitored "by
## construction rather than by whatever the parent happened to arrange". On
## Linux the injection channel is `LD_PRELOAD`, which children inherit from the
## kernel for free — so the interesting question is NOT "does a child inherit the
## shim" (it must) but "can a process in the tree LOSE the shim for its
## descendants". These two tests pin both halves of that property.
##
##   grandchild_of_launched_shell_is_monitored
##       Process DEPTH: a shell that forks a shell that forks a reader. The
##       grandchild's read must be in the evidence, under its own pid.
##
##   propagation_survives_exec_chain
##       Process IDENTITY across `exec`: a pid that replaces its image keeps
##       monitoring — including when the exec'ing program builds an EXPLICIT
##       `envp` that omits `LD_PRELOAD`, where free inheritance does not apply
##       and only the shim's active re-injection can save it.
##
## Two shapes here differ deliberately from the milestone's sketch, both for the
## same reason — the obvious spelling does not test what it appears to test:
##
## 1. The sketch's `sh -c 'sh -c "cat f"'` does NOT produce a grandchild.
##    Every POSIX shell tail-`exec`s the final command of a `-c` string, so all
##    three images (outer sh, inner sh, reader) land in ONE pid; measured on
##    mainline, that form yields exactly one `process-start` pid. It is an
##    exec-chain test wearing a process-tree test's name. Appending `; :` defeats
##    the tail-exec optimisation at each level and produces three genuinely
##    distinct pids, which is what "grandchild" has to mean for the assertion to
##    have teeth. The test asserts the distinct-pid depth so it cannot silently
##    decay back into the vacuous form.
##
## 2. A plain `execl` chain inherits `environ` — and with it `LD_PRELOAD` — from
##    the kernel, so it stays monitored even with io-mon's own propagation code
##    entirely disabled. Such a test passes both ways and is worse than no test.
##    The teeth are in the second arm, which rebuilds `envp` from scratch WITHOUT
##    `LD_PRELOAD` and hands it to `execve`. Only the shim's exec hook
##    (`repro_hook_execve` -> `envWithExecGen` -> `ct_linux_preload_env_with_exec_gen`,
##    keyed on `REPRO_MONITOR_SHIM_LIB`) puts the shim back. Mutating that choke
##    point turns this arm red and leaves the inheritance arm green — which is
##    precisely the distinction being pinned.
##
## The second arm drops ONLY `LD_PRELOAD` and preserves the rest of the
## environment on purpose. Wiping the whole environment would also remove
## `REPRO_MONITOR_DEP_SHM`, and the child would then fail to attach the set and
## be graded `mcIncomplete` by the LF-2 hard-fail rule. That is a different
## (and correct, honestly-reported) behaviour; folding it in here would make the
## test pass for the wrong reason.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

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

proc buildC(work, name, source: string): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result])
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc ensureSnoop(work: string): string =
  result = work / "io-mon"
  if not fileExists(result):
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & result, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

proc ensureShim(): string =
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(buildShim.output)
  check buildShim.code == 0
  findShimLibrary()

proc childEnvWith(shimLib: string): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result["REPRO_MONITOR_SHIM_LIB"] = shimLib

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

proc rootPidOf(dep: MonitorDepFile): uint64 =
  ## The first pid-bearing `process-start` is the monitored root.
  for r in dep.records:
    if r.kind == mrProcessStart and r.osPid != 0:
      return r.osPid
  0'u64

proc startPids(dep: MonitorDepFile): seq[uint64] =
  dep.records.filterIt(it.kind == mrProcessStart and it.osPid != 0)
    .mapIt(it.osPid).deduplicate()

## A reader that opens+reads argv[1]. Named distinctly per test so the
## `process-exec` record identifies exactly which image ran.
const readerSrc = """
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char buf[64];
  if (argc < 2) return 1;
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) return 2;
  if (read(fd, buf, sizeof(buf)) <= 0) return 3;
  close(fd);
  return 0;
}
"""

suite "io-mon Linux propagation to descendants (IoMon-Pipeline-Capture IM-2)":
  let work = getTempDir() / ("io-mon-propagation-" & $getCurrentProcessId())
  createDir(work)

  test "grandchild_of_launched_shell_is_monitored":
    # `sh -c 'sh -c "<reader> marker; :"; :'` — a shell whose child shell forks
    # the reader. ONLY the grandchild touches the marker, so the marker's
    # presence in the evidence is attributable to the grandchild alone.
    #
    # The `; :` suffixes are load-bearing: without them each shell tail-`exec`s
    # its final command and all three images collapse into ONE pid, so the test
    # would assert nothing about process depth. The distinct-pid check below
    # fails if that ever silently reverts.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    let reader = buildC(work, "grandchild_reader", readerSrc)
    let marker = work / "grandchild-marker.txt"
    writeFile(marker, "grandchild marker payload\n")
    let depfile = work / "grandchild.iomon"

    let inner = reader & " " & marker & "; :"
    let outer = "/bin/sh -c '" & inner & "'; :"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--",
      "/bin/sh", "-c", outer], childEnvWith(shimLib))
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)

    # The grandchild's read of the marker is in the evidence.
    check hasFileRead(dep, marker)
    # ...and the tree is graded fully monitored, with no unmonitored-subtree loss.
    check dep.completeness == mcComplete
    check not dep.records.anyIt(it.kind == mrEventLoss)

    # Genuine DEPTH: root sh, child sh, grandchild reader — three distinct pids.
    # (Guards against the tail-exec collapse described above.)
    let pids = startPids(dep)
    check pids.len >= 3

    # The reader really is a descendant, not the root re-execing in place.
    let root = rootPidOf(dep)
    check root != 0'u64
    let readerExecs = dep.records.filterIt(
      it.kind == mrProcessExec and reader in it.path)
    check readerExecs.len >= 1
    check readerExecs.allIt(it.osPid != 0'u64)
    check readerExecs.allIt(it.osPid != root)

  test "propagation_survives_exec_chain":
    # Two arms over the same property, separated so a mutation report can say
    # which mechanism actually held.
    let snoopBin = ensureSnoop(work)
    let shimLib = ensureShim()

    let reader = buildC(work, "execchain_reader", readerSrc)

    # -- arm (a): plain exec chain, environ inherited --------------------------
    # A pid that replaces its image via execl keeps monitoring. This is the
    # baseline property; it holds by kernel inheritance of LD_PRELOAD.
    let markerA = work / "execchain-inherit-marker.txt"
    writeFile(markerA, "exec chain inherit marker\n")
    let execer = buildC(work, "execchain_execer", """
#include <unistd.h>
int main(int argc, char **argv) {
  execl(argv[1], argv[1], argv[2], (char *)0);
  _exit(9);
}
""")
    let depA = work / "execchain-inherit.iomon"
    let capA = run(snoopBin, @["run", "--depfile", depA, "--",
      execer, reader, markerA], childEnvWith(shimLib))
    checkpoint(capA.output)
    check capA.code == 0

    let depFileA = readMonitorDepFile(depA)
    check hasFileRead(depFileA, markerA)
    check depFileA.completeness == mcComplete
    check not depFileA.records.anyIt(it.kind == mrEventLoss)
    # The post-exec image really did run under the same monitored pid.
    check depFileA.records.anyIt(
      it.kind == mrProcessExec and reader in it.path and it.osPid != 0'u64)

    # -- arm (b): explicit envp with LD_PRELOAD REMOVED -----------------------
    # THE TEETH. The exec'ing program copies its environment minus LD_PRELOAD
    # and calls execve with it, so the child cannot inherit the shim. Only the
    # shim's own exec-hook re-injection (keyed on REPRO_MONITOR_SHIM_LIB) can
    # keep the child monitored. Every other monitor variable is preserved, so a
    # failure here is a propagation failure and not an LF-2 attach failure.
    let markerB = work / "execchain-stripped-marker.txt"
    writeFile(markerB, "exec chain stripped marker\n")
    let stripper = buildC(work, "execchain_stripper", """
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv) {
  int n = 0;
  for (char **it = environ; *it != 0; it++) n++;
  char **child = (char **)calloc((size_t)n + 1, sizeof(char *));
  if (child == 0) _exit(8);
  int k = 0;
  for (char **it = environ; *it != 0; it++)
    if (strncmp(*it, "LD_PRELOAD=", 11) != 0) child[k++] = *it;
  child[k] = 0;
  execve(argv[1], &argv[1], child);
  _exit(9);
}
""")
    let depB = work / "execchain-stripped.iomon"
    let capB = run(snoopBin, @["run", "--depfile", depB, "--",
      stripper, reader, markerB], childEnvWith(shimLib))
    checkpoint(capB.output)
    check capB.code == 0

    let depFileB = readMonitorDepFile(depB)
    # The exec'd child was re-injected: its read is in the evidence...
    check hasFileRead(depFileB, markerB)
    # ...and no unmonitored-subtree downgrade was recorded for it.
    check depFileB.completeness == mcComplete
    check not depFileB.records.anyIt(it.kind == mrEventLoss)
    check depFileB.records.anyIt(
      it.kind == mrProcessExec and reader in it.path and it.osPid != 0'u64)
