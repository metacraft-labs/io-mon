## A `POSIX_SPAWN_SETEXEC` spawn is recorded ONCE, not twice.
##
## ## The defect
##
## `posix_spawnp` reaches the real implementation through libSystem's internal
## `posix_spawn`, which the body patch also intercepts — so one user-level
## spawn fires both hooks. `recordSetexecExec` ran in both, emitting two
## byte-identical `posix_spawn-setexec` exec records for a single in-place
## image replacement. `spawnForward` already solved exactly this problem for
## env-propagation and the SIP rewrite with an `inSpawnForward` depth guard;
## the record was simply emitted outside it.
##
## ## Why a duplicate is not cosmetic
##
## T0's coverage check compares tallies: for an anchored pid,
## `effectiveExecs >= starts` means the last exec landed in an image the shim
## could not load into, so the subtree behind it is unmonitored and the edge is
## downgraded. A duplicated exec inflates the left-hand side, so a **fully
## monitored** chain reports a loss it did not suffer.
##
## Measured before the fix, `arch -arch arm64 <prog>` through a drop-in:
## execs=3, starts=3 → reported as an unmonitored subtree, while the depfile
## plainly showed the shim loading in both the `arch` image and the target's.
## After: one record, execs=2, starts=3, no loss.
##
## The direction of that error is the safe one, which is why it survived: it
## costs a re-run, never a false cache hit. But it also makes any `arch`-style
## SETEXEC drop-in pointless, because the loss such a drop-in exists to prevent
## is reported anyway.
##
## Mocking: none. A real `posix_spawnp` with `POSIX_SPAWN_SETEXEC` under the
## real shim, asserted against the records it actually wrote. The synthetic
## arm at the end asserts the CLASSIFIER's sensitivity to the duplicate, which
## is the consumer whose answer changed.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

const repoRoot = currentSourcePath.parentDir.parentDir.parentDir

when not defined(macosx):
  echo "SETEXEC recording is macOS-only; nothing to assert here"
else:
  import io_mon

  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc synthStart(pid: uint64): MonitorRecord =
    MonitorRecord(kind: mrProcessStart, observationKind: moProcessStart,
      osPid: pid)

  proc synthSpawn(parent, child: uint64): MonitorRecord =
    MonitorRecord(kind: mrProcessSpawn, observationKind: moExecute,
      osPid: parent, childOsPid: child)

  proc synthSetexec(pid: uint64; path: string): MonitorRecord =
    ## The shape `recordSetexecExec` writes: an exec whose child pid is the
    ## process itself, tagged so the reader can tell an in-place replacement
    ## from an ordinary exec.
    MonitorRecord(kind: mrProcessExec, observationKind: moExecute, osPid: pid,
      childOsPid: pid, path: path, detail: "posix_spawn-setexec")

  suite "macOS SETEXEC spawn is recorded once":

    test "one posix_spawnp+SETEXEC yields exactly one exec record":
      let work = getTempDir() / ("io-mon-setexec-" & $getCurrentProcessId())
      removeDir(work)
      createDir(work)
      defer: removeDir(work)

      # A probe that re-images itself once, the way arch(1) does. The target is
      # incidental: the assertion is about how many records the SPAWN produced.
      let probeSrc = work / "setexec.c"
      writeFile(probeSrc, """
#include <spawn.h>
extern char **environ;
int main(void) {
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
  char *argv[] = { "/usr/bin/true", 0 };
  pid_t pid;
  posix_spawnp(&pid, "/usr/bin/true", 0, &attr, argv, environ);
  return 3; /* SETEXEC only returns on failure */
}
""")
      let probe = work / "setexec"
      let ccBin = getEnv("CC", "cc")
      let (ccOut, ccCode) = execCmdEx(quoteShell(ccBin) & " " &
        quoteShell(probeSrc) & " -o " & quoteShell(probe))
      doAssert ccCode == 0, "cc failed: " & ccOut

      let shim = buildShim()
      let fragmentDir = work / "frags"
      createDir(fragmentDir)

      var env = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): env[k] = v
      env["DYLD_INSERT_LIBRARIES"] = shim
      env["REPRO_MONITOR_SHIM_LIB"] = shim
      env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir

      let p = startProcess(probe, args = @[], env = env,
        options = {poStdErrToStdOut})
      let output = p.outputStream.readAll()
      let exitCode = p.waitForExit()
      p.close()
      checkpoint("probe exit=" & $exitCode & " out=" & output)

      let depfile = work / "cap.iomon"
      discard mergeFragments(fragmentDir, depfile)
      doAssert fileExists(depfile), "no depfile produced"
      let dep = readMonitorDepFile(depfile)

      let setexecRecords = dep.records.filterIt(
        it.kind == mrProcessExec and
        it.detail.contains("posix_spawn-setexec"))
      # One user-level spawn, one record. Two is the defect; zero would mean
      # the record was lost entirely — worse, and equally a failure.
      check setexecRecords.len == 1

    test "a monitored SETEXEC chain reports no unmonitored subtree":
      let records = @[
        synthSpawn(0, 100),                      # root-spawn anchor
        synthStart(100),                         # initial shim load
        synthSetexec(100, "/usr/bin/true"),
        synthStart(100),                         # the new image loaded the shim
      ]
      check unmonitoredSubtreeLossCount(records) == 0

    test "the duplicate the fix removes would have reported a phantom loss":
      let records = @[
        synthSpawn(0, 100),
        synthStart(100),
        synthSetexec(100, "/usr/bin/true"),
        synthSetexec(100, "/usr/bin/true"),      # the pre-fix double report
        synthStart(100),
      ]
      check unmonitoredSubtreeLossCount(records) == 1
