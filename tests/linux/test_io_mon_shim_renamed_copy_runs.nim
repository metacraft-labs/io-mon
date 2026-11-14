## A copy of the shim under another file name runs, and still patches the
## program's own inline syscalls.
##
## WHY. The startup scan patches every inline `syscall` it finds in the
## process's executable mappings except the system runtime and the shim
## itself. It used to recognize "the shim itself" by its file name
## (`/librepro_monitor_shim.`), so a byte-identical copy under any other name
## patched its own raw-syscall helpers with `int3` and then executed one,
## inside `repro_monitor_shim_init`, before its SIGTRAP handler could take
## it: every process the copy was preloaded into died of SIGTRAP (exit 133),
## and through the monitor the capture failed with no diagnostic. That is
## what an operator's `REPRO_MONITOR_SHIM_LIB` override to a renamed copy
## does (issue 2026-11-14-the-linux-shim-recognizes-its-own-mapping-by-file-
## name-so-a-renamed-copy-traps-on-its-own-syscalls). The scan now finds its
## own image by the address of its trap handler.
##
## WHAT THIS TEST GRADES.
## - Preloaded directly, a copy named `other-name.so` runs `cat` to the end
##   (exit 0, file printed), exactly as the canonically named copy does.
## - Through the monitor, with `REPRO_MONITOR_SHIM_LIB` naming the renamed
##   copy, a program whose only `openat` is an inline `syscall` instruction
##   exits 0 and its open is recorded. The record exists only if the scanner
##   patched the PROGRAM's site, so this also shows the fix did not stop the
##   scan from patching what it should.
##
## x86_64 only: no other architecture has the inline-syscall trap backend.
##
## Mocks: none. Real shim (built by the real builder), real programs, real
## files.

import std/[os, osproc, sequtils, streams, strtabs, unittest]

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

proc baseEnv(): StringTableRef =
  ## The caller's environment without any preload of its own, so the shim
  ## under test is the only preloaded library.
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result.del("LD_PRELOAD")

const hostSource = """
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The program's only `syscall` instruction for the open below. */
static long __attribute__((noinline))
raw4(long nr, long a0, long a1, long a2, long a3) {
  register long r10 __asm__("r10") = a3;
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10)
                   : "rcx", "r11", "memory");
  return ret;
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  long fd = raw4(SYS_openat, AT_FDCWD, (long)argv[1], O_RDONLY, 0);
  if (fd < 0) return 3;
  close((int)fd);
  return 0;
}
"""

suite "io-mon Linux shim: a renamed copy excludes itself from patching":
  when not defined(amd64):
    test "skipped off x86_64":
      skip()   # no inline-syscall trap backend on this architecture
  else:
    let work = expandFilename(getTempDir()) /
      ("io-mon-renamed-shim-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let renamed = work / "other-name.so"
    let canonical = work / "librepro_monitor_shim.so"
    copyFile(shimLib, renamed)
    copyFile(shimLib, canonical)
    let input = work / "a.txt"
    writeFile(input, "hello\n")

    test "preloaded directly, a renamed copy runs cat like the canonical one":
      let cat = findExe("cat", followSymlinks = false)
      require cat.len > 0
      for lib in [canonical, renamed]:
        checkpoint("LD_PRELOAD=" & lib)
        let env = baseEnv()
        env["LD_PRELOAD"] = lib
        let r = run(cat, @[input], env)
        checkpoint(r.output)
        # 133 = 128 + SIGTRAP: the shim trapped on its own patched syscall.
        check r.code == 0
        check r.output == "hello\n"

    test "through the monitor, a renamed copy captures an inline open":
      let snoopBin = work / "io-mon"
      let cli = run("nim", @[
        "c", "--hints:off", "--warnings:off", "--threads:on",
        "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
        "--out:" & snoopBin, snoopSrc])
      checkpoint(cli.output)
      require cli.code == 0
      let host = work / "inline-open"
      writeFile(host & ".c", hostSource)
      let hostCc = run(getEnv("CC", "cc"), @[host & ".c", "-O0", "-o", host])
      checkpoint(hostCc.output)
      require hostCc.code == 0

      let env = baseEnv()
      env["REPRO_MONITOR_SHIM_LIB"] = renamed
      let depfile = work / "renamed.iomon"
      let cap = run(snoopBin, @["run", "--depfile", depfile, "--", host,
        input], env)
      checkpoint(cap.output)
      check cap.code == 0
      let dep = readMonitorDepFile(depfile)
      for r in dep.records:
        if r.kind != mrLibraryLoad and r.kind != mrEnvRead:
          checkpoint($r.kind & " " & $r.observationKind & " " & r.path)
      check dep.records.anyIt(it.kind == mrFileOpen and it.path == input)
      # The renamed shim really was the one loaded.
      check dep.records.anyIt(it.kind == mrLibraryLoad and it.path == renamed)

    removeDir(work)
