## Real filesystem + compiler + production shim; no mocks. The libc arm works
## on every supported Linux architecture. x86_64 also exercises deferred inline
## classification after both pathname buffers and directory fds have expired.
import std/[os, osproc, sequtils, strtabs, strutils, tempfiles, unittest]
import io_mon
import build_test_shim
import unmonitored_env

const repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
const hostSource = """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/fs.h>

static long rawrename(int ofd, const char *old, int nfd, const char *new,
                      unsigned flags) {
#ifdef INLINE_CALL
  register long r10 __asm__("r10") = (long)new;
  register long r8 __asm__("r8") = flags;
  long r;
  __asm__ volatile("syscall" : "=a"(r)
    : "0"((long)SYS_renameat2), "D"((long)ofd), "S"(old), "d"((long)nfd),
      "r"(r10), "r"(r8) : "rcx", "r11", "memory");
  return r;
#else
  long r = syscall(SYS_renameat2, ofd, old, nfd, new, flags);
  return r == -1 ? -errno : r;
#endif
}
int main(int argc, char **argv) {
  if (argc < 2 || chdir(argv[1])) return 2;
  if (argc == 3 && strcmp(argv[2], "fault") == 0)
    return rawrename(AT_FDCWD, NULL, AT_FDCWD, "fault-output", 0) == -EFAULT
      ? 0 : 21;
  int oldfd = open("old", O_RDONLY | O_DIRECTORY);
  int newfd = open("new", O_RDONLY | O_DIRECTORY);
  if (oldfd < 0 || newfd < 0) return 3;
  char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) return 4;
  char *dst = page + 2048;
#define RENAME(ofd, old, nfd, new, flags) \
  (strcpy(page, old), strcpy(dst, new), \
   rawrename(ofd, page, nfd, dst, flags))
  /* Absolute paths ignore even invalid dirfds. */
  snprintf(page, 2048, "%s/old/absolute", argv[1]);
  snprintf(dst, 2048, "%s/new/absolute", argv[1]);
  if (rawrename(-1, page, -1, dst, 0)) return 22;
  memset(page, 'W', 4096);
  /* Each argument is passed as int, deliberately including AT_FDCWD. */
  if (RENAME(AT_FDCWD, "old/plain", AT_FDCWD, "new/plain", 0)) return 10;
  memset(page, 'W', 4096);
  if (RENAME(oldfd, "exclusive", newfd, "exclusive", RENAME_NOREPLACE))
    return 11;
  memset(page, 'W', 4096);
  if (RENAME(oldfd, "left", newfd, "right", RENAME_EXCHANGE)) return 12;
  memset(page, 'W', 4096);
  /* Directory publication is the exporter failure this regression covers. */
  if (RENAME(oldfd, "stage", newfd, "target", RENAME_EXCHANGE)) return 13;
  memset(page, 'W', 4096);
  if (RENAME(oldfd, "blocked", newfd, "occupied", RENAME_NOREPLACE)
      != -EEXIST) return 14;
  if (RENAME(oldfd, "missing", newfd, "failed", 0) != -ENOENT) return 15;
  if (RENAME(-1, "blocked", newfd, "badfd", 0) != -EBADF) return 16;
  if (RENAME(oldfd, "blocked", newfd, "badflags", 0x80000000u)
      != -EINVAL) return 17;
  memset(page, 'W', 4096);
  munmap(page, 4096);
  close(oldfd);
  close(newfd);
  /* Reuse both numbers with unrelated directories before the deferred drain. */
  if (open("decoy-old", O_RDONLY | O_DIRECTORY) != oldfd) return 18;
  if (open("decoy-new", O_RDONLY | O_DIRECTORY) != newfd) return 19;
  if (chdir("/")) return 20;
  return 0;
}
"""

proc command(cmd: string): string =
  let r = execCmdEx(cmd)
  doAssert r.exitCode == 0, cmd & "\n" & r.output
  r.output

suite "Linux raw renameat2 observes real mutations":
  test "libc and inline calls record both paths, flags, and trap-time names":
    let work = createTempDir("io-mon-raw-renameat2-", "")
    defer: removeDir(work)
    let shim = buildPrivateLinuxShimWithFlags(repoRoot, ["--parallelBuild:2"])
    echo "shim under test: " & shim
    let snoop = work / "io-mon"
    discard command("nim c --parallelBuild:2 --hints:off --warnings:off --threads:on --out:" &
      quoteShell(snoop) & " " & quoteShell(repoRoot / "cmd/io_mon_snoop.nim"))
    writeFile(work / "host.c", hostSource)
    var modes = @["libc"]
    when defined(amd64): modes.add "inline"
    for mode in modes:
      checkpoint("mode: " & mode)
      let host = work / (mode & "-host")
      discard command(quoteShell(getEnv("CC", "cc")) & " -O0 " &
        (if mode == "inline": "-DINLINE_CALL " else: "") &
        quoteShell(work / "host.c") & " -o " & quoteShell(host))
      let tree = work / mode
      for dir in ["old", "new", "old/stage", "new/target", "decoy-old", "decoy-new"]:
        createDir(tree / dir)
      for path in ["old/absolute", "old/plain", "old/exclusive", "old/left", "new/right",
          "old/stage/payload", "new/target/payload", "old/blocked", "new/occupied"]:
        writeFile(tree / path, path)
      let bare = execCmdEx(quoteShell(host) & " " & quoteShell(tree),
        env = unmonitoredEnv())
      check bare.exitCode == 0
      # Restore inputs so bare and monitored runs perform identical operations.
      removeDir(tree)
      for dir in ["old", "new", "old/stage", "new/target", "decoy-old", "decoy-new"]:
        createDir(tree / dir)
      for path in ["old/absolute", "old/plain", "old/exclusive", "old/left", "new/right",
          "old/stage/payload", "new/target/payload", "old/blocked", "new/occupied"]:
        writeFile(tree / path, path)
      var env = unmonitoredEnv()
      env["REPRO_MONITOR_SHIM_LIB"] = shim
      let depPath = work / (mode & ".iomon")
      let cap = execCmdEx(quoteShell(snoop) & " run --depfile " &
        quoteShell(depPath) & " -- " & quoteShell(host) & " " & quoteShell(tree),
        env = env)
      checkpoint(cap.output)
      check cap.exitCode == 0
      check not fileExists(tree / "old/plain")
      check readFile(tree / "new/plain") == "old/plain"
      check readFile(tree / "new/absolute") == "old/absolute"
      check readFile(tree / "new/exclusive") == "old/exclusive"
      check readFile(tree / "old/left") == "new/right"
      check readFile(tree / "new/right") == "old/left"
      check readFile(tree / "old/stage/payload") == "new/target/payload"
      check readFile(tree / "new/target/payload") == "old/stage/payload"
      check readFile(tree / "old/blocked") == "old/blocked"
      check readFile(tree / "new/occupied") == "new/occupied"
      let dep = readMonitorDepFile(depPath)
      for r in dep.records:
        if r.kind == mrEventLoss: checkpoint(r.detail)
      let renames = dep.records.filterIt(it.detail.startsWith("renameat2 "))
      check renames.len == 10  # three ordinary renames + two exchanges, both paths
      proc recorded(path: string; kind: MonitorRecordKind; flags, role: string): bool =
        renames.anyIt(it.path == tree / path and it.kind == kind and
          (" flags=" & flags & " ") in it.detail and
          (" " & role & " run=") in it.detail)
      check recorded("old/absolute", mrFileRead, "0", "source")
      check recorded("new/absolute", mrFileWrite, "0", "destination")
      check recorded("old/plain", mrFileRead, "0", "source")
      check recorded("new/plain", mrFileWrite, "0", "destination")
      check recorded("old/exclusive", mrFileRead, "1", "source")
      check recorded("new/exclusive", mrFileWrite, "1", "destination")
      for path in ["old/left", "old/stage"]:
        check recorded(path, mrFileWrite, "2", "exchange-left")
      for path in ["new/right", "new/target"]:
        check recorded(path, mrFileWrite, "2", "exchange-right")
      check not renames.anyIt("decoy" in it.path or "WWW" in it.path)
      check not dep.records.anyIt(it.kind == mrEventLoss)
      check dep.completeness == mcComplete

      # An unreadable operand must retain the existing fail-closed policy.
      # This separate capture cannot hide a loss in the successful-call oracle.
      let faultPath = work / (mode & "-fault.iomon")
      let fault = execCmdEx(quoteShell(snoop) & " run --depfile " &
        quoteShell(faultPath) & " -- " & quoteShell(host) & " " &
        quoteShell(tree) & " fault", env = env)
      check fault.exitCode == 0
      let failed = readMonitorDepFile(faultPath)
      check failed.completeness == mcIncomplete
      check failed.records.anyIt(it.kind == mrEventLoss and
        "raw syscall unsupported" in it.detail)
      check not failed.records.anyIt(it.detail.startsWith("renameat2 "))
