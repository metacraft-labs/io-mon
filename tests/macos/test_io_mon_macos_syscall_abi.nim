## Real ARM64 syscall forwarding and two-copy startup regression. No mocks:
## compile a C program, build the production shim privately, copy it to a second
## image, and execute the actual kernel calls with and without injection. Every
## child has a timeout; a startup hang fails and is killed/reaped by the fixture.
import std/[os, osproc, sequtils, streams, strtabs, strutils, tempfiles, unittest]

when defined(macosx):
  import std/posix
  import io_mon
  import build_test_shim
  import macos_backend_toggle

  const root = currentSourcePath().parentDir.parentDir.parentDir

  if paramCount() >= 2 and paramStr(1) == "--nested-reader":
    doAssert readFile(paramStr(2) / "inner-input") == "inner-input"
    quit(0)
  if paramCount() == 3 and paramStr(1) == "--nested-host":
    let work = paramStr(2)
    doAssert readFile(work / "outer-input") == "outer-input"
    putEnv(ShimLibOverrideEnv, paramStr(3))
    let inner = runMonitored(FsSnoopRequest(
      command: @[getAppFilename(), "--nested-reader", work],
      depFilePath: work / "inner.iomon"))
    doAssert inner.exitCode == 0
    doAssert inner.completeness == mcComplete
    doAssert readFile(work / "outer-input") == "outer-input"
    quit(0)
  if paramCount() == 4 and paramStr(1) == "--nested-outer":
    # A private process group lets the supervising fixture reap a wedged
    # launch tree without touching any other test's processes.
    doAssert setsid() >= 0
    let work = paramStr(2)
    putEnv(ShimLibOverrideEnv, paramStr(3))
    let outer = runMonitored(FsSnoopRequest(
      command: @[getAppFilename(), "--nested-host", work, paramStr(4)],
      depFilePath: work / "outer.iomon"))
    quit(outer.exitCode)

  proc runProbe(probe, input, mode, libraries, fragments: string):
      tuple[code: int, output: string] =
    var env = newStringTable(modeCaseSensitive)
    for key, value in envPairs():
      if not key.startsWith("REPRO_MONITOR_") and
          key notin ["DYLD_INSERT_LIBRARIES", "CT_SANDBOX_TOOLS_DIR"]:
        env[key] = value
    if libraries.len > 0:
      env["DYLD_INSERT_LIBRARIES"] = libraries
      env["REPRO_MONITOR_FRAGMENT_DIR"] = fragments
      env["REPRO_MONITOR_SESSION"] = "syscall-abi"
      applyMacosBackendToggle(env, "both")
    let child = startProcess(probe, args = @[input, mode], env = env,
      options = {poStdErrToStdOut})
    try:
      result.code = child.waitForExit(15_000)
      if result.code == -1:
        child.kill()
        discard child.waitForExit()
      result.output = child.outputStream.readAll()
    finally:
      child.close()

suite "macOS syscall ABI and nested image startup":
  when defined(macosx):
    let work = createTempDir("io-mon-syscall-abi-", "")
    defer: removeDir(work)
    let input = expandFilename(work) / "input"
    writeFile(input, repeat('x', 65536) & "syscall-abi-marker\n")
    let source = work / "probe.c"
    let probe = work / "probe"
    writeFile(source, """
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
static long (*volatile sc)(int, ...) = (long (*)(int, ...))syscall;
int main(int argc, char **argv) {
  if (argc != 3) return 10;
  unsigned char random[32] = {0};
  if (getentropy(random, sizeof random)) return 11;
  if (!strcmp(argv[2], "named")) {
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 12;
    char buf[32] = {0};
    if (pread(fd, buf, sizeof buf, 65536) != 19) return 13;
    if (close(fd) || strcmp(buf, "syscall-abi-marker\n")) return 14;
    puts("named-read-ok");
    return 0;
  }
  if (sc(SYS_getpid) != getpid()) return 20;
  errno = 0;
  if (sc(SYS_close, -1) != -1 || errno != EBADF) return 21;
  int fd = (int)sc(SYS_open, argv[1], O_RDONLY, 0);
  if (fd < 0) return 22;
  /* The return and offset must retain their high 32 bits. No large file is
     created: seeking beyond EOF does not allocate any data. */
  long far = (1L << 33) + 17;
  if (sc(SYS_lseek, fd, far, SEEK_SET) != far) return 23;
  if (sc(SYS_lseek, fd, 65536L, SEEK_SET) != 65536) return 24;
  char buf[32] = {0};
  if (sc(SYS_read, fd, buf, sizeof buf) != 19 ||
      strcmp(buf, "syscall-abi-marker\n")) return 25;
  /* mmap's sixth argument is a nonzero file offset, and its result is a
     full-width pointer. Verify the mapping's contents, not just its status. */
  void *p = (void *)sc(SYS_mmap, NULL, 4096UL, PROT_READ, MAP_PRIVATE, fd, 65536L);
  if (p == MAP_FAILED || memcmp(p, "syscall-abi-marker\n", 19)) return 26;
  if (sc(SYS_munmap, p, 4096UL)) return 27;
  if (sc(SYS_close, fd)) return 28;
  memset(random, 0xa5, sizeof random);
  if (sc(SYS_getentropy, random, sizeof random)) return 29;
  unsigned changed = 0;
  for (unsigned i = 0; i < sizeof random; ++i) changed |= random[i] ^ 0xa5;
  if (!changed) return 30;
  puts("syscall-read-ok");
  return 0;
}
""")
    let cc = getEnv("CC", "cc")
    let built = execCmdEx(quoteShell(cc) & " -O0 " & quoteShell(source) &
      " -o " & quoteShell(probe))
    doAssert built.exitCode == 0, built.output
    let shim = buildPrivateMacosShim(root)
    let second = work / "second.dylib"
    copyFile(shim, second)

    test "real variadic syscalls retain arguments, wide results and failure errno":
      for libraries in ["", shim]:
        let fragments = work / (if libraries.len == 0: "native" else: "syscalls")
        createDir(fragments)
        let got = runProbe(probe, input, "syscalls", libraries, fragments)
        checkpoint("libraries=" & libraries & " result=" & $got)
        check got.code == 0
        check "syscall-read-ok" in got.output
        if libraries.len > 0:
          let depfile = work / "syscalls.iomon"
          discard mergeFragments(fragments, depfile, currentRunId = "syscall-abi")
          let dep = readMonitorDepFile(depfile)
          # Forwarding works, but raw file operations still lack attribution.
          check dep.completeness == mcIncomplete
          check dep.records.anyIt(it.kind == mrEventLoss and
            "syscall(2)" in it.detail)

    test "distinct shim images start normally and still capture a real read":
      for i, libraries in [shim, shim & ":" & shim, shim & ":" & second]:
        let fragments = work / ("startup-" & $i)
        createDir(fragments)
        let got = runProbe(probe, input, "named", libraries, fragments)
        checkpoint("libraries=" & libraries & " result=" & $got)
        check got.code == 0
        check "named-read-ok" in got.output
        let depfile = work / ("startup-" & $i & ".iomon")
        discard mergeFragments(fragments, depfile, currentRunId = "syscall-abi")
        require fileExists(depfile)
        let dep = readMonitorDepFile(depfile)
        check dep.records.anyIt(it.kind == mrFileRead and it.path == input)

    test "independent sessions retain their own reads and nested child evidence":
      let nested = expandFilename(work) / "nested"
      createDir(nested)
      writeFile(nested / "outer-input", "outer-input")
      writeFile(nested / "inner-input", "inner-input")
      # Use a supervised driver role below so the monitor API can finish its
      # normal cleanup. The outer test kills it only if the whole run wedges.
      let runner = startProcess(getAppFilename(), args = @["--nested-outer",
        nested, shim, second], options = {poStdErrToStdOut})
      let code = runner.waitForExit(30_000)
      if code == -1:
        if getpgid(Pid(runner.processID)) == Pid(runner.processID):
          discard posix.kill(Pid(-runner.processID), SIGKILL)
        else:
          runner.kill()
        discard runner.waitForExit()
      let output = runner.outputStream.readAll()
      runner.close()
      checkpoint("nested exit=" & $code & " output=" & output)
      require code == 0
      let inner = readMonitorDepFile(nested / "inner.iomon")
      let outer = readMonitorDepFile(nested / "outer.iomon")
      check inner.completeness == mcComplete
      check inner.records.anyIt(it.kind == mrFileRead and
        it.path == nested / "inner-input")
      check outer.records.anyIt(it.kind == mrFileRead and
        it.path == nested / "outer-input")
      check outer.records.anyIt(it.kind == mrFileRead and
        it.path == nested / "inner-input")
      checkpoint("outer loss=" & $outer.records.filterIt(it.kind == mrEventLoss))
      check outer.completeness == mcComplete
  else:
    test "macOS-only syscall ABI":
      skip()
