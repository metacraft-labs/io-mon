## test_io_mon_linux_inline_asm_exit_group — M9.R.63.2 minimal repro.
##
## Reproduces the M9.R.62.4 residual escapee class: a Linux LD_PRELOAD-
## monitored process that
##   (1) has the shim loaded (constructor ran, recordProcessStart fired),
##   (2) issues a real captured-dependency event (a `read(2)`),
##   (3) terminates via an INLINE-ASSEMBLY `syscall #exit_group` opcode
##       emitted directly from user code — bypassing libc's `_exit`,
##       libc's `syscall(3)` wrapper, every default-terminating signal,
##       and the process-exit destructor.
##
## Before the M9.R.63.3 fix (test EXPECTED to fail with kill-before-flush):
##   dep.completeness == mcIncomplete
##   dep.records has at least one mrEventLoss with "kill-before-flush"
##
## After the M9.R.63.3 fix (test EXPECTED to pass):
##   dep.completeness == mcComplete
##   dep.records has the mrFileRead for `marker` AND no kill-before-flush
##   event-loss entry.
##
## The `IO_MON_M9R63_XFAIL` env var flips the assertion polarity so the
## test can be pinned as "expected regression" during Phase B, then
## flipped to "expected pass" after Phase C lands the policy refinement /
## SIGTRAP-handler flush wiring.

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

proc buildC(work, name, source: string; extraArgs: seq[string] = @[]): string =
  result = work / name
  let sourcePath = work / (name & ".c")
  writeFile(sourcePath, source)
  let cc = getEnv("CC", "cc")
  let built = run(cc, @[sourcePath, "-o", result] & extraArgs)
  checkpoint(name & " cc: " & built.output)
  check built.code == 0
  check fileExists(result)

proc hasFileRead(dep: MonitorDepFile; path: string): bool =
  dep.records.anyIt(it.kind == mrFileRead and
    it.observationKind == moFileRead and path in it.path)

proc hasKillBeforeFlushEventLoss(dep: MonitorDepFile): bool =
  dep.records.anyIt(it.kind == mrEventLoss and
    "kill-before-flush" in it.detail)

suite "io-mon Linux inline-asm exit_group escapee (M9.R.63.2 pin)":
  let work = getTempDir() / ("io-mon-inline-asm-exit-" & $getCurrentProcessId())
  createDir(work)

  test "process that reads then exits via inline-asm syscall #exit_group":
    ## Build the CLI + shim the same way test_io_mon_linux_stdio_ipc.nim
    ## does so this test is self-contained.
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

    let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    check buildShim.code == 0
    let shimLib = findShimLibrary()

    # The escape-vector probe: `read(2)` a marker file so a real captured-
    # dependency record is emitted, then die via inline-asm SYS_exit_group.
    #
    # The inline-asm sequence is deliberately open-coded (rather than
    # `#include <sys/syscall.h>` + `syscall()`) so it does NOT go through
    # libc's `syscall(3)` wrapper, LD_PRELOAD's `syscall` interposer, or
    # glibc's exported `_exit` symbol. This is the SAME shape as a real-
    # world statically-linked helper, a Go/Rust binary using
    # `libc::syscall_1(SYS_exit_group, ...)` with LTO, or an
    # optimised-out glibc `_exit` inline call.
    let probe = buildC(work, "inline_asm_exit_group", """
#include <fcntl.h>
#include <unistd.h>

static void inline_asm_exit_group(int status) {
  /* SYS_exit_group == 231 on x86_64.  Encoded as an inline `syscall`
   * instruction so it does NOT route through libc's `_exit` or
   * `syscall(3)` wrapper, both of which io-mon already hooks by symbol.
   * The `syscall` instruction (opcode 0F 05) is exactly the pattern
   * the stackable-hooks INT3 scanner is designed to catch. */
  register long rax __asm__("rax") = 231;
  register long rdi __asm__("rdi") = status;
  __asm__ volatile("syscall" : : "r"(rax), "r"(rdi) : "rcx", "r11", "memory");
  __builtin_unreachable();
}

int main(int argc, char **argv) {
  char buf[64];
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) inline_asm_exit_group(2);
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  if (n <= 0) inline_asm_exit_group(3);
  inline_asm_exit_group(0);
  return 0;  /* unreachable */
}
""")
    let marker = work / "inline-asm-marker.txt"
    writeFile(marker, "inline asm exit_group marker\n")
    let depfile = work / "inline-asm-exit.iomon"

    var childEnv = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): childEnv[k] = v
    childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe, marker],
      childEnv)
    checkpoint(cap.output)
    check cap.code == 0

    let dep = readMonitorDepFile(depfile)
    checkpoint("depfile completeness = " & $dep.completeness)
    checkpoint("depfile records=" & $dep.records.len &
      " event-loss count=" &
      $dep.records.countIt(it.kind == mrEventLoss))

    # Polarity switch: while the fix is pending, the assertion is that
    # the CURRENT baseline REGRESSES with the kill-before-flush signature.
    # After M9.R.63.3 lands, unset IO_MON_M9R63_XFAIL and the same test
    # asserts the fixed behavior.
    let xfail = getEnv("IO_MON_M9R63_XFAIL", "").len > 0
    if xfail:
      # Expected FAILURE mode — this is what the residual looks like
      # today. Documenting the class in a pinned test so the fix path is
      # unambiguous.
      check dep.completeness == mcIncomplete
      check hasKillBeforeFlushEventLoss(dep)
      # The `read(2)` DID happen — this class is not "shim never loaded",
      # it's "shim loaded, event buffered, but the flush was lost because
      # the inline-asm exit_group bypassed every symbol-level hook".
      check hasFileRead(dep, marker)
    else:
      # Expected PASS mode — the fix path must recover completeness AND
      # capture the read WITHOUT the synthetic kill-before-flush loss.
      check dep.completeness == mcComplete
      check hasFileRead(dep, marker)
      check not hasKillBeforeFlushEventLoss(dep)
