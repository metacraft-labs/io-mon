## 32-bit ARM: an image that may hold Thumb-state code fails CLOSED.
##
## The ARM inline syscall-site scanner discovers word-aligned ARM-state `svc #0`
## only; a Thumb `svc` (a 16-bit halfword) cannot be found soundly without a
## decoder. Before this test, a program issuing an inline `svc` from Thumb code
## was UNOBSERVED while its capture graded `mcComplete` with `eventLoss=0`
## (measured on rpi2 with a `-march=armv7-a -mthumb` openat of /etc/os-release)
## -- the one place the ARM port was weaker than fail-closed. Now every
## non-system executable mapping the scanner takes is judged from its
## `.ARM.attributes` / function-symbol parity, and a Thumb-capable image is
## recorded as the loss `linux inline raw-syscall scanner cannot cover
## Thumb-state code`, so the capture grades `mcIncomplete`.
##
## Both directions are measured here, on an ARM host only (elsewhere the suite
## skips: the judgement needs an ARM toolchain and the ARM shim):
##   * `t_thumb_image_is_a_loss`: a `-march=armv7-a -mthumb` program with an
##     inline `svc` openat is graded incomplete with that loss, and the open it
##     performed is indeed absent from the records (the gap is real, and
##     reported rather than hidden);
##   * `t_arm_only_image_is_not_a_loss`: the same program built the way the
##     Raspberry Pi OS userland is (ARMv6, hard-float: GCC cannot emit Thumb-1
##     hard-float code) carries no such loss and its inline `svc` openat IS
##     recorded -- the negative control that keeps the first case from being a
##     blanket downgrade of every ARM capture;
##   * `t_verdict_reads_the_attributes`: the judgement itself, on both images.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]
import io_mon
import io_mon/hooks/linux_arm_image

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  fixture = """
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
static long svc3(long nr, long a, long b, long c) {
  register long r0 __asm__("r0") = a; register long r1 __asm__("r1") = b;
  register long r2 __asm__("r2") = c; register long r6 __asm__("r6") = nr;
  __asm__ volatile("push {r7}\n\tmov r7, r6\n\tsvc #0\n\tpop {r7}"
                   : "+r"(r0) : "r"(r1), "r"(r2), "r"(r6) : "memory", "cc");
  return r0;
}
int main(int argc, char **argv) {
  long fd = svc3(SYS_openat, AT_FDCWD, (long)argv[1], O_RDONLY);
  if (fd >= 0) svc3(SYS_close, fd, 0, 0);
  return fd >= 0 ? 0 : 2;
}
"""

proc runCmd(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  defer: p.close()
  result.output = p.outputStream().readAll()
  result.code = p.waitForExit()

when defined(linux) and defined(arm):
  suite "arm: Thumb-capable images fail closed":
    let work = getTempDir() / ("iomon-arm-thumb-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    writeFile(work / "fx.c", fixture)
    let thumbBin = work / "fx-thumb"
    let armBin = work / "fx-armv6"
    let ccThumb = runCmd("gcc", @["-O1", "-march=armv7-a", "-mthumb",
      "-mfpu=vfpv3-d16", "-mfloat-abi=hard", "-o", thumbBin, work / "fx.c"])
    checkpoint(ccThumb.output)
    require ccThumb.code == 0
    let ccArm = runCmd("gcc", @["-O1", "-o", armBin, work / "fx.c"])
    checkpoint(ccArm.output)
    require ccArm.code == 0
    let snoopBin = work / "io-mon"
    let cli = runCmd("nim", @["c", "--hints:off", "--warnings:off", "--path:" & repoRoot / "src",
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    require cli.code == 0
    let buildShim = runCmd("bash", @[repoRoot / "scripts" / "build_shim.sh"])
    checkpoint(buildShim.output)
    require buildShim.code == 0
    let shimLib = findShimLibrary()
    let input = work / "input.txt"
    writeFile(input, "thumb fixture input\n")

    proc capture(bin, tag: string): MonitorDepFile =
      let depfile = work / (tag & ".iomon")
      var childEnv = newStringTable(modeCaseSensitive)
      for k, v in envPairs(): childEnv[k] = v
      childEnv["REPRO_MONITOR_SHIM_LIB"] = shimLib
      let cap = runCmd(snoopBin, @["run", "--depfile", depfile, "--", bin, input], childEnv)
      checkpoint(cap.output)
      check cap.code == 0
      readMonitorDepFile(depfile)

    test "t_verdict_reads_the_attributes":
      let thumb = armImageThumbVerdict(thumbBin)
      checkpoint("thumb: " & thumb.reason)
      check thumb.verdict == atvThumbPossible
      let arm = armImageThumbVerdict(armBin)
      checkpoint("armv6: " & arm.reason)
      check arm.verdict == atvArmOnly
      check armImageThumbVerdict(work / "fx.c").verdict == atvUnknown

    test "t_thumb_image_is_a_loss":
      let dep = capture(thumbBin, "thumb")
      checkpoint("completeness = " & $dep.completeness)
      check dep.completeness == mcIncomplete
      check dep.records.anyIt(it.kind == mrEventLoss and
        "cannot cover Thumb-state code" in it.detail and thumbBin in it.detail)
      # The gap is real: the Thumb-state inline openat left no record.
      check not dep.records.anyIt(it.kind == mrFileOpen and it.path == input)

    test "t_arm_only_image_is_not_a_loss":
      let dep = capture(armBin, "armv6")
      checkpoint("completeness = " & $dep.completeness)
      check not dep.records.anyIt(it.kind == mrEventLoss and
        "cannot cover Thumb-state code" in it.detail)
      check dep.records.anyIt(it.kind == mrFileOpen and it.path == input)

    removeDir(work)
else:
  suite "arm: Thumb-capable images fail closed":
    test "skipped: needs a 32-bit ARM host":
      skip()
