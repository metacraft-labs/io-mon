## test_io_mon_macos_r5_raw_syscall — ROUND-5 D: a monitored binary that reads files
## via raw syscalls (bypassing the named-symbol hooks) is no longer silently complete.
##
## CONFIRMED ROUND-5 BREAK (research/adversarial-2026-07-round5/unhooked): the
## interpose + body-patch backend only sees file I/O routed through libsystem's named
## `open`/`read`/… entries. A program that issues the syscalls DIRECTLY —
##   * an INLINE `svc #0x80` in its own code (Go / musl-static; p_svc_openread), or
##   * the (non-inlined) `syscall(2)` indirect trap (p_syscall_openread / sc_noinline)
## — read a marker's content with the dependency entirely ABSENT from the depfile,
## while completeness stayed mcComplete: a silent false cache hit (the cardinal sin).
##
## ROUND-5 FIX (make-safe by downgrade — the structural interpose blind spot cannot
## be CLOSED in-process; EndpointSecurity is the kernel-sourced fix):
##   * INLINE svc — scanned at load: the main executable's __TEXT,__text is checked
##     for `svc #0x80` (0xD4001001); a hit means the binary can bypass the hooks →
##     downgrade. A normal dynamically-linked build tool routes every syscall through
##     libsystem and scans clean (cc/clang/ld/rustc have zero inline svc), so this
##     never false-downgrades a normal build.
##   * `syscall(2)` — hooked: a file-family indirect syscall number downgrades.
##
## CARDINAL-SIN GUARD: a real cc / rustc compile MUST stay mcComplete (no false
## downgrade) and MUST NOT crash (the syscall hook sits on a general path).
##
## macOS-only; a no-op pass elsewhere.

import std/[os, strutils, unittest]
import io_mon

when defined(macosx):
  import std/[osproc, streams, strtabs]
  import macos_backend_toggle

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  r5unhooked = repoRoot / "research" / "adversarial-2026-07-round5" / "unhooked"

when defined(macosx):
  proc buildShim(): string =
    let (output, code) = execCmdEx("bash " &
      quoteShell(repoRoot / "scripts" / "build_shim.sh"))
    if code != 0:
      raise newException(IOError, "build_shim.sh failed: " & output)
    let shim = repoRoot / "build" / "lib" / "librepro_monitor_shim.dylib"
    doAssert fileExists(shim), "shim not produced at " & shim
    shim

  proc ccExe(src, outBin: string; extraFlags = "") =
    let cc = getEnv("CC", "cc")
    let (output, code) = execCmdEx(quoteShell(cc) & " -arch arm64 " & extraFlags &
      " " & quoteShell(src) & " -o " & quoteShell(outBin))
    doAssert code == 0, "cc failed (" & src & "): " & output
    doAssert fileExists(outBin), "probe not produced: " & outBin

  proc runProbe(shim, probe: string; args: seq[string]): MonitorDepFile =
    let runWork = getTempDir() / ("io-mon-r5raw-" & probe.extractFilename() &
      "-" & $getCurrentProcessId())
    removeDir(runWork); createDir(runWork)
    let fragmentDir = runWork / "frags"
    createDir(fragmentDir)
    var env = newStringTable(modeCaseSensitive)
    for k, v in envPairs():
      if k == "CT_SANDBOX_TOOLS_DIR": continue
      env[k] = v
    env["DYLD_INSERT_LIBRARIES"] = shim
    env["REPRO_MONITOR_SHIM_LIB"] = shim
    env["REPRO_MONITOR_FRAGMENT_DIR"] = fragmentDir
    applyMacosBackendToggle(env, "both")
    let p = startProcess(probe, args = args, env = env,
      options = {poStdErrToStdOut})
    discard p.outputStream.readAll()
    discard p.waitForExit()
    p.close()
    let depfile = runWork / "cap.rdep"
    discard mergeFragments(fragmentDir, depfile)
    doAssert fileExists(depfile)
    result = readMonitorDepFile(depfile)
    removeDir(runWork)

  proc marker(work: string): string =
    result = work / "marker.txt"
    writeFile(result, "raw-syscall-marker\n")

suite "io-mon macOS R5 raw-syscall blind spot (make-safe by downgrade)":
  when defined(macosx):
    let shim = buildShim()
    let work = getTempDir() / ("io-mon-r5raw-" & $getCurrentProcessId())
    removeDir(work); createDir(work)
    let mk = marker(work)

    test "INLINE svc open+read downgrades to mcIncomplete (main-__TEXT scan)":
      let bin = work / "p_svc_openread"
      ccExe(r5unhooked / "p_svc_openread.c", bin)
      let dep = runProbe(shim, bin, @[mk])
      check dep.completeness == mcIncomplete
      # The marker read is genuinely absent (that is the blind spot the downgrade
      # covers) — the guarantee is honest completeness, not capture.
      var sawMarker = false
      for r in dep.records:
        if r.kind == mrFileRead and r.path.contains("marker.txt"): sawMarker = true
      check not sawMarker

    test "non-inlined syscall(2) open+read downgrades to mcIncomplete (syscall hook)":
      # A function-pointer call to libsystem `syscall` at -O0 has NO inline svc in
      # its own __text, so the scan cannot see it — the syscall(2) hook catches it.
      let src = work / "sc_noinline.c"
      writeFile(src, """
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
long (*volatile sc)(int, ...) = (long (*)(int, ...))syscall;
int main(int c, char** v){
  int fd = (int)sc(SYS_open, v[1], O_RDONLY, 0);
  if (fd >= 0) { char b[64]; sc(SYS_read, fd, b, sizeof b); sc(SYS_close, fd); }
  return 0;
}
""")
      let bin = work / "sc_noinline"
      ccExe(src, bin, extraFlags = "-O0")
      let dep = runProbe(shim, bin, @[mk])
      check dep.completeness == mcIncomplete

    test "CARDINAL SIN: a normal cc compile stays mcComplete (scans clean)":
      # cc is dynamically linked and routes every syscall through libsystem, so its
      # __text has no inline svc and it never uses the syscall(2) escape hatch — it
      # must NOT be downgraded (a false downgrade re-runs every compile).
      writeFile(work / "hello.c", "int main(void){ return 0; }\n")
      var ccBin = getEnv("CC", "cc")
      if not ccBin.isAbsolute: ccBin = findExe(ccBin)
      let dep = runProbe(shim, ccBin,
        @["-c", work / "hello.c", "-o", work / "hello.o"])
      check dep.completeness == mcComplete
      var flagged = false
      for r in dep.records:
        if r.kind == mrEventLoss and r.detail.contains("raw-syscall"): flagged = true
        if r.kind == mrEventLoss and r.detail.contains("syscall(2)"): flagged = true
      check not flagged

    removeDir(work)
  else:
    test "R5 raw-syscall blind spot is macOS-only (no-op here)":
      check true
