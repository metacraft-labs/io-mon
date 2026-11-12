## The inline raw-syscall scanner decodes an image's CODE sections only.
##
## WHY. The x86_64 inline-syscall backend sweeps executable mappings with a
## length decoder and INT3-patches every `0f 05` it takes for a `syscall`.
## It swept every byte of an `r-xp` mapping, as if an executable segment held
## nothing but instructions. It does not: LLVM BOLT emits `.rodata`,
## `.eh_frame` and `.gcc_except_table` into its `R E` segment, and GNU ld's
## `-z noseparate-code` does the same. The upstream Rust 1.94.0 x86-64
## tarball's `librustc_driver` is BOLT-optimised; a PIC jump table in its
## `.rodata` (file offset 0x7ac40c5) holds the entry bytes `fa 0f 05 fe`. The
## sweep reported that entry as a syscall site and patched it to
## `fa cc 05 fe`; the next `switch` through the table jumped mid-instruction,
## and upstream rustc 1.94.0 died with SIGILL on any crate with a
## `macro_rules!`. Flipping that single byte in a copy of the library, with no
## shim loaded, reproduces the crash; the 16 real `syscall` instructions of
## the image all lie in `.bolt.org.text` and the 7 false sites all in
## `.eh_frame` and `.rodata` (measured 2026-10-31 on nixos-ci-bare-004).
##
## THE FIX. A file-backed mapping is scanned over the runtime ranges of the
## image's `SHF_EXECINSTR` sections only (`linux_image_code_ranges` in
## nim-stackable-hooks, read from the image's ELF section table). An image
## whose table cannot be read is not scanned at all and the gap is an
## event-loss record, never a reason to sweep the whole mapping.
##
## WHAT THIS TEST GRADES. A host linked with `-z noseparate-code` carries the
## rustc jump-table bytes as a `const` table in `.rodata` (which the linker
## places in the executable segment -- the host proves that precondition from
## its own /proc/self/maps before reporting anything) and one real inline
## `syscall` (getpid). Under the shim:
##   - section table readable: the table's `0f` is untouched, the `syscall`
##     IS patched (its first byte reads `cc`) and still works through the
##     trap handler, and the capture is complete with no "skipped image" loss;
##   - section table removed from a copy of the host (ELF header fields
##     zeroed): nothing in the image is patched, the raw syscall still works
##     (it was never trapped), and the capture is incomplete with an event
##     loss naming the copy;
##   - bare control: nothing is patched;
##   - section table removed, and the host then dlopens a library three times:
##     each dlopen re-runs the scan over every mapping, and the image is
##     reported as ONE loss, not once per scan.
## Against the shim before the fix the first arm reports `data-byte=cc`.
##
## x86_64 only: no other architecture has the inline-syscall trap backend.
## Mocks: none. Real shim, real host, real linker layout.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon
import build_test_shim
import unmonitored_env

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  skippedImageDetail = "skipped image without a readable executable-section table"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil):
    tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

const hostSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The exact bytes of the librustc_driver-24b10b5e3eb5af70.so jump-table entry
 * at .rodata 0x7ac40c4 that the whole-mapping sweep patched, followed by a
 * second `0f 05 xx` pattern. `used` keeps them; `const` puts them in .rodata,
 * which `-z noseparate-code` places inside the executable segment. */
__attribute__((used)) const unsigned char table[16] = {
  0xfa, 0x0f, 0x05, 0xfe, 0xea, 0xdf, 0x04, 0xfe,
  0x0f, 0x05, 0x01, 0x00, 0xbd, 0xf3, 0x04, 0xfe};

/* The program's only `syscall` instruction (SYS_getpid == 39): the scanner
 * must find and patch THIS one even though the data above is in the same
 * mapping. */
static long __attribute__((noinline)) raw_getpid(void) {
  long ret;
  __asm__ volatile("syscall" : "=a"(ret) : "0"(39L) : "rcx", "r11", "memory");
  return ret;
}

/* Does the /proc/self/maps entry holding `addr` belong to this executable and
 * carry the execute bit? That is the fixture precondition: without it the
 * data would sit in a read-only mapping the scanner never looks at. */
static int in_executable_mapping_of_self(const void *addr) {
  char self[4096];
  ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (n <= 0) return 0;
  self[n] = 0;
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) return 0;
  char line[4096];
  int ok = 0;
  while (fgets(line, sizeof(line), maps)) {
    unsigned long start, end;
    char perms[8];
    char path[4096] = "";
    if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %4095s", &start, &end, perms,
               path) < 3)
      continue;
    unsigned long a = (unsigned long)addr;
    if (a >= start && a < end) {
      ok = perms[2] == 'x' && strcmp(path, self) == 0;
      break;
    }
  }
  fclose(maps);
  return ok;
}

int main(int argc, char **argv) {
  printf("precondition exec-segment-data=%s\n",
         in_executable_mapping_of_self(table) ? "ok" : "FAILED");
  /* Read through a volatile pointer so the compiler cannot fold the constant
   * it knows into the printf: the byte must come from memory, where the shim
   * may have written. */
  const volatile unsigned char *live = table;
  printf("data-byte=%02x\n", live[1]);
  printf("data-byte2=%02x\n", live[8]);
  const unsigned char *code = (const unsigned char *)raw_getpid;
  const char *site = "not-found";
  for (int i = 0; i + 1 < 64; i++) {
    if (code[i] == 0x0f && code[i + 1] == 0x05) { site = "unpatched"; break; }
    if (code[i] == 0xcc && code[i + 1] == 0x05) { site = "patched"; break; }
  }
  printf("code-site=%s\n", site);
  printf("raw-getpid=%s\n", raw_getpid() == (long)getpid() ? "ok" : "mismatch");
  /* argv[1] dlopens: each one makes the shim re-scan every mapping. */
  int reloads = argc > 1 ? atoi(argv[1]) : 0;
  int loaded = 0;
  for (int i = 0; i < reloads; i++) {
    void *h = dlopen("libm.so.6", RTLD_NOW);
    if (h) { loaded++; dlclose(h); }
  }
  printf("dlopens=%d\n", loaded);
  return 0;
}
"""

type Fixture = object
  work, snoopBin, host, hostNoShdrs: string
  env: StringTableRef

proc stripSectionHeaders(src, dest: string) =
  ## A copy of the ELF image whose header no longer points at a section table:
  ## e_shoff (8 bytes at 0x28), e_shentsize, e_shnum and e_shstrndx (2 bytes
  ## each at 0x3a, 0x3c, 0x3e) are zeroed. The loader needs only program
  ## headers, so the copy runs unchanged; the scanner cannot learn where its
  ## code is.
  var bytes = readFile(src)
  doAssert bytes.len > 0x40 and bytes[0 .. 3] == "\x7fELF", "not an ELF image: " & src
  for i in 0x28 ..< 0x30: bytes[i] = '\0'
  for i in 0x3a ..< 0x40: bytes[i] = '\0'
  writeFile(dest, bytes)
  setFilePermissions(dest, getFilePermissions(src))

proc setUpFixture(): Fixture =
  result.work = expandFilename(getTempDir()) /
    ("io-mon-inline-scan-code-sections-" & $getCurrentProcessId())
  removeDir(result.work)
  createDir(result.work)
  let shimLib = buildPrivateLinuxShim(repoRoot)
  result.snoopBin = result.work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & result.snoopBin, snoopSrc])
  checkpoint(cli.output)
  doAssert cli.code == 0, "io-mon CLI build failed"
  let cc = getEnv("CC", "cc")
  result.host = result.work / "data-in-exec-segment"
  writeFile(result.host & ".c", hostSource)
  # `-z noseparate-code` merges .text and .rodata into one R E PT_LOAD, the
  # layout BOLT produces and the one the fixture needs.
  let hostCc = run(cc, @[result.host & ".c", "-O1", "-Wl,-z,noseparate-code",
    "-o", result.host, "-ldl"])
  checkpoint(hostCc.output)
  doAssert hostCc.code == 0, "host build failed"
  result.hostNoShdrs = result.work / "data-in-exec-segment-no-shdrs"
  stripSectionHeaders(result.host, result.hostNoShdrs)
  result.env = unmonitoredEnv()
  result.env["REPRO_MONITOR_SHIM_LIB"] = shimLib

proc lineValue(output, key: string): string =
  for line in output.splitLines():
    if line.startsWith(key & "="):
      return line[key.len + 1 .. ^1]
  ""

suite "io-mon Linux inline-syscall scan covers code sections only":
  when defined(linux) and defined(amd64):
    let f = setUpFixture()

    test "bare control: the host's layout holds data in its executable segment":
      let bare = run(f.host, @[], unmonitoredEnv())
      checkpoint(bare.output)
      check bare.code == 0
      # The fixture precondition, judged by the host itself. A FAILED here is
      # a linker that did not honour `-z noseparate-code`, not a scanner bug.
      check lineValue(bare.output, "precondition exec-segment-data") == "ok"
      check lineValue(bare.output, "data-byte") == "0f"
      check lineValue(bare.output, "data-byte2") == "0f"
      check lineValue(bare.output, "code-site") == "unpatched"
      check lineValue(bare.output, "raw-getpid") == "ok"

    test "monitored, section table readable: code is patched, data is not":
      let depfile = f.work / "readable.iomon"
      let cap = run(f.snoopBin, @["run", "--depfile", depfile, "--", f.host], f.env)
      checkpoint(cap.output)
      check cap.code == 0
      check lineValue(cap.output, "precondition exec-segment-data") == "ok"
      # The rustc jump-table byte survives: before the fix this read `cc`.
      check lineValue(cap.output, "data-byte") == "0f"
      check lineValue(cap.output, "data-byte2") == "0f"
      # And the real syscall in .text is still found and trapped.
      check lineValue(cap.output, "code-site") == "patched"
      check lineValue(cap.output, "raw-getpid") == "ok"
      let dep = readMonitorDepFile(depfile)
      checkpoint("completeness=" & $dep.completeness & " losses=" &
        $dep.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail))
      check dep.completeness == mcComplete
      check not dep.records.anyIt(it.kind == mrEventLoss and
        skippedImageDetail in it.detail)

    test "monitored, section table unavailable: nothing is patched and the gap is a loss":
      let depfile = f.work / "no-shdrs.iomon"
      let cap = run(f.snoopBin, @["run", "--depfile", depfile, "--", f.hostNoShdrs],
        f.env)
      checkpoint(cap.output)
      check cap.code == 0
      check lineValue(cap.output, "precondition exec-segment-data") == "ok"
      check lineValue(cap.output, "data-byte") == "0f"
      check lineValue(cap.output, "data-byte2") == "0f"
      # Without the table the scanner does not know where the code is, so it
      # leaves the whole image alone -- the syscall included.
      check lineValue(cap.output, "code-site") == "unpatched"
      check lineValue(cap.output, "raw-getpid") == "ok"
      let dep = readMonitorDepFile(depfile)
      let losses = dep.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail)
      checkpoint("completeness=" & $dep.completeness & " losses=" & $losses)
      check dep.completeness == mcIncomplete
      check losses.anyIt(skippedImageDetail in it and f.hostNoShdrs in it and
        "no-section-headers" in it)

    test "monitored, section table unavailable, three dlopens: the image is one loss":
      # Every dlopen re-enumerates and re-scans all mappings. The unreadable
      # image is still there each time; it must be counted once and reported
      # once (at startup), not re-reported with a growing count per scan.
      let depfile = f.work / "no-shdrs-dlopen.iomon"
      let cap = run(f.snoopBin, @["run", "--depfile", depfile, "--", f.hostNoShdrs, "3"],
        f.env)
      checkpoint(cap.output)
      check cap.code == 0
      check lineValue(cap.output, "dlopens") == "3"
      let dep = readMonitorDepFile(depfile)
      let skipped = dep.records.filterIt(it.kind == mrEventLoss and
        skippedImageDetail in it.detail).mapIt(it.detail)
      checkpoint("completeness=" & $dep.completeness & " skipped=" & $skipped)
      check dep.completeness == mcIncomplete
      check skipped.len == 1
      check skipped.anyIt("source=startup" in it and "images=1" in it and
        f.hostNoShdrs in it)

    test "monitored, section table readable, three dlopens: no loss":
      let depfile = f.work / "readable-dlopen.iomon"
      let cap = run(f.snoopBin, @["run", "--depfile", depfile, "--", f.host, "3"], f.env)
      checkpoint(cap.output)
      check cap.code == 0
      check lineValue(cap.output, "dlopens") == "3"
      check lineValue(cap.output, "data-byte") == "0f"
      check lineValue(cap.output, "code-site") == "patched"
      let dep = readMonitorDepFile(depfile)
      checkpoint("completeness=" & $dep.completeness & " losses=" &
        $dep.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail))
      check dep.completeness == mcComplete
  else:
    test "inline-syscall code-sections-only scan (x86_64 INT3 backend only)":
      skip()
