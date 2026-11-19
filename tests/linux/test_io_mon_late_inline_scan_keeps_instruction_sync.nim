## A late inline-syscall scan decodes code the startup scan patched on the
## startup scan's instruction boundaries, so it never patches a byte inside an
## instruction.
##
## WHY. Every `dlopen`/`dlmopen` re-runs the inline scan over every
## executable mapping the policy selects, including mappings the startup scan
## already patched, and every JIT transition re-scans the program's tracked
## anonymous code ranges. The x86-64 scanner is a linear sweep with
## an instruction-length decoder. At a site the startup scan patched, memory
## reads `cc 05 ...` instead of `0f 05 ...`: the decoder takes `cc` as a
## one-byte `int3` and `05` as the first byte of `add eax, imm32` (five bytes),
## so it resumes four bytes past the end of the original two-byte `syscall`,
## possibly inside the next instruction. A `0f 05` it meets before it falls
## back into step is presented as a site and `int3`-patched: a silent
## corruption of the monitored program (reprobuild-pm issue
## 2026-11-16-a-late-inline-syscall-scan-decodes-code-it-already-patched-and-
## can-lose-instruction-sync; Monitor-Hook-Shim.md §"Inline Raw-Syscall Site
## Scan (Linux)").
##
## The startup patch changes the code a second way: it `mprotect`s each
## patched page writable and back, and the kernel then keeps that page as a
## mapping of its own. A late scan that decoded each piece of the split
## mapping on its own would start the decoder at a page boundary, which can
## fall inside an instruction.
##
## WHAT THIS TEST GRADES, with a real host program run under the real shim.
## The host's `desync_probe` is
##
##   b8 27 00 00 00   mov  $39, %eax
##   0f 05            syscall              <- patched by the startup scan
##   b8 00 00 00 0f   mov  $0x0f000000, %eax
##   05 01 00 00 00   add  $1, %eax
##   c3               ret
##
## so it returns 0x0f000001. Decoded from the patched `cc 05`, the sweep reads
## `cc` and `05 b8 00 00 00` and lands on the `0f 05` formed by the last byte
## of the `mov` immediate and the `add` opcode. Patching it turns the
## immediate into 0xcc000000. Its `page_probe` starts a page with a `syscall`
## and ends it with an instruction that runs into the next page:
##
##   P-4096  b8 27 00 00 00 0f 05   mov $39, %eax; syscall  <- patched
##           90 ...                 nop up to P-3
##   P-3     b8 00 00 0f 05         mov $0x050f0000, %eax
##   P+2     05 01 00 00 00 c3      add $1, %eax; ret
##
## so it returns 0x050f0001. Decoded from the page boundary P, the sweep meets
## `0f 05` (the top of the immediate) first; patching it gives 0x05cc0001.
## Before the `dlopen` the host also writes a `syscall` over two nops of
## `late_slot` (through /proc/self/mem), so the late scan has one new site to
## find: that it is patched shows the late scan ran. The host calls both
## probes, `dlopen`s a library (a late scan), calls them again and lists
## every patched `syscall` byte:
##   - the probes return the same values before and after the late scan;
##   - the late scan patches the new site and nothing else the startup scan
##     did not.
##
## The site registry outlives the code it describes, so a patched address
## must cut the decode only where the sweep lands on it. In mode `jit` the
## host makes a W^X JIT page holding `mov $39,%eax; syscall; ret` (its site,
## at offset 5, is patched when the page turns executable), then rewrites
## the page in place with
##
##   90 90 48 b8 11 cc 05 0f 05 22 33 44 c3   nop; nop; movabs $imm64,%rax; ret
##
## whose immediate holds `cc 05` at the stale site and `0f 05` right after.
## A cut there would restart the sweep inside the immediate and patch the
## `0f`; the call must still return 0x443322050f05cc11.
##
## Falsifying mutations, each run against this test: decoding a late scan's
## ranges in one piece (`visitLinuxX8664SyscallMemory` over the whole range
## in place of `visitAroundOwnPatches`) makes `desync_probe` return 0xcc000001
## after the `dlopen` and patches a byte at the site + 6; scanning the pieces
## of a split mapping one by one (no `coalesceSplitImageMappings`) makes
## `page_probe` return 0x05cc0001 and patches the byte at P; cutting at every
## registered site that reads `cc 05`, without the walk that checks the sweep
## lands on it, makes the `jit` call return 0x44332205cc05cc11.
##
## x86_64 only: no other architecture's scanner decodes variable-length
## instructions. Mocks: none. Real shim, real host program, real compiler.

import foreign_preload_isolation

import std/[os, osproc, streams, strtabs, strutils, unittest]

import build_test_shim
import unmonitored_env

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = getEnv("STACKABLE_HOOKS_SRC",
    repoRoot.parentDir() / "nim-stackable-hooks" / "src")
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Spelled as bytes so the assembler cannot pick a shorter encoding. */
__asm__(".text\n.p2align 4\n.globl desync_probe\n"
        ".type desync_probe,@function\ndesync_probe:\n"
        "  .byte 0xb8, 0x27, 0x00, 0x00, 0x00\n"  /* mov $39, %eax */
        "  .byte 0x0f, 0x05\n"                    /* syscall (getpid) */
        "  .byte 0xb8, 0x00, 0x00, 0x00, 0x0f\n"  /* mov $0x0f000000, %eax */
        "  .byte 0x05, 0x01, 0x00, 0x00, 0x00\n"  /* add $1, %eax */
        "  ret\n");
extern unsigned int desync_probe(void);

__asm__(".text\n.p2align 12\n.globl page_probe\n"
        ".type page_probe,@function\npage_probe:\n"
        "  .byte 0xb8, 0x27, 0x00, 0x00, 0x00\n"  /* mov $39, %eax */
        "  .byte 0x0f, 0x05\n"                    /* syscall (getpid) */
        "  .skip 4096 - 7 - 3, 0x90\n"            /* nop up to P-3 */
        "  .byte 0xb8, 0x00, 0x00, 0x0f, 0x05\n"  /* mov $0x050f0000, %eax */
        "  .byte 0x05, 0x01, 0x00, 0x00, 0x00\n"  /* add $1, %eax */
        "  ret\n");
extern unsigned int page_probe(void);

/* Never called. Its two nops become a `syscall` before the dlopen:
 * b8 27 00 00 00 (mov $39,%eax), 90 90, c3. */
__asm__(".text\n.globl late_slot\n.type late_slot,@function\nlate_slot:\n"
        "  movl $39, %eax\n  nop\n  nop\n  ret\n");
extern void late_slot(void);

static int jit(void) {
  typedef unsigned long (*fn)(void);
  unsigned char *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (m == MAP_FAILED) return 2;
  memset(m, 0xc3, 4096);
  unsigned char first[] = {0xb8, 0x27, 0, 0, 0, 0x0f, 0x05, 0xc3};
  memcpy(m, first, sizeof first);
  mprotect(m, 4096, PROT_READ | PROT_EXEC);
  printf("jit-first=%s jit-patched=%02x\n",
         ((fn)m)() == (unsigned long)getpid() ? "ok" : "mismatch", m[5]);
  mprotect(m, 4096, PROT_READ | PROT_WRITE);
  unsigned char second[] = {0x90, 0x90, 0x48, 0xb8, 0x11, 0xcc, 0x05, 0x0f,
                            0x05, 0x22, 0x33, 0x44, 0xc3};
  memcpy(m, second, sizeof second);
  mprotect(m, 4096, PROT_READ | PROT_EXEC);
  printf("jit-second=%lx\n", ((fn)m)());
  return 0;
}

/* Every byte of this executable's executable mappings that reads `cc` in
 * memory where the file has `0f` (a patched `syscall`, or a patched byte that
 * was never one), as a file offset. */
static void print_sites(const char *label) {
  char self[4096];
  ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (n <= 0) { printf("%s=error\n", label); return; }
  self[n] = 0;
  int fd = open(self, O_RDONLY);
  FILE *maps = fopen("/proc/self/maps", "r");
  if (fd < 0 || !maps) { printf("%s=error\n", label); return; }
  char line[4096];
  printf("%s=", label);
  int first = 1;
  while (fgets(line, sizeof(line), maps)) {
    unsigned long start, end, offset;
    char perms[8], path[4096] = "";
    if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095s", &start, &end, perms,
               &offset, path) < 4)
      continue;
    if (perms[2] != 'x' || strcmp(path, self) != 0) continue;
    for (unsigned long a = start; a < end; a++) {
      unsigned char mem = *(const volatile unsigned char *)a, file = 0;
      if (mem != 0xcc) continue;
      if (pread(fd, &file, 1, (off_t)(offset + (a - start))) != 1) continue;
      if (file == 0x0f || file == 0x90) {
        printf("%s%lx", first ? "" : ",", offset + (a - start));
        first = 0;
      }
    }
  }
  printf("\n");
  fclose(maps);
  close(fd);
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "jit") == 0) return jit();
  printf("before=%x\n", desync_probe());
  printf("page-before=%x\n", page_probe());
  print_sites("sites");
  int mem = open("/proc/self/mem", O_RDWR);
  unsigned char code[2] = {0x0f, 0x05};
  off_t at = (off_t)(unsigned long)late_slot + 5;
  int wrote = mem >= 0 && pwrite(mem, code, 2, at) == 2;
  if (mem >= 0) close(mem);
  printf("late-write=%s\n", wrote ? "ok" : "failed");
  void *h = dlopen("libm.so.6", RTLD_NOW);
  printf("dlopen=%s\n", h ? "ok" : "failed");
  if (h) dlclose(h);
  printf("after=%x\n", desync_probe());
  printf("page-after=%x\n", page_probe());
  print_sites("late-sites");
  return 0;
}
"""

proc lineValue(output, key: string): string =
  for line in output.splitLines():
    if line.startsWith(key & "="):
      return line[key.len + 1 .. ^1]
  ""

suite "a late inline-syscall scan keeps the startup scan's instruction sync":
  when defined(linux) and defined(amd64):
    let work = expandFilename(getTempDir()) /
      ("io-mon-late-inline-sync-" & $getCurrentProcessId())
    removeDir(work)
    createDir(work)
    let shimLib = buildPrivateLinuxShim(repoRoot)
    let snoopBin = work / "io-mon"
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & snoopBin, snoopSrc])
    checkpoint(cli.output)
    doAssert cli.code == 0, "io-mon CLI build failed"
    let host = work / "late-sync-host"
    writeFile(host & ".c", hostSource)
    let cc = run(getEnv("CC", "cc"), @[host & ".c", "-O1", "-o", host, "-ldl"])
    checkpoint(cc.output)
    doAssert cc.code == 0, "host build failed"
    let env = unmonitoredEnv()
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib

    test "unmonitored, the probe computes 0x0f000001":
      let r = run(host, @[], env)
      checkpoint(r.output)
      check r.code == 0
      check lineValue(r.output, "before") == "f000001"
      check lineValue(r.output, "after") == "f000001"
      check lineValue(r.output, "page-before") == "50f0001"
      check lineValue(r.output, "page-after") == "50f0001"
      check lineValue(r.output, "sites") == ""

    test "a dlopen's scan patches no byte inside an instruction":
      let r = run(snoopBin, @["run", "--depfile", work / "late.iomon", "--",
                              host], env)
      checkpoint(r.output)
      check r.code == 0
      check lineValue(r.output, "dlopen") == "ok"
      check lineValue(r.output, "late-write") == "ok"
      # The startup scan patched each probe's one `syscall`, and the calls
      # through the trap still compute the right values.
      let sites = lineValue(r.output, "sites")
      check sites.split(',').len == 2
      check lineValue(r.output, "before") == "f000001"
      check lineValue(r.output, "page-before") == "50f0001"
      # The late scan ran (it patched the `syscall` written before it) and
      # decoded on the startup scan's boundaries: both `mov` immediates are
      # intact and nothing else was patched.
      check lineValue(r.output, "after") == "f000001"
      check lineValue(r.output, "page-after") == "50f0001"
      let late = lineValue(r.output, "late-sites").split(',')
      check late.len == 3
      for site in sites.split(','):
        check site in late

    test "a stale patched address inside new JIT code does not cut the decode":
      let r = run(snoopBin, @["run", "--depfile", work / "jit.iomon", "--",
                              host, "jit"], env)
      checkpoint(r.output)
      check r.code == 0
      # The first page's `syscall` was patched (so its address is registered)
      # and the call through the trap worked.
      check lineValue(r.output, "jit-first") == "ok jit-patched=cc"
      check lineValue(r.output, "jit-second") == "443322050f05cc11"
  else:
    test "late inline scan instruction sync (x86_64 INT3 backend only)":
      skip()
