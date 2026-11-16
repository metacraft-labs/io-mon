## A mapping patched from an inline site table gets exactly the sites a scan
## of it finds, and a table that does not describe the mapped bytes is never
## served.
##
## WHY. The shim decodes every executable section of an image at start-up to
## find its raw `syscall` instructions. A compiler image runs once per compile,
## so a build decoded the same 25 MB of `cc1` hundreds of times. A process that
## is not monitored (the build engine, here this test) now computes the result
## once per image (`computeSiteTable`), seals it into a memfd and hands it to
## the monitor host (`--inline-site-tables`), which names it to the tree. The
## shim serves a mapping from it only when the file, the code ranges and the
## code pages show that memory holds the bytes the table was computed from.
##
## WHAT THIS TEST GRADES, with a real host program that reports its own patched
## sites: every byte of its executable mapping that reads `cc` in memory where
## its file has `0f` (the first byte of a `syscall` the shim replaced with
## `int3`), or `90` for the one `syscall` the host writes over a nop at run
## time. The host's text holds three real `syscall` instructions, and its
## `.rodata` (placed in the executable segment by `-z noseparate-code`) holds
## `0f 05` data the scanner must not patch.
##   - served: the patched set equals a plain scan's, the table really was
##     used (the shim names it when the host did not issue it), and the
##     capture is complete when the host issued it;
##   - a table some other party supplied is used but leaves the capture
##     incomplete (the served-record stays an event loss);
##   - a table for another file, a table in an unsealed file, and a table for
##     this file computed before the file was changed are never served: the
##     image is scanned and the patched set is the scan's;
##   - code written after start-up (through /proc/self/mem, so the mapping is
##     not split by it) makes the next scan (a dlopen) decode instead of
##     serving, so the new site is patched exactly as a scan patches it; in a
##     program whose startup patches nothing (so no patch splits its code
##     mapping either) only the page check can tell.
##
## Falsifying mutations, each run against this test: serving a table without
## comparing the file identity fails the other-file and changed-file cases;
## not scanning a mapping the table does not serve fails those two and the
## late-code case; dropping the page check fails the unsplit-mapping case; a
## host that accepts the served-record of any table fails the
## handed-to-a-child case.
##
## x86_64 only: no other architecture has the inline-syscall trap backend.
## Mocks: none. Real shim, real host program, real compiler and linker, real
## memfd seals.

import foreign_preload_isolation

import std/[algorithm, os, osproc, posix, sequtils, streams, strtabs,
            strutils, unittest]

import io_mon
import io_mon/inline_site_table
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* `0f 05` data in .rodata, which `-z noseparate-code` puts in the executable
 * segment: a scan of the whole segment would patch it, the section-aware scan
 * must not. */
__attribute__((used)) const unsigned char table[16] = {
  0xfa, 0x0f, 0x05, 0xfe, 0xea, 0xdf, 0x04, 0xfe,
  0x0f, 0x05, 0x01, 0x00, 0xbd, 0xf3, 0x04, 0xfe};

#ifndef NO_SITES
static long __attribute__((noinline)) raw_getpid(void) {
  long ret;
  __asm__ volatile("syscall" : "=a"(ret) : "0"(39L) : "rcx", "r11", "memory");
  return ret;
}
/* Two more sites. getpid is a system call whose number alone proves it
 * names no path, so trapping it costs the capture nothing. */
static long __attribute__((noinline)) raw_getpid2(void) {
  long ret;
  __asm__ volatile("nop\n\tsyscall" : "=a"(ret) : "0"(39L) : "rcx", "r11", "memory");
  return ret;
}
static long __attribute__((noinline)) raw_getpid3(void) {
  long ret;
  __asm__ volatile("nop\n\tnop\n\tsyscall" : "=a"(ret) : "0"(39L) : "rcx", "r11", "memory");
  return ret;
}
#endif

/* Never called. Its two nops become a `syscall` at run time in mode "late":
 * b8 27 00 00 00 (mov $39,%eax), 90 90, c3. */
__asm__(".text\n.globl late_slot\n.type late_slot,@function\nlate_slot:\n"
        "  movl $39, %eax\n  nop\n  nop\n  ret\n");
extern void late_slot(void);

/* Every byte of this executable's file-backed executable mappings that is
 * `cc` in memory and `0f` in the file (a patched `syscall`), or `90` in the
 * file (the late slot's `syscall`, written at run time over a nop), as a file
 * offset. */
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
  const char *mode = argc > 1 ? argv[1] : "";
  printf("table-env=%s\n", getenv("REPRO_MONITOR_SITE_TABLES") ? "set" : "unset");
#ifndef NO_SITES
  printf("calls=%s\n", raw_getpid() == (long)getpid() &&
         raw_getpid2() == (long)getpid() && raw_getpid3() == (long)getpid()
         ? "ok" : "mismatch");
#else
  printf("calls=ok\n");
#endif
  printf("data-bytes=%02x%02x\n", ((const volatile unsigned char *)table)[1],
         ((const volatile unsigned char *)table)[8]);
  print_sites("sites");
  if (strcmp(mode, "late") == 0) {
    /* Write the `syscall` through /proc/self/mem: the page becomes a private
     * copy without any mprotect, so the mapping stays one mapping. */
    int mem = open("/proc/self/mem", O_RDWR);
    unsigned char code[2] = {0x0f, 0x05};
    off_t at = (off_t)(unsigned long)late_slot + 5;
    int wrote = mem >= 0 && pwrite(mem, code, 2, at) == 2;
    if (mem >= 0) close(mem);
    printf("late-write=%s\n", wrote ? "ok" : "failed");
    void *h = dlopen("libm.so.6", RTLD_NOW);
    if (h) dlclose(h);
    printf("late-slot=%lx\n", (unsigned long)late_slot);
    print_sites("late-sites");
  }
  if (strcmp(mode, "forge") == 0 && argc > 2) {
    /* A monitored process handing its child a table of its own choosing. */
    setenv("REPRO_MONITOR_SITE_TABLES", argv[2], 1);
    char *child[] = {argv[0], "", NULL};
    execv(argv[0], child);
    return 127;
  }
  return 0;
}
"""

type Fixture = object
  work, snoopBin, host, other, changed, noSites: string
  env: StringTableRef

proc lineValue(output, key: string): string =
  for line in output.splitLines():
    if line.startsWith(key & "="):
      return line[key.len + 1 .. ^1]
  ""

proc setUpFixture(): Fixture =
  result.work = expandFilename(getTempDir()) /
    ("io-mon-inline-site-table-" & $getCurrentProcessId())
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
  result.host = result.work / "site-table-host"
  writeFile(result.host & ".c", hostSource)
  let cc = run(getEnv("CC", "cc"), @[result.host & ".c", "-O1",
    "-Wl,-z,noseparate-code", "-o", result.host, "-ldl"])
  checkpoint(cc.output)
  doAssert cc.code == 0, "host build failed"
  # The same program without its three `syscall` instructions: its startup
  # scan patches nothing, so no mprotect splits its code mapping and a page
  # written later leaves the mapping's ranges as they were.
  result.noSites = result.work / "site-table-host-no-sites"
  let ccNoSites = run(getEnv("CC", "cc"), @[result.host & ".c", "-O1",
    "-DNO_SITES", "-Wl,-z,noseparate-code", "-o", result.noSites, "-ldl"])
  checkpoint(ccNoSites.output)
  doAssert ccNoSites.code == 0, "host build failed"
  # A second file with the same bytes: another inode, so another identity.
  result.other = result.work / "site-table-host-copy"
  copyFileWithPermissions(result.host, result.other)
  # A third copy, changed after its table is computed (see the test).
  result.changed = result.work / "site-table-host-changed"
  copyFileWithPermissions(result.host, result.changed)
  # The producer refuses a file changed within `defaultSettleNs`.
  sleep(int(defaultSettleNs div 1_000_000) + 200)
  result.env = unmonitoredEnv()
  result.env["REPRO_MONITOR_SHIM_LIB"] = shimLib

proc tableFor(paths: openArray[string]): string =
  var images: seq[SiteTableImage] = @[]
  for path in paths:
    let computed = computeSiteTable(path)
    doAssert computed.ok, path & ": " & computed.reason
    images.add computed.image
  encodeSiteTables(images)

proc sealed(bytes: string): tuple[fd: cint; path: string] =
  let made = createSealedSiteTableFile(bytes)
  doAssert made.fd >= 0, made.error
  (made.fd, "/proc/" & $getpid() & "/fd/" & $made.fd)

proc capture(f: Fixture; name: string; program: string; args: seq[string] = @[];
             table = ""; envTable = ""):
    tuple[output: string; code: int; dep: MonitorDepFile] =
  let depfile = f.work / (name & ".iomon")
  var cli = @["run", "--depfile", depfile]
  if table.len > 0:
    cli.add @["--inline-site-tables", table]
  cli.add "--"
  cli.add program
  cli.add args
  let env = newStringTable(modeCaseSensitive)
  for k, v in f.env: env[k] = v
  if envTable.len > 0:
    env[SiteTableEnv] = envTable
  let r = run(f.snoopBin, cli, env)
  checkpoint(name & ":\n" & r.output)
  (r.output, r.code, readMonitorDepFile(depfile))

proc losses(dep: MonitorDepFile): seq[string] =
  dep.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail)

proc servedLosses(dep: MonitorDepFile): seq[string] =
  dep.losses.filterIt(it.startsWith(SiteTableServedDetail))

proc siteList(output, key: string): seq[string] =
  let v = lineValue(output, key)
  if v.len == 0: @[] else: v.split(',').sorted()

suite "inline site tables serve exactly the scan's sites":
  when defined(linux) and defined(amd64):
    let f = setUpFixture()
    let scanned = f.capture("scan", f.host)
    let scanSites = siteList(scanned.output, "sites")

    test "plain scan: three sites in code, none in data, capture complete":
      check scanned.code == 0
      check lineValue(scanned.output, "calls") == "ok"
      check lineValue(scanned.output, "data-bytes") == "0f0f"
      check lineValue(scanned.output, "table-env") == "unset"
      check scanSites.len == 3
      check scanned.dep.completeness == mcComplete

    test "the producer's table lists the scan's sites":
      let computed = computeSiteTable(f.host)
      check computed.ok
      var total = 0
      for segment in computed.image.segments:
        total += segment.sites.len
      check total == scanSites.len

    test "a table the host issued is served, identically, and accepted":
      let t = sealed(tableFor([f.host]))
      defer: discard posix.close(t.fd)
      let issued = f.capture("issued", f.host, table = t.path)
      check issued.code == 0
      check lineValue(issued.output, "table-env") == "set"
      check lineValue(issued.output, "calls") == "ok"
      check lineValue(issued.output, "data-bytes") == "0f0f"
      check siteList(issued.output, "sites") == scanSites
      checkpoint($issued.dep.losses)
      check issued.dep.servedLosses.len == 0
      check issued.dep.completeness == mcComplete

    test "the same table, not issued by the host, is served but leaves a loss":
      let t = sealed(tableFor([f.host]))
      defer: discard posix.close(t.fd)
      var st: Stat
      doAssert fstat(t.fd, st) == 0
      let direct = f.capture("unissued", f.host, envTable = t.path)
      check direct.code == 0
      check siteList(direct.output, "sites") == scanSites
      let served = direct.dep.servedLosses
      checkpoint($served)
      # The shim used the table, and named it.
      check served.len == 1
      check served.anyIt(("table=" & $st.st_dev & ":" & $st.st_ino) in it)
      check direct.dep.completeness == mcIncomplete

    test "a monitored process handing its child another table: capture incomplete":
      let issuedTable = sealed(tableFor([f.host]))
      defer: discard posix.close(issuedTable.fd)
      let forged = sealed(tableFor([f.host]))
      defer: discard posix.close(forged.fd)
      let r = f.capture("forged", f.host, @["forge", forged.path],
                        table = issuedTable.path)
      check r.code == 0
      check siteList(r.output, "sites") == scanSites
      checkpoint($r.dep.losses)
      check r.dep.servedLosses.len == 1
      check r.dep.completeness == mcIncomplete

    test "a table for another file is not served: the image is scanned":
      let t = sealed(tableFor([f.other]))
      defer: discard posix.close(t.fd)
      let r = f.capture("other-file", f.host, envTable = t.path)
      check r.code == 0
      check siteList(r.output, "sites") == scanSites
      check r.dep.servedLosses.len == 0
      check r.dep.completeness == mcComplete

    test "a table in a file that is not sealed is not used":
      let plain = f.work / "plain-table"
      writeFile(plain, tableFor([f.host]))
      let r = f.capture("unsealed", f.host, envTable = plain)
      check r.code == 0
      check siteList(r.output, "sites") == scanSites
      check r.dep.servedLosses.len == 0
      check r.dep.completeness == mcComplete

    test "a table computed before the file changed is not served":
      let t = sealed(tableFor([f.changed]))
      defer: discard posix.close(t.fd)
      # Turn the never-called slot's two nops into a `syscall` IN THE FILE:
      # a scan now finds four sites, the stale table lists three.
      var bytes = readFile(f.changed)
      let marker = "\xb8\x27\x00\x00\x00\x90\x90\xc3"
      let at = bytes.find(marker)
      doAssert at > 0 and bytes.find(marker, at + 1) < 0
      bytes[at + 5] = '\x0f'
      bytes[at + 6] = '\x05'
      let fd = posix.open(cstring(f.changed), O_WRONLY)
      doAssert fd >= 0
      doAssert pwrite(fd, addr bytes[at + 5], 2, Off(at + 5)) == 2
      discard posix.close(fd)
      let fresh = f.capture("changed-scan", f.changed)
      let freshSites = siteList(fresh.output, "sites")
      check freshSites.len == scanSites.len + 1
      let r = f.capture("changed-table", f.changed, envTable = t.path)
      check r.code == 0
      check siteList(r.output, "sites") == freshSites
      check r.dep.servedLosses.len == 0

    test "code written after start-up is decoded on the next scan, not served":
      let t = sealed(tableFor([f.host]))
      defer: discard posix.close(t.fd)
      let plain = f.capture("late-scan", f.host, @["late"])
      check lineValue(plain.output, "late-write") == "ok"
      let plainLate = siteList(plain.output, "late-sites")
      # The scan after the dlopen patches the new `syscall` too.
      check plainLate.len == scanSites.len + 1
      let r = f.capture("late-table", f.host, @["late"], envTable = t.path)
      check lineValue(r.output, "late-write") == "ok"
      check siteList(r.output, "sites") == scanSites
      check siteList(r.output, "late-sites") == plainLate
      # The startup scan was served (the shim names the table).
      check r.dep.servedLosses.len == 1

    test "a page written after start-up in an unsplit mapping is decoded, not served":
      # The startup scan of this program patches nothing, so its code mapping
      # stays one mapping with the table's ranges; only the page check can
      # tell that the late `syscall` makes memory differ from the file.
      let t = sealed(tableFor([f.noSites]))
      defer: discard posix.close(t.fd)
      let plain = f.capture("no-sites-late-scan", f.noSites, @["late"])
      check lineValue(plain.output, "late-write") == "ok"
      check siteList(plain.output, "sites").len == 0
      let plainLate = siteList(plain.output, "late-sites")
      check plainLate.len == 1
      let r = f.capture("no-sites-late-table", f.noSites, @["late"],
                        envTable = t.path)
      check lineValue(r.output, "late-write") == "ok"
      check siteList(r.output, "sites").len == 0
      check siteList(r.output, "late-sites") == plainLate
      check r.dep.servedLosses.len == 1
  else:
    test "inline site tables (x86_64 INT3 backend only)":
      skip()
