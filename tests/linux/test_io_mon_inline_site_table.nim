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
## Every case runs twice: with the programs where the fixture built them, and
## again on a file system whose `stat` device is not the one
## `/proc/self/maps` prints. btrfs is one (`stat` reports the subvolume's
## device, maps the superblock's), and on a btrfs host the first run of the
## served cases failed because the shim then never served a table
## (reprobuild-pm issue
## 2026-11-22-io-mon-inline-site-table-tests-fail-four-cases-at-agents). The
## second run gets the same split on any host: after the first, this test
## process moves into a private user and mount namespace (`enterOverlay`) and
## runs the programs from an overlayfs that has the fixture directory as its
## lower layer, a tmpfs upper layer and `xino=off`, so `stat` reports the
## pseudo device the overlay gives that lower layer and maps the overlay's
## superblock device. The host program
## prints both, and every capture checks that they differ, so the run cannot
## pass on a layout that does not split them. Where the host
## refuses an unprivileged user namespace or the mounts made in it (a tmpfs
## and an overlay), those cases report an explicit skip, as
## test_io_mon_linux_tree_ledger does, and a run that sets
## `IO_MON_TEST_REQUIRE_USERNS=1` (CI does) fails them instead
## (`tests/helpers/userns_requirement.nim`): a lane that grants user
## namespaces but denies their capabilities, the way an AppArmor-restricted
## Ubuntu does, is the same defect.
##
## On such a file system the device and inode cannot prove that the file the
## shim opened is the mapped one, so the shim serves only when the mapped code
## bytes equal the opened file's. That comparison is graded in process
## (`serveSitesFromTable` on a real mapping in this test process): a mapping
## whose path now names a file with other code bytes, and a table for that
## file, is not served. No mount the test can make produces that state (on an
## overlay the inode in maps then differs), so the maps record is the test
## process's real one with two fields replaced: the device, set to `0:0`, a
## device `stat` never reports, as btrfs and overlayfs records carry one
## `stat` does not report, and the path and inode, set to the other file's.
##
## Falsifying mutations, each run against this test: serving a table without
## comparing the file identity fails the other-file and changed-file cases;
## not scanning a mapping the table does not serve fails those two and the
## late-code case; dropping the page check fails the unsplit-mapping case; a
## host that accepts the served-record of any table fails the
## handed-to-a-child case; refusing every mapping whose maps device is not
## the `stat` device fails the four served cases of the second run and the
## in-process served case; serving such a mapping without comparing its bytes
## fails the in-process other-bytes case; comparing memory with the file
## bytes at the wrong offsets (dropping the mapping's file offset) fails the
## nonzero-offset cases, whose program is linked with separate code so its
## executable segment does not start at offset 0, as every other fixture's
## does.
##
## x86_64 only: no other architecture has the inline-syscall trap backend.
## Mocks: none in the captures. Real shim, real host program, real compiler
## and linker, real memfd seals, a real overlayfs. The in-process case
## replaces the fields of a real maps record, as said above.

import foreign_preload_isolation

import std/[algorithm, os, osproc, posix, sequtils, streams, strtabs,
            strutils, unittest]

import io_mon
import io_mon/inline_site_table
import stackable_hooks/platform/linux_raw_syscalls
import stackable_hooks/platform/linux_image_code_ranges
import build_test_shim
import unmonitored_env
import userns_requirement

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
#include <sys/stat.h>
#include <sys/sysmacros.h>
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

/* The device /proc/self/maps names for this executable and the device
 * stat(2) reports for it, both as decimal major:minor. */
static void print_devices(void) {
  char self[4096], line[4096];
  ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
  FILE *maps = fopen("/proc/self/maps", "r");
  struct stat st;
  if (n <= 0 || !maps || stat("/proc/self/exe", &st) != 0) {
    printf("maps-dev=error\nstat-dev=error\n");
    if (maps) fclose(maps);
    return;
  }
  self[n] = 0;
  unsigned major_ = 0, minor_ = 0;
  int found = 0;
  while (!found && fgets(line, sizeof(line), maps)) {
    char path[4096] = "";
    if (sscanf(line, "%*s %*s %*s %x:%x %*s %4095s", &major_, &minor_,
               path) == 3 && strcmp(path, self) == 0)
      found = 1;
  }
  fclose(maps);
  if (found) printf("maps-dev=%u:%u\n", major_, minor_);
  else printf("maps-dev=missing\n");
  printf("stat-dev=%u:%u\n", major(st.st_dev), minor(st.st_dev));
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
  print_devices();
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

proc unshare(flags: cint): cint {.importc, header: "<sched.h>".}
proc mount(source, target, fstype: cstring; flags: culong; data: cstring): cint
  {.importc, header: "<sys/mount.h>".}
{.passc: "-D_GNU_SOURCE".}

const
  cloneNewUser = 0x10000000.cint
  cloneNewNs = 0x00020000.cint
  msRec = 0x4000.culong
  msSlave = 0x80000.culong

type
  Layout = enum
    lyDirect   ## the programs where the fixture built them
    lyOverlay  ## the same files through an overlay: maps and stat disagree

  Fixture = object
    work, snoopBin, host, other, noSites, swapped, separate: string
    changed: array[Layout, string]
    overlayUpper, overlayMerged: string
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
  # The same program linked with separate code, the linker's default: its
  # executable segment starts at a nonzero file offset, as a real
  # compiler's does, where every other fixture's code starts at offset 0.
  result.separate = result.work / "site-table-host-separate"
  let ccSeparate = run(getEnv("CC", "cc"), @[result.host & ".c", "-O1",
    "-Wl,-z,separate-code", "-o", result.separate, "-ldl"])
  checkpoint(ccSeparate.output)
  doAssert ccSeparate.code == 0, "host build failed"
  # A second file with the same bytes: another inode, so another identity.
  result.other = result.work / "site-table-host-copy"
  copyFileWithPermissions(result.host, result.other)
  # A third copy per layout, changed after its table is computed (see the
  # test).
  for layout in Layout:
    result.changed[layout] = result.work / ("site-table-host-changed-" & $layout)
    copyFileWithPermissions(result.host, result.changed[layout])
  # A copy whose never-called slot already holds a `syscall`: the same layout
  # and code ranges as the host, other code bytes.
  result.swapped = result.work / "site-table-host-swapped"
  block:
    var bytes = readFile(result.host)
    let marker = "\xb8\x27\x00\x00\x00\x90\x90\xc3"
    let at = bytes.find(marker)
    doAssert at > 0 and bytes.find(marker, at + 1) < 0
    bytes[at + 5] = '\x0f'
    bytes[at + 6] = '\x05'
    writeFile(result.swapped, bytes)
  # Where the overlay layout mounts its tmpfs and its overlay of `work`.
  result.overlayUpper = result.work & "-overlay-upper"
  result.overlayMerged = result.work & "-overlay-merged"
  createDir(result.overlayUpper)
  createDir(result.overlayMerged)
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

proc at(f: Fixture; layout: Layout; path: string): string =
  ## Where a program or table producer in `layout` sees the fixture file
  ## `path`. On the overlay that is the merged path, and the producer must
  ## read it there too: without `xino` an overlay reports each lower layer's
  ## files on a pseudo device of its own, so the identity `stat` gives
  ## through the overlay is not the one it gives for the layer's own path.
  if layout == lyOverlay: f.overlayMerged / path.relativePath(f.work)
  else: path

proc enterOverlay(f: Fixture): tuple[ok: bool; why: string] =
  ## Move this test process into a private user and mount namespace and mount
  ## an overlay of the fixture directory at `overlayMerged`: its lower layer
  ## is `work`, its upper layer a tmpfs, and `xino=off`, so `stat` of a file
  ## in it reports the pseudo device the overlay gives its lower layer while
  ## /proc/self/maps names the overlay's superblock, the split btrfs
  ## subvolumes show. The
  ## process itself moves, not only the captures, because a table is named
  ## as `/proc/<this process>/fd/<n>` and the kernel refuses that path to a
  ## process in another user namespace. Returns false, with the reason, when
  ## the host refuses an unprivileged user namespace or overlay mount; then
  ## checks with the host program that the layout really splits the devices.
  let uid = getuid()
  let gid = getgid()
  if unshare(cloneNewUser or cloneNewNs) != 0:
    let err = errno
    # EINVAL is a multi-threaded caller: a defect of this test, not the host.
    doAssert err != EINVAL, "unshare refused: this test process has threads"
    return (false, "unprivileged user namespaces are unavailable: " &
      $strerror(err))
  try:
    writeFile("/proc/self/setgroups", "deny")
    writeFile("/proc/self/uid_map", "0 " & $uid & " 1")
    writeFile("/proc/self/gid_map", "0 " & $gid & " 1")
  except IOError as e:
    return (false, "the user namespace cannot map this user: " & e.msg)
  # Slave, not private: a private copy would keep every host mount it copied
  # mounted for as long as this process lives.
  if mount("none", "/", nil, msRec or msSlave, nil) != 0:
    return (false, "cannot make / a slave mount: " & $strerror(errno))
  if mount("tmpfs", cstring(f.overlayUpper), "tmpfs", 0, nil) != 0:
    return (false, "cannot mount a tmpfs: " & $strerror(errno))
  createDir(f.overlayUpper / "u")
  createDir(f.overlayUpper / "w")
  let options = "lowerdir=" & f.work & ",upperdir=" & f.overlayUpper / "u" &
    ",workdir=" & f.overlayUpper / "w" & ",xino=off"
  if mount("overlay", cstring(f.overlayMerged), "overlay", 0,
           cstring(options)) != 0:
    return (false, "unprivileged overlay mounts are unavailable: " &
      $strerror(errno))
  let probe = run(f.at(lyOverlay, f.host), @[], f.env)
  checkpoint("overlay probe:\n" & probe.output)
  doAssert probe.code == 0, "the overlay probe failed: " & probe.output
  let mapsDev = lineValue(probe.output, "maps-dev")
  let statDev = lineValue(probe.output, "stat-dev")
  doAssert ':' in mapsDev and ':' in statDev and mapsDev != statDev,
    "the overlay does not split the maps and stat devices: " & probe.output
  (true, "")

proc capture(f: Fixture; layout: Layout; name: string; program: string;
             args: seq[string] = @[]; table = ""; envTable = ""):
    tuple[output: string; code: int; dep: MonitorDepFile] =
  let depfile = f.work / (name & "-" & $layout & ".iomon")
  var cli = @["run", "--depfile", depfile]
  if table.len > 0:
    cli.add @["--inline-site-tables", table]
  cli.add "--"
  cli.add f.at(layout, program)
  cli.add args
  let env = newStringTable(modeCaseSensitive)
  for k, v in f.env: env[k] = v
  if envTable.len > 0:
    env[SiteTableEnv] = envTable
  let r = run(f.snoopBin, cli, env)
  checkpoint(name & " (" & $layout & "):\n" & r.output)
  if layout == lyOverlay:
    # Every capture on the overlay must really see the split devices.
    check lineValue(r.output, "maps-dev") != lineValue(r.output, "stat-dev")
  (r.output, r.code, readMonitorDepFile(depfile))

proc losses(dep: MonitorDepFile): seq[string] =
  dep.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail)

proc servedLosses(dep: MonitorDepFile): seq[string] =
  dep.losses.filterIt(it.startsWith(SiteTableServedDetail))

proc siteList(output, key: string): seq[string] =
  let v = lineValue(output, key)
  if v.len == 0: @[] else: v.split(',').sorted()

template siteTableCases(f: Fixture; layout: Layout) =
  ## The served/not-served cases, run with the programs in `layout`. On the
  ## overlay their names say so, and where the host cannot make the overlay
  ## each reports an explicit skip.
  let availability =
    if layout == lyOverlay: f.enterOverlay() else: (true, "")
  template caseName(name: string): string =
    if layout == lyOverlay: name & " (maps names another device than stat)"
    else: name
  template inLayout(body: untyped) =
    if not availability.ok:
      skipOrRequireUserns(availability.why)
    else:
      body
  var scanned: tuple[output: string; code: int; dep: MonitorDepFile]
  if availability.ok:
    scanned = f.capture(layout, "scan", f.host)
  let scanSites = siteList(scanned.output, "sites")

  test caseName("plain scan: three sites in code, none in data, capture complete"):
    inLayout:
      check scanned.code == 0
      check lineValue(scanned.output, "calls") == "ok"
      check lineValue(scanned.output, "data-bytes") == "0f0f"
      check lineValue(scanned.output, "table-env") == "unset"
      check scanSites.len == 3
      check scanned.dep.completeness == mcComplete

  test caseName("the producer's table lists the scan's sites"):
    inLayout:
      let computed = computeSiteTable(f.at(layout, f.host))
      check computed.ok
      var total = 0
      for segment in computed.image.segments:
        total += segment.sites.len
      check total == scanSites.len

  test caseName("a table the host issued is served, identically, and accepted"):
    inLayout:
      let t = sealed(tableFor([f.at(layout, f.host)]))
      defer: discard posix.close(t.fd)
      let issued = f.capture(layout, "issued", f.host, table = t.path)
      check issued.code == 0
      check lineValue(issued.output, "table-env") == "set"
      check lineValue(issued.output, "calls") == "ok"
      check lineValue(issued.output, "data-bytes") == "0f0f"
      check siteList(issued.output, "sites") == scanSites
      checkpoint($issued.dep.losses)
      check issued.dep.servedLosses.len == 0
      check issued.dep.completeness == mcComplete

  test caseName("the same table, not issued by the host, is served but leaves a loss"):
    inLayout:
      let t = sealed(tableFor([f.at(layout, f.host)]))
      defer: discard posix.close(t.fd)
      var st: Stat
      doAssert fstat(t.fd, st) == 0
      let direct = f.capture(layout, "unissued", f.host, envTable = t.path)
      check direct.code == 0
      check siteList(direct.output, "sites") == scanSites
      let served = direct.dep.servedLosses
      checkpoint($served)
      # The shim used the table, and named it.
      check served.len == 1
      check served.anyIt(("table=" & $st.st_dev & ":" & $st.st_ino) in it)
      check direct.dep.completeness == mcIncomplete

  test caseName("a monitored process handing its child another table: capture incomplete"):
    inLayout:
      let issuedTable = sealed(tableFor([f.at(layout, f.host)]))
      defer: discard posix.close(issuedTable.fd)
      let forged = sealed(tableFor([f.at(layout, f.host)]))
      defer: discard posix.close(forged.fd)
      let r = f.capture(layout, "forged", f.host, @["forge", forged.path],
                        table = issuedTable.path)
      check r.code == 0
      check siteList(r.output, "sites") == scanSites
      checkpoint($r.dep.losses)
      check r.dep.servedLosses.len == 1
      check r.dep.completeness == mcIncomplete

  test caseName("code at a nonzero file offset is served from the table"):
    inLayout:
      let computed = computeSiteTable(f.at(layout, f.separate))
      check computed.ok
      check computed.image.segments.len > 0 and
        computed.image.segments.allIt(it.pOffset != 0)
      let plain = f.capture(layout, "separate-scan", f.separate)
      let plainSites = siteList(plain.output, "sites")
      check plainSites.len == 3
      let t = sealed(tableFor([f.at(layout, f.separate)]))
      defer: discard posix.close(t.fd)
      let r = f.capture(layout, "separate-table", f.separate, envTable = t.path)
      check r.code == 0
      check lineValue(r.output, "calls") == "ok"
      check siteList(r.output, "sites") == plainSites
      # Served (the shim names the table), not scanned.
      check r.dep.servedLosses.len == 1

  test caseName("a table for another file is not served: the image is scanned"):
    inLayout:
      let t = sealed(tableFor([f.at(layout, f.other)]))
      defer: discard posix.close(t.fd)
      let r = f.capture(layout, "other-file", f.host, envTable = t.path)
      check r.code == 0
      check siteList(r.output, "sites") == scanSites
      check r.dep.servedLosses.len == 0
      check r.dep.completeness == mcComplete

  test caseName("a table in a file that is not sealed is not used"):
    inLayout:
      let plain = f.work / "plain-table"
      writeFile(plain, tableFor([f.at(layout, f.host)]))
      let r = f.capture(layout, "unsealed", f.host, envTable = plain)
      check r.code == 0
      check siteList(r.output, "sites") == scanSites
      check r.dep.servedLosses.len == 0
      check r.dep.completeness == mcComplete

  test caseName("a table computed before the file changed is not served"):
    inLayout:
      let t = sealed(tableFor([f.at(layout, f.changed[layout])]))
      defer: discard posix.close(t.fd)
      # Turn the never-called slot's two nops into a `syscall` IN THE FILE:
      # a scan now finds four sites, the stale table lists three.
      let changedPath = f.at(layout, f.changed[layout])
      var bytes = readFile(changedPath)
      let marker = "\xb8\x27\x00\x00\x00\x90\x90\xc3"
      let at = bytes.find(marker)
      doAssert at > 0 and bytes.find(marker, at + 1) < 0
      bytes[at + 5] = '\x0f'
      bytes[at + 6] = '\x05'
      let fd = posix.open(cstring(changedPath), O_WRONLY)
      doAssert fd >= 0
      doAssert pwrite(fd, addr bytes[at + 5], 2, Off(at + 5)) == 2
      discard posix.close(fd)
      let fresh = f.capture(layout, "changed-scan", f.changed[layout])
      let freshSites = siteList(fresh.output, "sites")
      check freshSites.len == scanSites.len + 1
      let r = f.capture(layout, "changed-table", f.changed[layout], envTable = t.path)
      check r.code == 0
      check siteList(r.output, "sites") == freshSites
      check r.dep.servedLosses.len == 0

  test caseName("code written after start-up is decoded on the next scan, not served"):
    inLayout:
      let t = sealed(tableFor([f.at(layout, f.host)]))
      defer: discard posix.close(t.fd)
      let plain = f.capture(layout, "late-scan", f.host, @["late"])
      check lineValue(plain.output, "late-write") == "ok"
      let plainLate = siteList(plain.output, "late-sites")
      # The scan after the dlopen patches the new `syscall` too.
      check plainLate.len == scanSites.len + 1
      let r = f.capture(layout, "late-table", f.host, @["late"], envTable = t.path)
      check lineValue(r.output, "late-write") == "ok"
      check siteList(r.output, "sites") == scanSites
      check siteList(r.output, "late-sites") == plainLate
      # The startup scan was served (the shim names the table).
      check r.dep.servedLosses.len == 1

  test caseName("a page written after start-up in an unsplit mapping is decoded, not served"):
    inLayout:
      # The startup scan of this program patches nothing, so its code mapping
      # stays one mapping with the table's ranges; only the page check can
      # tell that the late `syscall` makes memory differ from the file.
      let t = sealed(tableFor([f.at(layout, f.noSites)]))
      defer: discard posix.close(t.fd)
      let plain = f.capture(layout, "no-sites-late-scan", f.noSites, @["late"])
      check lineValue(plain.output, "late-write") == "ok"
      check siteList(plain.output, "sites").len == 0
      let plainLate = siteList(plain.output, "late-sites")
      check plainLate.len == 1
      let r = f.capture(layout, "no-sites-late-table", f.noSites, @["late"],
                        envTable = t.path)
      check lineValue(r.output, "late-write") == "ok"
      check siteList(r.output, "sites").len == 0
      check siteList(r.output, "late-sites") == plainLate
      check r.dep.servedLosses.len == 1

suite "inline site tables serve exactly the scan's sites":
  when defined(linux) and defined(amd64):
    let f = setUpFixture()
    for layout in Layout:
      siteTableCases(f, layout)

    # In process, `serveSitesFromTable` on a real mapping of the host image in
    # this process, presented as btrfs or overlayfs present it (see the
    # header): maps names a device `stat` never reports.
    proc mapCode(path: string): LinuxExecutableMapping =
      ## A real mapping, in this process, of the first executable `PT_LOAD`
      ## of the image at `path`, as /proc/self/maps records it.
      let pageMask = uint64(sysconf(SC_PAGESIZE)) - 1
      let table = computeSiteTable(path)
      doAssert table.ok, table.reason
      let segment = table.image.segments[0]
      let spanStart = segment.pOffset and not pageMask
      let spanLen = ((segment.pOffset + segment.pFilesz + pageMask) and
        not pageMask) - spanStart
      let fd = posix.open(cstring(path), O_RDONLY)
      doAssert fd >= 0
      let base = mmap(nil, int(spanLen), PROT_READ or PROT_EXEC, MAP_PRIVATE,
                      fd, Off(spanStart))
      doAssert base != MAP_FAILED
      discard posix.close(fd)
      for m in enumerateLinuxExecutableMappings().mappings:
        if m.start == cast[uint](base):
          result = m
      doAssert result.path == path, path & " is not in /proc/self/maps"

    proc withoutDevice(mapping: LinuxExecutableMapping): LinuxExecutableMapping =
      result = mapping
      result.device = "0:0"

    let mapped = mapCode(f.host)
    let unbound = withoutDevice(mapped)
    let separateMapped = mapCode(f.separate)
    doAssert separateMapped.offset != 0,
      "the separate-code image's code does not start at a nonzero offset"

    proc served(table: string; mapping: LinuxExecutableMapping):
        tuple[used: bool; sites: seq[uint]] =
      let t = sealed(table)
      defer: discard posix.close(t.fd)
      let view = openSiteTableView(t.path)
      doAssert view.base != nil, "the sealed table was not opened"
      let probed = imageCodeRangesWithIdentity(mapping)
      doAssert probed.statOk and probed.ranges.diagnostic == licrOk
      var sites: seq[uint] = @[]
      let collect = proc(site: LinuxSyscallSite): bool {.closure, raises: [].} =
        sites.add site.address
        true
      result.used = serveSitesFromTable(view, mapping, probed.st,
                                        probed.ranges.ranges, collect)
      result.sites = sites

    proc scannedSites(mapping: LinuxExecutableMapping): seq[uint] =
      var sites: seq[uint] = @[]
      let collect = proc(site: LinuxSyscallSite): bool {.closure, raises: [].} =
        sites.add site.address
        true
      let ranges = linuxImageCodeRanges(mapping)
      doAssert ranges.diagnostic == licrOk
      for r in ranges.ranges:
        visitLinuxX8664SyscallMemory(cast[pointer](r.start),
                                     int(r.stop - r.start), collect)
      sites

    test "in process: the mapping's own maps record, the table is served":
      let r = served(tableFor([f.host]), mapped)
      check r.used
      check r.sites == scannedSites(mapped)
      check r.sites.len == 3

    test "in process: maps names another device, the same bytes are served":
      let r = served(tableFor([f.host]), unbound)
      check r.used
      check r.sites == scannedSites(mapped)
      check r.sites.len == 3

    test "in process: maps names another device, code at a nonzero offset is served":
      let r = served(tableFor([f.separate]), withoutDevice(separateMapped))
      check r.used
      check r.sites == scannedSites(separateMapped)
      check r.sites.len == 3

    test "in process: maps names another device, other bytes are not served":
      # The path (and inode) name a file with the host's layout and identity
      # the table records, but its code differs from the mapped bytes.
      var st: Stat
      doAssert stat(cstring(f.swapped), st) == 0
      var other = unbound
      other.path = f.swapped
      other.inode = uint64(st.st_ino)
      let swappedTable = computeSiteTable(f.swapped)
      doAssert swappedTable.ok, swappedTable.reason
      var swappedTotal = 0
      for segment in swappedTable.image.segments:
        swappedTotal += segment.sites.len
      check swappedTotal == 4   # the slot's `syscall` is one more site
      let r = served(tableFor([f.swapped]), other)
      check not r.used
      check r.sites.len == 0
  else:
    test "inline site tables (x86_64 INT3 backend only)":
      skip()
