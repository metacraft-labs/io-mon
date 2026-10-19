## test_io_mon_shim_static_tls_small_stack_threads — the preloaded shim must
## neither make a host's small-stack `pthread_create` fail nor overflow a
## small-stack thread inside a hook (Linux).
##
## THE DEFECT (reprobuild-pm issue
## 2026-10-02-action-monitor-prevents-declared-browser-launch): under full
## action monitoring Node 24 printed `pthread_create: Invalid argument` and
## Playwright's Chromium launch then timed out. Without the monitor it worked.
##
## WHY THE SHIM CAUSES IT. A library named in `LD_PRELOAD` is part of the
## initial link map, so glibc places its `PT_TLS` segment in the STATIC TLS
## block. nptl carves that block out of EVERY thread's stack, and
## `allocate_stack` rejects a caller-requested stack size that cannot hold
## `guard + static TLS + MINIMAL_REST_STACK` with EINVAL:
##   https://sourceware.org/git/?p=glibc.git;a=blob;f=nptl/allocatestack.c
##   (the `size < ((guardsize + tls_static_size_for_stack () +
##   MINIMAL_REST_STACK + pagesize_m1) & ~pagesize_m1)` check)
## The shim's TLS was 0x12408 = 74,760 bytes — almost all of it the
## fragment writer's per-thread slot (a 64 KiB batch buffer) plus a
## `static __thread char[PATH_MAX]` in the dlopen resolver — so any host
## thread created with an explicit 64 KiB stack failed. Node creates such
## threads; so do many runtimes that size worker stacks deliberately.
##
## THE SAME BUDGET, PAID PER CALL. Once such threads could be created, the
## hooks themselves overflowed them: a hook runs on the calling thread's
## stack, and the hook paths held multi-KiB stack arrays — a 64 KiB
## range-table scratch on every munmap/mprotect/mremap, a 16 KiB dep-set key
## buffer on every recorded call, ~16 KiB of PATH_MAX arrays in the dlopen
## resolver, 4 KiB path buffers on read/openat. A PTHREAD_STACK_MIN thread
## died with SIGSEGV on its first hooked `open`, and a 64 KiB one on its first
## `munmap`, even with the shim merely preloaded.
##
## WHAT THIS TEST GRADES — every property on both a debug and a `-d:release`
## shim (the suite builds debug; the release build is what ships):
##   1. `t_shim_static_tls_within_budget` — the shim's `PT_TLS` memsz, read
##      from the ELF program headers (parsed here, so the test does not depend
##      on `readelf` being installed), stays within one page. The first cause,
##      graded directly, with a message that says what to do instead.
##   2. `t_small_stack_threads_survive_preload_and_monitoring` — the symptoms.
##      A C probe creates one thread per candidate stack size
##      (PTHREAD_STACK_MIN, 32 KiB, 64 KiB, 128 KiB), first to start and exit,
##      then to drive the hooks on its own stack (`workerOps`: open/read/close,
##      stat, stdio, mmap/munmap, mprotect to executable, dlopen of a bare
##      soname). Every size must work WITHOUT the shim (else the host itself is
##      the limit) and then (a) with the shim merely preloaded and (b) under
##      real monitoring through the `io-mon run` CLI — on the default
##      shared-memory set transport and on the file-fallback transport
##      (`REPRO_MONITOR_DEP_SHM_DISABLE=1`), where the thread's first emit is
##      what brings the per-thread fragment slot into existence. The monitored
##      depfile must be `mcComplete` and contain the threads' read, so the test
##      also proves the slot's lazy allocation and thread-exit release keep
##      the worker's record.
##   3. `t_hooked_calls_stay_within_stack_budget` — the second cause, graded
##      directly: the worker runs on a canary-filled 1 MiB stack and the
##      deepest byte it touched under monitoring may exceed the shim-less run
##      by at most `HookStackBudget`. A hook frame that regrows by a few KiB
##      fails here with a number, before some thread size somewhere faults.
##   4. `t_node_starts_under_preload_and_monitoring` — the reported symptom
##      on the real runtime: `node -e` must start without printing
##      `pthread_create: Invalid argument`, preloaded and monitored. Node is
##      a declared dev-shell package; no network or Playwright is involved.
##
## Mocks: none. The real shim is built from source by `scripts/build_shim.sh`
## and injected into a real C program by the real `io-mon run` CLI; the only
## synthetic part is the probe program itself, whose whole point is to issue
## the exact `pthread_attr_setstacksize` + `pthread_create` sequence a host
## runtime does and make the calls a host thread makes.

import std/[os, osproc, sequtils, streams, strtabs, strutils, tables,
            unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  ShimStaticTlsBudget = 4096
    ## One page. Every byte here is subtracted from every thread's stack in
    ## every monitored process, so per-thread working storage belongs on the
    ## heap (allocated on first use) and only pointers and small scalars may
    ## live in TLS.

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

proc ensureSnoop(work: string): string =
  result = work / "io-mon"
  if not fileExists(result):
    let cli = run("nim", @[
      "c", "--hints:off", "--warnings:off", "--threads:on",
      "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
      "--out:" & result, snoopSrc])
    checkpoint(cli.output)
    check cli.code == 0

proc ensureShim(): string =
  let buildShim = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(buildShim.output)
  check buildShim.code == 0
  findShimLibrary()

proc baseEnv(): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  # A preload inherited from the test's own environment would make the
  # "without the shim" baseline meaningless.
  result.del("LD_PRELOAD")

proc readLe(data: string; off, width: int): uint64 =
  for i in countdown(width - 1, 0):
    result = (result shl 8) or uint64(ord(data[off + i]))

proc staticTlsMemsz(path: string): int =
  ## The `p_memsz` of the ELF's `PT_TLS` program header, or 0 when it has
  ## none. Layout per the System V gABI, "Program Header":
  ##   https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html
  ## Little-endian ELF32 and ELF64 are handled (every Linux target io-mon
  ## builds for); anything else fails the check rather than guessing.
  const PtTls = 7'u64
  let data = readFile(path)
  doAssert data.len >= 0x40 and data.startsWith("\x7fELF"),
    path & " is not an ELF file"
  doAssert data[5] == '\x01', path & " is not little-endian"
  let is64 = data[4] == '\x02'
  let phoff = int(if is64: readLe(data, 0x20, 8) else: readLe(data, 0x1C, 4))
  let phentsize = int(readLe(data, if is64: 0x36 else: 0x2A, 2))
  let phnum = int(readLe(data, if is64: 0x38 else: 0x2C, 2))
  for i in 0 ..< phnum:
    let ph = phoff + i * phentsize
    doAssert ph + phentsize <= data.len, path & ": truncated program headers"
    if readLe(data, ph, 4) == PtTls:
      return int(if is64: readLe(data, ph + 0x28, 8)
                 else: readLe(data, ph + 0x14, 4))
  0

const probeSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Two modes, one worker.
 *
 *   probe sizes <file|-> <ops|-> <size>...
 *     One thread per stack size (bytes, or "min" for
 *     sysconf(_SC_THREAD_STACK_MIN); PTHREAD_STACK_MIN is not a compile-time
 *     constant on glibc >= 2.34). One line per size:
 *       probe size=<bytes> rc=<pthread_create result> io=<bytes read or -1>
 *
 *   probe hw <file|-> <ops|->
 *     One thread on a 1 MiB caller-supplied stack pre-filled with a canary;
 *     after the join, the untouched prefix gives the deepest stack use:
 *       hw used=<bytes>
 *
 * <ops> is a comma list of what the worker does on its own stack, i.e. which
 * shim hooks run there: io (open+read+close, stat, fopen+fgets+fclose), mmap
 * (anonymous mmap + munmap), mprotect (an anonymous page made executable),
 * dlopen (a bare soname, which the shim resolves against the caller's
 * RUNPATH). The exit status is 0 whatever the results; the test grades the
 * lines. */
static const char *g_path;
static const char *g_ops;

static int has_op(const char *op) {
  return g_ops != NULL && strstr(g_ops, op) != NULL;
}

static void *worker(void *arg) {
  long got = -1;
  if (g_path != NULL && has_op("io")) {
    char buf[64];
    struct stat st;
    int fd = open(g_path, O_RDONLY);
    if (fd >= 0) {
      got = (long)read(fd, buf, sizeof(buf));
      close(fd);
    }
    if (stat(g_path, &st) != 0) got = -1;
    FILE *f = fopen(g_path, "r");
    if (f == NULL || fgets(buf, sizeof(buf), f) == NULL) got = -1;
    if (f != NULL) fclose(f);
  }
  if (has_op("mmap")) {
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m != MAP_FAILED) munmap(m, 4096);
  }
  if (has_op("mprotect")) {
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m != MAP_FAILED) {
      mprotect(m, 4096, PROT_READ | PROT_EXEC);
      munmap(m, 4096);
    }
  }
  if (has_op("dlopen")) {
    void *h = dlopen("libm.so.6", RTLD_NOW);
    if (h != NULL) dlclose(h);
  }
  *(long *)arg = got;
  return NULL;
}

static long stack_size_arg(const char *s) {
  return strcmp(s, "min") == 0 ? sysconf(_SC_THREAD_STACK_MIN) : atol(s);
}

int main(int argc, char **argv) {
  if (argc < 4) return 2;
  g_path = strcmp(argv[2], "-") == 0 ? NULL : argv[2];
  g_ops = strcmp(argv[3], "-") == 0 ? NULL : argv[3];
  if (strcmp(argv[1], "hw") == 0) {
    const size_t size = 1 << 20;
    unsigned char *base = mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 3;
    memset(base, 0xA5, size);
    pthread_attr_t attr;
    pthread_t th;
    long got = -1;
    pthread_attr_init(&attr);
    if (pthread_attr_setstack(&attr, base, size) != 0) return 4;
    if (pthread_create(&th, &attr, worker, &got) != 0) return 5;
    pthread_join(th, NULL);
    size_t untouched = 0;
    while (untouched < size && base[untouched] == 0xA5) untouched++;
    printf("hw used=%zu io=%ld\n", size - untouched, got);
    return 0;
  }
  for (int i = 4; i < argc; i++) {
    long size = stack_size_arg(argv[i]);
    pthread_attr_t attr;
    pthread_t th;
    long got = -1;
    pthread_attr_init(&attr);
    int rc = pthread_attr_setstacksize(&attr, (size_t)size);
    if (rc == 0) rc = pthread_create(&th, &attr, worker, &got);
    if (rc == 0) pthread_join(th, NULL);
    pthread_attr_destroy(&attr);
    printf("probe size=%ld rc=%d io=%ld\n", size, rc, got);
    fflush(stdout);
  }
  return 0;
}
"""

const
  candidateSizes = ["min", "32768", "65536", "131072"]
    ## Every size is graded twice: for thread CREATION (what static TLS
    ## breaks) and for a thread that runs the shim's hooks on its own stack
    ## (what deep hook frames break).
  workerOps = "io,mmap,mprotect,dlopen"
    ## The hooks each probe thread drives. See `probeSource`.
  HookStackBudget = 4096
    ## How much deeper a monitored thread's stack may go than the same thread
    ## without the shim, for `workerOps`. A hook runs on whatever stack the
    ## host gave the calling thread, and PTHREAD_STACK_MIN (16 KiB on x86_64)
    ## is a legal size, so per-call scratch belongs on the heap, not in
    ## multi-KiB stack arrays. Measured on x86_64 glibc 2.42, debug and release
    ## shims alike: before the fix +64 KiB (the mmap-family range-table
    ## scratch), +16.5 KiB on `io` (the dep-set key buffer) and +23 KiB on
    ## `dlopen`; after it at most +1.4 KiB on any path.

type ProbeResult = tuple[rc: int; io: int]

proc parseProbe(output: string): OrderedTable[int, ProbeResult] =
  ## `size -> (rc, io)` from the probe's lines; other output (the CLI's own
  ## diagnostics, a shim warning) is ignored.
  for line in output.splitLines():
    let s = line.strip()
    if not s.startsWith("probe "):
      continue
    var size, rc, io = 0
    for field in s.split(' ')[1 .. ^1]:
      let kv = field.split('=', 1)
      if kv.len != 2: continue
      case kv[0]
      of "size": size = parseInt(kv[1])
      of "rc": rc = parseInt(kv[1])
      of "io": io = parseInt(kv[1])
      else: discard
    result[size] = (rc: rc, io: io)

proc ensureReleaseShim(work: string): string =
  ## The shipped shim is a `-d:release` build, the suite's default is debug,
  ## and stack frames differ between the two, so every graded property is
  ## checked on both. Built into the test's own work dir so it never replaces
  ## the debug shim other tests discover.
  var env = baseEnv()
  env["IO_MON_BUILD_MODE"] = "release"
  env["IO_MON_SHIM_OUT_DIR"] = work / "release-lib"
  env["IO_MON_SHIM_NIMCACHE_DIR"] = work / "release-nimcache"
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"], env)
  checkpoint(built.output)
  check built.code == 0
  result = work / "release-lib" / "librepro_monitor_shim.so"
  check fileExists(result)

proc parseHighWater(output: string): int =
  ## `used` from the probe's `hw used=<bytes> io=<n>` line, or -1.
  result = -1
  for line in output.splitLines():
    let s = line.strip()
    if s.startsWith("hw used="):
      return parseInt(s["hw used=".len ..< s.find(' ', "hw used=".len)])

const transports = [("shm set transport", false), ("file transport", true)]

proc monitoredEnv(shimLib: string; fileFallback: bool): StringTableRef =
  result = baseEnv()
  result["REPRO_MONITOR_SHIM_LIB"] = shimLib
  if fileFallback:
    result["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"

suite "io-mon shim static TLS vs small-stack host threads":
  let work = getTempDir() / ("io-mon-static-tls-" & $getCurrentProcessId())
  createDir(work)
  let shims = [("debug", ensureShim()), ("release", ensureReleaseShim(work))]

  test "t_shim_static_tls_within_budget":
    for (mode, shimLib) in shims:
      check shimLib.len > 0
      let memsz = staticTlsMemsz(shimLib)
      checkpoint(mode & " shim PT_TLS memsz = " & $memsz & " bytes (budget " &
        $ShimStaticTlsBudget & "). glibc carves the static TLS of every " &
        "LD_PRELOAD'd library out of EVERY thread's stack and fails " &
        "pthread_create with EINVAL when a requested stack cannot hold it; " &
        "keep per-thread buffers on the heap and only pointers/scalars in " &
        "{.threadvar.} / __thread.")
      check memsz <= ShimStaticTlsBudget

  test "t_small_stack_threads_survive_preload_and_monitoring":
    let snoopBin = ensureSnoop(work)
    let probe = buildC(work, "small_stack_probe", probeSource,
      @["-pthread", "-ldl"])
    let marker = work / "small-stack-marker.txt"
    writeFile(marker, "read by a small-stack thread\n")

    # Baseline: which sizes does THIS host's libc accept with no shim at all,
    # with the worker doing everything it does below? A size the host itself
    # rejects (or cannot run the worker on) says nothing about the shim, so
    # only the accepted ones are graded.
    let bare = run(probe, @["sizes", marker, workerOps] & @candidateSizes,
      baseEnv())
    checkpoint("without shim:\n" & bare.output)
    check bare.code == 0
    let baseline = parseProbe(bare.output)
    check baseline.len == candidateSizes.len
    var accepted: seq[int]
    for size, r in baseline:
      if r.rc == 0 and r.io > 0: accepted.add size
    checkpoint("sizes accepted without the shim: " & $accepted)
    # PTHREAD_STACK_MIN and the 64 KiB of the reported failure must both be
    # usable on this host, or this test grades nothing that matters.
    check accepted.len == candidateSizes.len
    check 65536 in accepted

    proc grade(label, output: string; code: int; withIo: bool) =
      checkpoint(label & " (exit " & $code & "):\n" & output)
      # A thread that overflows its stack inside a hook kills the whole
      # process (SIGSEGV, 139), so the exit status is graded first.
      check code == 0
      let got = parseProbe(output)
      for size in accepted:
        check got.hasKey(size)
        if got.hasKey(size):
          if got[size].rc != 0:
            checkpoint(label & ": pthread_create(stacksize=" & $size &
              ") returned " & $got[size].rc & " (22 = EINVAL); it returned 0 " &
              "without the shim")
          check got[size].rc == 0
          if withIo:
            check got[size].io > 0

    for (mode, shimLib) in shims:
      # (a) Preloaded only — no monitor session, the realistic minimum.
      var preloadEnv = baseEnv()
      preloadEnv["LD_PRELOAD"] = shimLib
      let created = run(probe, @["sizes", "-", "-"] & @candidateSizes,
        preloadEnv)
      grade(mode & ", LD_PRELOAD only, create only", created.output,
        created.code, false)
      let worked = run(probe, @["sizes", marker, workerOps] & @candidateSizes,
        preloadEnv)
      grade(mode & ", LD_PRELOAD only, " & workerOps, worked.output,
        worked.code, true)

      # (b) Under real monitoring, on both transports: first threads that
      # only start and exit (creation is what static TLS breaks), then threads
      # that drive the hooks ON their own small stack. On the file transport
      # the read is the thread's first emit (the slot's lazy allocation and
      # thread-exit release). Every accepted size, PTHREAD_STACK_MIN included.
      for (transport, fileFallback) in transports:
        let label = mode & ", monitored, " & transport
        let env = monitoredEnv(shimLib, fileFallback)
        let tag = mode & "-" & $fileFallback
        let createDep = work / ("small-stack-create-" & tag & ".iomon")
        let c = run(snoopBin, @["run", "--depfile", createDep, "--", probe,
          "sizes", "-", "-"] & @candidateSizes, env)
        grade(label & ", create only", c.output, c.code, false)

        let ioDep = work / ("small-stack-io-" & tag & ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", ioDep, "--", probe,
          "sizes", marker, workerOps] & @candidateSizes, env)
        grade(label & ", " & workerOps, cap.output, cap.code, true)
        if fileExists(ioDep):
          let dep = readMonitorDepFile(ioDep)
          checkpoint(label & ": completeness " & $dep.completeness)
          check dep.completeness == mcComplete
          check dep.records.anyIt(it.kind == mrFileRead and marker in it.path)
        else:
          checkpoint(label & ": no depfile written")
          check fileExists(ioDep)

  test "t_hooked_calls_stay_within_stack_budget":
    # The cause of the small-stack faults, graded directly: run the worker
    # once on a canary-filled 1 MiB stack and compare the deepest byte it
    # touched with and without the shim. A hook frame that grows by a few KiB
    # fails here with a number long before some thread size somewhere starts
    # faulting.
    let snoopBin = ensureSnoop(work)
    let probe = buildC(work, "high_water_probe", probeSource,
      @["-pthread", "-ldl"])
    let marker = work / "high-water-marker.txt"
    writeFile(marker, "read on a canary stack\n")
    let bare = run(probe, @["hw", marker, workerOps], baseEnv())
    checkpoint("without shim: " & bare.output)
    check bare.code == 0
    let bareUsed = parseHighWater(bare.output)
    check bareUsed > 0
    for (mode, shimLib) in shims:
      for (transport, fileFallback) in transports:
        let label = mode & ", monitored, " & transport
        let depfile = work / ("high-water-" & mode & "-" & $fileFallback &
          ".iomon")
        let cap = run(snoopBin, @["run", "--depfile", depfile, "--", probe,
          "hw", marker, workerOps], monitoredEnv(shimLib, fileFallback))
        check cap.code == 0
        let used = parseHighWater(cap.output)
        checkpoint(label & ": stack high-water " & $used & " bytes vs " &
          $bareUsed & " without the shim (+" & $(used - bareUsed) &
          ", budget +" & $HookStackBudget & ")")
        check used > 0
        check used - bareUsed <= HookStackBudget

  test "t_node_starts_under_preload_and_monitoring":
    # The reported symptom itself, on the real runtime: Node 24 sizes some of
    # its own threads explicitly and printed `pthread_create: Invalid
    # argument` under the shim. `nodejs` is a declared package of io-mon's dev
    # shell (flake.nix), so its absence fails here rather than skipping.
    let shimLib = shims[1][1]   # the release build, the one that ships
    let snoopBin = ensureSnoop(work)
    let node = findExe("node")
    checkpoint("node: " & node)
    check node.len > 0
    const okMarker = "io-mon-node-started"
    let script = "console.log('" & okMarker & "')"

    var preloadEnv = baseEnv()
    preloadEnv["LD_PRELOAD"] = shimLib
    let preloaded = run(node, @["-e", script], preloadEnv)
    checkpoint("node, LD_PRELOAD only:\n" & preloaded.output)
    check preloaded.code == 0
    check okMarker in preloaded.output
    check "pthread_create" notin preloaded.output

    var env = baseEnv()
    env["REPRO_MONITOR_SHIM_LIB"] = shimLib
    let depfile = work / "node.iomon"
    let cap = run(snoopBin, @["run", "--depfile", depfile, "--", node, "-e",
      script], env)
    checkpoint("node, monitored:\n" & cap.output)
    check cap.code == 0
    check okMarker in cap.output
    check "pthread_create" notin cap.output

  removeDir(work)
