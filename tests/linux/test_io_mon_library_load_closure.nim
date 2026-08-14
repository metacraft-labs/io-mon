## Linux: the monitored process's runtime shared-library closure must actually
## be observed, and where it cannot be observed the capture must say so.
##
## THE DEFECT THIS PINS. `ld.so` maps a shared object through its own internal
## `__mmap`/`__open64_nocancel`, which do not traverse `LD_PRELOAD` symbol
## interposition, so none of the shim's file hooks ever fired for a
## loader-driven load. Measured before the fix: a monitored `gcc -c` loads ten
## shared objects and the depfile contained ZERO of them while reporting
## `completeness=mcComplete`. Every one of those libraries is a real content
## dependency — upgrade `libisl.so.19` in place and the compiler's behaviour can
## change — so a consumer caching on that set serves stale results and has no
## way to know.
##
## The fix observes the loader's link map (`dl_iterate_phdr`) instead of hooking
## the calls that populate it, mirroring the macOS arm's
## `_dyld_register_func_for_add_image`, and PROVES the enumeration was complete
## using the loader's own `dlpi_adds` counter. The tests below are organised
## around that claim: first the ground-truth comparison, then one test per case
## where coverage is awkward — each of which must end in either an observation
## or an honest downgrade, never a silent `mcComplete`.
##
## NO MOCKS. Real `cc`-built shared objects, the real shim, the real `io-mon
## run` driver, the real loader, and `strace -f` as an INDEPENDENT monitor for
## the ground truth. The ground truth is measured in the same test run rather
## than hard-coded, so the assertions state the invariant instead of a snapshot
## of one machine.

import std/[algorithm, os, osproc, sequtils, sets, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"

proc run(cmd: string; args: seq[string]; env: StringTableRef = nil;
         workDir = ""): tuple[output: string; code: int] =
  let p = startProcess(cmd, args = args, env = env, workingDir = workDir,
    options = {poStdErrToStdOut, poUsePath})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (output, code)

proc canonical(path: string): string =
  try: expandFilename(path)
  except OSError, IOError: path

proc straceOpenedLibraries(argv: seq[string]; logPath, workDir: string):
    HashSet[string] =
  ## The INDEPENDENT ground truth: every `.so` an `openat`/`open` returned a
  ## valid descriptor for, according to `strace -f`. A different monitor,
  ## implemented at a different layer (ptrace, not symbol interposition), which
  ## is what makes it evidence rather than a restatement of io-mon's own view.
  discard run("strace",
    @["-f", "-e", "trace=openat,open", "-o", logPath] & argv, workDir = workDir)
  result = initHashSet[string]()
  if not fileExists(logPath): return
  for line in readFile(logPath).splitLines():
    # `openat(AT_FDCWD, "/path/lib.so", O_RDONLY|O_CLOEXEC) = 3`
    let eq = line.rfind('=')
    if eq < 0: continue
    let status = line[eq + 1 .. ^1].strip()
    if status.len == 0 or status[0] == '-': continue    # failed probe
    let q1 = line.find('"')
    if q1 < 0: continue
    let q2 = line.find('"', q1 + 1)
    if q2 < 0: continue
    let path = line[q1 + 1 ..< q2]
    if ".so" in path and fileExists(path):
      result.incl canonical(path)

proc libraryLoads(dep: MonitorDepFile): HashSet[string] =
  for r in dep.records:
    if r.kind == mrLibraryLoad and r.path.len > 0:
      result.incl canonical(r.path)

proc describe(name: string; s: HashSet[string]): string =
  name & " (" & $s.len & "): " & toSeq(s.items).sorted.join("\n      ")

suite "io-mon Linux runtime library closure":
  let work = getTempDir() / ("io-mon-libload-" & $getCurrentProcessId())
  removeDir(work)
  createDir(work)

  let cc = getEnv("CC", "cc")
  let shimBuild = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(shimBuild.output)
  require shimBuild.code == 0
  let shimLib = findShimLibrary()

  let snoopBin = work / "io-mon"
  let cli = run("nim", @[
    "c", "--hints:off", "--warnings:off", "--threads:on",
    "--path:" & (repoRoot / "src"), "--path:" & hooksSrc,
    "--out:" & snoopBin, snoopSrc])
  checkpoint(cli.output)
  require cli.code == 0

  proc childEnvWith(extra: openArray[(string, string)] = []): StringTableRef =
    result = newStringTable(modeCaseSensitive)
    for k, v in envPairs(): result[k] = v
    result["REPRO_MONITOR_SHIM_LIB"] = shimLib
    for (k, v) in extra: result[k] = v

  proc captureRun(argv: seq[string]; depfile: string;
                  extraEnv: openArray[(string, string)] = [];
                  workDir = ""): tuple[dep: MonitorDepFile; code: int;
                                       output: string] =
    let res = run(snoopBin, @["run", "--depfile", depfile, "--"] & argv,
      childEnvWith(extraEnv), workDir)
    require fileExists(depfile)
    (readMonitorDepFile(depfile), res.code, res.output)

  # A plugin and a program that loads it various ways.
  proc buildLib(name: string; answer: int): string =
    result = work / ("lib" & name & ".so")
    let src = work / (name & ".c")
    writeFile(src,
      "int " & name & "_answer(void) { return " & $answer & "; }\n")
    let built = run(cc, @["-shared", "-fPIC", src, "-o", result])
    checkpoint(built.output)
    require built.code == 0

  test "a monitored compile observes its whole loader closure (vs strace)":
    createDir(work / "include")
    writeFile(work / "include" / "deep.h", "#define DEEP 17\n")
    writeFile(work / "unit.c",
      "#include <stdio.h>\n#include \"deep.h\"\n" &
      "int main(void){ printf(\"%d\\n\", DEEP); return 0; }\n")
    let compileArgs = @[cc, "-I", work / "include", "-c", work / "unit.c",
                        "-o", work / "unit.o"]

    let truth = straceOpenedLibraries(compileArgs, work / "gcc.strace", work)
    checkpoint(describe("strace ground truth", truth))
    # Without this the whole test could pass vacuously on a toolchain that
    # loads nothing.
    require truth.len >= 3

    let cap = captureRun(compileArgs, work / "gcc.rdep", workDir = work)
    require cap.code == 0
    let observed = libraryLoads(cap.dep)
    checkpoint(describe("io-mon library-load records", observed))

    # THE SET RELATION, stated as a relation and not a count: everything the
    # independent monitor saw the process load must be in what io-mon observed.
    let missed = truth - observed
    if missed.len > 0:
      checkpoint(describe("NOT observed by io-mon", missed))
    check missed.len == 0
    check truth <= observed

    # The other direction is deliberately NOT an equality. io-mon's own shim is
    # in the process, so its DT_NEEDED libraries are loaded too and appear in
    # the capture but not in the unmonitored strace. That is over-capture — the
    # safe direction — but it is recorded here so the asymmetry is a stated
    # property rather than an unexamined difference.
    let extra = observed - truth
    checkpoint(describe("observed but not in strace (monitor-induced)", extra))

    # And the capture is still honest about itself.
    check cap.dep.completeness == mcComplete

  test "the pre-fix defect specifically: .so paths are present at all":
    # A blunt, hard-to-game restatement. Before the fix this set was EMPTY while
    # completeness read mcComplete; any assertion that can pass on an empty set
    # is not pinning the defect.
    let dep = readMonitorDepFile(work / "gcc.rdep")
    let observed = libraryLoads(dep)
    check observed.len > 0
    check observed.anyIt(it.endsWith(".so") or ".so." in it)

  test "AWKWARD CASE: an object loaded BEFORE the shim initialised is observed":
    # The strongest form of "before us": a DT_NEEDED of the main executable, so
    # the loader maps it as part of the initial closure — before any ELF
    # constructor runs at all, therefore before the shim's.
    #
    # This is the case an event hook structurally cannot cover, and the reason
    # the design enumerates loader STATE rather than subscribing to load
    # EVENTS: there is no point early enough to install a hook that would have
    # seen this.
    let plug = buildLib("early", 42)
    let app = work / "early_app"
    writeFile(work / "early_app.c",
      "int early_answer(void);\n#include <stdio.h>\n" &
      "int main(void){ printf(\"%d\\n\", early_answer()); return 0; }\n")
    let built = run(cc, @[work / "early_app.c", "-o", app, plug,
                          "-Wl,-rpath," & work])
    checkpoint(built.output)
    require built.code == 0

    let cap = captureRun(@[app], work / "early.rdep")
    checkpoint(cap.output)
    require cap.code == 0
    let observed = libraryLoads(cap.dep)
    checkpoint(describe("observed", observed))
    check canonical(plug) in observed
    check cap.dep.completeness == mcComplete

  test "the startup closure is published BEFORE the program can use it":
    # WHY THIS TEST EXISTS: without it, deleting the startup scan entirely
    # changes NOTHING that the rest of this file can detect. The shutdown scan
    # enumerates the same link map, and for a process that exits cleanly nothing
    # has been unloaded, so every startup library is still recorded — the two
    # scans are redundant on the happy path. (Verified by mutation: removing
    # `scanLoadedLibraries("startup-closure")` left all seven other tests green.)
    #
    # The startup scan earns its place on the UNHAPPY path, and it is the same
    # LF-7 publish-before-return discipline the read hooks follow: the process
    # can act on a library's bytes from its first instruction, so the dependency
    # must be in consumer-owned memory before `main` runs — not at exit, which
    # a `SIGKILL` never reaches. A capture that loses the closure of a killed
    # process is a capture that under-reports what that process consumed.
    let plug = buildLib("killed", 5)
    let app = work / "killed_app"
    writeFile(work / "killed_app.c", """
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
int killed_answer(void);
int main(void) {
  /* USE the library, so its bytes have demonstrably been consumed ... */
  printf("%d\n", killed_answer());
  fflush(stdout);
  /* ... and then die in the one way that runs no destructor and no exit hook,
     so the shutdown scan cannot be what saves this. */
  kill(getpid(), SIGKILL);
  return 0;
}
""")
    let built = run(cc, @[work / "killed_app.c", "-o", app, plug,
                          "-Wl,-rpath," & work])
    checkpoint(built.output)
    require built.code == 0

    let cap = captureRun(@[app], work / "killed.rdep")
    checkpoint(cap.output)
    let observed = libraryLoads(cap.dep)
    checkpoint(describe("observed", observed))
    check canonical(plug) in observed

  test "AWKWARD CASE: a dlopen from a worker thread is observed":
    # Concurrent loads from a thread the shim never saw start. The scan is
    # driven by the interposed `dlopen` on whichever thread performed it, and
    # the enumeration is serialised, so the result must not depend on which
    # thread did the loading.
    let a = buildLib("thra", 1)
    let b = buildLib("thrb", 2)
    let app = work / "thread_app"
    writeFile(work / "thread_app.c", """
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
static void *loader(void *arg) {
  void *h = dlopen((const char *)arg, RTLD_NOW);
  if (h == NULL) { fprintf(stderr, "dlopen-failed: %s\n", dlerror()); return (void*)1; }
  return NULL;
}
int main(int argc, char **argv) {
  pthread_t t1, t2;
  void *r1, *r2;
  pthread_create(&t1, NULL, loader, argv[1]);
  pthread_create(&t2, NULL, loader, argv[2]);
  pthread_join(t1, &r1);
  pthread_join(t2, &r2);
  if (r1 != NULL || r2 != NULL) return 1;
  printf("threads ok\n");
  return 0;
}
""")
    let built = run(cc, @[work / "thread_app.c", "-o", app, "-ldl", "-lpthread"])
    checkpoint(built.output)
    require built.code == 0

    let cap = captureRun(@[app, a, b], work / "thread.rdep")
    checkpoint(cap.output)
    require cap.code == 0
    let observed = libraryLoads(cap.dep)
    checkpoint(describe("observed", observed))
    check canonical(a) in observed
    check canonical(b) in observed
    check cap.dep.completeness == mcComplete

  test "AWKWARD CASE: a dlopen'd-then-dlclosed object is still observed":
    # The object is gone by process exit, so an exit-time-only scan would miss
    # it. It is captured because the scan runs at the load, while it is mapped.
    let plug = buildLib("transient", 7)
    let app = work / "transient_app"
    writeFile(work / "transient_app.c", """
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
  void *h = dlopen(argv[1], RTLD_NOW);
  if (h == NULL) { fprintf(stderr, "dlopen-failed: %s\n", dlerror()); return 1; }
  dlclose(h);
  printf("transient ok\n");
  return 0;
}
""")
    let built = run(cc, @[work / "transient_app.c", "-o", app, "-ldl"])
    checkpoint(built.output)
    require built.code == 0

    let cap = captureRun(@[app, plug], work / "transient.rdep")
    checkpoint(cap.output)
    require cap.code == 0
    check canonical(plug) in libraryLoads(cap.dep)

  test "AWKWARD CASE: an UNOBSERVABLE load DOWNGRADES instead of claiming":
    # The case the design cannot observe: a load that never reaches the
    # interposed `dlopen` and is undone before the next scan — what glibc's own
    # internal `__libc_dlopen_mode` does for NSS and gconv modules. It is
    # simulated faithfully here by fetching libc's own `dlopen`/`dlclose` and
    # calling them directly, which is exactly the code path libc takes
    # internally: our wrapper is bypassed, and the object is unmapped again
    # before exit.
    #
    # The claim under test is NOT that this is observed — it is not, and no
    # sampling design can observe it. The claim is that io-mon KNOWS it did not
    # observe it. The loader's own `dlpi_adds` counter says one more load
    # happened than the scans enumerated, and that discrepancy has to become an
    # `mcIncomplete`, because the alternative is a silent gap inside a
    # `mcComplete` — strictly worse than the defect this whole change fixes.
    let plug = buildLib("hidden", 99)
    let app = work / "hidden_app"
    writeFile(work / "hidden_app.c", """
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
  void *(*raw_dlopen)(const char *, int);
  int (*raw_dlclose)(void *);
  void *libc = dlopen(argv[2], RTLD_NOW);   /* observed: goes through the shim */
  void *h;
  if (libc == NULL) { fprintf(stderr, "libc-handle-failed: %s\n", dlerror()); return 2; }
  raw_dlopen = (void *(*)(const char *, int))dlsym(libc, "dlopen");
  raw_dlclose = (int (*)(void *))dlsym(libc, "dlclose");
  if (raw_dlopen == NULL || raw_dlclose == NULL) { fprintf(stderr, "no-raw-dl\n"); return 3; }
  h = raw_dlopen(argv[1], RTLD_NOW);        /* NOT observed: bypasses the shim */
  if (h == NULL) { fprintf(stderr, "raw-dlopen-failed: %s\n", dlerror()); return 4; }
  raw_dlclose(h);                            /* and gone before the exit scan */
  printf("hidden ok\n");
  return 0;
}
""")
    let built = run(cc, @[work / "hidden_app.c", "-o", app, "-ldl"])
    checkpoint(built.output)
    require built.code == 0

    # Find the libc the app itself is linked against, so the handle is real.
    let lddOut = run("bash", @["-c", "ldd " & app & " | grep -o '/[^ ]*libc\\.so[^ ]*' | head -1"])
    let libcPath = lddOut.output.strip()
    checkpoint("libc: " & libcPath)
    require libcPath.len > 0

    let cap = captureRun(@[app, plug, libcPath], work / "hidden.rdep")
    checkpoint(cap.output)
    require cap.code == 0

    # The honest outcome: not observed, and SAID SO.
    check canonical(plug) notin libraryLoads(cap.dep)
    check cap.dep.completeness == mcIncomplete
    let reasons = cap.dep.records
      .filterIt(it.kind == mrEventLoss and "library-load" in it.detail)
    checkpoint("downgrade reasons: " & reasons.mapIt(it.detail).join(" | "))
    # A downgrade with no stated reason is only marginally better than a false
    # complete: the consumer cannot tell a library-coverage gap from a killed
    # process.
    check reasons.len > 0

  test "AWKWARD CASE: a statically-linked binary downgrades (no shim at all)":
    # No `ld.so`, so `LD_PRELOAD` cannot reach it and the shim is never loaded:
    # io-mon observes NOTHING from this process, libraries included. Coverage
    # here is not provided by the library-load machinery at all — it is
    # provided by the root/subtree guard, which sees a spawned process that
    # never reported a process-start. Included because "statically linked" is
    # otherwise exactly the case where a library-load capability could quietly
    # claim completeness over a process it never entered.
    let app = work / "freestanding"
    writeFile(work / "freestanding.c", """
static long sys3(long n, long a, long b, long c) {
  long r;
  __asm__ volatile ("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                    : "rcx", "r11", "memory");
  return r;
}
static const char msg[] = "freestanding ok\n";
void _start(void) {
  sys3(1, 1, (long)msg, sizeof(msg) - 1);
  sys3(60, 0, 0, 0);
  __builtin_unreachable();
}
""")
    let built = run(cc, @["-static", "-nostdlib", "-nostartfiles",
                          "-fno-stack-protector", "-fno-pie", "-no-pie",
                          work / "freestanding.c", "-o", app])
    checkpoint(built.output)
    if built.code != 0:
      skip()
    else:
      let bare = run(app, @[])
      require bare.code == 0
      let cap = captureRun(@[app], work / "static.rdep")
      checkpoint(cap.output)
      check cap.code == 0
      check cap.dep.completeness == mcIncomplete
