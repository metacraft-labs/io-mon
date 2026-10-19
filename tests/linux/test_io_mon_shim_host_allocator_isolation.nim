## test_io_mon_shim_host_allocator_isolation — the preloaded shim must never
## call back into the HOST's allocator while it records an observation
## (Linux).
##
## THE DEFECT. Chromium 143 headless launched in 0.8 s without the shim and
## hung forever with it. PartitionAlloc holds its (non-recursive) lock and
## calls `syscall(SYS_mprotect)`; the shim's raw-syscall hook records the
## call, the Nim record allocates, and that allocation reached Chromium's own
## `__libc_malloc` — PartitionAlloc's allocator shim exports the glibc
## `__libc_*` names
## (base/allocator/partition_allocator/src/partition_alloc/shim/
## allocator_shim_override_glibc.h) — which waited on the lock its own caller
## held. A second thread deadlocked the same way through the `clock_gettime`
## hook. `shim/linux_private_heap.c` existed to prevent exactly this ("rustc's
## allocator calls clock_gettime while holding its own lock"), but it named
## glibc's allocator as `__libc_malloc`, and symbol lookup searches the
## executable first, so a host that exports that name got its own allocator
## back. See glibc's lookup order:
##   https://sourceware.org/glibc/wiki/Linker_Namespaces
##   https://www.akkadia.org/drepper/dsohowto.pdf (§1.5.4 "Lookup Scope")
##
## THE HOST. A small C program, built here, that replaces the WHOLE malloc
## family — `malloc`/`free`/`calloc`/`realloc`, the memalign family,
## `malloc_usable_size` AND the `__libc_*` aliases — with a bump arena behind
## a NON-recursive lock that records its owner. Re-entering that lock on the
## thread that holds it is exactly the Chromium deadlock; instead of hanging,
## the host prints `HOST-ALLOCATOR-REENTERED <who>` and `_exit`s with 97, so
## the failure is immediate and named. While holding the lock, on the main
## thread and on worker threads, it makes the calls the shim hooks:
## `syscall(SYS_mprotect)`, `mprotect`, `mmap`/`munmap`, `clock_gettime`,
## `open`/`read`/`close`.
##
## THE SECOND DEFECT. Resolving glibc's allocator inside libc.so.6 fixed
## Chromium and broke bash. glibc's main arena grows with sbrk, and bash 5.2
## built with its bundled malloc — the stdenv bash behind every nixpkgs
## gcc-wrapper — owns the program break: it grows it with sbrk(n) and gives
## its top block back with sbrk(-n), assuming nobody else moved it. With both
## in one process `gcc --version` died with SIGSEGV in bash's
## internal_malloc. The shim's heap is now its own allocator over mmap, and
## the exec hooks no longer replace the host's `environ` with an array from
## that heap (a host that manages `environ` with its own allocator, as bash
## does, would free or realloc it). See `shim/linux_private_heap.c`.
##
## THE SECOND HOST. A C program whose allocator, like bash's, IS the program
## break, and which checks what bash does not: before every sbrk it verifies
## the break is where it left it (`HOST-BREAK-MOVED`, exit 98), and it refuses
## to free or realloc a pointer it did not allocate (`HOST-FOREIGN-FREE`,
## exit 99). It interleaves its own allocations with hooked calls, frees
## what scandir and realpath(NULL) hand it, installs its own `environ`, and
## in a forked child lets an execvp PATH search fail, reallocs `environ`
## (bash's pattern), then execs a monitored child that reads a marker.
##
## WHAT THIS TEST GRADES — on a debug and a release shim:
##   1. `t_private_heap_is_the_shims_own` — the entry point the shim's private
##      heap allocates through lives in the shim itself (`dladdr` from inside
##      the host): neither the executable's allocator nor glibc's.
##   2. `t_break_owning_host_keeps_its_break_and_its_pointers` — the second
##      host completes without either detector firing, preloaded and under
##      `io-mon run` on both transports; the depfiles are `mcComplete` and
##      contain the child's marker read.
##   3. `t_host_allocator_lock_never_reentered` — the host completes, without
##      re-entering its allocator, preloaded and under `io-mon run` on both
##      transports; the monitored depfiles are `mcComplete` and contain the
##      marker read every thread made while holding the lock.
##   4. `t_every_real_function_slot_is_primed` — every lazily resolved libc
##      entry point the hooks forward to is resolved by the constructor, so no
##      hook calls dlsym (which frees and allocates through the host's
##      allocator) on the host's time.
## A bounded `timeout` turns any hang the re-entry detector cannot see (a
## different lock, a different thread) into a failure rather than a stuck
## suite.
##
## Mocks: the hosts' allocators are deliberately minimal stand-ins for
## PartitionAlloc/tcmalloc/jemalloc-style replacements and for bash's bundled
## malloc. They are justified: the
## property under test is "the shim never calls the executable's allocator
## from hook context", and only an allocator the test controls can detect a
## re-entry and fail loudly instead of deadlocking. Everything else — the shim,
## the `io-mon run` CLI, the transports, the kernel — is real. The real
## Chromium launch is checked by hand (see the change that added this test):
## adding Chromium to the dev shell would put a several-hundred-MB closure in
## every contributor's shell.

import std/[os, osproc, sequtils, streams, strtabs, strutils, unittest]

import io_mon

const
  repoRoot = currentSourcePath().parentDir().parentDir().parentDir()
  hooksSrc = repoRoot.parentDir() / "nim-stackable-hooks" / "src"
  snoopSrc = repoRoot / "cmd" / "io_mon_snoop.nim"
  HostTimeoutSeconds = "120"
    ## A healthy run takes well under a second; a hang means a deadlock the
    ## re-entry detector could not see.

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

proc baseEnv(): StringTableRef =
  result = newStringTable(modeCaseSensitive)
  for k, v in envPairs(): result[k] = v
  result.del("LD_PRELOAD")

proc ensureShim(): string =
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"])
  checkpoint(built.output)
  check built.code == 0
  findShimLibrary()

proc ensureReleaseShim(work: string): string =
  ## The shipped shim is a `-d:release` build; the suite's default is debug.
  var env = baseEnv()
  env["IO_MON_BUILD_MODE"] = "release"
  env["IO_MON_SHIM_OUT_DIR"] = work / "release-lib"
  env["IO_MON_SHIM_NIMCACHE_DIR"] = work / "release-nimcache"
  let built = run("bash", @[repoRoot / "scripts" / "build_shim.sh"], env)
  checkpoint(built.output)
  check built.code == 0
  result = work / "release-lib" / "librepro_monitor_shim.so"
  check fileExists(result)

const hostSource = """
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* ---- the host allocator: a bump arena behind a non-recursive lock ------ */

#define ARENA_BYTES (512UL << 20)
static unsigned char *arena;
static size_t arena_used;
static volatile long lock_owner;      /* tid holding the lock, 0 when free */
static const char *lock_holder_what;  /* what the holder is doing */

static long tid(void) { return syscall(SYS_gettid); }

/* Inline-asm syscalls: the detector must not itself enter the shim's hooks
 * (the shim interposes write() and syscall()). */
static long raw3(long nr, long a, long b, long c) {
#if defined(__x86_64__)
  long ret;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return ret;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a;
  register long x1 __asm__("x1") = b;
  register long x2 __asm__("x2") = c;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
  return x0;
#else
#error "unsupported architecture"
#endif
}

static void say(const char *s) { raw3(SYS_write, 2, (long)s, (long)strlen(s)); }

static void lock_enter(const char *what) {
  long self = tid();
  if (__atomic_load_n(&lock_owner, __ATOMIC_ACQUIRE) == self) {
    /* PartitionAlloc would futex-wait here forever. */
    say("HOST-ALLOCATOR-REENTERED by=");
    say(what);
    say(" while=");
    say(lock_holder_what != NULL ? lock_holder_what : "?");
    say("\n");
    raw3(SYS_exit_group, 97, 0, 0);
  }
  long expected = 0;
  while (!__atomic_compare_exchange_n(&lock_owner, &expected, self, 0,
                                      __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
    expected = 0;
    sched_yield();
  }
  lock_holder_what = what;
}

static void lock_leave(void) {
  lock_holder_what = NULL;
  __atomic_store_n(&lock_owner, 0, __ATOMIC_RELEASE);
}

typedef struct { size_t size; size_t pad; } hdr;

static void *bump(size_t size, size_t align, const char *what) {
  lock_enter(what);
  if (arena == NULL) {
    /* Raw syscall: the arena itself must not depend on anything. */
    long p = syscall(SYS_mmap, 0, ARENA_BYTES, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == -1) { lock_leave(); return NULL; }
    arena = (unsigned char *)p;
  }
  if (align < 16) align = 16;
  uintptr_t base = (uintptr_t)arena + arena_used + sizeof(hdr);
  uintptr_t user = (base + align - 1) & ~(uintptr_t)(align - 1);
  size_t end = (size_t)(user - (uintptr_t)arena) + size;
  if (end > ARENA_BYTES) { lock_leave(); errno = ENOMEM; return NULL; }
  ((hdr *)(user - sizeof(hdr)))->size = size;
  arena_used = end;
  lock_leave();
  return (void *)user;
}

static size_t usable(void *p) { return p ? ((hdr *)p - 1)->size : 0; }

void *malloc(size_t n) { return bump(n, 16, "malloc"); }
void free(void *p) {
  if (p == NULL) return;          /* like every real allocator: no lock */
  lock_enter("free");
  lock_leave();
}
void *calloc(size_t a, size_t b) {
  size_t n = a * b;
  if (b != 0 && n / b != a) { errno = ENOMEM; return NULL; }
  void *p = bump(n, 16, "calloc");
  if (p) memset(p, 0, n);
  return p;
}
void *realloc(void *old, size_t n) {
  void *p = bump(n, 16, "realloc");
  if (p && old) memcpy(p, old, usable(old) < n ? usable(old) : n);
  return p;
}
void *memalign(size_t al, size_t n) { return bump(n, al, "memalign"); }
void *aligned_alloc(size_t al, size_t n) { return bump(n, al, "aligned_alloc"); }
int posix_memalign(void **out, size_t al, size_t n) {
  void *p = bump(n, al, "posix_memalign");
  if (!p) return ENOMEM;
  *out = p;
  return 0;
}
void *valloc(size_t n) { return bump(n, 4096, "valloc"); }
void *pvalloc(size_t n) { return bump((n + 4095) & ~4095UL, 4096, "pvalloc"); }
size_t malloc_usable_size(void *p) { return usable(p); }
/* What PartitionAlloc's allocator_shim_override_glibc.h also exports. */
void *__libc_malloc(size_t n) { return bump(n, 16, "__libc_malloc"); }
void __libc_free(void *p) { free(p); }
void *__libc_calloc(size_t a, size_t b) { return calloc(a, b); }
void *__libc_realloc(void *p, size_t n) { return realloc(p, n); }
void *__libc_memalign(size_t al, size_t n) { return memalign(al, n); }

/* ---- the workload: hooked calls made WHILE holding the allocator lock -- */

static const char *g_marker;

static long hooked_calls_under_lock(const char *who) {
  long got = -1;
  char buf[64];
  struct timespec ts;
  lock_enter(who);
  long page = syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page != -1) {
    syscall(SYS_mprotect, page, 4096, PROT_READ);            /* PartitionAlloc */
    mprotect((void *)page, 4096, PROT_READ | PROT_WRITE);
    syscall(SYS_munmap, page, 4096);
  }
  void *m = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (m != MAP_FAILED) munmap(m, 8192);
  clock_gettime(CLOCK_MONOTONIC, &ts);                       /* ThreadPool */
  clock_gettime(CLOCK_REALTIME, &ts);
  int fd = open(g_marker, O_RDONLY);
  if (fd >= 0) {
    got = (long)read(fd, buf, sizeof(buf));
    close(fd);
  }
  lock_leave();
  return got;
}

static void *worker(void *arg) {
  *(long *)arg = hooked_calls_under_lock("worker-hooked-calls");
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  g_marker = argv[1];
  /* Report whether the shim is in this process and where its private heap
   * allocates from. Outside the lock: dladdr may allocate. */
  int shim_loaded = dlsym(RTLD_DEFAULT, "repro_monitor_shim_init") != NULL;
  void *(*entry)(void) =
      (void *(*)(void))dlsym(RTLD_DEFAULT, "repro_linux_private_heap_malloc_entry");
  const char *heap = "missing";
  Dl_info info;
  if (entry != NULL) {
    void *fn = entry();
    heap = fn == NULL ? "none" :
           (dladdr(fn, &info) && info.dli_fname ? info.dli_fname : "unknown");
  }
  printf("host shim-loaded=%d private-heap=%s\n", shim_loaded, heap);
  fflush(stdout);

  long reads = 0;
  if (hooked_calls_under_lock("main-hooked-calls") > 0) reads++;
  enum { WORKERS = 4 };
  pthread_t th[WORKERS];
  long got[WORKERS];
  for (int i = 0; i < WORKERS; i++)
    if (pthread_create(&th[i], NULL, worker, &got[i]) != 0) return 3;
  for (int i = 0; i < WORKERS; i++) {
    pthread_join(th[i], NULL);
    if (got[i] > 0) reads++;
  }
  printf("host done reads=%ld of %d\n", reads, WORKERS + 1);
  return reads == WORKERS + 1 ? 0 : 4;
}
"""

const breakHostSource = """
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* A host allocator in the style of bash 5.2's bundled malloc
 * (lib/malloc/malloc.c), which the nixpkgs stdenv bash behind every
 * gcc-wrapper uses: the program break IS its heap. It grows it with sbrk(n)
 * and, when the block at the top of what it last allocated is freed, gives it
 * back with sbrk(-n) ("lesscore") -- assuming nobody else moved the break.
 * bash does not check; this host does, so the class fails by name instead of
 * as a SIGSEGV somewhere later:
 *   HOST-BREAK-MOVED  someone else (the shim) grew or shrank the break;
 *   HOST-FOREIGN-FREE the host was handed memory its allocator never made
 *                     (e.g. an `environ` array from the shim's heap) and
 *                     freed or realloc'd it. */
static long raw3(long nr, long a, long b, long c) {
#if defined(__x86_64__)
  long ret;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return ret;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a;
  register long x1 __asm__("x1") = b;
  register long x2 __asm__("x2") = c;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
  return x0;
#endif
}
static void die(const char *what, const char *where, int code) {
  raw3(SYS_write, 2, (long)what, (long)strlen(what));
  raw3(SYS_write, 2, (long)where, (long)strlen(where));
  raw3(SYS_write, 2, (long)"\n", 1);
  raw3(SYS_exit_group, code, 0, 0);
}

#define MAGIC 0x6261736862726b20ULL   /* low bit clear: it carries ALIGNED */
#define ALIGNED 0x1ULL
typedef struct { uint64_t magic; uint64_t size; } hdr;   /* 16 bytes */
static char *memtop;     /* where THIS allocator last left the break */

static void check_break(const char *where) {
  if (memtop != NULL && (char *)sbrk(0) != memtop)
    die("HOST-BREAK-MOVED by someone else before ", where, 98);
}
static size_t block_bytes(size_t n) { return (sizeof(hdr) + n + 15) & ~(size_t)15; }

void *malloc(size_t n) {
  check_break("malloc");
  size_t total = block_bytes(n);
  char *p = sbrk((intptr_t)total);
  if (p == (char *)-1) return NULL;
  memtop = p + total;
  hdr *h = (hdr *)p;
  h->magic = MAGIC;
  h->size = n;
  return h + 1;
}
static hdr *header_of(void *ptr, const char *who) {
  hdr *h = (hdr *)ptr - 1;
  if ((h->magic & ~ALIGNED) != MAGIC)
    die("HOST-FOREIGN-FREE in ", who, 99);
  return h;
}
void free(void *ptr) {
  if (ptr == NULL) return;
  hdr *h = header_of(ptr, "free");
  int aligned = (h->magic & ALIGNED) != 0;
  size_t total = block_bytes(h->size);
  h->magic = 0;
  if (!aligned && (char *)h + total == memtop) {   /* bash's lesscore */
    check_break("free (giving the top back)");
    sbrk(-(intptr_t)total);
    memtop = (char *)h;
  }
}
void *calloc(size_t a, size_t b) {
  if (b != 0 && a > SIZE_MAX / b) return NULL;
  void *p = malloc(a * b);
  if (p) memset(p, 0, a * b);
  return p;
}
void *realloc(void *old, size_t n) {
  if (old == NULL) return malloc(n);
  hdr *h = header_of(old, "realloc");
  void *p = malloc(n);
  if (p) memcpy(p, old, h->size < n ? h->size : n);
  free(old);
  return p;
}
static void *aligned_block(size_t align, size_t n) {
  if (align < 16) align = 16;
  check_break("memalign");
  size_t total = sizeof(hdr) + n + align;
  char *p = sbrk((intptr_t)total);
  if (p == (char *)-1) return NULL;
  memtop = p + total;
  uintptr_t user = ((uintptr_t)p + sizeof(hdr) + align - 1) & ~(uintptr_t)(align - 1);
  hdr *h = (hdr *)user - 1;
  h->magic = MAGIC | ALIGNED;
  h->size = n;
  return (void *)user;
}
void *memalign(size_t al, size_t n) { return aligned_block(al, n); }
void *aligned_alloc(size_t al, size_t n) { return aligned_block(al, n); }
int posix_memalign(void **out, size_t al, size_t n) {
  void *p = aligned_block(al, n);
  if (!p) return 12;
  *out = p;
  return 0;
}
void *valloc(size_t n) { return aligned_block(4096, n); }
void *pvalloc(size_t n) { return aligned_block(4096, (n + 4095) & ~(size_t)4095); }
size_t malloc_usable_size(void *p) { return p ? ((hdr *)p - 1)->size : 0; }

extern char **environ;

static long read_marker(const char *path) {
  char buf[64];
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -1;
  long n = read(fd, buf, sizeof(buf));
  close(fd);
  return n;
}

int main(int argc, char **argv) {
  if (argc >= 3 && strcmp(argv[1], "child") == 0)
    return read_marker(argv[2]) > 0 ? 0 : 20;
  if (argc < 3) return 2;
  const char *marker = argv[1], *dir = argv[2];
  struct stat st;

  /* Interleave the host's own allocations with hooked calls the shim
   * records, freeing at the top so the lesscore path runs. */
  for (int i = 0; i < 300; ++i) {
    char *p = malloc((size_t)(i * 37) % 3000 + 1);
    if (p == NULL) return 3;
    p[0] = 1;
    if (read_marker(marker) <= 0) return 4;
    if (stat(dir, &st) != 0) return 5;
    free(p);
  }

  /* Memory the hooked libc APIs hand back is the host's to free. */
  struct dirent **list;
  int n = scandir(dir, &list, NULL, alphasort);
  if (n < 0) return 6;
  for (int i = 0; i < n; ++i) free(list[i]);
  free(list);
  char *rp = realpath(marker, NULL);
  if (rp == NULL) return 7;
  free(rp);
  DIR *d = opendir(dir);
  if (d == NULL || readdir(d) == NULL) return 8;
  closedir(d);

  /* bash's way with environ: its own array from its own malloc. */
  char **original_environ = environ;
  size_t count = 0;
  while (environ[count] != NULL) count++;
  char **own = malloc((count + 2) * sizeof(char *));
  if (own == NULL) return 9;
  memcpy(own, environ, count * sizeof(char *));
  own[count] = "HOST_OWNED_ENVIRON=1";
  own[count + 1] = NULL;
  environ = own;

  pid_t pid = fork();
  if (pid < 0) return 10;
  if (pid == 0) {
    /* A PATH search that fails leaves this process running with whatever
     * the exec path did to environ; the host then manages it again. */
    char *none[] = {"io-mon-no-such-program", NULL};
    execvp(none[0], none);
    char **grown = realloc(environ, (count + 3) * sizeof(char *));
    if (grown == NULL) _exit(11);
    environ = grown;
    char *again[] = {argv[0], "child", (char *)marker, NULL};
    execvp(argv[0], again);
    _exit(12);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return 13;
  if (!WIFEXITED(status)) return 14;
  if (WEXITSTATUS(status) != 0) return 100 + WEXITSTATUS(status);
  environ = original_environ;   /* never leave environ dangling */
  free(own);
  printf("host done\n");
  return 0;
}
"""

proc shimBasename(path: string): bool =
  path.extractFilename == "librepro_monitor_shim.so"

proc hostLine(output, key: string): string =
  for line in output.splitLines():
    if line.startsWith("host ") and key in line:
      return line
  ""

proc privateHeap(output: string): string =
  let line = hostLine(output, "private-heap=")
  let at = line.find("private-heap=")
  if at < 0: "" else: line[at + "private-heap=".len .. ^1].strip()

suite "io-mon shim never re-enters the host's allocator":
  let work = getTempDir() / ("io-mon-host-alloc-" & $getCurrentProcessId())
  createDir(work)
  let shims = [("debug", ensureShim()), ("release", ensureReleaseShim(work))]
  let host = buildC(work, "allocator_host", hostSource,
    @["-O1", "-pthread", "-rdynamic", "-ldl"])
  let marker = work / "host-alloc-marker.txt"
  writeFile(marker, "read while the host allocator lock is held\n")

  proc runHost(args: seq[string]; env: StringTableRef):
      tuple[output: string; code: int] =
    run("timeout", @["-s", "KILL", HostTimeoutSeconds] & args, env)

  test "t_host_runs_without_shim":
    # Control: the host itself is sound — no re-entry, every read succeeds.
    let bare = runHost(@[host, marker], baseEnv())
    checkpoint("without shim (exit " & $bare.code & "):\n" & bare.output)
    check bare.code == 0
    check "host shim-loaded=0" in bare.output
    check "host done reads=5 of 5" in bare.output

  test "t_private_heap_is_the_shims_own":
    for (mode, shimLib) in shims:
      var env = baseEnv()
      env["LD_PRELOAD"] = shimLib
      let r = runHost(@[host, marker], env)
      checkpoint(mode & ", LD_PRELOAD (exit " & $r.code & "):\n" & r.output)
      check "host shim-loaded=1" in r.output
      let heap = privateHeap(r.output)
      checkpoint(mode & ": the shim's private heap allocates through " & heap &
        "; it must be the shim's own allocator — neither the executable's, " &
        "which exports the same names, nor glibc's, whose main arena shares " &
        "the program break with sbrk-based host allocators")
      check shimBasename(heap)

  test "t_break_owning_host_keeps_its_break_and_its_pointers":
    # The bash class: a host whose allocator owns the program break and
    # frees what the hooked libc APIs (and `environ`) hand it. The shim must
    # neither move the break nor give the host memory from its own heap.
    let snoopBin = ensureSnoop(work)
    let breakHost = buildC(work, "break_host", breakHostSource, @["-O1"])
    let dir = work / "break-host-dir"
    createDir(dir)
    writeFile(dir / "a.txt", "a")
    writeFile(dir / "b.txt", "b")
    let bare = runHost(@[breakHost, marker, dir], baseEnv())
    checkpoint("without shim (exit " & $bare.code & "):\n" & bare.output)
    check bare.code == 0
    check "host done" in bare.output
    for (mode, shimLib) in shims:
      var preloadEnv = baseEnv()
      preloadEnv["LD_PRELOAD"] = shimLib
      let pre = runHost(@[breakHost, marker, dir], preloadEnv)
      checkpoint(mode & ", LD_PRELOAD only (exit " & $pre.code & "):\n" &
        pre.output)
      check "HOST-BREAK-MOVED" notin pre.output
      check "HOST-FOREIGN-FREE" notin pre.output
      check pre.code == 0
      for (transport, fileFallback) in [("shm set transport", false),
                                        ("file transport", true)]:
        let label = mode & ", monitored, " & transport
        var env = baseEnv()
        env["REPRO_MONITOR_SHIM_LIB"] = shimLib
        if fileFallback:
          env["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"
        let depfile = work / ("break-host-" & mode & "-" & $fileFallback &
          ".iomon")
        let cap = runHost(@[snoopBin, "run", "--depfile", depfile, "--",
          breakHost, marker, dir], env)
        checkpoint(label & " (exit " & $cap.code & "):\n" & cap.output)
        check "HOST-BREAK-MOVED" notin cap.output
        check "HOST-FOREIGN-FREE" notin cap.output
        check cap.code == 0
        check "host done" in cap.output
        if fileExists(depfile):
          let dep = readMonitorDepFile(depfile)
          checkpoint(label & ": completeness " & $dep.completeness & "; " &
            $dep.records.filterIt(it.kind == mrEventLoss).mapIt(it.detail))
          check dep.completeness == mcComplete
          check dep.records.anyIt(it.kind == mrFileRead and marker in it.path)
        else:
          check fileExists(depfile)

  test "t_host_allocator_lock_never_reentered":
    let snoopBin = ensureSnoop(work)
    for (mode, shimLib) in shims:
      var preloadEnv = baseEnv()
      preloadEnv["LD_PRELOAD"] = shimLib
      let pre = runHost(@[host, marker], preloadEnv)
      checkpoint(mode & ", LD_PRELOAD only (exit " & $pre.code & "):\n" &
        pre.output)
      check "HOST-ALLOCATOR-REENTERED" notin pre.output
      check pre.code == 0
      check "host done reads=5 of 5" in pre.output

      for (transport, fileFallback) in [("shm set transport", false),
                                        ("file transport", true)]:
        let label = mode & ", monitored, " & transport
        var env = baseEnv()
        env["REPRO_MONITOR_SHIM_LIB"] = shimLib
        if fileFallback:
          env["REPRO_MONITOR_DEP_SHM_DISABLE"] = "1"
        let depfile = work / ("host-alloc-" & mode & "-" & $fileFallback &
          ".iomon")
        let cap = runHost(@[snoopBin, "run", "--depfile", depfile, "--",
          host, marker], env)
        checkpoint(label & " (exit " & $cap.code & "):\n" & cap.output)
        check "HOST-ALLOCATOR-REENTERED" notin cap.output
        check cap.code == 0
        check "host shim-loaded=1" in cap.output
        check "host done reads=5 of 5" in cap.output
        if fileExists(depfile):
          let dep = readMonitorDepFile(depfile)
          checkpoint(label & ": completeness " & $dep.completeness)
          check dep.completeness == mcComplete
          check dep.records.anyIt(it.kind == mrFileRead and marker in it.path)
        else:
          check fileExists(depfile)

  test "t_every_real_function_slot_is_primed":
    # The hooks forward to libc through `real_*_ptr` slots that are filled by
    # dlsym on first use unless the constructor primes them, and dlsym frees
    # and allocates through the host's allocator (see
    # `ct_linux_preload_prime_real_functions`). A slot added without a priming
    # line would reopen the deadlock only for hosts whose first call of that
    # function happens under their allocator lock — rare enough that no
    # behavioural test would notice — so the list is checked against the
    # declarations here.
    let runtime = readFile(repoRoot / "src" / "io_mon" / "hooks" /
      "linux_preload_runtime.nim")
    let primeAt = runtime.find("void ct_linux_preload_prime_real_functions(void) {")
    check primeAt >= 0
    let primeEnd = runtime.find("\n}\n", primeAt)
    let prime = runtime[primeAt .. primeEnd]
    var declared: seq[string]
    for line in runtime.splitLines():
      let t = line.strip()
      if t.startsWith("static ct_") and t.endsWith("_ptr = NULL;"):
        declared.add t.split(' ')[2]
    checkpoint("declared slots: " & $declared.len)
    check declared.len > 40
    for slot in declared:
      let primed = ("(" & slot & ",") in prime or
        (slot == "real_dlsym_ptr" and "ct_linux_preload_real_dlsym(" in prime)
      if not primed:
        checkpoint(slot & " is not primed in ct_linux_preload_prime_real_functions")
      check primed

  removeDir(work)
