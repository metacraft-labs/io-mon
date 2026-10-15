/* Keep the shim's owned allocations out of an executable's interposed heap.
 *
 * WHY. The shim records observations from inside hooks, i.e. inside whatever
 * the host was doing when it made the observed call — and hosts make such
 * calls while holding their own allocator's lock: rustc's allocator calls
 * clock_gettime under its lock, and Chromium's PartitionAlloc calls
 * syscall(SYS_mprotect) under its lock. If recording that observation
 * allocates from the host's allocator, the host waits on a lock its own
 * caller holds and never wakes up (Chromium 143 headless hung forever under
 * the shim; tests/linux/test_io_mon_shim_host_allocator_isolation reproduces
 * it with a host that detects the re-entry). So every allocation the shim
 * makes for itself must come from glibc's OWN allocator, whatever allocator
 * the executable installs.
 *
 * HOW. GNU ld --wrap=malloc,calloc,realloc,free (linux_preload.nim) redirects
 * this DSO's own references to the __wrap_* functions below. --wrap only
 * redirects THIS DSO's references; it does not replace the host's allocator.
 *
 * WHICH ALLOCATOR. These used to call `__libc_malloc` and friends BY NAME.
 * That name is resolved like any other symbol: the global lookup scope
 * starts with the executable (then LD_PRELOAD objects, then the executable's
 * dependencies in load order), and the first definition wins —
 *   https://www.akkadia.org/drepper/dsohowto.pdf (section 1.5.4, "Lookup Scope")
 *   https://man7.org/linux/man-pages/man8/ld.so.8.html (LD_PRELOAD)
 * Allocator replacements that want to catch glibc-internal callers export
 * those exact names too; PartitionAlloc does so in
 * base/allocator/partition_allocator/src/partition_alloc/shim/
 * allocator_shim_override_glibc.h. For such a host the "private" heap was the
 * host's heap. Now the four entry points are looked up IN libc.so.6 ITSELF:
 * dlopen(LIBC_SO, RTLD_NOLOAD) returns the already-loaded libc's handle, and
 * dlsym on a handle searches only that object and its own dependencies, so a
 * definition in the executable or in another preload cannot be returned. The
 * result is then checked with dladdr: it must live in the same object as the
 * handle.
 *
 * WHEN. Resolution calls the loader (dlopen, dlsym, dladdr, dlclose), and the
 * loader allocates with the process's malloc — the host's — and takes the
 * loader lock. Doing that inside a hook, under a host lock, would reintroduce
 * the deadlock this file exists to prevent. So it runs EAGERLY, in a
 * constructor of priority 101 (before this DSO's default-priority
 * constructors, including the shim's own initialisation), where no host code
 * is running yet on this thread. An allocation this DSO makes before that
 * constructor runs resolves lazily on the spot; that can only happen during
 * loading, before the host has run any code of its own.
 *
 * IF RESOLUTION FAILS (no libc handle, a missing symbol, or a pointer that is
 * not in libc), the shim does NOT fall back to the host's allocator. It uses
 * a minimal allocator over anonymous mmap, issued as raw system calls: each
 * block is its own mapping with a header recording its size. It is slow and
 * wasteful, and it touches no lock and no allocator but the kernel's, which
 * is the property that matters. repro_linux_private_heap_source() reports
 * which one is in use.
 *
 * Ownership audit: Nim useMalloc cells, linux_pod_tables copies, raw-syscall
 * snapshots, the dlopen-resolver scratch and linux_preload_runtime's exec
 * environments are all allocated and freed within the shim. No libc-returned
 * or host-owned allocation is passed to these frees, and no pointer from
 * these mallocs is freed by libc or the host. Keep that invariant when adding
 * foreign APIs — it is also what makes the mmap fallback safe: its blocks
 * never reach another allocator's free.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <features.h>
#include <gnu/lib-names.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#ifndef __GLIBC__
#error "The private glibc heap is only available on glibc builds"
#endif

/* The shim's portable raw-syscall wrapper (linux_preload.nim). Raw, because
 * this DSO interposes mmap/munmap itself. */
extern long repro_linux_raw_syscall6(long nr, long a1, long a2, long a3,
                                    long a4, long a5, long a6);
/* The shim's handles on the real loader entry points: this DSO interposes
 * dlopen and dlsym, and those interpositions record. */
extern void *ct_linux_preload_real_dlopen(char *path, int flags);
extern void *ct_linux_preload_real_dlsym(void *handle, char *name);

typedef void *(*heap_malloc_fn)(size_t);
typedef void *(*heap_calloc_fn)(size_t, size_t);
typedef void *(*heap_realloc_fn)(void *, size_t);
typedef void (*heap_free_fn)(void *);

enum { HEAP_UNRESOLVED = 0, HEAP_LIBC = 1, HEAP_MMAP = 2 };

static heap_malloc_fn heap_malloc;
static heap_calloc_fn heap_calloc;
static heap_realloc_fn heap_realloc;
static heap_free_fn heap_free;
static int heap_source = HEAP_UNRESOLVED; /* written once, then read-only */

/* ---- the fallback: one anonymous mapping per block ---------------------- */

typedef struct {
  size_t mapped; /* bytes in the whole mapping, header included */
  size_t size;   /* bytes the caller asked for */
} mmap_block;

#define MMAP_HEADER ((sizeof(mmap_block) + 15) & ~(size_t)15)

static void *mmap_malloc(size_t size) {
  if (size > SIZE_MAX - MMAP_HEADER - 4096) return NULL;
  size_t mapped = (size + MMAP_HEADER + 4095) & ~(size_t)4095;
  long p = repro_linux_raw_syscall6(SYS_mmap, 0, (long)mapped,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p < 0 && p > -4096) return NULL; /* -errno */
  mmap_block *b = (mmap_block *)p;
  b->mapped = mapped;
  b->size = size;
  return (char *)b + MMAP_HEADER; /* anonymous memory is already zeroed */
}

static void mmap_free(void *ptr) {
  if (ptr == NULL) return;
  mmap_block *b = (mmap_block *)((char *)ptr - MMAP_HEADER);
  (void)repro_linux_raw_syscall6(SYS_munmap, (long)b, (long)b->mapped, 0, 0,
                                0, 0);
}

static void *mmap_calloc(size_t count, size_t size) {
  if (size != 0 && count > SIZE_MAX / size) return NULL;
  return mmap_malloc(count * size);
}

static void *mmap_realloc(void *ptr, size_t size) {
  if (ptr == NULL) return mmap_malloc(size);
  if (size == 0) { mmap_free(ptr); return NULL; }
  mmap_block *b = (mmap_block *)((char *)ptr - MMAP_HEADER);
  void *fresh = mmap_malloc(size);
  if (fresh == NULL) return NULL;
  memcpy(fresh, ptr, b->size < size ? b->size : size);
  mmap_free(ptr);
  return fresh;
}

/* ---- resolution --------------------------------------------------------- */

static int same_object(void *fn, const void *base) {
  Dl_info info;
  return fn != NULL && dladdr(fn, &info) != 0 && info.dli_fbase == base;
}

static void resolve_heap(void) {
  if (__atomic_load_n(&heap_source, __ATOMIC_ACQUIRE) != HEAP_UNRESOLVED)
    return;
  heap_malloc_fn m = NULL;
  heap_calloc_fn c = NULL;
  heap_realloc_fn r = NULL;
  heap_free_fn f = NULL;
  int ok = 0;
  void *libc = ct_linux_preload_real_dlopen((char *)LIBC_SO,
                                            RTLD_LAZY | RTLD_NOLOAD);
  if (libc != NULL) {
    m = (heap_malloc_fn)ct_linux_preload_real_dlsym(libc, "__libc_malloc");
    c = (heap_calloc_fn)ct_linux_preload_real_dlsym(libc, "__libc_calloc");
    r = (heap_realloc_fn)ct_linux_preload_real_dlsym(libc, "__libc_realloc");
    f = (heap_free_fn)ct_linux_preload_real_dlsym(libc, "__libc_free");
    /* All four from one object, and that object is the one the handle
     * names (gnu_get_libc_version is only defined by glibc's libc). */
    Dl_info anchor;
    void *version = ct_linux_preload_real_dlsym(libc, "gnu_get_libc_version");
    ok = version != NULL && dladdr(version, &anchor) != 0 &&
        same_object((void *)m, anchor.dli_fbase) &&
        same_object((void *)c, anchor.dli_fbase) &&
        same_object((void *)r, anchor.dli_fbase) &&
        same_object((void *)f, anchor.dli_fbase);
    dlclose(libc); /* RTLD_NOLOAD took a reference; libc stays loaded */
  }
  /* A failed dlsym leaves an error string on this thread; consume it so the
   * host's next dlerror() does not report the shim's lookup. */
  (void)dlerror();
  if (ok) {
    heap_malloc = m;
    heap_calloc = c;
    heap_realloc = r;
    heap_free = f;
  } else {
    heap_malloc = mmap_malloc;
    heap_calloc = mmap_calloc;
    heap_realloc = mmap_realloc;
    heap_free = mmap_free;
  }
  /* Concurrent first callers (only possible before the constructor) compute
   * the same answer; the release store publishes the pointers with it. */
  __atomic_store_n(&heap_source, ok ? HEAP_LIBC : HEAP_MMAP, __ATOMIC_RELEASE);
}

__attribute__((constructor(101)))
static void repro_linux_private_heap_init(void) {
  resolve_heap();
}

static inline void ensure_heap(void) {
  if (__builtin_expect(
          __atomic_load_n(&heap_source, __ATOMIC_ACQUIRE) == HEAP_UNRESOLVED, 0))
    resolve_heap();
}

/* ---- the wrapped entry points ------------------------------------------- */

__attribute__((visibility("hidden")))
void *__wrap_malloc(size_t size) { ensure_heap(); return heap_malloc(size); }

__attribute__((visibility("hidden")))
void *__wrap_calloc(size_t count, size_t size) {
  ensure_heap();
  return heap_calloc(count, size);
}

__attribute__((visibility("hidden")))
void *__wrap_realloc(void *ptr, size_t size) {
  ensure_heap();
  return heap_realloc(ptr, size);
}

__attribute__((visibility("hidden")))
void __wrap_free(void *ptr) {
  if (ptr == NULL) return;
  ensure_heap();
  heap_free(ptr);
}

/* ---- introspection (tests) ---------------------------------------------- */

/* The function the shim's private heap allocates through, so a test can ask
 * dladdr which object it lives in; NULL when the mmap fallback is in use. */
void *repro_linux_private_heap_malloc_entry(void) {
  ensure_heap();
  return heap_source == HEAP_LIBC ? (void *)heap_malloc : NULL;
}

/* 1 = glibc's allocator, resolved inside libc.so.6; 2 = mmap fallback. */
int repro_linux_private_heap_source(void) {
  ensure_heap();
  return heap_source;
}
