/* The shim's private heap: every allocation the shim makes for itself.
 *
 * WHY THE SHIM NEEDS ITS OWN HEAP. The shim records observations from inside
 * hooks, i.e. inside whatever the host was doing when it made the observed
 * call, and allocating from the host's allocator there is not safe:
 *
 *   - Hosts make hooked calls while holding their allocator's lock. rustc's
 *     allocator calls clock_gettime under its lock; Chromium's PartitionAlloc
 *     calls syscall(SYS_mprotect) under its lock. If recording that call
 *     allocates from the host's allocator, the host waits on a lock its own
 *     caller holds, forever (Chromium 143 headless hung under the shim;
 *     tests/linux/test_io_mon_shim_host_allocator_isolation).
 *
 *   - Hosts own the program break. A host with its own sbrk-based allocator
 *     — bash 5.2 built with its bundled malloc (lib/malloc/malloc.c), as the
 *     nixpkgs stdenv bash that runs every gcc-wrapper is — grows the heap
 *     with sbrk(n) and, when it frees the block at the top of what IT last
 *     allocated, gives memory back with sbrk(-n) (`lesscore`). It assumes
 *     nobody else moved the break in between. The previous version of this
 *     file allocated from glibc's main arena, which ALSO grows with sbrk
 *     (`__default_morecore`): glibc's region ended up above bash's, bash's
 *     sbrk(-n) cut into it, and both allocators then handed out the same
 *     memory. `gcc --version` through such a wrapper died with SIGSEGV in
 *     bash's internal_malloc (measured on x86_64 NixOS, glibc 2.35 and 2.37
 *     wrappers, with gdb tracing every sbrk caller; making glibc avoid the
 *     break with GLIBC_TUNABLES=glibc.malloc.mmap_threshold=0 made the crash
 *     disappear). Regression test:
 *     tests/linux/test_io_mon_shim_host_allocator_isolation.
 *
 * So the shim's heap must use neither the host's allocator nor glibc's, and
 * must never touch the program break. This file is a small allocator over
 * anonymous mmap, issued as raw system calls (this DSO interposes
 * mmap/munmap, and those interpositions record):
 *
 *   - power-of-two size classes from 32 to 64 KiB (block size includes a
 *     16-byte header), each with a free list and a bump region carved from
 *     256 KiB slabs on demand (pages of a slab are touched only as blocks are
 *     handed out); slabs are never returned to the kernel;
 *   - anything larger is its own mapping, unmapped on free.
 *
 * LOCKING, AND WHY IT CAN NEVER HANG THE HOST. One spin lock per class (no
 * futex, no pthread: nothing here may call into anything that could be
 * hooked or that allocates); lock hold times are a few pointer operations
 * plus, on a refill, one mmap. A lock this heap waits on forever would hang
 * the host, and three situations would otherwise produce one:
 *
 *   - re-entry on the same thread: a signal handler that makes a hooked call
 *     (open, write and clock_gettime are async-signal-safe) interrupts a
 *     thread that is inside this allocator, and recording that call
 *     allocates. A thread-local flag marks "inside the allocator"; a call
 *     that finds it set takes no lock at all (see below);
 *   - a lock inherited from a thread that does not exist in this process: a
 *     child created with fork() while another thread held it, or with a raw
 *     clone() that runs no atfork handlers. fork() is covered by
 *     pthread_atfork (prepare takes every class lock, parent and child
 *     release them, and the child then reclaims any lock still held). The
 *     raw clone()s the shim observes (its syscall(2) replacement and the
 *     inline-syscall trap) call repro_linux_private_heap_after_raw_fork_child
 *     in the child, which reclaims every held lock. A reclaimed class's free
 *     list and bump region are abandoned (leaked), never trusted: the vanished
 *     holder may have been halfway through updating them;
 *   - anything else, for instance a raw clone() the shim cannot see: a waiter
 *     gives up after PH_WAIT_NS, remembers the exact lock value it gave up
 *     on, and does not wait on that same hold again.
 *
 * A call that cannot or must not take its class lock still succeeds: malloc
 * maps the block on its own (the large-allocation path, which takes no
 * lock), and free of a class block leaks it. Both are correct, merely more
 * expensive, and occur only in the situations above.
 *
 * Each lock is a sequence word: even means free, odd means held, and every
 * acquire and release adds one. That is what lets a waiter recognise "the
 * same hold I already timed out on" without knowing who holds it.
 *
 * pthread_atfork registration happens in a priority-101 constructor, the
 * first this DSO runs, so its prepare step runs after the shim's other
 * prepare handlers and its child step before theirs (which may allocate).
 *
 * HOW CALLS GET HERE. GNU ld --wrap=malloc,calloc,realloc,free
 * (linux_preload.nim) redirects THIS DSO's own references to the __wrap_*
 * functions below; it does not change the host's allocator.
 *
 * OWNERSHIP. Memory from this heap never leaves the shim, and the shim never
 * frees memory it did not allocate here. In particular every hook hands the
 * host libc's own results untouched (scandir's namelist, realpath's buffer,
 * fdopendir's DIR*, getenv's string), and the exec hooks do not replace the
 * host's `environ` (see ct_linux_preload_dispatch_execvp). Nim useMalloc
 * cells, linux_pod_tables copies, raw-syscall snapshots, the dlopen-resolver
 * scratch and the exec environments passed to execve are all allocated and
 * freed within the shim. Keep that invariant when adding foreign APIs.
 */
#define _GNU_SOURCE
#include <features.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#ifndef __GLIBC__
#error "The private heap is only built for glibc shims"
#endif

/* The shim's portable raw-syscall wrapper (linux_preload.nim). */
extern long repro_linux_raw_syscall6(long nr, long a1, long a2, long a3,
                                      long a4, long a5, long a6);

#define PH_HEADER 16u              /* keeps user pointers 16-byte aligned */
#define PH_MIN_SHIFT 5u            /* smallest block: 32 bytes */
#define PH_CLASSES 12u             /* 32 B .. 64 KiB */
#define PH_SLAB_BYTES ((size_t)256u * 1024u)
#define PH_PAGE ((size_t)4096u)
#define PH_LARGE ((uint32_t)0xFFFFFFFFu)
#define PH_MAGIC ((uint32_t)0x70484D73u)
/* How long a waiter spins on one hold before treating it as never ending.
 * Legitimate holds last microseconds; this only bounds the abnormal cases
 * listed at the top of the file. */
#define PH_WAIT_NS 200000000L      /* 200 ms */
#define PH_YIELDS_PER_CLOCK 64u
/* The same bound when the clock cannot be read. */
#define PH_MAX_YIELDS (1u << 22)

typedef struct {
  uint32_t magic;
  uint32_t cls;     /* size class, or PH_LARGE */
  size_t size;      /* the size the caller asked for (for realloc) */
} ph_header;        /* exactly PH_HEADER bytes on LP64 */

_Static_assert(sizeof(ph_header) == PH_HEADER, "ph_header must be 16 bytes");
_Static_assert(PH_HEADER >= _Alignof(max_align_t),
                "user pointers must be aligned for any type");
_Static_assert(PH_CLASSES <= 16, "ph_fork_held is a 16-bit mask");

typedef struct ph_free {
  struct ph_free *next;
} ph_free;

static ph_free *ph_free_lists[PH_CLASSES];
static char *ph_bump[PH_CLASSES];      /* next never-used block */
static char *ph_bump_end[PH_CLASSES];  /* end of the slab ph_bump is in */
static uint32_t ph_locks[PH_CLASSES];  /* sequence words: odd = held */
static uint32_t ph_given_up[PH_CLASSES]; /* the odd value a waiter gave up on */

/* Per-thread state. The default TLS model, like the shim's Nim threadvars:
 * initial-exec would mark the whole shim DF_STATIC_TLS, and its 672-byte TLS
 * block would then no longer fit the static TLS surplus glibc reserves for
 * libraries loaded with dlopen (rtld.optional_static_tls, 512 bytes). */
static __thread unsigned char ph_inside;
static __thread unsigned char ph_fork_state;
static __thread uint16_t ph_fork_held;
/* The held lock values of a fork in progress. Global, not per thread: only
 * the thread whose prepare step took the locks writes or reads it until its
 * parent or child step releases them, and the locks exclude every other
 * forking thread from prepare in that time. */
static uint32_t ph_fork_seq[PH_CLASSES];

static void *ph_map(size_t bytes) {
  long p = repro_linux_raw_syscall6(SYS_mmap, 0, (long)bytes,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p < 0 && p > -4096) return NULL; /* -errno */
  return (void *)p;
}

static void ph_unmap(void *p, size_t bytes) {
  (void)repro_linux_raw_syscall6(SYS_munmap, (long)p, (long)bytes, 0, 0, 0, 0);
}

static long ph_now_ns(void) {
  struct timespec ts;
  if (repro_linux_raw_syscall6(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&ts,
                                0, 0, 0, 0) != 0)
    return 0;
  return (long)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

/* Take class `cls`'s lock, or give up. Returns the held (odd) value to pass
 * to ph_unlock, or 0 when the caller must not touch the class. */
static uint32_t ph_lock(unsigned cls) {
  uint32_t v = __atomic_load_n(&ph_locks[cls], __ATOMIC_RELAXED);
  uint32_t watched = 0; /* the hold being timed; 0 = none yet */
  long deadline = 0;
  unsigned yields = 0;
  for (;;) {
    if ((v & 1u) == 0) {
      if (__atomic_compare_exchange_n(&ph_locks[cls], &v, v + 1u, 0,
                                      __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return v + 1u;
      continue; /* v now holds the current value */
    }
    /* A hold some waiter already outlasted: do not wait on it again. */
    if (v == __atomic_load_n(&ph_given_up[cls], __ATOMIC_RELAXED)) return 0;
    if (v != watched) { /* a different hold: the lock is making progress */
      watched = v;
      deadline = 0;
      yields = 0;
    }
    (void)repro_linux_raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    int expired = ++yields >= PH_MAX_YIELDS;
    if (!expired && yields % PH_YIELDS_PER_CLOCK == 0) {
      long now = ph_now_ns();
      if (deadline == 0) deadline = now + PH_WAIT_NS;
      else expired = now - deadline > 0;
    }
    if (expired) {
      __atomic_store_n(&ph_given_up[cls], v, __ATOMIC_RELAXED);
      return 0;
    }
    v = __atomic_load_n(&ph_locks[cls], __ATOMIC_RELAXED);
  }
}

static void ph_unlock(unsigned cls, uint32_t held) {
  __atomic_store_n(&ph_locks[cls], held + 1u, __ATOMIC_RELEASE);
}

/* A lock still held here belongs to a thread that does not exist in this
 * process. Abandon what it guarded (its holder may have been mid-update) and
 * free the lock. Called only where this thread is the only one. */
static void ph_reclaim_orphaned_locks(void) {
  for (unsigned c = 0; c < PH_CLASSES; ++c) {
    uint32_t v = __atomic_load_n(&ph_locks[c], __ATOMIC_RELAXED);
    if ((v & 1u) == 0) continue;
    ph_free_lists[c] = NULL;
    ph_bump[c] = NULL;
    ph_bump_end[c] = NULL;
    __atomic_store_n(&ph_locks[c], v + 1u, __ATOMIC_RELEASE);
  }
}

/* What this thread's pthread_atfork prepare step did, for its parent and
 * child steps: nothing, took the class locks in ph_fork_held, or found the
 * thread already inside the allocator (fork() from a signal handler that
 * interrupted an allocation) and took none. */
enum { PH_FORK_NONE = 0, PH_FORK_LOCKED = 1, PH_FORK_INTERRUPTED = 2 };

static void ph_atfork_prepare(void) {
  if (ph_inside) {
    /* The interrupted call's lock cannot be taken again. The child reclaims
     * it as orphaned; in the parent the interrupted call finishes. */
    ph_fork_state = PH_FORK_INTERRUPTED;
    ph_fork_held = 0;
    return;
  }
  ph_inside = 1;
  uint16_t held = 0;
  for (unsigned c = 0; c < PH_CLASSES; ++c) {
    uint32_t v = ph_lock(c);
    if (v != 0) {
      held |= (uint16_t)(1u << c);
      ph_fork_seq[c] = v;
    }
  }
  ph_fork_held = held;
  ph_fork_state = PH_FORK_LOCKED;
}

static void ph_atfork_release_held(void) {
  if (ph_fork_state == PH_FORK_LOCKED) {
    for (unsigned c = PH_CLASSES; c-- > 0;)
      if (ph_fork_held & (1u << c)) ph_unlock(c, ph_fork_seq[c]);
    ph_inside = 0;
  }
  ph_fork_held = 0;
  ph_fork_state = PH_FORK_NONE;
}

static void ph_atfork_parent(void) { ph_atfork_release_held(); }

static void ph_atfork_child(void) {
  ph_atfork_release_held();
  ph_reclaim_orphaned_locks();
}

/* For the shim's raw fork/clone observers (linux_preload_runtime.nim): in a
 * child created without CLONE_VM by a raw system call, no atfork handler
 * ran. The calling thread is in a hook, not in this allocator, so every held
 * lock is orphaned. Must not be called for CLONE_VM children, which share
 * the parent's live locks. */
__attribute__((visibility("hidden")))
void repro_linux_private_heap_after_raw_fork_child(void) {
  ph_reclaim_orphaned_locks();
}

__attribute__((constructor(101)))
static void repro_linux_private_heap_init(void) {
  pthread_atfork(ph_atfork_prepare, ph_atfork_parent, ph_atfork_child);
}

/* The class whose block holds `size` user bytes plus the header, or
 * PH_CLASSES when it needs its own mapping. */
static unsigned ph_class_for(size_t size) {
  if (size > ((size_t)1 << (PH_MIN_SHIFT + PH_CLASSES - 1)) - PH_HEADER)
    return PH_CLASSES;
  size_t need = size + PH_HEADER;
  unsigned cls = 0;
  while (((size_t)1 << (PH_MIN_SHIFT + cls)) < need) ++cls;
  return cls;
}

static size_t ph_block_bytes(unsigned cls) {
  return (size_t)1 << (PH_MIN_SHIFT + cls);
}

static size_t ph_large_mapping_bytes(size_t size) {
  return (size + PH_HEADER + PH_PAGE - 1) & ~(PH_PAGE - 1);
}

/* A block of its own mapping. Takes no lock, so it is also the path for
 * calls that cannot take their class lock. */
static ph_header *ph_map_own(size_t size) {
  if (size > SIZE_MAX - PH_HEADER - PH_PAGE) return NULL;
  ph_header *h = (ph_header *)ph_map(ph_large_mapping_bytes(size));
  if (h != NULL) h->cls = PH_LARGE;
  return h;
}

/* A block of class `cls`, or NULL. Called with the class locked. */
static ph_header *ph_take(unsigned cls) {
  ph_free *f = ph_free_lists[cls];
  if (f != NULL) {
    ph_free_lists[cls] = f->next;
    return (ph_header *)f;
  }
  size_t block = ph_block_bytes(cls);
  if (ph_bump[cls] == NULL ||
      (size_t)(ph_bump_end[cls] - ph_bump[cls]) < block) {
    char *slab = (char *)ph_map(PH_SLAB_BYTES);
    if (slab == NULL) return NULL;
    ph_bump[cls] = slab;
    ph_bump_end[cls] = slab + PH_SLAB_BYTES;
  }
  ph_header *h = (ph_header *)ph_bump[cls];
  ph_bump[cls] += block;
  return h;
}

static void *ph_malloc(size_t size) {
  unsigned cls = ph_class_for(size);
  ph_header *h = NULL;
  if (cls != PH_CLASSES && !ph_inside) {
    ph_inside = 1;
    uint32_t held = ph_lock(cls);
    if (held != 0) {
      h = ph_take(cls);
      ph_unlock(cls, held);
      if (h != NULL) h->cls = cls;
    }
    ph_inside = 0;
    if (held != 0 && h == NULL) return NULL; /* out of memory */
  }
  if (h == NULL) {
    h = ph_map_own(size);
    if (h == NULL) return NULL;
  }
  h->magic = PH_MAGIC;
  h->size = size;
  return (char *)h + PH_HEADER;
}

static ph_header *ph_header_of(void *ptr) {
  ph_header *h = (ph_header *)((char *)ptr - PH_HEADER);
  /* A pointer this heap did not hand out (or one already freed) would
   * corrupt it; stop instead of freeing someone else's memory into our free
   * lists. */
  if (h->magic != PH_MAGIC) __builtin_trap();
  return h;
}

static void ph_free_block(void *ptr) {
  if (ptr == NULL) return;
  ph_header *h = ph_header_of(ptr);
  h->magic = 0;
  if (h->cls == PH_LARGE) {
    ph_unmap(h, ph_large_mapping_bytes(h->size));
    return;
  }
  unsigned cls = h->cls;
  if (cls >= PH_CLASSES) __builtin_trap();
  if (ph_inside) return; /* re-entered from a signal handler: leak it */
  ph_inside = 1;
  uint32_t held = ph_lock(cls);
  if (held != 0) {
    ph_free *f = (ph_free *)h;
    f->next = ph_free_lists[cls];
    ph_free_lists[cls] = f;
    ph_unlock(cls, held);
  }
  ph_inside = 0;
}

/* ---- the wrapped entry points ------------------------------------------- */

__attribute__((visibility("hidden")))
void *__wrap_malloc(size_t size) { return ph_malloc(size); }

__attribute__((visibility("hidden")))
void *__wrap_calloc(size_t count, size_t size) {
  if (size != 0 && count > SIZE_MAX / size) return NULL;
  size_t total = count * size;
  void *p = ph_malloc(total);
  if (p == NULL) return NULL;
  /* Recycled class blocks are dirty; a block with its own mapping is fresh
   * from mmap and already zero. */
  if (((ph_header *)((char *)p - PH_HEADER))->cls != PH_LARGE)
    memset(p, 0, total);
  return p;
}

__attribute__((visibility("hidden")))
void *__wrap_realloc(void *ptr, size_t size) {
  if (ptr == NULL) return ph_malloc(size);
  if (size == 0) { ph_free_block(ptr); return NULL; }
  ph_header *h = ph_header_of(ptr);
  if (h->cls != PH_LARGE) {
    if (ph_class_for(size) == h->cls) {
      h->size = size;
      return ptr;
    }
  } else if (ph_large_mapping_bytes(size) ==
              ph_large_mapping_bytes(h->size)) {
    h->size = size; /* still fits the pages it already has */
    return ptr;
  }
  void *fresh = ph_malloc(size);
  if (fresh == NULL) return NULL; /* the original block is untouched */
  memcpy(fresh, ptr, h->size < size ? h->size : size);
  ph_free_block(ptr);
  return fresh;
}

__attribute__((visibility("hidden")))
void __wrap_free(void *ptr) { ph_free_block(ptr); }

/* ---- introspection (tests) ---------------------------------------------- */

/* Exported so a test can check from inside a host where the shim's
 * allocations come from: this DSO, never the host's or glibc's allocator. */
void *repro_linux_private_heap_malloc_entry(void) {
  return (void *)__wrap_malloc;
}

/* Drives the paths of this heap that a host reaches only by accident — a
 * signal handler re-entering it, a lock inherited from a vanished thread, a
 * hold that never ends — and the malloc/calloc/realloc/free contracts, from
 * inside a real host process. Returns 0, or the number of the first check
 * that failed. Test-only: call it while no other thread can allocate in the
 * shim, because it holds and forges class locks. It leaks a few blocks, as
 * those paths do by design. tests/linux/test_io_mon_shim_private_heap. */
int repro_linux_private_heap_selftest(void) {
#define PH_CHECK(n, cond) do { if (!(cond)) return (n); } while (0)
  /* malloc(0): a unique, freeable pointer; free(NULL) is a no-op. */
  void *z1 = __wrap_malloc(0), *z2 = __wrap_malloc(0);
  PH_CHECK(1, z1 != NULL && z2 != NULL && z1 != z2);
  __wrap_free(z1);
  __wrap_free(z2);
  __wrap_free(NULL);

  /* Alignment and content across every class boundary and into large. */
  static const size_t sizes[] = {1, 15, 16, 17, 31, 32, 33, 100, 1000, 4080,
                                  4096, 32752, 32768, 65519, 65520, 65521,
                                  70000, 300000};
  enum { NS = sizeof(sizes) / sizeof(sizes[0]) };
  for (unsigned i = 0; i < NS; ++i) {
    unsigned char *p = __wrap_malloc(sizes[i]);
    PH_CHECK(2, p != NULL && ((uintptr_t)p % _Alignof(max_align_t)) == 0);
    memset(p, 0xA5, sizes[i]);
    /* grow into every other size, then back: content survives */
    for (unsigned j = 0; j < NS; ++j) {
      size_t keep = sizes[i] < sizes[j] ? sizes[i] : sizes[j];
      unsigned char *q = __wrap_realloc(p, sizes[j]);
      PH_CHECK(3, q != NULL && ((uintptr_t)q % 16) == 0);
      for (size_t k = 0; k < keep; ++k) PH_CHECK(4, q[k] == 0xA5);
      memset(q, 0xA5, sizes[j]);
      p = __wrap_realloc(q, sizes[i]);
      PH_CHECK(5, p != NULL);
      for (size_t k = 0; k < keep; ++k) PH_CHECK(6, p[k] == 0xA5);
      memset(p, 0xA5, sizes[i]);
    }
    __wrap_free(p);
  }

  /* calloc: overflow refused; a recycled (dirty) block comes back zeroed. */
  PH_CHECK(7, __wrap_calloc(SIZE_MAX / 2 + 1, 2) == NULL);
  PH_CHECK(8, __wrap_malloc(SIZE_MAX - 8) == NULL);
  PH_CHECK(9, __wrap_realloc(NULL, SIZE_MAX - 8) == NULL);
  unsigned char *dirty = __wrap_malloc(200);
  PH_CHECK(10, dirty != NULL);
  memset(dirty, 0xFF, 200);
  __wrap_free(dirty);
  unsigned char *clean = __wrap_calloc(10, 20);
  PH_CHECK(11, clean != NULL);
  for (int k = 0; k < 200; ++k) PH_CHECK(12, clean[k] == 0);
  /* realloc(p, 0) frees and returns NULL; a failed realloc keeps p. */
  PH_CHECK(13, __wrap_realloc(clean, 0) == NULL);
  void *kept = __wrap_malloc(64);
  PH_CHECK(14, kept != NULL && __wrap_realloc(kept, SIZE_MAX - 8) == NULL);
  __wrap_free(kept);

  unsigned cls = ph_class_for(100);
  long t0, t1;

  /* Re-entry on one thread (a signal handler interrupting an allocation):
   * the interrupted call holds the lock; a nested call must neither wait
   * for it nor touch the class. */
  void *before = __wrap_malloc(100);
  PH_CHECK(20, before != NULL);
  ph_inside = 1;
  uint32_t held = ph_lock(cls);
  PH_CHECK(21, held != 0);
  t0 = ph_now_ns();
  void *nested = __wrap_malloc(100);
  t1 = ph_now_ns();
  PH_CHECK(22, nested != NULL && ((uintptr_t)nested % 16) == 0);
  PH_CHECK(23, t1 - t0 < PH_WAIT_NS / 4);
  PH_CHECK(24, ((ph_header *)((char *)nested - PH_HEADER))->cls == PH_LARGE);
  __wrap_free(nested);
  __wrap_free(before);              /* a class block: leaked, not queued */
  PH_CHECK(25, __atomic_load_n(&ph_locks[cls], __ATOMIC_RELAXED) == held);
  ph_unlock(cls, held);
  ph_inside = 0;

  /* A lock inherited from a vanished thread, reclaimed by the raw-fork
   * child hook: the class works again and its old free list is gone. */
  void *x = __wrap_malloc(100);
  PH_CHECK(30, x != NULL);
  __wrap_free(x);                   /* x is now on the free list */
  __atomic_store_n(&ph_locks[cls],
                    __atomic_load_n(&ph_locks[cls], __ATOMIC_RELAXED) + 1u,
                    __ATOMIC_RELAXED);
  repro_linux_private_heap_after_raw_fork_child();
  PH_CHECK(31, (__atomic_load_n(&ph_locks[cls], __ATOMIC_RELAXED) & 1u) == 0);
  void *y = __wrap_malloc(100);
  PH_CHECK(32, y != NULL && y != x);
  PH_CHECK(33, ((ph_header *)((char *)y - PH_HEADER))->cls == cls);
  __wrap_free(y);

  /* A hold that never ends and that nothing reclaims: the first waiter
   * gives up after about PH_WAIT_NS and is served by its own mapping; later
   * callers do not wait on the same hold; a new hold is waited on again. */
  uint32_t forged = __atomic_load_n(&ph_locks[cls], __ATOMIC_RELAXED) + 1u;
  __atomic_store_n(&ph_locks[cls], forged, __ATOMIC_RELAXED);
  t0 = ph_now_ns();
  void *w1 = __wrap_malloc(100);
  t1 = ph_now_ns();
  PH_CHECK(40, w1 != NULL);
  PH_CHECK(41, t1 - t0 >= PH_WAIT_NS / 2 && t1 - t0 < 20 * PH_WAIT_NS);
  t0 = ph_now_ns();
  void *w2 = __wrap_malloc(100);
  __wrap_free(y = __wrap_malloc(110)); /* free of a class block: leaked */
  t1 = ph_now_ns();
  PH_CHECK(42, w2 != NULL && t1 - t0 < PH_WAIT_NS / 4);
  __wrap_free(w1);
  __wrap_free(w2);
  ph_unlock(cls, forged);
  void *w3 = __wrap_malloc(100);
  PH_CHECK(43, w3 != NULL &&
                    ((ph_header *)((char *)w3 - PH_HEADER))->cls == cls);
  __wrap_free(w3);
  return 0;
#undef PH_CHECK
}
