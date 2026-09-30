/* Keep the shim's owned allocations out of an executable's interposed heap.
 * rustc's allocator calls clock_gettime while holding its own lock. Recording
 * that observation must not call back into that allocator. GNU ld --wrap only
 * redirects this DSO's references; it does not replace the host's allocator.
 *
 * Ownership audit: Nim useMalloc cells, linux_pod_tables copies, raw-syscall
 * snapshots and linux_preload_runtime's exec environments are all allocated
 * and freed within the shim. No libc-returned or host-owned allocation is
 * passed to these frees. Keep that invariant when adding foreign APIs.
 */
#include <stddef.h>
#include <features.h>
#ifndef __GLIBC__
#error "The private glibc heap is only available on glibc builds"
#endif

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

__attribute__((visibility("hidden")))
void *__wrap_malloc(size_t size) { return __libc_malloc(size); }

__attribute__((visibility("hidden")))
void *__wrap_calloc(size_t count, size_t size) {
  return __libc_calloc(count, size);
}

__attribute__((visibility("hidden")))
void *__wrap_realloc(void *ptr, size_t size) {
  return __libc_realloc(ptr, size);
}

__attribute__((visibility("hidden")))
void __wrap_free(void *ptr) { __libc_free(ptr); }
