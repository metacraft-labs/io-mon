when not defined(macosx):
  {.error: "repro_monitor_hooks/macos_bodypatch is macOS-only".}

## macOS body-patch backend
## ========================
##
## This module closes the well-known ``__DATA,__interpose`` blind spot on
## macOS. Interpose (the legacy backend in ``macos_interpose.nim``) only
## rewrites a binary's *own* lazy/chained import bindings, so it can ONLY
## intercept calls a binary makes through its own import stubs. It MISSES file
## operations performed by shared-cache-internal callers — e.g. ``fopen`` calls
## ``open$NOCANCEL`` *inside* ``libsystem_c`` without ever touching the
## monitored binary's import table, so the open is invisible to interpose.
##
## The body-patch backend intercepts the libsystem syscall *wrappers* by
## REPLACING their code mapping with a branch to our hook (the Dobby /
## substrate ``mach_vm_remap`` overwrite technique). Patching the *callee*'s
## entry catches ALL callers — shared-cache-internal ones included.
##
## Why ``mach_vm_remap`` and not ``mprotect``
## ------------------------------------------
## Under macOS 11+ on Apple Silicon you CANNOT make an existing code-signed
## executable page writable in-process: ``mprotect``/``vm_protect`` →
## ``EACCES``/``KERN_PROTECTION_FAILURE`` and ``VM_PROT_COPY`` faults with
## ``SIGBUS``. This is the hardened W^X / code-signing enforcement (see Apple's
## "Porting Just-In-Time Compilers to Apple Silicon" and the dyld shared-cache
## immutability design). The proven workaround — validated empirically on this
## machine (see ``research/macos-bodypatch/{matrix.c,remap.c,internal3.c}``) —
## is to build a *fresh* page that is a copy of the original with the patched
## prologue, mark IT executable, then OVERWRITE the original VA's mapping with
## the fresh page via ``mach_vm_remap(..., VM_FLAGS_OVERWRITE, ...)``. This
## works under SIP with NO entitlements, NO root, NO re-signing, for the
## default (non-hardened-runtime, ad-hoc/linker-signed) binaries our build and
## test system produces.
##
## References:
##   * Dobby / substrate arm64 inline-hook technique (mach_vm_remap overwrite).
##   * Apple, "Porting Just-In-Time Compilers to Apple Silicon" (W^X / MAP_JIT).
##   * dyld shared-cache page-protection model (immutable, signed __TEXT).
##
## The patched prologue is a 16-byte absolute branch to the hook:
##   ``ldr x16,#8 ; br x16 ; .quad hookAddr``
## i.e. the words ``0x58000050, 0xd61f0200`` followed by the 8-byte hook
## address. We do NOT build a prologue-copying trampoline (that SIGILLs on
## PC-relative instructions such as ``adrp``); instead every hook forwards to
## the real kernel via the RAW syscall, which is correct for these thin syscall
## wrappers and also guarantees no infinite re-entry into the now-patched
## named symbol.
##
## This backend is purely ADDITIVE to interpose: a given call hits AT MOST ONE
## layer (interpose redirects the binary's own import-stub calls before they
## reach libsystem, so those never reach the body-patched callee; body-patch
## catches the shared-cache-internal + ``$NOCANCEL`` calls interpose never
## sees), so no de-duplication is required.

{.emit: """
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>

/*
 * Idempotency registry of already-patched target VAs. The shim installs all
 * patches in the constructor, single-threaded, before any other thread can be
 * running (DYLD constructors run before main), so this fixed-size, lock-free
 * table is race-free in practice. We never patch the same VA twice: a second
 * patch would copy the ALREADY-patched page (the branch stub) into the new
 * copy, harmlessly, but re-installing wastes a page and risks confusing
 * diagnostics, so we guard against it. The table is intentionally small —
 * the io-mon shim hooks well under this many distinct syscall-wrapper VAs.
 */
#define REPRO_BODYPATCH_MAX_TARGETS 64
static uintptr_t repro_bodypatch_seen[REPRO_BODYPATCH_MAX_TARGETS];
static size_t repro_bodypatch_seen_count = 0;

static int repro_bodypatch_already(uintptr_t target) {
  for (size_t i = 0; i < repro_bodypatch_seen_count; i++) {
    if (repro_bodypatch_seen[i] == target) return 1;
  }
  return 0;
}

static void repro_bodypatch_remember(uintptr_t target) {
  if (repro_bodypatch_seen_count < REPRO_BODYPATCH_MAX_TARGETS) {
    repro_bodypatch_seen[repro_bodypatch_seen_count++] = target;
  }
}

/*
 * Install a body patch: overwrite the code mapping at `target` so that calling
 * it branches to `hook`. Implements the proven recipe (see module doc).
 *
 * Returns 0 on success; nonzero on failure (caller treats failure as
 * non-fatal — reduced capture degrades to "re-run", never a false skip):
 *   1  bad arguments (NULL target/hook)
 *   2  the 16-byte patch would straddle a page boundary and the spanning page
 *      could not be covered (we copy 2 pages to handle the straddle, so this
 *      only triggers on allocation failure for the 2-page case)
 *   3  mach_vm_allocate failed
 *   4  mach_vm_protect (RX on the fresh copy) failed
 *   5  mach_vm_remap OVERWRITE failed
 *
 * Idempotent: a target already patched returns 0 without re-patching.
 */
int repro_macos_bodypatch_install(void *target, void *hook) {
  if (target == NULL || hook == NULL) return 1;

  uintptr_t taddr = (uintptr_t)target;
  if (repro_bodypatch_already(taddr)) return 0;

  const size_t patch_len = 16; /* ldr x16,#8 ; br x16 ; .quad hook */
  long pg = sysconf(_SC_PAGESIZE);
  uintptr_t page_base = taddr & ~(uintptr_t)(pg - 1);
  uintptr_t offset = taddr - page_base;

  /*
   * The 16-byte patch must fit inside the copied region. Syscall-wrapper
   * entries are page-resident, but defensively handle a target whose 16-byte
   * patch would cross the page end by copying TWO pages instead of one, so the
   * patch never falls off the end of the copy.
   */
  size_t copy_len = (size_t)pg;
  if (offset + patch_len > (size_t)pg) {
    copy_len = (size_t)pg * 2;
  }

  mach_vm_address_t new_page = 0;
  kern_return_t kr = mach_vm_allocate(mach_task_self(), &new_page,
                                      copy_len, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) return 3;

  /* Copy the original code, then splice in the absolute-branch prologue. */
  memcpy((void *)new_page, (void *)page_base, copy_len);
  uint32_t *p = (uint32_t *)(new_page + offset);
  p[0] = 0x58000050u;                         /* ldr x16, #8            */
  p[1] = 0xd61f0200u;                         /* br  x16                */
  *(uint64_t *)&p[2] = (uint64_t)(uintptr_t)hook; /* .quad hook         */

  /* Make the fresh copy read+execute (RX) before remapping it into place. */
  kr = mach_vm_protect(mach_task_self(), new_page, copy_len, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    mach_vm_deallocate(mach_task_self(), new_page, copy_len);
    return 4;
  }

  /*
   * Overwrite the mapping at the original page VA with the fresh RX page.
   * VM_FLAGS_OVERWRITE makes mach_vm_remap replace the existing (signed,
   * shared-cache) mapping rather than placing the copy elsewhere — this is
   * the crux that sidesteps in-place W^X enforcement.
   */
  mach_vm_address_t dst = (mach_vm_address_t)page_base;
  vm_prot_t cur = 0, max = 0;
  kr = mach_vm_remap(mach_task_self(), &dst, copy_len, 0,
                     VM_FLAGS_OVERWRITE, mach_task_self(), new_page, FALSE,
                     &cur, &max, VM_INHERIT_COPY);
  if (kr != KERN_SUCCESS) {
    mach_vm_deallocate(mach_task_self(), new_page, copy_len);
    return 5;
  }

  /* Flush the i-cache for the patched 16 bytes so the new branch is fetched. */
  sys_icache_invalidate(target, patch_len);
  repro_bodypatch_remember(taddr);
  return 0;
}

/*
 * Resolve a libsystem symbol by name and body-patch it to `hook`. Symbols that
 * do not exist on this OS (dlsym returns NULL) are skipped and counted as
 * "absent" — that is expected and not an error. Counters are written through
 * the provided pointers so the caller can log an install summary.
 */
void repro_macos_bodypatch_install_named(const char *name, void *hook,
                                          int *installed, int *failed,
                                          int *absent) {
  void *target = dlsym(RTLD_DEFAULT, name);
  if (target == NULL) {
    if (absent) (*absent)++;
    return;
  }
  int rc = repro_macos_bodypatch_install(target, hook);
  if (rc == 0) {
    if (installed) (*installed)++;
  } else {
    if (failed) (*failed)++;
  }
}
""".}

proc reproMacosBodypatchInstall*(target, hook: pointer): cint
    {.importc: "repro_macos_bodypatch_install", cdecl.}
  ## Reusable library entry point (high fan-in): install one body patch.
  ## Returns 0 on success, nonzero on failure (see the C source for codes).
  ## Idempotent and non-fatal on failure by contract.

proc reproMacosBodypatchInstallNamed*(name: cstring; hook: pointer;
    installed, failed, absent: ptr cint)
    {.importc: "repro_macos_bodypatch_install_named", cdecl.}
  ## Resolve `name` via ``dlsym(RTLD_DEFAULT, ...)`` and body-patch it. NULL
  ## symbols are counted as absent and skipped. Counters are incremented
  ## through the supplied pointers.
