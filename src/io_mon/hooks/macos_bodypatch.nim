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
##
## The spawn family (the trampoline path)
## ---------------------------------------
## The file hooks above forward to the kernel via the RAW syscall, which needs
## no trampoline. The spawn family is different: ``posix_spawn`` is NOT a thin
## syscall wrapper — its libsystem implementation marshals a private
## ``_posix_spawn_args_desc`` structure (file-actions, spawnattr, the port
## array, …) before issuing ``SYS_posix_spawn``. Re-implementing that marshalling
## by hand would be fragile and version-coupled. So for the spawn hooks we must
## forward into the ORIGINAL wrapper body so its own marshalling runs — but we
## CANNOT call it by name (the name is now body-patched and would re-enter
## infinitely), and we cannot ``dlsym`` it (same patched address). The classic
## solution is a TRAMPOLINE: a fresh RX stub that runs the original function's
## displaced first 4 instructions (the prologue we overwrote with our branch),
## then jumps back into the original body at byte +16. Calling the trampoline is
## therefore equivalent to calling the un-patched original.
##
## Relocatability constraint (why some functions stay interpose-only)
## ------------------------------------------------------------------
## A trampoline that COPIES the original prologue is only correct if those 4
## instructions are position-INDEPENDENT: a copied PC-relative instruction
## (``adr``/``adrp``, ``b``/``bl``, ``b.cond``, ``cbz``/``cbnz``,
## ``tbz``/``tbnz``, ``ldr`` literal) would compute its target relative to the
## TRAMPOLINE's address, not the original's, and silently corrupt control flow or
## a loaded address. We therefore run a CONSERVATIVE relocatability check on the
## 4 prologue words first; if ANY is PC-relative we refuse to build the
## trampoline and SKIP body-patching that one function — it stays interpose-only
## (the prior behaviour), a safe degradation (the downstream fail-safe still
## re-runs an unmonitored subtree). The instruction-encoding masks are documented
## inline against the Arm Architecture Reference Manual (ARM ARM), section C4.1
## "A64 instruction set encoding".

{.emit: """
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libkern/OSCacheControl.h>

#include <mach-o/dyld.h>
#define REPRO_SHIM_IMAGE_SUBSTR "librepro_monitor_shim"
static int repro_bodypatch_addr_in_shim(const void *addr) {
  Dl_info info;
  if (addr == NULL) return 0;
  if (dladdr(addr, &info) == 0) return 0;
  if (info.dli_fname == NULL) return 0;
  return strstr(info.dli_fname, REPRO_SHIM_IMAGE_SUBSTR) != NULL ? 1 : 0;
}

static void *repro_bodypatch_resolve_libsystem(const char *name) {
  if (name == NULL) return NULL;
  char mangled[128];
  size_t n = strlen(name);
  if (n + 2 > sizeof(mangled)) return NULL;
  mangled[0] = '_';
  memcpy(mangled + 1, name, n);
  mangled[n + 1] = '\0';
  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; i++) {
    const char *img = _dyld_get_image_name(i);
    if (img != NULL && strstr(img, REPRO_SHIM_IMAGE_SUBSTR) != NULL) continue;
    const struct mach_header *header = _dyld_get_image_header(i);
    if (header == NULL) continue;
    NSSymbol sym = NSLookupSymbolInImage(header, mangled,
      NSLOOKUPSYMBOLINIMAGE_OPTION_BIND |
      NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR);
    if (sym) {
      void *ptr = NSAddressOfSymbol(sym);
      if (ptr && !repro_bodypatch_addr_in_shim(ptr)) return ptr;
    }
  }
  return NULL;
}

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
  void *target = repro_bodypatch_resolve_libsystem(name);
  if (target == NULL) {
    if (absent) (*absent)++;
    return;
  }
  if (repro_bodypatch_addr_in_shim(target)) {
    if (failed) (*failed)++;
    return;
  }
  int rc = repro_macos_bodypatch_install(target, hook);
  if (rc == 0) {
    if (installed) (*installed)++;
  } else {
    if (failed) (*failed)++;
  }
}

/* =========================================================================
 * Trampoline facility for the spawn family.
 *
 * Unlike the thin syscall wrappers (open/read/stat/...) which forward to the
 * kernel via a RAW syscall, posix_spawn must forward into the ORIGINAL wrapper
 * BODY so libsystem's own _posix_spawn_args_desc marshalling runs. We build a
 * trampoline = [original's first 16 bytes] + [absolute branch to original+16],
 * so calling the trampoline runs the displaced prologue then continues into the
 * rest of the original body. See the module doc for the full rationale.
 * =========================================================================
 */

/*
 * CONSERVATIVE relocatability check for a single AArch64 instruction word.
 *
 * Returns 1 if `insn` is PC-relative (and therefore NOT safe to copy into a
 * trampoline at a different address), 0 otherwise. We decode by the documented
 * top-bit encodings from the Arm Architecture Reference Manual (ARM ARM),
 * "A64 instruction set encoding" (C4.1). Each mask isolates the fixed opcode
 * bits of a PC-relative class; we err on the side of "relocatable=false" — any
 * doubt means we skip body-patching that function (safe degradation).
 */
static int repro_bodypatch_insn_is_pcrel(uint32_t insn) {
  /* ADRP: op=1, bits[28:24]=10000  -> (insn & 0x9F000000) == 0x90000000.
   * ADR : op=0, bits[28:24]=10000  -> (insn & 0x9F000000) == 0x10000000.
   * Both form a PC-relative address (ARM ARM C6.2.10/C6.2.11). */
  if ((insn & 0x9F000000u) == 0x90000000u) return 1; /* ADRP */
  if ((insn & 0x9F000000u) == 0x10000000u) return 1; /* ADR  */

  /* Unconditional branch (immediate): B  -> (insn & 0xFC000000)==0x14000000,
   * BL -> ==0x94000000. PC-relative 26-bit imm (ARM ARM C6.2.34/C6.2.36). */
  if ((insn & 0xFC000000u) == 0x14000000u) return 1; /* B  */
  if ((insn & 0xFC000000u) == 0x94000000u) return 1; /* BL */

  /* Conditional branch B.cond: (insn & 0xFF000010)==0x54000000.
   * PC-relative 19-bit imm (ARM ARM C6.2.27). */
  if ((insn & 0xFF000010u) == 0x54000000u) return 1; /* B.cond */

  /* Compare-and-branch CBZ/CBNZ: (insn & 0x7E000000)==0x34000000.
   * PC-relative 19-bit imm (ARM ARM C6.2.41/C6.2.42). */
  if ((insn & 0x7E000000u) == 0x34000000u) return 1; /* CBZ/CBNZ */

  /* Test-and-branch TBZ/TBNZ: (insn & 0x7E000000)==0x36000000.
   * PC-relative 14-bit imm (ARM ARM C6.2.346/C6.2.347). */
  if ((insn & 0x7E000000u) == 0x36000000u) return 1; /* TBZ/TBNZ */

  /* Load register (literal) LDR/LDRSW/PRFM literal: (insn & 0x3B000000)
   * ==0x18000000. PC-relative 19-bit imm (ARM ARM C6.2.131 etc.). */
  if ((insn & 0x3B000000u) == 0x18000000u) return 1; /* LDR literal */

  return 0;
}

/*
 * Check whether the 4-instruction (16-byte) prologue at `target` is safely
 * relocatable (no PC-relative instruction). Returns 1 if relocatable, 0 if not.
 */
static int repro_bodypatch_prologue_relocatable(const void *target) {
  const uint32_t *p = (const uint32_t *)target;
  for (int i = 0; i < 4; i++) {
    if (repro_bodypatch_insn_is_pcrel(p[i])) return 0;
  }
  return 1;
}

/*
 * Build a trampoline for `target`. On success returns the trampoline entry
 * point (callable, ABI-identical to the un-patched `target`) and writes 0 to
 * *err. On failure returns NULL and writes a nonzero code to *err:
 *   1  bad arguments
 *   2  prologue not relocatable (a PC-relative instruction) -> SKIP body-patch
 *   3  mach_vm_allocate failed
 *   4  mach_vm_protect (RX) failed
 *
 * The trampoline layout (5 instructions / 24 bytes, then an 8-byte target):
 *   [orig insn 0][orig insn 1][orig insn 2][orig insn 3]   (displaced prologue)
 *   ldr x16,#8 ; br x16 ; .quad (target+16)                (resume into body)
 *
 * Must be called BEFORE the body patch overwrites `target`'s prologue, so the
 * original 4 instructions are still readable at `target`.
 */
void *repro_macos_bodypatch_build_trampoline(void *target, int *err) {
  if (err) *err = 0;
  if (target == NULL) { if (err) *err = 1; return NULL; }

  if (!repro_bodypatch_prologue_relocatable(target)) {
    if (err) *err = 2;
    return NULL;
  }

  /* 4 displaced instructions + (ldr x16,#8 ; br x16) + 8-byte absolute target. */
  const size_t tramp_words = 6;            /* 4 + 2 instruction words   */
  const size_t tramp_len = tramp_words * sizeof(uint32_t) + sizeof(uint64_t);

  mach_vm_address_t tramp = 0;
  kern_return_t kr = mach_vm_allocate(mach_task_self(), &tramp, tramp_len,
                                      VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) { if (err) *err = 3; return NULL; }

  uint32_t *t = (uint32_t *)tramp;
  const uint32_t *src = (const uint32_t *)target;
  t[0] = src[0];
  t[1] = src[1];
  t[2] = src[2];
  t[3] = src[3];                              /* displaced original prologue */
  t[4] = 0x58000050u;                         /* ldr x16, #8                 */
  t[5] = 0xd61f0200u;                         /* br  x16                     */
  *(uint64_t *)&t[6] = (uint64_t)(uintptr_t)target + 16u; /* resume at body  */

  kr = mach_vm_protect(mach_task_self(), tramp, tramp_len, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    mach_vm_deallocate(mach_task_self(), tramp, tramp_len);
    if (err) *err = 4;
    return NULL;
  }

  sys_icache_invalidate((void *)tramp, tramp_len);
  return (void *)tramp;
}

/*
 * Resolve `name`, build a trampoline for it, then body-patch it to `hook`. The
 * trampoline (the original wrapper, callable without re-entry) is stored through
 * *out_trampoline so the hook can forward into the original marshalling body.
 *
 * Order matters: the trampoline is built FIRST (it copies the original
 * prologue), and only if that succeeds do we install the body patch. If the
 * function is absent (dlsym NULL) we count it absent and skip; if the prologue
 * is not relocatable (or any trampoline/patch step fails) we count it failed,
 * leave *out_trampoline NULL, and DO NOT patch — the function stays
 * interpose-only (safe degradation; the fail-safe still re-runs).
 */
void repro_macos_bodypatch_install_named_tramp(const char *name, void *hook,
                                               void **out_trampoline,
                                               int *installed, int *failed,
                                               int *absent) {
  if (out_trampoline) *out_trampoline = NULL;
  void *target = repro_bodypatch_resolve_libsystem(name);
  if (target == NULL) {
    if (absent) (*absent)++;
    return;
  }
  if (repro_bodypatch_addr_in_shim(target)) {
    if (failed) (*failed)++;
    return;
  }
  int terr = 0;
  void *tramp = repro_macos_bodypatch_build_trampoline(target, &terr);
  if (tramp == NULL) {
    /* Not relocatable, or allocation/protect failed: skip body-patch entirely
     * so we never corrupt control flow. Interpose still covers the direct
     * call; the fail-safe re-runs an unmonitored subtree. */
    if (failed) (*failed)++;
    return;
  }
  int rc = repro_macos_bodypatch_install(target, hook);
  if (rc == 0) {
    if (out_trampoline) *out_trampoline = tramp;
    if (installed) (*installed)++;
  } else {
    /* Patch failed after the trampoline was built: drop the trampoline (we will
     * not use it) and count the failure. The original is untouched. */
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
  ## Resolve `name` to the REAL libsystem symbol — walking the dyld images and
  ## SKIPPING the shim's own image so the shim's ``__DATA,__interpose`` wrappers
  ## are never returned (``dlsym`` would return ``repro_wrap_<name>`` here, whose
  ## body-patch would corrupt the shim's own code) — then body-patch it. Symbols
  ## that no non-shim image exports are counted absent and skipped; a target that
  ## still resolves into the shim image is refused (counted failed). Counters are
  ## incremented through the supplied pointers.

proc reproMacosBodypatchBuildTrampoline*(target: pointer; err: ptr cint): pointer
    {.importc: "repro_macos_bodypatch_build_trampoline", cdecl.}
  ## Reusable library entry point (high fan-in): build a trampoline that runs
  ## ``target``'s displaced 16-byte prologue then resumes into its body, so the
  ## original function can be invoked AFTER its entry is body-patched without
  ## re-entry. Returns the trampoline entry (callable like the original) or NULL
  ## on failure, with a nonzero code written through ``err`` (2 == the prologue
  ## is not relocatable, so body-patching must be skipped). Must be called BEFORE
  ## the body patch overwrites the prologue.

proc reproMacosBodypatchInstallNamedTramp*(name: cstring; hook: pointer;
    outTrampoline: ptr pointer; installed, failed, absent: ptr cint)
    {.importc: "repro_macos_bodypatch_install_named_tramp", cdecl.}
  ## Resolve ``name`` to the REAL libsystem symbol (skipping the shim's own image
  ## so the shim's interpose wrappers are not returned — ``dlsym`` would return
  ## ``repro_wrap_posix_spawn``, whose ``ADRP`` prologue is non-relocatable so the
  ## trampoline would be skipped AND the patch would corrupt the shim), build its
  ## trampoline, then body-patch it to ``hook``,
  ## storing the trampoline through ``outTrampoline`` so the hook can forward
  ## into the original wrapper body (needed for ``posix_spawn``, whose private
  ## ``_posix_spawn_args_desc`` marshalling must run). Absent symbols are
  ## counted; a non-relocatable prologue (or any failure) leaves the function
  ## interpose-only — a safe degradation. Counters are incremented through the
  ## supplied pointers.
