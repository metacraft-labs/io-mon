# macOS body-patch research

These standalone proof programs establish the feasibility of the macOS
"body-patch" filesystem-monitoring backend that io-mon's injected shim uses to
close the `__DATA,__interpose` blind spot. They were validated empirically on
Apple Silicon (M1 Max, macOS 26) under SIP with no entitlements, no root, and
no re-signing — exactly the conditions the io-mon build/test system produces
(default, non-hardened-runtime, ad-hoc/linker-signed binaries).

The production implementation lives in:

- `src/io_mon/hooks/macos_bodypatch.nim` — the reusable body-patcher
  (`repro_macos_bodypatch_install` / `..._install_named`).
- `src/io_mon/shim/macos_interpose.nim` — installs the patches in the shim
  constructor, gated by `IO_MON_MACOS_BACKEND` (`bodypatch` | `interpose` |
  `both`, default `both`).
- `src/io_mon/hooks/macos_interpose_runtime.nim` — the raw-syscall forwarders
  the hooks use (so they never re-enter the now-patched named symbols).
- `tests/test_io_mon_macos_bodypatch.nim` — the regression test asserting the
  positive capture under body-patch and its absence under interpose-only.

## The programs

- `matrix.c` — proves you CANNOT make an existing code-signed executable page
  writable in-process: `mprotect`/`vm_protect` → `EACCES` /
  `KERN_PROTECTION_FAILURE`, `VM_PROT_COPY` → `SIGBUS`. Do NOT use that path.
- `remap.c` — proves the WORKING technique: allocate a fresh page, copy the
  original, patch the prologue, mark the copy RX, then `mach_vm_remap(...,
  VM_FLAGS_OVERWRITE, ...)` over the original VA. Works for both own `__TEXT`
  and shared-cache callees.
- `internal3.c` — the end-to-end proof: body-patching `open` /
  `open$NOCANCEL` / `__open_nocancel` intercepts `fopen`'s
  shared-cache-internal `open` — the call `__DATA,__interpose` cannot see.
- `ent1.plist` — sample entitlements used during exploration (NOT required by
  the working technique).

## The technique (validated)

1. Page-align the target; `mach_vm_allocate` a fresh page (or two if the
   16-byte patch would straddle a page boundary).
2. `memcpy` the original page(s) into the copy.
3. Write the absolute-branch prologue into the copy:
   `ldr x16,#8 ; br x16 ; .quad hook` = `0x58000050, 0xd61f0200`, then the
   8-byte hook address (16 bytes total).
4. `mach_vm_protect` the copy to `VM_PROT_READ | VM_PROT_EXECUTE`.
5. `mach_vm_remap(mach_task_self(), &origPageVA, len, 0, VM_FLAGS_OVERWRITE,
   mach_task_self(), newPage, FALSE, &cur, &max, VM_INHERIT_COPY)`.
6. `sys_icache_invalidate(target, 16)`.

The hook forwards to the kernel via the RAW syscall (`syscall(SYS_open, ...)`),
never via the named symbol / dlsym / RTLD_NEXT (which is now patched and would
re-enter infinitely). No prologue-copying trampoline is built — that SIGILLs on
PC-relative instructions (`adrp`); raw-syscall forwarding is correct for these
thin syscall wrappers.

### References

- Dobby / Substrate arm64 inline-hook technique (`mach_vm_remap` overwrite).
- Apple, "Porting Just-In-Time Compilers to Apple Silicon" (W^X / `MAP_JIT`).
- dyld shared-cache page-protection model (immutable, signed `__TEXT`).
