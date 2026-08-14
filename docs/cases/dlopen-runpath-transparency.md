# Case: `dlopen` interposition must not change the target's library resolution

**Status:** Resolved (Linux shim) — fix `fix(linux-shim): resolve dlopen soname against the caller's RUNPATH`.
**Area:** `src/io_mon/hooks/linux_preload_runtime.nim` (Linux `LD_PRELOAD` shim).
**Class:** Monitor transparency — the shim must observe, never alter, the monitored program's behavior.

## Symptom

Under monitoring, a Nix-built Nim compiler failed to compile with:

```
could not load: libpcre.so(.3|.1|)
```

The identical command succeeds **unmonitored**. The compiler `dlopen`s `libpcre.so.1`
(Nim's `std/re`) and finds it via its **own** `DT_RUNPATH` (`…/pcre-8.45/lib`). Only
the io-mon shim being `LD_PRELOAD`ed makes it fail. This first surfaced as a chronic
red `Test` job in the reprobuild CI (the provider-compile edge is monitored).

## Root cause — the RUNPATH hijack

The shim interposes `dlopen` by exporting a `dlopen` symbol whose wrapper calls the
real `dlopen` (obtained via `dlsym(RTLD_NEXT, "dlopen")`) **from inside the shim
object**. glibc determines the *calling object* from the call's return address, so it
attributes the `dlopen` to the **shim** and resolves a bare soname
(`"libpcre.so.1"`, no `/`) against the **shim's** `DT_RPATH`/`DT_RUNPATH` — which has
no pcre — instead of the original caller's. Every candidate is `ENOENT`.

This is a general transparency defect: **any** monitored program that `dlopen`s a
library by soname relying on its own `DT_RUNPATH`/`DT_RPATH` is silently
mis-resolved while monitored. pcre was merely the first trigger (it appeared when the
toolchain switched to a Nim fork whose compiler links `std/re` and dlopens libpcre
via a private RUNPATH).

It is well-known prior art: RenderDoc's `LD_PRELOAD` hook hit the exact bug, first on
NixOS (empty `/lib`, resolution relies entirely on RUNPATH) — see
[renderdoc#3403](https://github.com/baldurk/renderdoc/issues/3403), still unresolved
in-tool there.

## Reproduction

- Self-contained: a program with a private `-Wl,--enable-new-dtags,-rpath,<dir>`
  (`DT_RUNPATH`) that `dlopen`s a bare soname reachable only via that RUNPATH.
  Succeeds unmonitored; **fails** under the (pre-fix) shim; the absolute-path and
  missing-soname cases are unaffected.
- Concrete: `LD_PRELOAD=<shim> IO_MON_MUTE=1 <nimfork>/bin/nim c -d:reproProviderMode
  … repro.nim` → `could not load: libpcre.so`. Adding
  `LD_LIBRARY_PATH=<pcre>/lib` makes it pass (proving it is a RUNPATH-resolution
  hijack, since `LD_LIBRARY_PATH` is consulted regardless of the calling object).

## Alternatives considered

### A. Stop wrapping `dlopen`; drive load-observation from the `mmap`/`openat` hooks — **rejected**

The `dlopen` hook's real job is to run `scanInlineSyscallPatchesForNewMappings()`
after a new object loads. Idea: detect the new `PROT_EXEC` mapping via the already
present `mmap`/`openat` hooks and drop the `dlopen` symbol wrapper entirely (removing
the hijack).

Rejected because it is **unsound on glibc**: the dynamic loader maps `.so` segments
and opens the file via **internal aliases / direct inline syscalls** (`__mmap`,
`__open64_nocancel`) that do **not** traverse `LD_PRELOAD` symbol interposition, so
the interposed `mmap`/`openat` hooks never fire for loader mappings. The re-scan for
late `dlopen`s would stop running → regressed inline-syscall coverage. (io-mon's
inline-syscall patching does observe the loader's *patched* code, but the loader's
own mapping syscalls are not visible through the *symbol* hooks this option relies
on.)

### B. Resolve the soname against the **caller's** RUNPATH, then call the real `dlopen` with an absolute path — **chosen**

Keep the wrapper but stop letting it change resolution. For a bare soname the wrapper
captures `__builtin_return_address(0)`, finds the caller's `link_map`
(`dladdr1(…, RTLD_DL_LINKMAP)`), reads its `DT_RPATH`/`DT_RUNPATH` (walking `l_ld`,
since the public `struct link_map` does not expose glibc's private `l_info[]`), and
replicates glibc's search order — **RPATH-if-no-RUNPATH → `LD_LIBRARY_PATH` →
RUNPATH**, with `$ORIGIN` expanded — handing the real `dlopen` an absolute path. On a
miss it passes the soname through unchanged, so glibc's caller-independent
`ld.so.cache` + default paths still apply (never *worse* than today). Runs under the
shim's reentrancy guard so its own `getenv`/`access` don't recurse or record spurious
deps. Only the path string handed to the real `dlopen` changes; hook bodies, dlmopen
namespace handling, vdso handling and all recording are untouched.

Chosen because it is surgical, verified, keeps the existing architecture, and is
strictly more correct than the state of the art for in-tool `dlopen` interposition
(RenderDoc never shipped a fix). This is the same algorithm the loader itself uses
(`ld.so(8)`).

### C. `LD_AUDIT` / rtld-audit (`la_objsearch` / `la_objopen`) — **deferred (principled future direction)**

glibc's auditing API is the textbook-correct *transparent* mechanism:
`la_objsearch` is called on every search candidate and, when it **returns the name
unchanged, resolution is completely unaltered** (pure observation); `la_objopen`
fires when a new object loads and hands you its `link_map` (resolved `l_name`) —
exactly the "a library just loaded" signal + dependency path, delivered by the loader
with no interposition. `LD_AUDIT` and `LD_PRELOAD` coexist (audit loads first).

Deferred, not adopted now, because of real cost: the audit library runs in a
**separate link-map namespace** (its own libc), so if the single io-mon `.so` is
listed in both `LD_AUDIT` and `LD_PRELOAD` it is loaded **twice** and cannot trivially
share the preload instance's recording state (it would have to push through the shm
queue io-mon already owns); and one must **not** define `la_symbind*`/return bind
flags or lazy PLT resolution is disabled (large per-symbol overhead) — io-mon needs
only `la_objsearch`/`la_objopen`/`la_activity` returning `0` flags. This is a
design-note-sized re-architecture of load observation, worth doing if io-mon ever
wants to stop wrapping `dlopen` at all.

### D. Prepend the caller's search dirs to `LD_LIBRARY_PATH` — **consumer-side stopgap only**

RenderDoc's workaround and the reprobuild CI stopgap. Zero shim code, unblocks a
specific consumer immediately, but coarse (whole process) and does not make the shim
transparent for other programs. Useful to green a pipeline while the shim fix
propagates; not a fix.

### E. Move file/library observation to the syscall level (`seccomp` user-notify / eBPF / ptrace) — **out of scope**

Sidesteps the entire `LD_PRELOAD`-transparency class by never sitting between the
target and the loader. This is where modern build/security sandboxes trend, but it is
a fundamental re-architecture away from io-mon's deliberate `LD_PRELOAD` +
inline-syscall-patch design (chosen for ~1–5% overhead vs ptrace's ~50%). Noted as
the strategic endgame, not this change.

## Decision

Ship **B** now. Track **C (`LD_AUDIT`)** as the principled evolution of library-load
observation. Use **D** as a per-consumer stopgap while the shim fix propagates
through pins. **E** is a separate, larger architectural discussion.

## Residual risks / known gaps

- ~~The `dlopen`'d `.so`'s own load is still not recorded as a file-read
  *dependency*~~ — **RESOLVED** by
  [linux-library-load-observation.md](linux-library-load-observation.md): the shim now
  observes the loader's link map with `dl_iterate_phdr` (scans at init, after each
  interposed `dlopen`/`dlmopen`, and at shutdown) and records every loaded object as an
  `mrLibraryLoad` content dependency, with the loader's own `dlpi_adds` counter used to
  prove the enumeration missed nothing. Alternative **C** (`LD_AUDIT`) below remains the
  documented future direction for the one residual it cannot observe. Original note,
  for the record: glibc opens it internally
  (`__open64_nocancel`) and the real `dlopen` runs under the reentrancy guard, so
  nested opens are bypassed; before the fix `dlopen` failed outright, so nothing was
  captured either. Documented as the `adversarial-raw-syscall` capability gap. A
  low-risk follow-up could record the resolved path in `repro_hook_dlopen` (it would
  churn golden depfiles, so it was kept out of this transparency fix).
- Resolves the caller's **own** RPATH/RUNPATH, not the full loader-chain RPATH that
  glibc also consults; on a miss it falls through to unmodified glibc behavior, so it
  cannot be worse than today.
- `$LIB` / `$PLATFORM` DT tokens are not expanded (only `$ORIGIN`); such dirs are
  skipped and left to glibc's fallback.
- Arch scope: the `l_ld` `DT_STRTAB` read assumes `!DL_RO_DYN_SECTION` (true for
  x86-64 / aarch64 glibc). dlmopen non-base namespaces keep their existing
  fail-closed handling.

## Verification

- nim + libpcre: pre-fix shim fails; rebuilt shim `[SuccessX]`; `strace` shows nim
  opens `…/pcre-8.45/lib/libpcre.so.1` — resolved via the **caller's** RUNPATH.
- Self-contained C repro: unmonitored OK → pre-fix shim FAILS (the bug) → rebuilt
  shim OK, with slash-passthrough and graceful-miss both intact.
- No regression: `tests/linux/test_io_mon_linux_stdio_ipc.nim` — all 31 subtests
  `[OK]`, including "late dlopen and base dlmopen capture plugin libc reads" and
  "startup shared library inline syscall openat/read captures dependency." Full
  monitored nim compile: exit 0, `eventLossCount=0`, dependency set intact.

## Upstream sources

- RenderDoc — [Linux `dlopen()` hook doesn't respect RUNPATHs (#3403)](https://github.com/baldurk/renderdoc/issues/3403) — the same bug in a mature `LD_PRELOAD` tool, unresolved in-tool.
- [`rtld-audit(7)`](https://man7.org/linux/man-pages/man7/rtld-audit.7.html) — `la_objsearch` / `la_objopen` / `la_activity` (the transparent observation path).
- SentinelLabs — [Leveraging `LD_AUDIT`](https://www.sentinelone.com/labs/leveraging-ld_audit-to-beat-the-traditional-linux-library-preloading-technique/) — `LD_AUDIT`/`LD_PRELOAD` coexistence and load order.
- [`ld.so(8)`](https://www.man7.org/linux/man-pages/man8/ld.so.8.html) — RPATH/RUNPATH/`LD_LIBRARY_PATH`/`$ORIGIN` search order replicated by fix B.
- [`dlopen(3)`](https://man7.org/linux/man-pages/man3/dlopen.3.html) — `DT_RUNPATH` resolution of the calling object; [`dladdr(3)`](https://www.man7.org/linux/man-pages/man3/dladdr.3.html) — `dladdr1` / `RTLD_DL_LINKMAP`.
- "Resolving the Correct Library: A Loader-Level Defense Solution Against Shared Object Hijacking" — [arXiv](https://arxiv.org/pdf/2605.26665) (la_objsearch-based loader-level observation).
- Sandbox-architecture context: [BuildXL sandboxing (detours)](https://github.com/microsoft/BuildXL/blob/main/Documentation/Specs/Sandboxing.md), [Filesystem sandboxing with eBPF — LWN](https://lwn.net/Articles/803890/).
