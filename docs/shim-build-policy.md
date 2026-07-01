# io-mon shim build policy

io-mon injects `librepro_monitor_shim` into arbitrary host programs
(`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` on Linux). Its hooks run *inside*
those programs, sometimes in **hostile contexts** — most importantly **inside
libmalloc**, which grows an arena via `mmap` while holding its arena lock.

io-mon's stance is deliberately **conservative**: compile the shim as close to
plain C as its feature set allows, minimize compiler-injected "magic," and keep
any code path reachable from a hostile context out of the Nim runtime entirely.

For the general hazard analysis and the menu of settings, see
`nim-stackable-hooks/docs/compilation-settings.md`. This document records io-mon's
concrete choices and the reasoning.

## Build settings

The shim is built (see `scripts/build_shim.sh` and
`src/io_mon/shim/macos_interpose.nim.cfg`) with:

- `--stackTrace:off --lineTrace:off` — removes the per-proc `framePtr` **threadvar**
  push. A monitor shim never needs Nim stack traces; error context is carried in the
  records it emits.
- `-d:noSignalHandler` — the shim must **not** install signal handlers. Doing so
  clobbers the host program's own handlers — e.g. rustc installs a `SIGSEGV`
  handler on a sigaltstack for stack-overflow detection, and the Rust/Go runtimes
  rely on theirs. A monitor observes; it does not handle the host's faults.
- `--mm:arc` — deterministic reference counting, no background cycle-collector
  thread; more C-like than `orc`. The shim's data has no reference cycles.
- `--threads:on` — required: the shim records from every host thread.

We deliberately **keep `--exceptions:goto`** (the default) rather than
`--exceptions:quirky`, even though `goto` injects the `nimInErrorMode` threadvar
access at proc entry. The writer/codec genuinely use exceptions (`EnvelopeError`,
`IOError`) for fragment-flush error handling, and `quirky` would make those
silently unsound. The residual hazard — entering a Nim proc that touches
`nimInErrorMode` from a hostile context — is handled structurally instead (below),
which is more robust than relying on any one compiler setting. (Verified: the
`mmap` crash this policy is written around survives `--exceptions:quirky`,
`--stackTrace:off`, `--tlsEmulation:off` and `-d:danger` — no single setting is a
substitute for keeping the hostile path in C.)

The `IO_MON_DEBUG_*` diagnostic toggles remain compiled in (they are
`when not defined(release)`), because the settings above do not define `release`.

## The structural rule (what actually keeps us safe)

> **No code path reachable from inside libmalloc may touch any thread-local
> (Nim `{.threadvar.}` *or* C `__thread`/`_Thread_local`) or allocate.**

On macOS a thread-local in an inserted image is a dyld TLV whose first per-thread
access `malloc`s; reached from inside libmalloc that re-enters the allocator under
its own lock and corrupts the heap. This is not fixable by compiler settings —
even an application `{.threadvar.}` on that path is unsafe (see the stackable-hooks
doc for the measurements).

**Audit (current):** `mmap` is the **only** hooked function libmalloc calls
internally — `munmap`, `mprotect`, `madvise`, `mremap`, `vm_allocate`, `brk`/`sbrk`
are not hooked. The dyld add-image callback runs in dyld's post-map context (not
malloc-reentrant) and is safe in practice.

**How `mmap` obeys the rule:** `repro_wrap_mmap` decides from the mmap **flags
alone**, in pure C, whether a mapping could ever be recorded. Only a `MAP_SHARED`
mapping with a real fd can (a `MAP_SHARED|PROT_WRITE` file content-write or a
`MAP_SHARED` shm read — see `recordMmap`), and libmalloc never issues those. Every
other mapping — every anonymous allocator map, every private file map, every
fd-less map — forwards via the raw inline-asm `SYS_mmap` syscall **without entering
Nim and without touching any thread-local**. The Nim hook (and its `inMmapHook`
`{.threadvar.}` re-entrancy guard) therefore runs only for `MAP_SHARED`+fd
mappings, which are never issued from inside libmalloc. All recording behaviour is
preserved. See `tests/macos/test_io_mon_macos_mmap_reentrancy.nim`.

## Adding a new hook — checklist

1. **Can the host's libmalloc/dyld/signal machinery call this function
   internally?** (mmap/munmap/madvise/mremap/mprotect/vm_*, or anything a signal
   handler might invoke.) If **no** — a normal Nim hook is fine.
2. If **yes** — the hot path must stay in **C** in the `repro_wrap_*` thunk: decide
   from the raw arguments whether the call is even interesting, and forward via the
   raw syscall for the common case. Do **not** enter the Nim `repro_hook_*` for the
   common case.
3. If that path unavoidably needs per-thread state, use
   `nim-stackable-hooks/src/stackable_hooks/safe_tls` (pthread-backed), **never** a
   `{.threadvar.}` or `__thread`.
4. Add a regression test that exercises the hook from inside a real allocator on
   multiple threads (a heavy multi-threaded toolchain like `rustc` is the reliable
   reproducer — see the mmap-reentrancy test).
