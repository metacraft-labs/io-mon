# Case: Linux reported `mcComplete` while observing none of the runtime library closure

**Status:** Resolved (Linux shim).
**Area:** `src/io_mon/hooks/linux_preload_runtime.nim`, `src/io_mon/shim/linux_preload.nim`,
`src/io_mon/capabilities.nim`, `src/io_mon/writer.nim`.
**Class:** Cardinal sin — a false complete. An input channel was entirely
unobserved and the capture said it was complete anyway.

## Symptom

A monitored `gcc -c` of a trivial translation unit:

```
$ strace -f -e trace=openat gcc -c unit.c    # 10 shared objects opened
$ io-mon run --depfile gcc.rdep -- gcc -c unit.c
$ io-mon inspect gcc.rdep | head -1
RMDF version=1 records=365 completeness=mcComplete
$ io-mon inspect gcc.rdep | grep -c '\.so'
0
```

Ten shared objects — `libisl.so.19`, `libmpfr.so.6`, `libmpc.so.3`, `libgmp.so.10`,
`libbfd-2.44.so`, `libz.so.1`, `libsframe.so.1`, `libc`, `libdl`, `libm` — were loaded
and consumed. Zero appeared in the capture, which reported `mcComplete`.

Upgrade `libisl.so.19` in place and the compiler's behaviour can change. A consumer
keying a content-addressed cache on this set serves a stale result and has no signal
that anything is missing. `src/io_mon/types.nim` (T3b) had already argued this exact
case for macOS — a cache fingerprinting only the depfile "would serve a STALE result
after an in-place compiler-library upgrade" — and macOS acted on it. Linux did not.

## Root cause — two independent defects that hid each other

**1. Nothing observed loader-driven loads.** `ld.so` maps a dependency using internal
`__mmap` / `__open64_nocancel` calls. Those do **not** traverse `LD_PRELOAD` symbol
interposition, so the shim's `open`/`openat`/`mmap` hooks never fire for any library
the loader maps. The interposed `dlopen` only ever saw *explicit* runtime loads, and
even then recorded nothing.

**2. The declared gap could not downgrade.** `mcapLibraryLoad` was correctly listed in
`LinuxPreloadKnownUnsupportedCapabilities`, so the depfile *said* the capability was
missing — but `depFileFromOwnedRecords` derived the profile with an **empty
required-set**, and a gap only clears `evidenceComplete` when it is marked `required`,
which only happens for capabilities in that set. Every gap was emitted `required=false`
and could never affect completeness. `architecture.md` said "every uncertainty
downgrades to `mcIncomplete`"; the wiring did not.

Either defect alone would have been visible. Together, the honest declaration was
made and then discarded.

## Fix

**Observe via the loader, do not interpose it** — the same decision the macOS arm made
with `_dyld_register_func_for_add_image`. `dl_iterate_phdr` walks the loader's own
link map, so what it reports is what the loader has, regardless of which code path put
it there.

Scans run at three points:

| Point | What it covers |
| --- | --- |
| shim init (ELF constructor) | The **entire** initial closure. `ld.so` maps every object before running any constructor, so objects loaded *before* the shim existed are visible — the case an event hook structurally cannot cover. Also satisfies publish-before-use: the closure is in consumer-owned memory before `main` runs. |
| after each interposed `dlopen`/`dlmopen` | The explicit runtime load, recorded before the handle is returned (LF-7) and while the object is still mapped, so a later `dlclose` cannot erase it. |
| shutdown | Closes the account (below). |

**Coverage is proven, not assumed.** `struct dl_phdr_info` carries `dlpi_adds`, the
loader's cumulative count of loads. A load in a window is one io-mon saw iff the object
was still mapped at the next scan, so `newlyEnumerated == adds - lastAdds` proves the
window was fully covered. A shortfall means an object was loaded and unloaded unseen —
glibc's internal `__libc_dlopen_mode` for NSS or gconv modules — and emits an
event-loss marker that downgrades the capture. **The one case this design cannot
observe, it detects.**

The capability then moves to `LinuxPreloadSupportedCapabilities`, and
`InputEvidenceCapabilities` is introduced and passed as the required-set when a depfile
is finalised, so that a *future* missing input channel downgrades instead of being
declared and ignored. See `architecture.md` §2 for why that set is narrower than "every
declared gap".

## Alternatives considered

### A. `LD_AUDIT` / `la_objopen` — deferred (strictly more complete, materially more cost)

The loader calls `la_objopen` for **every** object load including loader-internal ones,
so it needs no accounting and has no sampling residual. Not adopted because an audit
library is loaded into its **own link-map namespace with its own libc**: the single
io-mon `.so` listed in both `LD_AUDIT` and `LD_PRELOAD` is loaded twice and the audit
copy cannot share the preload copy's recording state — it would have to attach to the
shm transport independently, i.e. a second injected copy of io-mon in every monitored
process. That buys coverage of a case this design already **detects and reports**, so
it is a real improvement with a real price, not a correctness fix. (Also: `la_symbind`
must not be defined or lazy PLT resolution is disabled process-wide.)

### B. `/proc/self/maps` — rejected

Also state-based and also sees loader mappings, but it is an inference from the VM
layout rather than the loader's own view: it costs a syscall and a parse per scan, it
cannot distinguish a loaded object from an ordinary file mapping, and it offers no
equivalent of `dlpi_adds`, so the coverage proof would not be available.

### C. Record from the interposed `dlopen` only — rejected

What the shim already had the hook for. It cannot see the startup closure at all, which
is where all ten of the `gcc` libraries are, and it cannot see loader-internal loads.
It is the mechanism that produced the defect.

## Residual risks / known gaps

- A process `SIGKILL`ed before its shutdown scan loses the closing account, so a
  loader-internal load in that window is neither observed nor detected. This is the
  pre-existing kill-before-flush inherent-loss class, not a new one; alternative A
  closes it.
- Libraries loaded by the shim itself (`libpthread`, `librt`) appear in the capture and
  not in an unmonitored `strace`. That is monitor-induced **over**-capture — the safe
  direction — and cannot be filtered, since the same file may equally be a genuine
  dependency of the program.
- A `dlpi_name` the loader records relatively cannot be resolved to a file and is
  counted as a coverage gap rather than guessed. Not observed in practice on glibc.

## Verification

- `tests/linux/test_io_mon_library_load_closure.nim` — captured-vs-`strace` as a set
  relation in the same run (`truth ⊆ observed`, 0 missed of 10), plus one test per
  awkward case: loaded-before-the-shim, publish-before-use under `SIGKILL`, `dlopen`
  from a worker thread, `dlopen`+`dlclose`, an unobservable load that must downgrade,
  and a statically-linked binary (no shim at all — covered by the subtree guard).
- `tests/portable/test_io_mon_capabilities.nim` — the capability is advertised, it is
  in `InputEvidenceCapabilities`, a missing input capability downgrades with an empty
  consumer ask, and a non-input gap does **not** destroy the signal.
