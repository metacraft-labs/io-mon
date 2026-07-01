# io-mon

Cross-platform filesystem I/O monitoring for Nim.

`io-mon` captures the set of files **read** and **written** by a monitored
process tree and persists that observation in a compact binary depfile format
(`RMDF`). It is built on top of
[`nim-stackable-hooks`](https://github.com/metacraft-labs/nim-stackable-hooks),
the interpose framework that installs the read/write/exec hooks into the
monitored process.

## Scope & responsibilities

**io-mon IS** the cross-platform filesystem/process **observation** layer. It
watches a monitored process tree and records, as it happens:

- file **reads**, **writes**, **opens**, and existence **probes**
  (`stat`/`access`/`getattrlist`), plus directory enumerations;
- content dependencies the bare `open`/`read` path misses — clonefile/CoW and
  hardlink sources, `mmap(MAP_SHARED|PROT_WRITE)` write-backs, and
  **library loads** (dependent dylibs + `dlopen`, mapped by dyld via low-level
  kernel `mmap` that bypasses the hooked `open`);
- **process** spawns / execs / starts (the process tree);
- **IPC** connects (`connect(2)` to AF_UNIX/AF_INET peers, with the peer pid)
  so a build that talks to an out-of-tree daemon can be detected.

It emits these as an **RMDF dependency depfile** carrying an honest
**completeness signal**: `mcComplete` is asserted **only** when the capture is
provably complete; otherwise the depfile is marked `mcIncomplete`, meaning the
consumer must conservatively re-run / re-build rather than trust the observed
set. io-mon ships the machinery that makes this work: the injected
interpose + body-patch shim (macOS), the `LD_PRELOAD` shim (Linux), the
`CreateRemoteThread`+`LoadLibraryW` injected hooks (Windows), the SIP-bypass
sandbox-tools drop-in propagation (macOS), and the depfile reader / writer /
merge.

**io-mon is NOT** a build system, a cache, an incremental test runner, or a
policy/enforcement sandbox. It does **not** decide what to rebuild or which
tests to skip. It supplies the *observed dependency set + completeness signal*;
a **consumer** — reprobuild's build engine, or CodeTracer's incremental test
runner — makes the caching / skip decisions. The dependency direction is
strictly one-way (`reprobuild → io-mon`, `codetracer → io-mon`, never the
reverse).

### Correctness contract (the cardinal sin)

io-mon must **never** claim `mcComplete` when it might have missed a
dependency. A false `mcComplete` becomes a consumer **false cache hit** or
**false test-skip** — the single worst failure mode. Every uncertainty is
therefore resolved by **downgrading to `mcIncomplete`** (fail-safe → re-run):
a partial/corrupt fragment write, an un-injected spawn child, an `exec`/SETEXEC
into an un-injectable (hardened/SIP) image, a root that stripped
`DYLD_INSERT_LIBRARIES` (see the `expectedRootPid` root-guard in
`mergeFragments`), or an IPC connect to an out-of-tree daemon all force
`mcIncomplete`. This contract has been exercised by the adversarial-hardening
campaigns in
`reprobuild-specs/MacOS-Monitoring-Adversarial-Hardening.milestones.org` (the
`adv_*` / `r2_*` corpora under `research/`). **Known residual gaps**, tracked
honestly: raw-syscall / indirect-syscall and XPC/Mach-IPC observation are
structurally invisible to the in-process interpose backend (adversarial
hardening #6) — these are the motivation for the designed/skeletoned
**EndpointSecurity** backend (`reprobuild-specs/MacOS-EndpointSecurity-Backend.md`),
which is behind the off-by-default `-d:ioMonEndpointSecurity` define and refuses
to start as an honest stub today.

### Platform scope

- **macOS** — most complete: interpose (`__DATA,__interpose`) **and** body-patch
  (`mach_vm_remap` overwrite) always run together, additively, working under SIP
  with no entitlements/root for the ad-hoc-signed binaries the build/test system
  produces.
- **Linux** — `LD_PRELOAD` shim. The exported wrapper symbols and monitor hook
  bodies are io-mon-owned, while reusable `RTLD_NEXT` lookup and reentrancy
  mechanics come from `stackable_hooks/platform/linux_preload`; exported libc
  `syscall(2)` wrapper patching comes from
  `stackable_hooks/platform/linux_raw_syscalls`. It captures direct
  `open`/`read` paths, glibc `fopen`/`fread` stream reads, and `connect(2)` IPC
  establishment; a monitored process that talks to an out-of-tree Unix/TCP
  daemon now fails closed as `mcIncomplete`. Raw `syscall(2)` and safe
  main-executable/startup non-system application-DSO inline `0f 05` paths are
  classified by io-mon for common file dependencies (`open`/`openat`/`openat2`,
  `read` after fd mapping, `close`, and `access`/`readlink`/`statx`-style
  probes); unsupported raw syscalls still emit event-loss and downgrade to
  `mcIncomplete`.
  Main-executable, startup non-system application-owned shared-object, and
  post-constructor `dlopen`/`dlmopen` application-DSO inline `0f 05` syscall
  sites are scanned and patched through the same stackable raw-syscall
  INT3/SIGTRAP substrate. Anonymous/private executable mappings created through
  the preload `mmap` wrapper, or made executable later through tracked
  `mprotect`, are incrementally scanned with the same substrate; anonymous
  writable+executable mappings fail closed because code can be written after
  the immediate scan. The anonymous ownership table is maintained across
  `munmap` removal/splitting and fully tracked `mremap` moves/resizes; live
  anonymous executable `mprotect` transitions are scanned only when every live
  executable anonymous byte in the requested range is covered by that lifecycle,
  and partial-overlap `mremap` ownership escapes fail closed instead of
  inheriting stale ownership. Linux libc-visible positioned/vector and
  zero-copy content movers (`pread`, `readv`, `preadv`, `sendfile`,
  `copy_file_range`, and `splice`) now record the source as a file read and
  the destination as a file write when bytes move. Direct raw `syscall(2)`
  variants of `sendfile`, `copy_file_range`, and `splice` are also classified
  when the relevant file side is known from io-mon's fd table; unsafe or
  unknown-fd cases remain fail-closed rather than being reported complete.
  Linux libc-visible
  `link`/`linkat` records hardlink source identity and alias output evidence,
  and `rename`/`renameat`/`renameat2` records the final output path for
  rename-staged writes. Linux libc-visible `getenv`, `uname`, and `sysconf`
  are recorded as observed inputs; `clock_gettime`, `gettimeofday`, and
  `time` are recorded as time-read evidence; successful `getrandom` calls
  emit non-determinism evidence. These non-file observations do not by
  themselves make monitoring incomplete; callers decide whether their policy
  invalidates on them. Known residuals: startup DSOs
  under excluded system/runtime prefixes and executable mappings not owned by
  the preload `mmap` lifecycle are not scanned yet; direct raw path-mutation
  syscalls, pre-existing hardlink aliases, direct raw/vDSO clock/time paths,
  inherited/unknown-fd zero-copy cases, and broader Linux non-file APIs outside
  the current libc-visible subset still need dedicated hooks or
  stackable-backed scanner/classifier integration. The default Linux profile is therefore an
  `LD_PRELOAD` completeness profile, not a native/adversarial production
  profile: consumers that require those residual threat models must request the
  explicit capabilities (`adversarial-raw-syscall`,
  `executable-mapping-lifecycle`, `external-content`, `library-load`,
  `path-mutation`, `path-identity`, `observed-env`, `non-determinism`) and
  treat the resulting required capability gap as `mcIncomplete`.
- **Windows** — injected hooks via `CreateRemoteThread`+`LoadLibraryW` (needs
  validation under the DIY toolchain).
- **EndpointSecurity** — designed/skeletoned (see above), not yet a shipping
  backend.

See [docs/usage.md](docs/usage.md) for the CLI and library usage guides, and
[repro.nim](repro.nim) for building/testing io-mon through reprobuild.

## What's in the box

`import io_mon` re-exports the full public API:

- **`io_mon/types`** — the wire data model: `MonitorRecord`,
  `MonitorDepFile`, the observation/record/capability enums, the
  `FsSnoopRequest`/`FsSnoopStreamItem` driver types, and the `RMDF` format
  constants.
- **`io_mon/writer`** — encodes records into the canonical binary depfile,
  including the per-thread fragment-log fast path (open-once, batched,
  crash-recoverable) and `writeCanonical` / `encodeCanonical`.
- **`io_mon/reader`** — validates and decodes a depfile back into records
  (`readMonitorDepFile`, `tryReadMonitorDepFile`, `streamMonitorDepFile`).
- **`io_mon/render`** — text / JSON / JSONL rendering of records and depfiles.
- **`io_mon/capabilities`** — backend capability profiles and the
  capability-gap evidence model.
- **`io_mon/fs_snoop`** — the driver that runs a command under the interpose
  monitor and produces a depfile.
- **`io_mon/windows_injector`** — the Windows `CreateRemoteThread` +
  `LoadLibraryW` injector (the Windows substitute for the macOS
  `DYLD_INSERT_LIBRARIES` env-var injection).
- **`io_mon/shim/*`** + **`io_mon/hooks/*`** — the syscall-interpose shim
  (built on `nim-stackable-hooks`) that actually injects into a monitored
  process and captures the read/written paths. macOS body-patch installation
  and Linux preload resolver/reentrancy plus exported `syscall(2)` patch
  mechanics are stackable-owned; io-mon owns target decisions, hook bodies,
  RMDF/event writing, and completeness policy. The platform entry points
  (`shim/macos_interpose`, `shim/linux_preload`, `shim/windows_interpose`)
  build as a shared library (`--app:lib`); `fs_snoop` loads it at runtime.
  These are NOT imported by `import io_mon` — they are `--app:lib` entry
  points with constructors and an interpose section, built directly.

## Building the interpose shim

The shim builds into a shared library whose name is kept **byte-identical** to
reprobuild's historical shim, `librepro_monitor_shim.{dylib,so,dll}`, and whose
exported interpose ABI (`repro_monitor_shim_*` / `repro_hook_*` /
`repro_macos_*` / `ct_linux_preload_*`, plus the macOS `__DATA,__interpose`
section) is preserved verbatim. This keeps the shim a **drop-in** for every
consumer that locates it by that filename — including io-mon's own
`fs_snoop.findShimLibrary` and (in M7) reprobuild's build engine.

```sh
nimble buildShim        # or: scripts/build_shim.sh
# → build/lib/librepro_monitor_shim.<ext>
```

## macOS monitoring mechanisms

On macOS the shim ALWAYS runs BOTH complementary, additive monitoring
mechanisms — there is no user-facing backend selector. It "just works":

- **interpose** — the `__DATA,__interpose` mechanism. Its static section is
  linked into the shim unconditionally (it cannot be added or removed at
  runtime), so dyld always rebinds the monitored binary's *own* import bindings
  to the shim's thunks. It MISSES file operations made by shared-cache-internal
  callers (e.g. `fopen` → `open$NOCANCEL` *inside* `libsystem_c`).
- **body-patch** — replaces the libsystem syscall-wrapper entry points
  themselves (the `mach_vm_remap` overwrite / Dobby-style technique; see
  `stackable_hooks/platform/macos_bodypatch.nim` and
  `research/macos-bodypatch/`). The
  constructor ALWAYS installs it, so it catches ALL callers, closing the
  interpose blind spot.

A given call is recorded by exactly one mechanism at its own layer, so the two
are purely additive (no de-duplication needed).

Body-patch works under SIP with no entitlements, no root, and no re-signing for
the default (non-hardened-runtime, ad-hoc/linker-signed) binaries the build/test
system produces. A failed install is non-fatal: the capture degrades to
"re-run" downstream, never a false skip.

### Debug-only per-mechanism diagnostic toggles

For DIAGNOSIS ONLY, and ONLY in NON-release (debug) shims, each mechanism has
its own opt-in disable toggle (one env var per mechanism — scalable as more
mechanisms are added). They enable a clean A/B to attribute a captured record
(or a regression) to a specific mechanism:

- `IO_MON_DEBUG_DISABLE_BODYPATCH=1` — skip the body-patch install (interpose
  only).
- `IO_MON_DEBUG_DISABLE_INTERPOSE=1` — keep the static `__interpose` section
  linked (it cannot be removed) but make its thunks STOP RECORDING: they forward
  each call to the real libsystem function via the (possibly body-patched) named
  entry, so body-patch records it if active and nothing is recorded if not
  (body-patch only).
- `IO_MON_DEBUG_SKIP=<names>` — comma-separated body-patch target names to skip
  installing (finer-grained body-patch diagnosis).

In a RELEASE shim every `IO_MON_DEBUG_*` env read is compiled out: the toggles
are no-ops and BOTH mechanisms are always on, so the diagnostic knobs can never
weaken a production capture.

## Relocation note

io-mon is a faithful **relocation** of reprobuild's
`repro_monitor_depfile` fs-snoop stack AND its `repro_monitor_shim` +
`repro_monitor_hooks` interpose closure — the same sources, with the package
namespaces renamed (`repro_monitor_depfile` → `io_mon`,
`repro_monitor_shim` → `io_mon/shim`, `repro_monitor_hooks` → `io_mon/hooks`)
and the one small `extendedPath` path helper (formerly `repro_core/paths`)
vendored locally, so io-mon has **no dependency on reprobuild**. The binary
`RMDF` format and the producer identifier, and the shim's exported interpose
ABI + shared-library name, are kept byte-identical — so depfiles round-trip
identically and the shim is a drop-in replacement for reprobuild's fs-snoop in
M7.

## Dependency direction (one-way)

```
codetracer (test runner) ──▶ io-mon
reprobuild (build engine) ──▶ io-mon
```

Both the CodeTracer incremental test runner and the reprobuild build engine
depend on io-mon for filesystem-monitoring; io-mon depends only on
`nim-stackable-hooks`. io-mon must never depend back on either consumer.
reprobuild's own fs-snoop implementation is retired once io-mon parity is
validated (it is replaced wholesale by io-mon).

## Building and testing

io-mon is a standard Nimble package. With the sibling `nim-stackable-hooks`
checkout available:

```sh
nimble test
# or, directly:
nim c -r --path:../nim-stackable-hooks/src tests/test_io_mon_parity_with_fs_snoop.nim
nim c -r --path:../nim-stackable-hooks/src tests/test_io_mon_builds_standalone.nim
```

The nimble tasks are: `nimble buildShim` (the shim shared library),
`nimble buildSnoop` (the `io-mon` CLI), and `nimble test` (the suite).

### Building and testing with reprobuild

[`repro.nim`](repro.nim) exposes io-mon's build/test as reprobuild edges so a
developer on any OS can drive them through the engine. From inside the io-mon
checkout (with `nim-stackable-hooks` checked out as a sibling):

```sh
repro build io-mon          # the io-mon CLI (the `default` collection)
repro build io-mon:shim     # the librepro_monitor_shim shared library
repro build io-mon:test     # compile + run the full test suite
```

From a sibling repo, the same qualified `io-mon:<target>` selectors apply.
Each edge wraps the corresponding existing build entry point verbatim
(`scripts/build_shim.sh`, `nimble buildSnoop`, `nimble test`) — see the
top-of-file comment in `repro.nim` for the rationale and the
`nim-stackable-hooks` sibling requirement.
