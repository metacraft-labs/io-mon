# io-mon

Cross-platform filesystem I/O monitoring for Nim.

`io-mon` captures the set of files **read** and **written** by a monitored
process tree and persists that observation in a compact binary depfile format
(`RMDF`). It is built on top of
[`nim-stackable-hooks`](https://github.com/metacraft-labs/nim-stackable-hooks),
the interpose framework that installs the read/write/exec hooks into the
monitored process.

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
  process and captures the read/written paths. The platform entry points
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
  `src/io_mon/hooks/macos_bodypatch.nim` and `research/macos-bodypatch/`). The
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
