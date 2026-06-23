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

## Relocation note

io-mon is a faithful **relocation** of reprobuild's
`repro_monitor_depfile` fs-snoop stack — the same sources, with the package
namespace renamed from `repro_monitor_depfile` to `io_mon` and the one small
`extendedPath` path helper (formerly `repro_core/paths`) vendored locally so
io-mon has **no dependency on reprobuild**. The binary `RMDF` format and the
producer identifier are kept byte-identical, so depfiles round-trip
identically between reprobuild's fs-snoop and io-mon.

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
