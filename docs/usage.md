# io-mon usage

This guide documents the **`io-mon` command-line tool** and the **`io_mon`
library**. For what io-mon is responsible for (and what it deliberately is
not), see the *Scope & responsibilities* section of the [README](../README.md).

For building/testing io-mon through reprobuild, see [`repro.nim`](../repro.nim);
for the standalone build, see *Building and testing* in the README.

---

## Command-line tool: `io-mon`

The CLI (`cmd/io_mon_snoop.nim`, built to `build/bin/io-mon` by
`nimble buildSnoop`) is a thin entry point over the `runFsSnoopCli` driver in
`src/io_mon/fs_snoop.nim`. It has two verbs: **`run`** (capture) and
**`inspect`** (render an existing depfile).

### `io-mon run` — capture a command's dependencies

```
io-mon run [options] -- <command> [args...]
```

`run` injects the interpose shim around `<command>` (via
`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` on Linux,
`CreateRemoteThread`+`LoadLibraryW` on Windows), runs the command, merges the
captured fragments, and writes the RMDF depfile. The CLI's own exit code is the
monitored command's exit status on success, or non-zero on a capture error
(the driver never raises — it converts errors to a stderr diagnostic + non-zero
exit so an out-of-process caller can fail-safe).

The `run` verb is optional for backward compatibility: a bare
`io-mon --depfile <out> -- <command>` works identically (the legacy
reprobuild `repro internal io monitor` form).

Options (each accepts both `--flag value` and `--flag=value`):

| Option | Meaning |
| --- | --- |
| `--depfile PATH` | Where to write the captured RMDF depfile. If omitted, a temp file is used and discarded after rendering. |
| `--events MODE` | Stream the captured records in MODE. One of `none` (default), `text`, `jsonl`, `binary` / `binary-stream`. |
| `--format MODE` | Alias for `--events` (same `FsSnoopOutputMode` values). |
| `--event-stream PATH` | Write the streamed events to PATH instead of stderr. **Required** when MODE is `binary`/`binary-stream` (so the binary stream stays separate from child output). |
| `--capture-stdio` | Capture the child's merged stdout+stderr instead of inheriting the parent's stdio (mirrors how the reprobuild engine launches monitored actions). |
| `--capture-stdio-path PATH` | Like `--capture-stdio`, but dump the captured bytes to PATH (implies `--capture-stdio`). |
| `--` | End of options; everything after is the command + args to run. **Required.** |

With `--events text` / `--events jsonl` and no `--event-stream`, the rendered
event stream goes to **stderr**.

Example — capture what a compile reads/writes:

```sh
io-mon run --depfile build.rdep -- cc -c hello.c -o hello.o
io-mon inspect build.rdep
```

### `io-mon inspect` — render an existing depfile

```
io-mon inspect <depfile> [--format text|json]
```

`inspect` decodes and prints a previously captured RMDF depfile. The format
defaults to `text`; `json` emits the full structured form. (`--events` is
accepted as an alias for `--format` here.)

> **Note:** `inspect` supports only `text` and `json`. `jsonl` is a *streaming*
> mode for `run --events jsonl`, not an `inspect` format — passing
> `--format jsonl` to `inspect` errors. (`renderMonitorDepFile` in
> `src/io_mon/render.nim` only implements `text` and `json`.)

Sample `text` output:

```
RMDF version=1 records=4 completeness=mcComplete
#0 mrProcessStart pid=54321 tid=1
#1 mrFileRead pid=54321 tid=1 path=/usr/include/stdio.h
#2 mrLibraryLoad pid=54321 tid=1 path=/usr/lib/libfoo.dylib detail=...
#3 mrFileWrite pid=54321 tid=1 path=/path/to/hello.o
summary records=4 processes=1 observations=3 eventLoss=0
```

The `completeness=` field on the first line is the **honest completeness
signal**: `mcComplete` means the capture is provably complete and the consumer
may trust the observed set; `mcIncomplete` means the consumer must
conservatively re-run. The record-kind tokens (`mrProcessStart`, `mrFileRead`,
`mrFileWrite`, `mrPathProbe`, `mrLibraryLoad`, `mrIpcConnect`, `mrEventLoss`, …)
correspond to `MonitorRecordKind`.

### Environment variables

Variables a user or consumer cares about:

| Variable | Role |
| --- | --- |
| `REPRO_MONITOR_SHIM_LIB` | **Operator override** for the shim shared-library path. Honoured first by `findShimLibrary()`; otherwise the canonical `build/lib/librepro_monitor_shim.<ext>` layout is probed. |
| `CT_SANDBOX_TOOLS_DIR` | macOS SIP bypass: directory of non-SIP drop-ins for `/bin/sh`, `/bin/cat`, coreutils, etc. If unset, `run` creates and populates a temp one. Point it at a pre-built portable bundle (`scripts/build-sandbox-tools.sh`) to widen subtree coverage. |
| `IO_MON_BREAKAWAY_REPORT_DIR` | Directory where a cooperating "trusted daemon" drops breakaway reports; `mergeFragments` folds the daemon-read files into the depfile and exempts the daemon's pid from the IPC-connect downgrade (BuildXL Trusted-Tools prior art). |

Variables the **driver sets for the shim** (you normally do not set these by
hand): `REPRO_MONITOR_FRAGMENT_DIR` (per-capture fragment-log dir),
`REPRO_MONITOR_OUTPUT` (depfile path), `REPRO_MONITOR_SESSION` (capture id).

Variables for the **shim build script** (`scripts/build_shim.sh`):
`STACKABLE_HOOKS_SRC` (sibling `nim-stackable-hooks/src` override),
`IO_MON_SHIM_OUT_DIR`, `IO_MON_SHIM_NIMCACHE_DIR` (absolute output / nimcache
dirs for read-only source trees), `IO_MON_BUILD_MODE` (`debug` | `release`).

**Debug-only diagnostics** — these are compiled out of a `release` shim and are
no-ops there; in a `debug` shim they enable per-mechanism A/B attribution
**only** and can never weaken a production capture:
`IO_MON_DEBUG_DISABLE_BODYPATCH`, `IO_MON_DEBUG_DISABLE_INTERPOSE`,
`IO_MON_DEBUG_SKIP=<names>`.

---

## Library: `import io_mon`

`import io_mon` (`src/io_mon.nim`) re-exports the public API of every submodule:
`types`, `capabilities`, `writer`, `reader`, `render`, and `fs_snoop`. (The
`shim/*` and `hooks/*` modules are `--app:lib` entry points, not part of the
importable API.)

### Key types (`io_mon/types`)

- `MonitorDepFile` — the decoded depfile: `version`, `producerVersion`,
  `backendFamily`, `requiredFeatures`, **`completeness`** (`MonitorCompleteness`),
  `profile`, `capabilityGaps`, `summary`, and `records: seq[MonitorRecord]`.
- `MonitorRecord` — one observation: `kind: MonitorRecordKind`,
  `observationKind`, `seq`, `osPid`, `parentOsPid`, `threadId`, `childOsPid`,
  `result`, `flags`, `probeResult`, `path`, `detail`.
- `MonitorRecordKind` — `mrProcessStart`, `mrProcessExec`, `mrProcessSpawn`,
  `mrFileOpen`, `mrFileRead`, `mrPathProbe`, `mrFileWrite`, `mrEventLoss`,
  `mrDirectoryEnumerate`, `mrBackendProfile`, `mrCapabilityGap`,
  `mrIpcConnect`, `mrLibraryLoad`. (Wire-stable; new kinds are appended, never
  renumbered.)
- `MonitorCompleteness` — `mcComplete` | `mcIncomplete`.
- `FsSnoopRequest` — the capture request the CLI driver consumes (`command`,
  `depFilePath`, `eventStreamPath`, `streamMode`, the stdio-capture fields).

### Reading a captured depfile (`io_mon/reader`)

```nim
import io_mon

let dep = readMonitorDepFile("build.rdep")   # raises MonitorDepFileReaderError on bad/partial data
if dep.completeness == mcComplete:
  for r in dep.records:
    if r.kind in {mrFileRead, mrLibraryLoad}:
      echo "input: ", r.path
    elif r.kind == mrFileWrite:
      echo "output: ", r.path
else:
  # NEVER treat an mcIncomplete capture as an authoritative dependency set —
  # the consumer must conservatively re-run / rebuild.
  discard
```

- `readMonitorDepFile(path)` / `readMonitorDepFile(path, options)` — decode +
  validate; raises `MonitorDepFileReaderError` on a missing/truncated/corrupt
  file (a partial RMDF write fails validation by design — it must not be
  trusted).
- `tryReadMonitorDepFile(path, options): MonitorDepFileReaderResult` — non-raising
  variant returning `Option[MonitorDepFile]` + diagnostics.
- `streamMonitorDepFile(path)` — iterator over `FsSnoopStreamItem`s (records +
  a trailing summary) without materialising the full record seq.

### Writing / merging (`io_mon/writer`)

- `mergeFragments(fragmentDir, outputPath; breakawayReportDir = ""; expectedRootPid = 0): MonitorDepFile`
  — merge a capture's per-thread fragment logs into the canonical depfile and
  compute completeness.
- `writeCanonical(outputPath, records)` / `encodeCanonical(records): seq[byte]`
  — encode an explicit record set (used by tests and by consumers that
  synthesize records).

### Rendering (`io_mon/render`)

- `renderMonitorDepFile(path, format)` — `format` is `"text"` or `"json"`.
- `renderMonitorDepFileText` / `renderMonitorDepFileJson` — render an
  in-memory `MonitorDepFile`.
- `renderMonitorStreamItemText` / `renderMonitorStreamItemJsonl` — render a
  single stream item.

### Driving a capture (`io_mon/fs_snoop`)

- `runFsSnoopCli(programName, args): int` — the full CLI grammar as a library
  call (what `cmd/io_mon_snoop.nim` delegates to). Never raises; returns the
  exit code.
- `findShimLibrary(): string` — resolve the shim shared library
  (`$REPRO_MONITOR_SHIM_LIB` first, then the canonical build layout); empty
  string if none found.

### The launcher contract (completeness root-guard)

A consumer that spawns the **root** process under the shim itself (rather than
via `runFsSnoopCli`) **must** pass the root pid it spawned as `expectedRootPid`
to `mergeFragments`. This is the R1 root-guard: a SIP/hardened/notarized root
(e.g. `/bin/cat`) strips `DYLD_INSERT_LIBRARIES`, emits no `mrProcessStart`, and
leaves an empty fragment set — without the root pid the merge would falsely
assert `mcComplete` over that empty set (a zero-effort false cache hit). Passing
the pid makes the merge downgrade an un-monitored root to `mcIncomplete`. The
built-in `runMonitoredCommand` already does this; any custom launcher must too.
Passing `0` (the default) preserves legacy behaviour for callers merging
hand-built fragment dirs with no single known root.
