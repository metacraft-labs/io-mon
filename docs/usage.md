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
captured fragments, and writes the iomon depfile. The CLI's own exit code is the
monitored command's exit status on success, or non-zero on a capture error
(the driver never raises — it converts errors to a stderr diagnostic + non-zero
exit so an out-of-process caller can fail-safe).

The `run` verb is optional for backward compatibility: a bare
`io-mon --depfile <out> -- <command>` works identically (the legacy
reprobuild `repro internal io monitor` form).

Options (each accepts both `--flag value` and `--flag=value`):

| Option | Meaning |
| --- | --- |
| `--depfile PATH` | Where to write the captured iomon depfile. If omitted, a temp file is used and discarded after rendering. |
| `--events MODE` | Stream the captured records in MODE. One of `none` (default), `text`, `jsonl`, `binary` / `binary-stream`. |
| `--format MODE` | Alias for `--events` (same `FsSnoopOutputMode` values). |
| `--event-stream PATH` | Write the streamed events to PATH instead of stderr. **Required** when MODE is `binary`/`binary-stream` (so the binary stream stays separate from child output). |
| `--interest TOKENS` | The event categories to capture, as a comma-separated subset of `file,proc,lib,nondet,ipc` (the `REPRO_MONITOR_INTEREST` vocabulary — see [event-interest-filter.md](contributors/event-interest-filter.md)). **Omitting the flag, or passing an empty value in either spelling (`--interest ""` and `--interest=` alike), means all categories**, so every existing invocation keeps its current behaviour and a consumer that wants a reduced set must ask for one on each run; forgetting costs capture work, never a missed dependency. An unknown token alongside known ones is ignored (a newer consumer may name a category this build does not have); a value naming *no* known token is refused rather than silently widened to "all". |
| `--evidence SCOPE` | How much of what the monitor observes is **written down**. One of `full` (default) or `reads-only`. See [Evidence scope](#evidence-scope--how-much-of-what-is-observed-is-recorded) below (and [evidence-scope.md](contributors/evidence-scope.md)) — **`reads-only` carries a named hazard**. An unknown value is refused rather than widened to `full`. |
| `--capture-stdio` | Capture the child's merged stdout+stderr instead of inheriting the parent's stdio (mirrors how the reprobuild engine launches monitored actions). |
| `--capture-stdio-path PATH` | Like `--capture-stdio`, but dump the captured bytes to PATH (implies `--capture-stdio`). |
| `--` | End of options; everything after is the command + args to run. **Required.** |

With `--events text` / `--events jsonl` and no `--event-stream`, the rendered
event stream goes to **stderr**.

Example — capture what a compile reads/writes:

```sh
io-mon run --depfile build.iomon -- cc -c hello.c -o hello.o
io-mon inspect build.iomon
```

#### Evidence scope — how much of what is observed is recorded

```sh
io-mon run --evidence=full        # the default
io-mon run --evidence=reads-only
```

`--evidence` selects **how much of what the monitor observes is written down**.
It does not change what the monitor observes: the same events are detected
either way, and a monitoring *failure* still downgrades the capture to
`mcIncomplete` exactly as it does today.

`full` records every observation, including **failed lookups** — searches for
paths that do not exist.

`reads-only` records only lookups that **found something**. Measured on one
`nim c` in this repo, with 81 `--path` entries on the command line: **8,663
records down to 2,548 (−70.6%)**, and the 6,115 records removed are failed
existence lookups and nothing else — the set of lookups that found something is
identical in both captures. A build performs far more searching than reading,
and most of what it searches for is absent.

It exists so io-mon's dependency evidence can be compared like for like with
tools that consume compiler-emitted depfiles (ninja via `gcc -MD`), which list
headers actually opened and never headers searched for.

Omitting `--evidence` means `full`. Writing it and naming nothing this build can
evaluate — an unknown scope (`--evidence=writes-only`) or no scope at all
(`--evidence=`) — is refused, naming what was rejected and the valid set, rather
than being widened back to `full`: silently widening would discard the reduction
you asked for without a word.

##### The hazard, exactly

The risk is **one-directional**. It affects the question *"is this build up to
date?"*, and only for changes of one shape — something that did not exist, or
could not be reached, becoming available:

| change to your tree | detected under `reads-only`? |
|---|---|
| a file the build read is **modified** | ✓ yes |
| a file the build read is **deleted** | ✓ yes |
| a file is **added** that shadows one earlier in a search path | ✗ **no** |
| a file that **exists but could not be opened** becomes openable (a `chmod`, a directory replaced by a file) | ✗ **no** |

Rows 3 and 4 are one rule with two faces: **`reads-only` records only lookups
that succeeded, so any later change that makes an unsuccessful lookup succeed is
invisible.** Row 1 does not cover row 4, however much it looks as though it
should — the file is **not recorded at all**, so "a file the build read" never
names it.

Row 4 exists because the record cannot tell *why* a lookup failed: `open`
returns `-1` for `ENOENT` and for `EACCES` alike, a failed `stat` is classified
as "absent" whatever the reason, and no errno is carried in the depfile. So
`EACCES`, `EISDIR` and `ELOOP` lookups are dropped alongside genuine absences.
Measured on a real `nim c`: 5 of 2,104 dropped records name a path that exists
(all `/dev/tty`).

Worked example: compiling a module, the compiler looks for
`libs/repro_core/src/repro_core/types.nim`, does not find it, and resolves
`types` from elsewhere. Under `full` that failed lookup is recorded, so creating
that file later invalidates the action. Under `reads-only` it is not recorded,
the key is unchanged, and the build reports "up to date" while compiling against
the old module. This is the same staleness ninja exhibits when you add a header
earlier in the include path.

Recovery is a capture at `--evidence=full` (or a clean build); nothing is
corrupted.

##### What it does **not** affect

- **What was built.** The output bytes are a function of the inputs actually
  used, so a narrower *record* of those inputs does not change the artefact.
- **Completeness grading.** `reads-only` is a deliberate choice, not a
  monitoring failure, so it does not report `mcIncomplete`; a real monitoring
  failure still does. An `mrEventLoss` can never be dropped by the narrowing.

##### How a consumer is protected

Every depfile records the scope it was captured under. Read it through the
accessors, never off the field:

```nim
let dep = readMonitorDepFile(path)
if not observedEvidenceScopeCovers(dep, esFull):
  if statesUnevaluableEvidenceScope(dep):
    echo "capture declares evidence scope '",
      dep.observedEvidenceScopeToken, "', which this build cannot evaluate"
  # …recompute locally rather than trust it.
```

- **Absent** stamp ⇒ `esFull`. Every depfile written before this existed
  recorded everything, so it keeps its meaning.
- **Present and recognised** ⇒ that scope.
- **Present but unrecognised** (a scope a newer io-mon added) ⇒ covers nothing;
  every consumer rejects, and `observedEvidenceScopeToken` names what it
  declared so the residual can be reported rather than merely detected.

The check is one-way on purpose: full evidence is strictly stronger, so it is
always acceptable to a `reads-only` consumer. The scope is **not** part of any
action-cache key — keying on it would stop a careful teammate's full-evidence
result from being usable by anyone who opted into the reduced scope.

### `io-mon inspect` — render an existing depfile

```
io-mon inspect <depfile> [--format text|json]
```

`inspect` decodes and prints a previously captured iomon depfile. The format
defaults to `text`; `json` emits the full structured form. (`--events` is
accepted as an alias for `--format` here.)

> **Note:** `inspect` supports only `text` and `json`. `jsonl` is a *streaming*
> mode for `run --events jsonl`, not an `inspect` format — passing
> `--format jsonl` to `inspect` errors. (`renderMonitorDepFile` in
> `src/io_mon/render.nim` only implements `text` and `json`.)

Sample `text` output:

```
iomon version=1 records=4 completeness=mcComplete
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
| `REPRO_MONITOR_SHIM_LIB` | **Operator override** for the shim shared-library path. Honoured first by `findShimLibrary()`; otherwise the canonical `build/lib/librepro_monitor_shim.<ext>` layout is probed. A set-but-nonexistent value is a **hard error**, never a silent fall-back to a discovered shim — see below. |
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

let dep = readMonitorDepFile("build.iomon")   # raises MonitorDepFileReaderError on bad/partial data
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
  file (a partial iomon write fails validation by design — it must not be
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
  string if no discovery candidate is found. If `$REPRO_MONITOR_SHIM_LIB` is
  **set but does not name an existing file**, this raises `IOError` rather than
  returning a discovered shim: an override is a pin, so honouring it "first"
  has to mean honouring it, not preferring it. Falling through would run the
  capture under a *different* shim than the operator pinned and still report
  `mcComplete`, with no diagnostic anywhere — a stale pin or a typo would
  silently change the provenance of the evidence.

### The public host API — `runMonitored` (the blessed parent-host entry point)

A parent that wants io-mon's guarantees around an arbitrary command should call
the **public batch host API** rather than shelling out to the CLI or
hand-rolling the shm/consumer setup:

```nim
import io_mon

var req: FsSnoopRequest
req.command = @["cc", "-c", "hello.c", "-o", "hello.o"]
req.depFilePath = "build.iomon"
req.streamMode = fsoNone

let res = runMonitored(req)          # owns the ENTIRE lifecycle
if res.exitCode == 0 and res.completeness == mcComplete:
  for r in res.records:
    if r.kind in {mrFileRead, mrLibraryLoad}: echo "input: ", r.path
else:
  discard                            # mcIncomplete ⇒ conservatively re-run
```

- `runMonitored(req: FsSnoopRequest): MonitorResult` — the §5 consumer-side
  batch entry point, and the reference behaviour every other launch path is
  diffed against. It runs the whole producer/consumer lifecycle: resolve
  the shim → (Linux) create the consumer-owned `nim-shm-gset` and export
  `REPRO_MONITOR_DEP_SHM` + `REPRO_MONITOR_APP_ID` → inject the shim and spawn
  the process tree → wait → run the §4.1 descendant grace → snapshot the deduped
  set → write the canonical depfile (passing the spawned root pid as the R1
  root-guard) → on finish `markConsumerGone` + detach. **LF-2** (no orphan
  spill: a producer never runs without a consumer) and **LF-4** (consumer
  liveness) hold *by construction* for any parent that uses it.
  Prefer this to copying `fs_snoop`'s driver: a copy that skips the set/consumer
  setup is exactly the producer-with-no-consumer bug (LF-2) this API prevents.
  It still raises on a genuine setup failure (no shim / unsupported platform);
  the CLI wrapper `runFsSnoopCli` converts those to a diagnostic + non-zero exit.
  Since DH-2 it is literally `finishMonitor(startMonitor(req))` — see
  *The decomposed host API* below — so the batch and streaming forms are one
  implementation and cannot drift apart.
- `MonitorResult` — `exitCode` (the monitored command's status), `depFilePath`
  (where the canonical iomon depfile was written), and `depFile` (the merged
  `MonitorDepFile`: `records`, `completeness`, summary, …). Convenience
  accessors `res.completeness` and `res.records` read through to `depFile`.

`REPRO_MONITOR_APP_ID` scopes the cross-restart reaper so one application never
reaps another's shared-memory segments; it defaults to `"io-mon"`. A consumer
that shares a segments directory (e.g. reprobuild/codetracer) sets it to its own
tag before calling `runMonitored`, and the API re-exports the resolved value to
the child so producers derive the same reaper scope.

### Per-call environment and working directory

`FsSnoopRequest.env` (a `seq[(string, string)]`) and `FsSnoopRequest.cwd` apply
to the monitored child ONLY. `env` entries are layered on top of the environment
this process already has (later duplicates win), and io-mon's own injection
variables are applied on top of those, so a caller can extend `LD_PRELOAD` but
cannot switch monitoring off by accident. `cwd` empty means "inherit the host's
current directory". On Windows the composed environment is case-insensitive, as
the OS's is, so a `Path` entry in `env` overrides the inherited `PATH` rather
than joining it as a second variable — and, for the same reason, spelling an
injection variable in a different case does not get you a second copy that might
win: `repro_monitor_shim_lib` in `env` still loses to io-mon's
`REPRO_MONITOR_SHIM_LIB`.

`runMonitored` mutates **nothing** process-global on any of the three arms: the
injection variables travel through the spawn, so N monitors may run concurrently
on N threads of one host process and each gets its own uncontaminated evidence
(IoMon-Decomposed-Host-API DH-1). On POSIX the spawn is
`osproc.startProcess(env = …)`; on Windows it is
`stackable_hooks.runWithMonitorShim`, whose `env` parameter takes the child's
**complete** environment and encodes it into an explicit `CreateProcessW`
environment block. All three arms compose that environment with one helper
(`fs_snoop.childEnv`), so the layering rule above holds identically everywhere.

One residual exception, documented at the call site: on **macOS** `osproc`
implements `workingDir` with a process-global `setCurrentDir` around
`posix_spawn`, so a non-empty `cwd` is not thread-safe there. Linux `chdir`s in
the forked child and Windows passes `lpCurrentDirectory`, so both are.

Executable resolution still uses the HOST's `PATH` on every arm, and `env` does
not redirect it — same answer on all three arms, reached three different ways:

- **Linux.** `osproc`'s fork path resolves `command[0]` with `findExe` *inside
  the forked child*, whose `environ` is still the parent's, and then `execve`s
  the resolved absolute path with the child's environment. The search therefore
  never sees `env`.
- **macOS.** `osproc` uses `posix_spawnp(…, env)` instead, and `posix_spawnp`
  takes its `PATH` from the **calling** process's environment, not from the
  `envp` it is handed.
- **Windows.** `CreateProcessW` is called with `lpApplicationName = NULL`, whose
  documented search uses the **calling** process's `PATH` and never
  `lpEnvironment`'s. (`runWithMonitorShim` resolves a bare `command[0]` with
  `findExe` for its MSYS/Cygwin fork-runtime check, i.e. from that same host
  `PATH`, so the image it inspects is the image that runs.)

Only the Linux row has been verified by execution in this workspace; the other
two are read off the platform contracts. Pass an absolute `command[0]` when
`env` changes `PATH` and you care which binary runs. `depFilePath`,
`eventStreamPath` and `captureStdioPath` are resolved by the host, not the
child, and are unaffected by `cwd`.

### The decomposed host API — `startMonitor` / `pollMonitor` / `finishMonitor`

`runMonitored` blocks until the monitored command exits, which serialises a
caller whose scheduler polls N in-flight children in one loop. The same
lifecycle is therefore available in three steps (IoMon-Decomposed-Host-API
DH-2):

```nim
var handles: seq[MonitorHandle] = @[]
for req in requests:
  handles.add startMonitor(req)          # consumer up, tree spawned, no wait

var results: seq[MonitorResult] = @[]
var remaining = handles.len
while remaining > 0:
  for i in 0 ..< handles.len:
    if handles[i].live and pollMonitor(handles[i]):   # never blocks (see below)
      results.add finishMonitor(move(handles[i]))     # CONSUMES the handle
      dec remaining
  sleep(5)
```

- `startMonitor(req: FsSnoopRequest): MonitorHandle` — everything `runMonitored`
  does before its wait. Raises on a genuine setup failure, and a raise leaves
  nothing behind (no spawned tree, no mapped consumer, no scratch directory).
- `pollMonitor(h: var MonitorHandle): bool` — `true` once the monitored root has
  exited. Non-blocking on POSIX. It is not a drain: the transport dedups at the
  producer and is snapshotted once at finish, so polling more often gets no
  consumer-side work done sooner — what it buys is the caller's own scheduling.
  Raises `ValueError` on a handle that is not live.
- `finishMonitor(h: sink MonitorHandle): MonitorResult` — waits if the root has
  not exited, runs the §4.1 descendant grace (unskippably — see below),
  snapshots the set, writes the canonical depfile, releases the consumer. The
  result is obtainable only by giving up the handle.
- `monitorLifecycleCounts(): tuple[started, finished, released, live, settled: int]`
  — the process-wide census. A host can assert `live == 0` at shutdown;
  `finished < released` means somebody dropped a handle; `settled` counts the
  monitors whose §4.1 descendant guard ran, and equals `finished` (see below).

**The §4.1 descendant guard is not yours to remember** (DH-3). A monitored tree
can leave a DETACHED DESCENDANT behind — the root exits, but a daemonized child
keeps reading and writing files outside the evidence. io-mon detects that by
scanning `/proc/*/environ` for this run's injection needles and, past a grace
window (`IO_MON_LINUX_DESCENDANT_GRACE_MS`, default 500), publishing an
event-loss marker that downgrades the edge to `mcIncomplete`. Reporting
`mcComplete` where the batch entry point reports `mcIncomplete` would be a false
cache hit for the whole action, so the guard is **not** exported as a step you
call: it is the first act of the single funnel every `MonitorResult`'s evidence
is produced by, and that funnel refuses to merge for a monitor the guard has not
marked. A decomposed host therefore grades an edge exactly as `runMonitored`
does, and cannot opt out. Pinned by
`tests/linux/test_io_mon_external_host_descendant_guard.nim`, which runs a real
detached descendant past a real grace window down both launch paths.

**The two launch paths produce the same evidence, and that is measured** (DH-4).
`runMonitored` and a host driving `startMonitor` → `pollMonitor` →
`finishMonitor` yield an identical `MonitorDepFile` for the same action — the
same records, the same completeness, the same loss markers, the same backend
diagnostics — down to the detached-descendant case, not just the happy path.
Pinned by `tests/linux/test_io_mon_evidence_identical_across_launch_paths.nim`,
which renders every field of both edges and compares them byte for byte.

Two things a host should know about that guarantee, because they bound it:

- **What cannot be equal, and is normalised in the comparison:** OS pids (and
  the child pid an `mrProcessSpawn` carries in `result`), the per-call run id
  stamped into a record's `detail` as `run=<id>`, the pid list a §4.1 marker
  carries as `pids=…`, and the kernel object id in a `localfd:<dev>:<ino>`
  channel pseudo-path. Everything else — every real filesystem path included —
  matches exactly.
- **WHEN you finish a monitor is yours to choose, and it moves the grace
  window.** The §4.1 window opens when `finishMonitor` runs, which for a polled
  host is whenever its scheduler gets round to it. A descendant that dies in
  that extra interval is graded `mcComplete` by a host that dawdled and
  `mcIncomplete` by one that did not — on identical inputs, with nothing wrong.
  That is inherent to owning the wait, not a defect: the grade is an honest
  statement about what was still alive when the launcher looked. A host that
  wants the batch entry point's timing should call `finishMonitor` as soon as
  `pollMonitor` answers `true`.

A DROPPED handle does not run the guard, deliberately: it is an EVIDENCE step,
and a dropped handle publishes no edge for a loss marker to downgrade. The
SAFETY of a surviving descendant does not depend on it — the root is reaped
before the consumer is released, and a descendant that outlives the consumer
then fast-fails with `emConsumerGone` instead of growing a set with no reader.

**`MonitorHandle` is exclusive, and dropping it finishes it.** Moving the wait
out of `runMonitored` is what re-opens the LF-2 window (§4.1: a producer still
publishing into a fragment directory its launcher has already deleted), so the
handle carries the guarantee itself rather than asking the caller to remember a
rule:

- it **cannot be copied** (`=copy` is `{.error.}`), so two owners of one consumer
  is not a state that can be written down — and the restriction propagates
  through `seq`s, arrays and wrapping objects, which is what an N-way poll loop
  holds; and
- **dropping it reaps the monitored root before releasing the consumer**
  (`=destroy`), on every path out of the owning scope including an exception.
  So an early `return`, a `break`, or a forgotten `finishMonitor` costs you the
  WAIT you tried to skip and the EVIDENCE you did not ask for — never an
  orphaned producer. Nothing is killed: dropping a handle blocks exactly as long
  as `runMonitored` would have.

A host killed with `SIGKILL` runs no destructor; that case belongs to the
`shm_gset` cross-restart reaper and is no different from `runMonitored`.

> **WINDOWS.** `stackable_hooks.runWithMonitorShim` spawns and waits in one
> blocking call and exposes no pollable handle, so on that arm `startMonitor`
> only prepares the injection (nothing is running when it returns) and the first
> `pollMonitor` performs the whole run before answering `true`. An N-way poll
> loop therefore executes serially there. Stated rather than hidden behind a
> `false`, which would spin forever. Lifting it needs a non-blocking spawn
> upstream.

### The launcher contract (completeness root-guard)

A consumer that spawns the **root** process under the shim itself (rather than
via `runFsSnoopCli`) **must** pass the root pid it spawned as `expectedRootPid`
to `mergeFragments`. This is the R1 root-guard. A root can fail to be monitored
without failing to run: on macOS a SIP/hardened/notarized root (e.g. `/bin/cat`)
strips `DYLD_INSERT_LIBRARIES`; on Windows an injected root whose shim loaded but
never initialised installs no hooks. Either way it emits no `mrProcessStart` and
leaves an empty fragment set, and without the root pid the merge falsely asserts
`mcComplete` over that empty set (a zero-effort false cache hit). Passing the pid
makes the merge downgrade an un-monitored root to `mcIncomplete`. The built-in
`runMonitored` already does this on all three arms — Windows since
nim-stackable-hooks' `WindowsInjectionResult` gained `rootPid`; any custom
launcher must too. Passing `0` (the default) preserves legacy behaviour for
callers merging hand-built fragment dirs with no single known root.
