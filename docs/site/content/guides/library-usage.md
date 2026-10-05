---
title: Library Usage (Nim)
description: Programmatic integration with io_mon in Nim, covering depfile parsing, runMonitored, and the decomposed host API.
section: guides
order: 4
---

# Library Usage (Nim)

The `io_mon` package provides a high-level, idiomatic Nim library for driving monitoring sessions, managing process lifecycles, and parsing canonical depfiles.

```nim
import io_mon
```

Importing `io_mon` re-exports the full public API across `types`, `reader`, `writer`, `render`, and `fs_snoop`.

---

## Reading & Validating Depfiles

Use `readMonitorDepFile` to load and decode `.iomon` files:

```nim
import io_mon

try:
  let dep = readMonitorDepFile("build.iomon")

  # 1. Always verify completeness before trusting dependencies!
  if dep.completeness != mcComplete:
    echo "Warning: capture is incomplete (reason: ", dep.capabilityGaps, ")"
    quit(1)

  # 2. Iterate through recorded observations
  for r in dep.records:
    case r.kind
    of mrFileRead, mrLibraryLoad:
      echo "Input file: ", r.path
    of mrFileWrite:
      echo "Output file: ", r.path
    of mrPathProbe:
      echo "Probed existence: ", r.path, " (result: ", r.probeResult, ")"
    else:
      discard

except MonitorDepFileReaderError as e:
  echo "Corrupt or invalid depfile: ", e.msg
```

For non-raising decoding, use `tryReadMonitorDepFile`:

```nim
let res = tryReadMonitorDepFile("build.iomon")
if res.depFile.isSome:
  let dep = res.depFile.get()
  # ...
```

---

## Driving Monitored Executions

Instead of invoking the CLI out-of-process, host applications can drive monitoring directly in Nim.

### 1. Batch API (`runMonitored`)

The simplest approach is `runMonitored`, which synchronously runs a command, manages shared-memory setup and teardown, waits for completion, and returns a `MonitorResult`:

```nim
import io_mon

var req: FsSnoopRequest
req.command = @["cc", "-c", "main.c", "-o", "main.o"]
req.depFilePath = "build.iomon"
req.streamMode = fsoNone

let result = runMonitored(req)

if result.exitCode == 0 and result.completeness == mcComplete:
  echo "Successfully built and captured ", result.records.len, " records."
else:
  echo "Command failed (exit code ", result.exitCode, ") or capture was incomplete."
```

#### Safety Properties

- **Zero Orphan Guarantee**: Allocates and binds shared-memory transports so that monitored child processes never outlive their monitoring session.
- **Thread Safety**: Does not modify process-global environment variables during spawn; multiple threads in a host process can execute concurrent `runMonitored` calls safely.

---

### 2. Decomposed API (`startMonitor` / `pollMonitor` / `finishMonitor`)

When building a build engine or job runner that executes many commands concurrently in a single non-blocking event loop, use the decomposed host API:

```nim
import std/os
import io_mon

var handles: seq[MonitorHandle] = @[]

# Launch multiple monitored jobs concurrently
for job in jobs:
  var req: FsSnoopRequest
  req.command = job.command
  req.depFilePath = job.outDepfile
  handles.add startMonitor(req)

# Non-blocking poll loop
var results: seq[MonitorResult] = @[]
var pending = handles.len

while pending > 0:
  for i in 0 ..< handles.len:
    if handles[i].live and pollMonitor(handles[i]):
      # finishMonitor consumes the handle (sink argument)
      results.add finishMonitor(move(handles[i]))
      dec pending
  sleep(5)
```

#### Key Guarantees of the Decomposed API

1. **Strict Linearity (`MonitorHandle`)**: `MonitorHandle` cannot be copied (`=copy` is disabled). The only way to obtain the resulting `MonitorResult` is to move and consume the handle with `finishMonitor`.
2. **Deterministic Cleanup**: If a `MonitorHandle` is dropped early (e.g. due to an exception, `break`, or early `return`), its destructor reaps the monitored child and tears down shared-memory segments before releasing resources, avoiding leaked child processes.
3. **Detached Descendant Guard**: If a child forks a background daemon that stays alive after the main process exits, `finishMonitor` detects surviving descendant processes, flags event loss, and safely downgrades the capture to `mcIncomplete`.
