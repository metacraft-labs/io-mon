# io-mon

`io-mon` is a cross-platform filesystem and process monitoring library and command-line tool written in Nim. It tracks the exact files read, written, and probed by a monitored process tree, exporting them to a compact, canonical binary format called the Repro Monitor Depfile Format (`RMDF`).

It is used by incremental build systems and test runners (like `reprobuild` and `CodeTracer`) to determine dependency sets with a strong completeness guarantee.

## Features

- **File System Observation**: Captures file opens, reads, writes, path probes (`stat`, `access`), and directory listings.
- **Process Tracking**: Traces the entire lifetime of a spawned process tree across forks, execs, and spawns.
- **IPC Detection**: Observes IPC connections (`connect` calls to TCP or UNIX sockets) to detect out-of-tree dependencies (like compiler daemons).
- **Hidden Dependency Resolution**: Captures shared library loads, hardlinks, copy-on-write (`clonefile`) mappings, and shared memory write-backs (`mmap`).
- **Completeness Signal**: Includes an honest completeness status (`mcComplete` / `mcIncomplete`). If any event could not be observed reliably (e.g., hardened binaries, inline system calls, or unmonitored daemons), it immediately downgrades to incomplete, enabling consumers to fail-safe and trigger rebuilds.

## Platform Support

- **macOS**: Utilizes dynamic library insertion (`DYLD_INSERT_LIBRARIES` interposition) combined with system-level function body patching to ensure complete capture, bypassing SIP limitations.
- **Linux**: Injects hooks via `LD_PRELOAD` alongside raw assembly system call patching using a SIGTRAP/INT3 substrate to capture low-level and static binary activity.
- **Windows**: Injects monitoring hooks via remote thread creation (`CreateRemoteThread` + `LoadLibraryW`).

## Quick Start

### Command Line CLI

Build the CLI using `just` or `nimble`:

```bash
just build
```

Capture the dependencies of a compilation run:

```bash
build/bin/io-mon run --depfile compile.rdep -- gcc main.c -o main
```

Inspect the generated binary depfile in text format:

```bash
build/bin/io-mon inspect compile.rdep
```

For full CLI options, environment variables, and config configurations, see [docs/usage.md](docs/usage.md).

### Library API

Import `io_mon` to programmatically parse, validate, and query dependency files in Nim:

```nim
import io_mon

let dep = readMonitorDepFile("compile.rdep")
if dep.completeness == mcComplete:
  for record in dep.records:
    if record.kind == mrFileRead:
      echo "Read file: ", record.path
```

## Documentation Directory

- **[docs/usage.md](docs/usage.md)**: Full guide to CLI flags, environment variables, and library APIs.
- **[docs/contributors/architecture.md](docs/contributors/architecture.md)**: Contributor details on mechanisms, SIP bypasses, and platform internals.
- **[docs/contributors/building-and-testing.md](docs/contributors/building-and-testing.md)**: Compilation instructions, test suite directory structure, and platform test writing guidelines.
- **[docs/contributors/shim-build-policy.md](docs/contributors/shim-build-policy.md)**: Threadvar/allocator re-entrancy rules and compilation settings for hook safety.
