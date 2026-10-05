# io-mon

> Cross-platform filesystem and process monitoring library and CLI. Traces exact file reads, writes, and path probes across process hierarchies with provable completeness guarantees for incremental builds.

📖 **Documentation: <https://metacraft-labs.github.io/io-mon/>** — complete user guide, CLI reference, library guide, and depfile format specification.

---

## Installation

### Quick install

Install the latest release using the official Metacraft Labs bootstrapper:

- **POSIX Shell (Linux, macOS, WSL)**:
  ```bash
  curl -fsSL https://install-package.metacraft-labs.com/io-mon/sh | sh
  ```
- **PowerShell (Windows)**:
  ```powershell
  irm https://install-package.metacraft-labs.com/io-mon/pwsh | iex
  ```

### Package managers

`io-mon` is published across official Metacraft package repositories:

- **Debian / Ubuntu**:
  ```bash
  sudo apt-get install -y metacraft-io-mon
  ```
  _(Requires `deb.metacraft-labs.com` repository keyring; see [docs](https://metacraft-labs.github.io/io-mon/getting_started/installation))_
- **Fedora / RHEL / openSUSE**:
  ```bash
  sudo dnf install -y metacraft-io-mon
  ```
  _(Requires `rpm.metacraft-labs.com` repository)_
- **macOS (Homebrew)**:
  ```bash
  brew tap metacraft-labs/metacraft
  brew install io-mon
  ```
- **Windows (Scoop)**:
  ```powershell
  scoop bucket add metacraft https://github.com/metacraft-labs/metacraft-desktop-packages
  scoop install io-mon
  ```
- **Nix**:
  ```bash
  nix profile install github:metacraft-labs/nixpkgs#io-mon
  ```

Direct binary archives and release checksums are available on [GitHub Releases](https://github.com/metacraft-labs/io-mon/releases).

---

## Quick Start

### Command Line CLI

Capture the dependencies of any build command into a binary `.iomon` depfile:

```bash
io-mon run --depfile compile.iomon -- gcc -c main.c -o main.o
```

Inspect the generated depfile in human-readable text:

```bash
io-mon inspect compile.iomon
```

Or format as structured JSON:

```bash
io-mon inspect compile.iomon --format json
```

### Nim Library

Use the `io_mon` package to drive monitored child executions or read depfiles programmatically:

```nim
import io_mon

# 1. Drive a monitored execution directly
var req: FsSnoopRequest
req.command = @["gcc", "-c", "main.c", "-o", "main.o"]
req.depFilePath = "compile.iomon"

let result = runMonitored(req)

# 2. Inspect the provable completeness signal
if result.exitCode == 0 and result.completeness == mcComplete:
  for r in result.records:
    if r.kind in {mrFileRead, mrLibraryLoad}:
      echo "Input: ", r.path
    elif r.kind == mrFileWrite:
      echo "Output: ", r.path
else:
  echo "Build failed or capture was incomplete; conservative invalidation required."
```

---

## Core Capabilities

- **Deep Process Hierarchy Tracking**: Traces child processes across `fork`, `execve`, and `posix_spawn` without missing short-lived sub-commands.
- **Exhaustive Filesystem Observation**: Intercepts file reads, writes, path existence checks (`stat`/`access`), directory listings, dynamic library loads (`dlopen`), and memory write-backs (`mmap`).
- **Honest Completeness Guarantee**: Every capture reports an explicit `completeness` signal (`mcComplete` or `mcIncomplete`). Consumers never rely on false cache hits from unmonitored binaries or dropped events.
- **Evidence Scopes**: Choose between `full` evidence (records all lookups including failed probes) and `reads-only` evidence (records successful reads only, matching compiler depfiles).
- **Public Batch & Event-Loop APIs**: Supports both blocking batch execution (`runMonitored`) and non-blocking event-loop polling (`startMonitor` / `pollMonitor` / `finishMonitor`).

---

## Documentation

- **[User Guide & Reference](https://metacraft-labs.github.io/io-mon/)** (source in `docs/site/`):
  - [Overview & Concepts](https://metacraft-labs.github.io/io-mon/getting_started/overview)
  - [Installation Guide](https://metacraft-labs.github.io/io-mon/getting_started/installation)
  - [Quickstart Tutorial](https://metacraft-labs.github.io/io-mon/getting_started/quickstart)
  - [Monitoring Builds](https://metacraft-labs.github.io/io-mon/guides/monitoring-builds)
  - [Capturing & Streaming Events](https://metacraft-labs.github.io/io-mon/guides/capturing-events)
  - [Evidence Scope & Hazards](https://metacraft-labs.github.io/io-mon/guides/evidence-scope)
  - [Library Usage (Nim)](https://metacraft-labs.github.io/io-mon/guides/library-usage)
  - [CLI Reference](https://metacraft-labs.github.io/io-mon/reference/cli-reference)
  - [Depfile Format & Records](https://metacraft-labs.github.io/io-mon/reference/depfile-format)
  - [Environment Variables](https://metacraft-labs.github.io/io-mon/reference/environment-variables)
- **Contributor Guides**:
  - [`docs/contributors/architecture.md`](docs/contributors/architecture.md) — internal architecture, interception mechanisms, and SIP handling.
  - [`docs/contributors/building-and-testing.md`](docs/contributors/building-and-testing.md) — compilation instructions, test suite structure, and CI gates.
  - [`docs/contributors/event-transport-and-loss-freedom.md`](docs/contributors/event-transport-and-loss-freedom.md) — shared memory transport and loss-freedom invariants.
  - [`docs/contributors/shim-build-policy.md`](docs/contributors/shim-build-policy.md) — compilation flags, thread-local storage rules, and hook safety.
  - [`docs/contributors/evidence-scope.md`](docs/contributors/evidence-scope.md) — evidence scope implementation details.
- **Developer Instructions**: See [`AGENTS.md`](AGENTS.md).

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
