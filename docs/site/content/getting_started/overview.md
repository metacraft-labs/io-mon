---
title: Overview & Concepts
description: Core concepts of io-mon, cross-platform interception mechanisms, process tracing, and honest completeness guarantees.
section: getting_started
order: 1
---

# Overview & Concepts

`io-mon` is designed to solve a fundamental challenge in incremental compilation and hermetic execution: **accurate, automatic dependency detection without compiler cooperation**.

Most traditional build systems rely on compiler-emitted dependency lists (such as `gcc -MD` generating `.d` files). While effective for standard C/C++ compilation, this model fails when:

- Compilers or tools do not emit depfiles.
- Build commands invoke multi-stage shell scripts, sub-processes, or generators.
- Implicit dependencies (shared libraries, dynamic configurations, path probes) are loaded outside the compiler's knowledge.

`io-mon` acts as a transparent, high-performance monitoring layer that wraps any command, traces all filesystem and process activity across child trees, and outputs a canonical binary depfile (`.iomon`).

---

## Architecture & Platform Mechanisms

`io-mon` employs distinct, low-overhead interception mechanisms tailored to each host operating system:

| Platform    | Injection Mechanism                   | Interception Techniques                                                                                                                                              |
| :---------- | :------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Linux**   | `LD_PRELOAD` dynamic linker insertion | C library function hooks, supplemented by raw assembly system call interception (`SIGTRAP`/`INT3`) for static and low-level binaries.                                |
| **macOS**   | `DYLD_INSERT_LIBRARIES` interposition | Function body patching to capture system library calls, paired with non-SIP tool drop-ins to maintain tracing across Apple's System Integrity Protection boundaries. |
| **Windows** | Early thread injection                | Remote thread creation (`CreateRemoteThread`) and module injection (`LoadLibraryW`) into spawned processes.                                                          |

### Process Lifecycle Tracking

When a monitored root process runs, `io-mon` tracks the full lifetime of all descendant processes across:

- `fork` and `vfork`
- `execve`, `fexecve`, and `posix_spawn`
- Windows process creation (`CreateProcessW`)

Every event records the exact originating `osPid`, `parentOsPid`, and `threadId`, producing a complete tree of execution.

---

## The Completeness Guarantee

The core design principle of `io-mon` is **honest completeness**:

> **Rule**: An incomplete dependency record is worse than no record at all. A false cache hit creates silent, persistent build corruption.

Every `.iomon` depfile contains a `completeness` field:

- **`mcComplete`**: The monitor observed every operation with provable integrity. The consumer can safely store action results in a cache.
- **`mcIncomplete`**: The monitor encountered an unmonitored boundary (such as an untracked SIP binary, an inline unhooked syscall, an out-of-band IPC connection, or buffer overflow). Consumers must treat this as a signal to conservatively invalidate or re-run the action.

---

## Evidence Scopes

`io-mon` supports two evidence capture modes:

1. **`full` (Default)**: Records every filesystem observation, including _failed lookups_ (e.g. searching for include files across search directories that returned `ENOENT`). This provides mathematically airtight cache invalidation: if a file is later created where an earlier lookup failed, the cache is invalidated.
2. **`reads-only`**: Records only files that were successfully opened or read. This reduces depfile size significantly (often 70%+ fewer records) and matches the behaviour of traditional compiler-emitted depfiles. However, it carries a specific hazard regarding newly created shadowing files. See [Evidence Scope & Hazards](/guides/evidence-scope) for details.

---

## Next Steps

- Proceed to [Installation](/getting_started/installation) to install `io-mon` on your system.
- Follow the [Quickstart](/getting_started/quickstart) to run your first capture.
- For deep contributor details on memory layout, lock-free ring buffers, and platform-specific shims, refer to the contributor documentation in [`docs/contributors/`](https://github.com/metacraft-labs/io-mon/tree/dev/docs/contributors).
