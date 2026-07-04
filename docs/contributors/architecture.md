# io-mon Architecture & Design

This document details the architectural principles, target platforms, correctess contract, and in-depth mechanism designs for `io-mon`.

---

## 1. Scope & Responsibilities

`io-mon` is a dedicated **observation layer** for filesystem and process activity. It is designed to trace a monitored process tree's accesses to gather precise dependency maps.

### What io-mon observes:

- **File System Operations**: Opens, reads, writes, existence probes (`stat`/`access`/`getattrlist`), and directory listings.
- **Hidden Dependencies**: Clonefile/CoW, hardlink aliases, `mmap(MAP_SHARED|PROT_WRITE)` write-backs, and low-level dynamic library mapping (bypassing hooked libc `open`).
- **Process Trees**: Child process creation (`exec`/`spawn`/`fork`).
- **IPC Linkage**: Out-of-process connections to daemons (AF_UNIX/AF_INET sockets including remote peer process IDs).

### What io-mon is NOT:

- **A build coordinator**: It doesn't schedule builds, enforce sandbox policies, or maintain dependency graphs.
- **A cache**: It only serves as the observer for tools like `reprobuild` or `codetracer` that implement their own caching / skip strategies.
- **Bi-directional**: The dependency tree is strictly one-way: `reprobuild → io-mon`, `codetracer → io-mon`.

---

## 2. Correctness Contract (The "Cardinal Sin")

The worst outcome of a monitored run is a **false complete signal**. If `io-mon` claims a capture is complete when it might have missed a file read/write, the consuming build system could make a false cache hit or skip a test suite run incorrectly.

To prevent this:

- `io-mon` defines a completeness enum: `mcComplete` | `mcIncomplete`.
- **Every uncertainty downgrades to `mcIncomplete`**.
- Scenarios triggering `mcIncomplete` include:
  - Interrupted or corrupt fragment log writing.
  - Spawning child processes under hardened/SIP-protected environments that prevent shim insertion.
  - Encountering inline assembly syscalls (`svc #0x80` in Go/static binaries) that bypass standard library wrappers.
  - IPC connection to unknown out-of-tree daemons.

---

## 3. Platform Monitoring Mechanisms

### macOS

- **Interpose (`__DATA,__interpose`)**: Standard DYLD technique. dyld rebinds the target binary's import bindings to our shim's thunks. It misses syscalls made inside standard libraries (e.g., `fopen` calling internal `open$NOCANCEL` inside `libsystem_c`).
- **Body-Patching**: Overwrites entry points of libsystem syscall wrappers (e.g., via `mach_vm_remap` overwrites). The constructor installs this automatically to catch all callers and close the interpose blind spot.
- **SIP Bypass**: System Integrity Protection (SIP) automatically strips `DYLD_INSERT_LIBRARIES` for binaries in `/bin`, `/usr/bin`, etc. `io-mon` handles this by mapping system calls to GNU drop-in equivalents (sandbox-tools) that are not protected by SIP.
- **Diagnostics (Debug builds only)**: Toggles such as `IO_MON_DEBUG_DISABLE_BODYPATCH`, `IO_MON_DEBUG_DISABLE_INTERPOSE`, and `IO_MON_DEBUG_SKIP` allow isolating mechanisms for A/B testing.

### Linux

- **`LD_PRELOAD` Shim**: Injects wrapper symbols that route filesystem activity to the monitor.
- **Raw Syscall Hooking**: Uses a raw-syscall SIGTRAP substrate to intercept inline `0f 05` assembly instructions inside main executable pages and custom dynamic libraries.
- **File Transfers**: Tracks vector/zero-copy operations (`pread`, `readv`, `sendfile`, `copy_file_range`, `splice`) and records them as reads/writes.
- **Non-File Tracking**: Logs `getenv`, `uname`, `sysconf` accesses, system time calls, and `getrandom` non-determinism events.

### Windows

- **Hook Injection**: Hooks APIs using `CreateRemoteThread` and `LoadLibraryW` to inject shims into child processes, mirroring macOS environment variables.

---

## 4. Relocation & Sibling Topologies

`io-mon` is structured as a relocated standalone package extracted from `reprobuild`.

- It maintains zero dependency on `reprobuild`.
- It depends solely on `nim-stackable-hooks`.
- Standardized binary format (`RMDF` version 1) and ABI names (`repro_monitor_shim_*`) are kept byte-identical so it remains a drop-in replacement across the suite.
