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

#### How that invariant is actually enforced

The rule above was, for a period, stated here and not wired. `depFileFromOwnedRecords`
derived the backend profile with an **empty required-set**, and a declared capability
gap only clears `evidenceComplete` when it is marked `required` — which only happens
for capabilities in that set. So every backend gap was emitted with `required=false`
and could not affect completeness. A backend could declare in the depfile that it
cannot observe an entire class of inputs and still report `mcComplete`; Linux did
exactly that for library loads, and a monitored `gcc -c` reported `mcComplete` having
observed none of the ten shared objects it loaded.

The fix is `InputEvidenceCapabilities` (`src/io_mon/capabilities.nim`), passed as the
required-set when a depfile is finalised. It is the set of capabilities whose absence
means **an input channel is unobserved**, and it is deliberately narrower than "every
declared gap":

| Gap class | Example | Downgrades? | Why |
| --- | --- | --- | --- |
| Missing input channel | `mcapLibraryLoad` | **yes** | Real content inputs, observed by nothing else, no substitute record |
| Alternative backend | `mcapEndpointSecurity`, `mcapHybrid` | no | Says another implementation was not used, not that anything went unobserved |
| Enforcement | `mcapAuthorizationEnforcement` | no | io-mon observes; it never claimed to deny |
| Output-side / identity | `mcapPathMutation`, `mcapPathIdentity` | no | A missed mutation record is not an input a cache key silently omits |
| Partial with a substitute | `mcapSymlink`, `mcapExternalContent` | no | A read through a symlink still records a path resolving to the same bytes |
| Threat model | `mcapAdversarialRawSyscall`, `mcapExecutableMappingLifecycle` | no | The profile's diagnostics already tell consumers to request these explicitly |

Downgrading on *every* declared gap would make Linux permanently `mcIncomplete` and
destroy the signal — a different way of being useless, not a fix. A consumer that
wants a wider bar still calls `evaluateMonitorEvidence` with its own required-set;
`InputEvidenceCapabilities` is the floor, not the ceiling.
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
- **Library-Load Observation (`dl_iterate_phdr`)**: `ld.so` maps a shared object through
  internal `__mmap` / `__open64_nocancel` calls that do **not** traverse `LD_PRELOAD`
  symbol interposition, so no file hook can ever see a loader-driven load. io-mon
  therefore **asks the loader for its link map** instead of hooking the calls that
  populate it — the Linux counterpart of the macOS arm's
  `_dyld_register_func_for_add_image`. Scans run at shim init (which sees the *entire*
  initial closure, because `ld.so` maps everything before running any ELF constructor),
  after each interposed `dlopen`/`dlmopen` (before the handle is returned, so the
  dependency is published before the program can act on it), and at shutdown.
  Coverage is **proven, not assumed**: each scan compares the count of newly-enumerated
  objects against the loader's own cumulative `dlpi_adds`, so a load that happened
  without being enumerated — a loader-internal `__libc_dlopen_mode` undone before the
  next scan — is detected and emits an event-loss marker that downgrades the capture.
  Residual: a process `SIGKILL`ed before its shutdown scan loses the closing account
  (the pre-existing kill-before-flush inherent-loss class). `LD_AUDIT`'s `la_objopen`
  would close that at the cost of a second injected copy of io-mon per process, in its
  own link-map namespace — see `docs/cases/dlopen-runpath-transparency.md` alternative C.
- **File Transfers**: Tracks vector/zero-copy operations (`pread`, `readv`, `sendfile`, `copy_file_range`, `splice`) and records them as reads/writes.
- **Non-File Tracking**: Logs `getenv`, `uname`, `sysconf` accesses, system time calls, and entropy (non-determinism) events. The entropy surface is `getrandom` (libc symbol, raw syscall and vDSO entry) plus the glibc >= 2.36 BSD set `getentropy` / `arc4random` / `arc4random_buf` / `arc4random_uniform`, deduped once per process per source — the same cross-platform observation contract the macOS shim follows (see `mrNonDeterministic` in `src/io_mon/types.nim`).

### Windows

- **Hook Injection**: Hooks APIs using `CreateRemoteThread` and `LoadLibraryW` to inject shims into child processes, mirroring macOS environment variables.

---

## 4. Relocation & Sibling Topologies

`io-mon` is structured as a relocated standalone package extracted from `reprobuild`.

- It maintains zero dependency on `reprobuild`.
- It depends solely on `nim-stackable-hooks`.
- Standardized binary format (`RMDF` version 1) and ABI names (`repro_monitor_shim_*`) are kept byte-identical so it remains a drop-in replacement across the suite.
