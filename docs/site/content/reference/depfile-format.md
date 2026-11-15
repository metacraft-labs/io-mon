---
title: Depfile Format & Records
description: Detailed technical specification of the .iomon binary depfile header, body, record taxonomy, and completeness states.
section: reference
order: 2
---

# Depfile Format & Records

`io-mon` depfiles are stored in a compact, canonical binary format with the `.iomon` extension.

---

## File Header

Every `.iomon` file begins with a binary header:

- **Magic Identifier**: 4 bytes (`IOMN`).
- **Format Version**: Wire version number (currently `2`). A reader accepts every version from `1` up to the one it
  was built with, and rejects a newer file as `mrUnsupportedVersion`. The version is bumped whenever a writer can emit
  bytes an older reader would reject, such as a new record kind (`IomonVersion` in `src/io_mon/types.nim`). Version `2`
  added `mrConnectAttempt`.
- **Producer Version**: Version identifier of the `io-mon` binary that wrote the file.
- **Backend Family**: Identifies the host capture engine (`posix-preload`, `macos-interpose`, `windows-shim`).
- **Completeness Status**: The critical validation flag:
  - `mcComplete`: The capture observed every operation with provable integrity.
  - `mcIncomplete`: The monitor detected unmonitored boundaries, dropped events, or unaccounted daemons.

---

## Record Taxonomy (`MonitorRecordKind`)

The depfile body consists of a sequence of binary records representing discrete operations:

| Record Kind            | Description                                     | Key Fields                         |
| :--------------------- | :---------------------------------------------- | :--------------------------------- |
| `mrProcessStart`       | Process initialization under the monitor        | `osPid`, `parentOsPid`, `path`     |
| `mrProcessExec`        | Execution of a new binary image via `execve`    | `osPid`, `path`                    |
| `mrProcessSpawn`       | Creation of a child process                     | `osPid`, `childPid`                |
| `mrFileOpen`           | File descriptor acquisition                     | `osPid`, `path`, `flags`           |
| `mrFileRead`           | Content read from a regular file or link        | `osPid`, `path`                    |
| `mrPathProbe`          | File metadata check (`stat`, `access`)          | `osPid`, `path`, `probeResult`     |
| `mrFileWrite`          | File creation, modification, or truncation      | `osPid`, `path`                    |
| `mrDirectoryEnumerate` | Reading directory entries (`opendir`/`readdir`) | `osPid`, `path`                    |
| `mrLibraryLoad`        | Shared library load (`dlopen`, `LoadLibraryW`)  | `osPid`, `path`, `detail`          |
| `mrIpcConnect`         | Connection to a UNIX or TCP socket              | `osPid`, `path`, `detail`          |
| `mrConnectAttempt`     | Failed TCP (AF_INET/AF_INET6) connect           | `osPid`, `path`, `detail`          |
| `mrEventLoss`          | Transport buffer saturation or dropped event    | `osPid`, `detail`                  |
| `mrBackendProfile`     | Environmental telemetry and host flags          | `detail`                           |
| `mrCapabilityGap`      | Platform boundary that prevented observation    | `detail`                           |

---

## Record Data Structure

In Nim, records are represented by the `MonitorRecord` object:

```nim
type
  MonitorRecord* = object
    kind*: MonitorRecordKind
    observationKind*: uint8
    seq*: uint64
    osPid*: int64
    parentOsPid*: int64
    threadId*: int64
    childOsPid*: int64
    result*: int64
    flags*: uint32
    probeResult*: uint8
    path*: string
    detail*: string
```

### Path Spelling

On Linux and macOS a recorded file path is the path as the process spelled it, made absolute. It is **not**
symlink-resolved, and it can still contain `..`:

- A relative path is made absolute using the process's working directory at the moment of the call (or, for a `*at`
  call, the directory its descriptor names). On macOS, when that directory cannot be named, the path is kept as passed
  and the capture is graded incomplete, so a consumer never anchors it on a guessed directory.
- Only a leading `..` of a relative path is folded into that directory. A `..` after a component of the path is kept,
  because in `link/../x` it applies to where `link` points, not to the directory that holds `link`.
- An absolute path is recorded unchanged.

A consumer that asks whether a path lies beneath some root must therefore resolve it itself, lexically and through
symlinks, rather than compare the recorded text: `/root/a/../../etc/passwd` and `/root/link/secret` (with `link` a
symlink out of `/root`) both start with `/root/`.

- On Windows, paths are normalized to uppercase drive letters and backslash delimiters.

### The Process-Start Image

The `path` of an `mrProcessStart` is the exception to the rules above: it is the file the process image runs, as the
kernel resolved it (`/proc/self/exe` on Linux, `proc_pidpath` on macOS, `QueryFullProcessImageNameW` on Windows),
absolute and symlink-resolved. It names the program that ran even when the exec or spawn record only carries a bare
name looked up in the program's own `PATH`, a relative path, or a descriptor. An image that could not be read is an
empty `path` with the `detail` token `image=unresolved`. Like every shim record it is reported by the monitored process
itself, so it is as trustworthy as the exec and file records and no more. See `docs/usage.md`, "The process-start
image".
