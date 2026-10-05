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
- **Format Version**: Wire version number (currently `1`).
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
| `mrProcessStart`       | Process initialization under the monitor        | `osPid`, `parentOsPid`, `threadId` |
| `mrProcessExec`        | Execution of a new binary image via `execve`    | `osPid`, `path`                    |
| `mrProcessSpawn`       | Creation of a child process                     | `osPid`, `childPid`                |
| `mrFileOpen`           | File descriptor acquisition                     | `osPid`, `path`, `flags`           |
| `mrFileRead`           | Content read from a regular file or link        | `osPid`, `path`                    |
| `mrPathProbe`          | File metadata check (`stat`, `access`)          | `osPid`, `path`, `probeResult`     |
| `mrFileWrite`          | File creation, modification, or truncation      | `osPid`, `path`                    |
| `mrDirectoryEnumerate` | Reading directory entries (`opendir`/`readdir`) | `osPid`, `path`                    |
| `mrLibraryLoad`        | Shared library load (`dlopen`, `LoadLibraryW`)  | `osPid`, `path`, `detail`          |
| `mrIpcConnect`         | Connection attempt to a UNIX or TCP socket      | `osPid`, `detail`                  |
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

### Path Canonicalization

All recorded file paths are normalized and canonicalized:

- Symlinks are resolved to their target destinations.
- Relative paths are converted to absolute paths using the process's working directory at the moment of the call.
- Redundant `/./` and `/../` segments are removed.
- On Windows, paths are normalized to uppercase drive letters and backslash delimiters.
