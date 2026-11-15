# On Windows, a directory listed by a child process is not recorded, and the capture is still graded complete

|             |                                                                                                                                                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Status      | open                                                                                                                                                                                                                     |
| Recorded    | 2026-11-15                                                                                                                                                                                                               |
| Observed in | io-mon `35829647` (the pin of reprobuild `agents` `b1961633da`), driven through reprobuild's `internal io monitor run` on Windows 11 x86_64. `src/io_mon/shim/windows_interpose.nim` is unchanged at `agents` `5ecff95`  |
| Area        | `src/io_mon/shim/windows_interpose.nim` (`snoopNtQueryDirectoryFile`, `snoopNtQueryDirectoryFileEx`, `snoopNtCreateFile`, `rememberHandlePath`); `src/io_mon/capabilities.nim` (`WindowsInterposeSupportedCapabilities`) |

## Observed

The probe is a Nim compile run under the monitor. Its module runs a
directory listing at compile time, in a child process:

```nim
const b = staticExec("ls listdir")              # probe 2: Git for Windows' MSYS ls
const b = staticExec("cmd /c dir /b listdir")   # probe 3: cmd's dir
```

`listdir` holds one file. In both captures:

- `completeness` is `mcComplete`. No capability gap names directory
  enumeration.
- The child is observed and injected. There is a `process-spawn` (`ls listdir`,
  detail `CreateProcessW fork-runtime=msys-2.0.dll`, and `cmd /c dir /b
listdir`) and a `process-start` of `…\usr\bin\ls.exe` and
  `C:\Windows\System32\cmd.exe`, each with detail `shim-loaded`.
- No record of kind `directory-enumerate` or `file-open` names `listdir`.
  The only records that name it are path probes: three `NtCreateFile` probes
  of `…\listdir` (probe 2), and `NtQueryAttributesFile` probes of
  `…\listdir` and `…\listdir\*` (probe 3).
- The compiler's own `FindFirstFileW` calls are recorded as
  `directory-enumerate` (detail `FindFirstFileW`), 285 records in each
  capture.

So the listing happened in a monitored process, the capture claims to be
complete, and nothing in it says that the directory's contents were read.

## Expected

`WindowsInterposeSupportedCapabilities` lists `mcapDirectoryEnumerate`
("mrDirectoryEnumerate (FindFirstFileEx family)"). A capture that claims
the capability and is graded `mcComplete` records every directory listing a
monitored process makes, whichever route it takes. The routes here are
FindFirstFileExW or `NtQueryDirectoryFile(Ex)` on a handle opened by any NT
open call. A listing the shim cannot attribute to a path is reported as a
loss (or a capability gap), not dropped.

Not specified beyond that. Proposed: when a handle being enumerated has no
known path, record a loss rather than nothing.

## Evidence

The two probes above. Each captured `nim c apps/foo/foo.nim` over a scratch
tree `apps/foo/{foo.nim, listdir/one.txt, hello.exe}` through reprobuild's
`internal io monitor run`, then read the capture's records whose path
contains the scratch tree. The counts and details above
are from the two captures.

**Inferred from the code, not measured:** `snoopNtQueryDirectoryFile` and
`snoopNtQueryDirectoryFileEx` emit a record only when the enumerated handle
has a path in `handlePaths` (`dirPath.len > 0`). Otherwise they return
silently. Paths are remembered by `rememberHandlePath`, which is called from
the CreateFileW arms and from `snoopNtCreateFile`, and only when the open
requested data access. `NtOpenFile` is not in the hook registry. The MSYS
runtime opens directories through the NT layer, so a directory handle opened
with `NtOpenFile`, or with an `NtCreateFile` the shim classified as a probe,
is enumerated with no path known, and the record is dropped with no loss.
Whether this is the path `ls.exe` and `cmd.exe` took was not confirmed with
a per-call trace.

## Impact

A consumer that keys work on directory listings misses these, and has no
way to know it did, because the capture is graded complete. For example, a
dependency list derived from a compile's capture lacks the directory that a
compile-time `staticExec` command lists, so a new file added there does not
invalidate the output. Reprobuild met this while deriving its helper
binaries' dependency lists from io-mon captures on Windows.

## Related

- On Windows, a `FindFirstFileW` on a regular file's own name (an existence
  check) is recorded as `directory-enumerate` with the file's path.
  The consumer has to tell this apart from a listing by itself. That is a
  separate classification question and is not recorded as a defect here.
