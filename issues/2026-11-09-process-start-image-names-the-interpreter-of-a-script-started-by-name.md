# The process-start image names the interpreter, not the executed file, when the kernel runs an interpreter for it

|             |                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------- |
| Status      | open                                                                                              |
| Recorded    | 2026-11-09                                                                                        |
| Observed in | io-mon `c8bc874` plus the change that added the process-start image; see each case for how        |
| Area        | `src/io_mon/shim/linux_preload.nim`, `src/io_mon/shim/macos_interpose.nim` (`recordProcessStart`) |

## Observed

`mrProcessStart.path` is the file the kernel runs (docs/usage.md, "The
process-start image"). When the kernel runs an interpreter on behalf of the
executed file, that is the interpreter, and which file was executed has to
come from somewhere else. Three routes, each with a different answer:

1. **A `#!` script started by a bare name or a relative path**
   (`posix_spawnp`, `execvp`, Linux and macOS). Measured on Linux: a script
   started by name records the interpreter (`/usr/bin/bash`) as its image,
   and the exec or spawn record carries only the name. The kernel passes the
   script's path to the interpreter as an argument, and the interpreter's open
   and read of the script are recorded with the script's path made absolute,
   but nothing ties them to the start.
2. **`fexecve` / `execveat(AT_EMPTY_PATH)` of a `#!` script** (Linux).
   Measured: the interpreter is handed `/dev/fd/<n>` and opens and reads that
   name. Those records name `/dev/fd/<n>`, not a location. In this case the
   gap is covered by other records: the shim's `fexecve` hook records the exec
   with the descriptor's path (`process-exec path=<dir>/myscript.sh`), and the
   interpreter's read through the inherited descriptor is also recorded
   against the script's path (`file-read … detail=inherited-fd`). The capture
   was complete.
3. **Linux `binfmt_misc`.** By reading the kernel's
   `Documentation/admin-guide/binfmt-misc.rst`, not measured (registering a
   handler needs root): the image is the registered interpreter. With the `O`
   (open-binary) or `C` (credentials, which implies `O`) flag, the kernel opens
   the executed file itself and hands the interpreter a descriptor
   (`AT_EXECFD`), so the interpreter need not open the file by any path. Then
   no record names the executed file: the exec record has the name as passed,
   the start has the interpreter, and there is no open. A dynamically linked
   handler (Wine, Mono, a JVM launcher) loads the shim, so nothing else grades
   the capture incomplete. Without those flags the interpreter is passed the
   path, as for `#!`.

## Expected

A process whose image is an interpreter the kernel started for another file
also records that file, resolved the same way (absolute, physical). On Linux
the name the exec was given is `getauxval(AT_EXECFN)` (after glibc's PATH
search for `execvp`), which shim init can resolve against the working
directory it starts in, the exec's own; with `binfmt_misc`'s `O` flag the
executed file is `AT_EXECFD`, which can be named through
`/proc/self/fd/<n>`. macOS passes the same name as the interpreter's script
argument and in the `executable_path=` apple string. The field needs a place
that can hold a path with spaces (not a `detail` token as written today).

## Impact

A consumer that drops its own approximation for exec-by-name in favour of the
process-start image cannot see an action-provided script started by name
(route 1), unless it also judges what the interpreter read, and cannot see an
action-provided file run through a `binfmt_misc` handler with the `O` or `C`
flag at all (route 3). Route 2 is covered by the exec record.
