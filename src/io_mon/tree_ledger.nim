## The tree ledger: the run's own list of the processes it saw come into
## existence, kept as one empty file per process in the fragment directory.
##
## WHY IT EXISTS. The macOS tree-lifetime guard's census finds a live
## descendant by reading its argument/environment area (`KERN_PROCARGS2`) and
## looking for this run's needles. That area is the process's LIVE memory, not
## a copy the kernel took at exec: a process may overwrite it in place
## (setproctitle-style; PostgreSQL does this on Darwin), and the census then
## cannot tell it from an unrelated process. The ledger is evidence that does
## not live in the process's own memory: after the root exits, the guard checks
## that every ledger entry is gone (`io_mon/macos_tree_guard`).
##
## WHY A FILE PER PROCESS AND NOT THE RECORD STREAM. The `mrProcessStart` /
## `mrProcessSpawn` records carry the same (pid, start time) identities, but
## they are not usable for this:
##  * they sit in the producer's batch until it flushes, and a process that
##    stays alive and quiet never flushes it;
##  * they are gated by the event interest (`ecProcessTree`), so a capture that
##    did not ask for `proc` has none;
## and either gap hides exactly the process the check is for. A ledger entry is
## written synchronously, ungated, before the code that creates or becomes the
## process returns to the program.
##
## WHO WRITES AN ENTRY (macOS shim, `shim/macos_interpose`):
##  * every process that loads the shim, for itself, at shim init (before
##    `main`) and in the child of a hooked `fork` (before `fork` returns there);
##  * the parent of a hooked `fork` / `posix_spawn(p)`, for the child, before
##    the call returns to the program;
##  * the exec hooks, for the calling pid, before the image is replaced (a
##    `vfork` child runs no fork hook, and an exec into an image that never
##    loads the shim keeps its pid and start time).
## The same process may be written several times; the name is its identity, so
## the later writes find the file already there.
##
## A write that fails for any reason other than "already there" is reported by
## the writer as an `mrEventLoss`, so a capture whose ledger may be short is
## never graded complete.

import std/[algorithm, os, strutils]

const
  TreeLedgerPrefix* = "repro-tree-"
  TreeLedgerExt* = ".iomon-tree"
    ## Distinct from `.iomon-frag` and `.io-mon-reading`: the merge walks the
    ## fragment directory by extension and never reads these.

type
  TreeLedgerEntry* = tuple[pid: int, startUsec: uint64]
    ## `startUsec` is the kernel process start time in microseconds since the
    ## epoch (`proc_pidinfo(PROC_PIDTBSDINFO)`, the same value as
    ## `kinfo_proc.kp_proc.p_starttime`), or 0 when the writer could not read
    ## it.

proc treeLedgerName*(pid: int; startUsec: uint64): string =
  TreeLedgerPrefix & $pid & "-" & $startUsec & TreeLedgerExt

when defined(posix):
  var ledgerErrno {.importc: "errno", header: "<errno.h>".}: cint
  proc ledgerOpen(path: cstring; flags: cint; mode: cint): cint
    {.importc: "open", header: "<fcntl.h>", varargs.}
  proc ledgerClose(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
  var
    O_WRONLY_C {.importc: "O_WRONLY", header: "<fcntl.h>".}: cint
    O_CREAT_C {.importc: "O_CREAT", header: "<fcntl.h>".}: cint
    O_EXCL_C {.importc: "O_EXCL", header: "<fcntl.h>".}: cint
    O_CLOEXEC_C {.importc: "O_CLOEXEC", header: "<fcntl.h>".}: cint
    EEXIST_C {.importc: "EEXIST", header: "<errno.h>".}: cint

  proc markTreeLedger*(fragmentDir: string; pid: int;
                       startUsec: uint64): cint {.raises: [].} =
    ## Create the ledger entry for (pid, startUsec). Returns 0 when the entry
    ## exists afterwards (created now or earlier), otherwise the errno. The
    ## caller must have muted its own hooks.
    if fragmentDir.len == 0 or pid <= 0:
      return 0
    let path = fragmentDir & "/" & treeLedgerName(pid, startUsec)
    let fd = ledgerOpen(path.cstring,
      O_WRONLY_C or O_CREAT_C or O_EXCL_C or O_CLOEXEC_C, cint(0o644))
    if fd >= 0:
      discard ledgerClose(fd)
      return 0
    let err = ledgerErrno
    if err == EEXIST_C: 0 else: (if err == 0: cint(-1) else: err)

proc parseTreeLedgerName*(name: string; entry: var TreeLedgerEntry): bool =
  ## Parse `repro-tree-<pid>-<startUsec>.iomon-tree`.
  if not (name.startsWith(TreeLedgerPrefix) and name.endsWith(TreeLedgerExt)):
    return false
  let core = name[TreeLedgerPrefix.len ..< name.len - TreeLedgerExt.len]
  let dash = core.find('-')
  if dash <= 0 or dash == core.len - 1:
    return false
  try:
    let pid = parseInt(core[0 ..< dash])
    let start = parseBiggestUInt(core[dash + 1 .. ^1])
    if pid <= 0:
      return false
    entry = (pid, uint64(start))
    true
  except ValueError:
    false

proc readTreeLedger*(fragmentDir: string;
                     entries: var seq[TreeLedgerEntry]): bool =
  ## Every ledger entry in `fragmentDir`, sorted. False when the directory
  ## could not be listed (the caller fails closed).
  entries.setLen(0)
  if fragmentDir.len == 0 or not dirExists(fragmentDir):
    return false
  try:
    for kind, path in walkDir(fragmentDir, relative = true, checkDir = true):
      if kind != pcFile:
        continue
      var e: TreeLedgerEntry
      if parseTreeLedgerName(path, e):
        entries.add e
  except OSError:
    return false
  entries.sort(proc (a, b: TreeLedgerEntry): int =
    result = cmp(a.pid, b.pid)
    if result == 0: result = cmp(a.startUsec, b.startUsec))
  true
