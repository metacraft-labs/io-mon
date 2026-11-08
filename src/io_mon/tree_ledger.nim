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
## WHO WRITES AN ENTRY (macOS shim, `shim/macos_interpose`; the Linux shim,
## `shim/linux_preload`, at the same four points):
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
##
## LINUX: the Linux descendant scan reads `/proc/<pid>/environ`, which is the
## `env_start..env_end` range of the process's own stack, so the same in-place
## overwrite hides a descendant from it. The Linux guard checks the same
## ledger (`fs_snoop.waitForLinuxInjectedDescendants`); there the start time
## is field 22 of `/proc/<pid>/stat` (USER_HZ ticks since boot, the unit the
## scan's start-time prune already uses), read by `linuxProcStartTicks`.
##
## LINUX ALSO WRITES AN ENTRY for children whose creation never reaches the
## fork hook, so their parent writes none:
##  * every child of a libc fork, for itself, from the libc atfork child
##    handler, which glibc runs for its INTERNAL forks too (`daemon(3)` and
##    `forkpty(3)` call `__fork`, never the interposed `fork`);
##  * every child of a raw fork-like call (`syscall(SYS_fork / SYS_clone /
##    SYS_clone3)`, a trapped inline clone, glibc's `clone(3)` without
##    CLONE_VM, `_Fork(3)`), for itself, from the raw-fork child callback;
##  * a CLONE_VM process that is neither a thread nor a vfork child, which
##    shares its creator's memory and gets no child notification, written by
##    its creator before `clone` returns (glibc's `clone(3)` and
##    `syscall(SYS_clone / SYS_clone3)`).
## The Linux shim writes every entry through raw system calls (the `*Sys`
## writers below): allocation- and lock-free, because the child-side writes
## run in a child that may hold another thread's lock image, and free of any
## thread-local state, because the CLONE_VM creator writes while the child
## already runs on its memory (and, without CLONE_SETTLS, on its TLS). A
## child-side or creator-side failure is reported through the shim's
## pre-encoded fork-child loss frame. Every Linux writer also records its
## pid namespace, and one that cannot read it reports a failed write
## (`linuxPidNamespaceSys`). Children of `posix_spawn`, `system(3)`
## and `popen(3)` (glibc spawns with CLONE_VM | CLONE_VFORK, its parent
## suspended until the child execs) exec an image that writes its own entry
## at shim init. An image the shim cannot enter is reported where the shim
## sees the spawn (the public posix_spawn hooks); `system(3)` and `popen(3)`
## spawn internally, so for them that holds only while `/bin/sh` is an image
## the shim can enter (issue
## `2026-11-08-linux-system-popen-of-an-uninjectable-shell-is-unseen`).

import std/[algorithm, os, strutils]

const
  TreeLedgerPrefix* = "repro-tree-"
  TreeLedgerExt* = ".iomon-tree"
    ## Distinct from `.iomon-frag` and `.io-mon-reading`: the merge walks the
    ## fragment directory by extension and never reads these.

type
  TreeLedgerEntry* = tuple[pid: int, startUsec: uint64]
    ## `startUsec` is the kernel process start time — on macOS in
    ## microseconds since the epoch (`proc_pidinfo(PROC_PIDTBSDINFO)`, the
    ## same value as `kinfo_proc.kp_proc.p_starttime`), on Linux in USER_HZ
    ## ticks since boot (field 22 of `/proc/<pid>/stat`) — or 0 when the
    ## writer could not read it.

proc treeLedgerName*(pid: int; startUsec: uint64): string =
  TreeLedgerPrefix & $pid & "-" & $startUsec & TreeLedgerExt

# The raw writers below run in a fork child in any state and, for a CLONE_VM
# process, beside a child that shares this thread's TLS: no Nim stack-trace
# frame (kept in a threadvar) may be pushed on their way.
{.push stackTrace: off, lineTrace: off.}
when defined(posix):
  var ledgerErrno {.importc: "errno", header: "<errno.h>".}: cint
  proc ledgerOpen(path: cstring; flags: cint; mode: cint): cint
    {.importc: "open", header: "<fcntl.h>", varargs.}
  proc ledgerClose(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
  var
    O_WRONLY_C {.importc: "O_WRONLY", header: "<fcntl.h>".}: cint
    O_RDONLY_C {.importc: "O_RDONLY", header: "<fcntl.h>".}: cint
    O_CREAT_C {.importc: "O_CREAT", header: "<fcntl.h>".}: cint
    O_EXCL_C {.importc: "O_EXCL", header: "<fcntl.h>".}: cint
    O_CLOEXEC_C {.importc: "O_CLOEXEC", header: "<fcntl.h>".}: cint
    EEXIST_C {.importc: "EEXIST", header: "<errno.h>".}: cint

  const LedgerPathCap = 4096 + 128
    ## PATH_MAX plus the longest entry name (prefix, two 20-digit numbers,
    ## extension). A longer fragment directory is refused (ENAMETOOLONG).
  var ENAMETOOLONG_C {.importc: "ENAMETOOLONG", header: "<errno.h>".}: cint
  var ENOENT_C {.importc: "ENOENT", header: "<errno.h>".}: cint

  proc ledgerAppend(buf: var array[LedgerPathCap, char]; pos: var int;
                    text: openArray[char]): bool {.raises: [].} =
    if pos + text.len >= LedgerPathCap:
      return false
    for c in text:
      buf[pos] = c
      inc pos
    true

  proc ledgerAppendDec(buf: var array[LedgerPathCap, char]; pos: var int;
                       value: uint64): bool {.raises: [].} =
    var digits {.noinit.}: array[20, char]
    var n = 0
    var v = value
    while true:
      digits[n] = char(ord('0') + int(v mod 10))
      inc n
      v = v div 10
      if v == 0: break
    if pos + n >= LedgerPathCap:
      return false
    for i in countdown(n - 1, 0):
      buf[pos] = digits[i]
      inc pos
    true

  proc ledgerCreate(buf: var array[LedgerPathCap, char]; pos: int): cint
      {.raises: [].} =
    ## Create the file named by `buf[0 ..< pos]` exclusively: 0 when it
    ## exists afterwards (created now or earlier), otherwise the errno.
    buf[pos] = '\0'
    let fd = ledgerOpen(cast[cstring](addr buf[0]),
      O_WRONLY_C or O_CREAT_C or O_EXCL_C or O_CLOEXEC_C, cint(0o644))
    if fd >= 0:
      discard ledgerClose(fd)
      return 0
    let err = ledgerErrno
    if err == EEXIST_C: 0 else: (if err == 0: cint(-1) else: err)

  proc ledgerDirPrefix(buf: var array[LedgerPathCap, char]; pos: var int;
                       fragmentDir: cstring): bool {.raises: [].} =
    var i = 0
    while fragmentDir[i] != '\0':
      if pos + 1 >= LedgerPathCap:
        return false
      buf[pos] = fragmentDir[i]
      inc pos
      inc i
    ledgerAppend(buf, pos, "/")

  proc markTreeLedgerRaw*(fragmentDir: cstring; pid: int;
                          startUsec: uint64): cint {.raises: [].} =
    ## Create the ledger entry for (pid, startUsec). Returns 0 when the entry
    ## exists afterwards (created now or earlier), otherwise the errno. The
    ## caller must have muted its own hooks.
    ##
    ## ALLOCATION- AND LOCK-FREE (a stack buffer and raw libc calls), so a
    ## fork child may call it in any state: in the libc atfork child handler,
    ## before the private heap's own handler has run, and in a child that
    ## skips monitor bookkeeping because another thread held a shim lock.
    if fragmentDir == nil or fragmentDir[0] == '\0' or pid <= 0:
      return 0
    var buf {.noinit.}: array[LedgerPathCap, char]
    var pos = 0
    if not (ledgerDirPrefix(buf, pos, fragmentDir) and
            ledgerAppend(buf, pos, TreeLedgerPrefix) and
            ledgerAppendDec(buf, pos, uint64(pid)) and
            ledgerAppend(buf, pos, "-") and
            ledgerAppendDec(buf, pos, startUsec) and
            ledgerAppend(buf, pos, TreeLedgerExt)):
      return ENAMETOOLONG_C
    ledgerCreate(buf, pos)

  proc markTreeLedger*(fragmentDir: string; pid: int;
                       startUsec: uint64): cint {.raises: [].} =
    ## `markTreeLedgerRaw` for a Nim string directory (no copy is made).
    if fragmentDir.len == 0:
      return 0
    markTreeLedgerRaw(cstring(fragmentDir), pid, startUsec)

proc parseLinuxProcStatStart*(buf: openArray[char]; n: int): uint64 =
  ## Field 22 (start time, USER_HZ ticks since boot) of one
  ## `/proc/<pid>/stat` line, 0 when it cannot be read. The comm field (2)
  ## may hold spaces and parentheses, so the scan starts after the LAST ')'.
  var closeParen = -1
  for i in countdown(min(n, buf.len) - 1, 0):
    if buf[i] == ')':
      closeParen = i
      break
  if closeParen < 0:
    return 0
  var idx = closeParen + 2
  var field = 3
  let limit = min(n, buf.len)
  while idx < limit and field < 22:
    while idx < limit and buf[idx] != ' ': inc idx
    while idx < limit and buf[idx] == ' ': inc idx
    inc field
  if field != 22:
    return 0
  var value = 0'u64
  var digits = 0
  while idx < limit and buf[idx] in {'0' .. '9'}:
    value = value * 10 + uint64(ord(buf[idx]) - ord('0'))
    inc idx
    inc digits
  if digits > 0: value else: 0

when defined(linux):
  proc ledgerRead(fd: cint; buf: pointer; n: csize_t): int
    {.importc: "read", header: "<unistd.h>".}

  proc linuxProcStartTicks*(pid: int): uint64 {.raises: [].} =
    ## Field 22 of `/proc/<pid>/stat`, or 0 when it cannot be read. The shim
    ## calls this inside its hooks (muted) for itself and for the child of a
    ## hooked fork / posix_spawn, and in a fork child in any state, so it is
    ## allocation- and lock-free: the path and the file contents live in
    ## stack buffers and the file is read with raw libc calls.
    if pid <= 0:
      return 0
    var path {.noinit.}: array[LedgerPathCap, char]
    var pos = 0
    if not (ledgerAppend(path, pos, "/proc/") and
            ledgerAppendDec(path, pos, uint64(pid)) and
            ledgerAppend(path, pos, "/stat")):
      return 0
    path[pos] = '\0'
    let fd = ledgerOpen(cast[cstring](addr path[0]), O_RDONLY_C or O_CLOEXEC_C,
      cint(0))
    if fd < 0:
      return 0
    var buf {.noinit.}: array[1024, char]
    let r = ledgerRead(fd, addr buf[0], csize_t(buf.len))
    discard ledgerClose(fd)
    if r <= 0:
      return 0
    parseLinuxProcStatStart(buf, r)

const TreeLedgerPidNsPrefix* = TreeLedgerPrefix & "pidns-"
  ## `repro-tree-pidns-<inode>.iomon-tree`: the Linux PID NAMESPACE a ledger
  ## writer ran in. A ledger pid is the pid as its writer saw it, which is
  ## relative to the writer's pid namespace: in a tree that runs
  ## `unshare --pid --fork`, the new namespace's first process sees itself as
  ## pid 1, and pid 1 in the host's `/proc` is the host's init. A guard can
  ## check an entry only when it shares the writer's namespace, so every
  ## Linux writer also leaves one marker per namespace it wrote from, and the
  ## guard reads the markers before trusting any pid (`fs_snoop`). The inode
  ## is the one `/proc/self/ns/pid` names (`pid:[<inode>]`, namespaces(7)),
  ## which is the same for every process in the namespace and distinct across
  ## namespaces. `parseTreeLedgerName` rejects these names, so a reader that
  ## predates them (the macOS guard) ignores them.

proc treeLedgerPidNsName*(inode: uint64): string =
  TreeLedgerPidNsPrefix & $inode & TreeLedgerExt

proc parseTreeLedgerPidNsName*(name: string; inode: var uint64): bool =
  ## Parse `repro-tree-pidns-<inode>.iomon-tree`.
  if not (name.startsWith(TreeLedgerPidNsPrefix) and
          name.endsWith(TreeLedgerExt)):
    return false
  let core = name[TreeLedgerPidNsPrefix.len ..< name.len - TreeLedgerExt.len]
  if core.len == 0:
    return false
  try:
    let v = parseBiggestUInt(core)
    if v == 0:
      return false
    inode = uint64(v)
    true
  except ValueError:
    false

proc readTreeLedgerPidNamespaces*(fragmentDir: string;
                                  inodes: var seq[uint64]): bool =
  ## Every pid-namespace marker in `fragmentDir`, sorted. False when the
  ## directory could not be listed (the caller fails closed).
  inodes.setLen(0)
  if fragmentDir.len == 0 or not dirExists(fragmentDir):
    return false
  try:
    for kind, path in walkDir(fragmentDir, relative = true, checkDir = true):
      if kind != pcFile:
        continue
      var ino = 0'u64
      if parseTreeLedgerPidNsName(path, ino):
        inodes.add ino
  except OSError:
    return false
  inodes.sort()
  true

proc parsePidNamespaceLink*(link: openArray[char]; n: int): uint64 =
  ## The inode of a `/proc/<pid>/ns/pid` link target, `pid:[<inode>]`, or 0.
  let limit = min(n, link.len)
  var i = 0
  while i < limit and link[i] != '[': inc i
  inc i
  var value = 0'u64
  var digits = 0
  while i < limit and link[i] in {'0' .. '9'}:
    value = value * 10 + uint64(ord(link[i]) - ord('0'))
    inc i
    inc digits
  if digits > 0 and i < limit and link[i] == ']': value else: 0

when defined(linux):
  proc ledgerReadlink(path: cstring; buf: pointer; n: csize_t): int
    {.importc: "readlink", header: "<unistd.h>".}

  proc linuxSelfPidNamespace*(): uint64 {.raises: [].} =
    ## The inode of this process's pid namespace (`/proc/self/ns/pid`), or 0
    ## when it cannot be read (no `/proc`, or a kernel without namespaces).
    ## Raw libc into stack buffers; safe inside a muted hook.
    var buf {.noinit.}: array[64, char]
    let n = ledgerReadlink("/proc/self/ns/pid", addr buf[0], csize_t(buf.len))
    if n <= 0:
      return 0
    parsePidNamespaceLink(buf, n)

  proc markTreeLedgerPidNamespaceRaw*(fragmentDir: cstring;
                                      inode: uint64): cint {.raises: [].} =
    ## Create the marker for pid namespace `inode`. Returns 0 when it exists
    ## afterwards, otherwise the errno, exactly as `markTreeLedgerRaw`, and
    ## like it allocation- and lock-free.
    if fragmentDir == nil or fragmentDir[0] == '\0' or inode == 0:
      return 0
    var buf {.noinit.}: array[LedgerPathCap, char]
    var pos = 0
    if not (ledgerDirPrefix(buf, pos, fragmentDir) and
            ledgerAppend(buf, pos, TreeLedgerPidNsPrefix) and
            ledgerAppendDec(buf, pos, inode) and
            ledgerAppend(buf, pos, TreeLedgerExt)):
      return ENAMETOOLONG_C
    ledgerCreate(buf, pos)

  proc markTreeLedgerPidNamespace*(fragmentDir: string;
                                   inode: uint64): cint {.raises: [].} =
    if fragmentDir.len == 0:
      return 0
    markTreeLedgerPidNamespaceRaw(cstring(fragmentDir), inode)

  # --- The same writers over a caller-supplied raw system call --------------
  #
  # The `*Sys` variants issue every call through `sys` (the shim passes its
  # raw syscall primitive), so they enter no libc wrapper, no interposed
  # hook, and touch neither `errno` nor any other thread-local state: the
  # error comes back as the return value. That is what lets the creator of a
  # CLONE_VM process write the child's entry while the child, which shares
  # the creator's memory and (without CLONE_SETTLS) its TLS, already runs,
  # and lets a fork child write its own entry before anything else in it is
  # consistent. Results follow the kernel's `-errno` convention.

  type LedgerSyscall* = proc (nr, a1, a2, a3, a4, a5, a6: clong): clong
    {.cdecl, gcsafe, raises: [].}

  var
    SYS_openat_C {.importc: "SYS_openat", header: "<sys/syscall.h>".}: clong
    SYS_read_C {.importc: "SYS_read", header: "<sys/syscall.h>".}: clong
    SYS_close_C {.importc: "SYS_close", header: "<sys/syscall.h>".}: clong
    SYS_readlinkat_C {.importc: "SYS_readlinkat",
      header: "<sys/syscall.h>".}: clong
    AT_FDCWD_C {.importc: "AT_FDCWD", header: "<fcntl.h>".}: cint

  proc ledgerCreateSys(sys: LedgerSyscall; buf: var array[LedgerPathCap, char];
                       pos: int): cint {.raises: [].} =
    ## `ledgerCreate` through `sys`: 0 when the file exists afterwards,
    ## otherwise the errno.
    buf[pos] = '\0'
    let fd = sys(SYS_openat_C, clong(AT_FDCWD_C), cast[clong](addr buf[0]),
      clong(O_WRONLY_C or O_CREAT_C or O_EXCL_C or O_CLOEXEC_C), clong(0o644),
      0, 0)
    if fd >= 0:
      discard sys(SYS_close_C, fd, 0, 0, 0, 0, 0)
      return 0
    if cint(-fd) == EEXIST_C: 0 else: cint(-fd)

  proc markTreeLedgerSys*(sys: LedgerSyscall; fragmentDir: cstring; pid: int;
                          startUsec: uint64): cint {.raises: [].} =
    ## `markTreeLedgerRaw` through `sys`.
    if fragmentDir == nil or fragmentDir[0] == '\0' or pid <= 0:
      return 0
    var buf {.noinit.}: array[LedgerPathCap, char]
    var pos = 0
    if not (ledgerDirPrefix(buf, pos, fragmentDir) and
            ledgerAppend(buf, pos, TreeLedgerPrefix) and
            ledgerAppendDec(buf, pos, uint64(pid)) and
            ledgerAppend(buf, pos, "-") and
            ledgerAppendDec(buf, pos, startUsec) and
            ledgerAppend(buf, pos, TreeLedgerExt)):
      return ENAMETOOLONG_C
    ledgerCreateSys(sys, buf, pos)

  proc markTreeLedgerPidNamespaceSys*(sys: LedgerSyscall; fragmentDir: cstring;
                                      inode: uint64): cint {.raises: [].} =
    ## `markTreeLedgerPidNamespaceRaw` through `sys`.
    if fragmentDir == nil or fragmentDir[0] == '\0' or inode == 0:
      return 0
    var buf {.noinit.}: array[LedgerPathCap, char]
    var pos = 0
    if not (ledgerDirPrefix(buf, pos, fragmentDir) and
            ledgerAppend(buf, pos, TreeLedgerPidNsPrefix) and
            ledgerAppendDec(buf, pos, inode) and
            ledgerAppend(buf, pos, TreeLedgerExt)):
      return ENAMETOOLONG_C
    ledgerCreateSys(sys, buf, pos)

  proc linuxProcStartTicksSys*(sys: LedgerSyscall; pid: int): uint64
      {.raises: [].} =
    ## `linuxProcStartTicks` through `sys`.
    if pid <= 0:
      return 0
    var path {.noinit.}: array[LedgerPathCap, char]
    var pos = 0
    if not (ledgerAppend(path, pos, "/proc/") and
            ledgerAppendDec(path, pos, uint64(pid)) and
            ledgerAppend(path, pos, "/stat")):
      return 0
    path[pos] = '\0'
    let fd = sys(SYS_openat_C, clong(AT_FDCWD_C), cast[clong](addr path[0]),
      clong(O_RDONLY_C or O_CLOEXEC_C), 0, 0, 0)
    if fd < 0:
      return 0
    var buf {.noinit.}: array[1024, char]
    let r = sys(SYS_read_C, fd, cast[clong](addr buf[0]), clong(buf.len), 0, 0,
      0)
    discard sys(SYS_close_C, fd, 0, 0, 0, 0, 0)
    if r <= 0:
      return 0
    parseLinuxProcStatStart(buf, int(r))

  proc linuxPidNamespaceSys*(sys: LedgerSyscall; inode: var uint64): cint
      {.raises: [].} =
    ## The caller's pid namespace for a ledger writer: 0 with `inode` set to
    ## the inode `/proc/self/ns/pid` names, or 0 with `inode` = 0 when this
    ## kernel provably has no pid namespaces (`/proc/self` resolves but has
    ## no `ns/pid` link, so every pid is global), otherwise the errno: the
    ## namespace is UNKNOWN.
    ##
    ## WHY UNKNOWN IS AN ERROR. A ledger pid is relative to its writer's pid
    ## namespace, and the guard trusts an entry only when no marker names
    ## another namespace. A writer that cannot read its namespace (no `/proc`
    ## in its mount namespace or chroot) and writes no marker would leave
    ## namespace-relative pids the guard checks against unrelated host
    ## processes: pid 1 of a new namespace is the host's init, which predates
    ## the root and is skipped, so a surviving descendant there would go
    ## unseen. The writer reports the failure as a lost ledger write instead.
    inode = 0
    var buf {.noinit.}: array[64, char]
    let n = sys(SYS_readlinkat_C, clong(AT_FDCWD_C),
      cast[clong](cstring("/proc/self/ns/pid")), cast[clong](addr buf[0]),
      clong(buf.len), 0, 0)
    if n > 0:
      inode = parsePidNamespaceLink(buf, int(n))
      return (if inode != 0: 0 else: ENOENT_C)
    let selfLen = sys(SYS_readlinkat_C, clong(AT_FDCWD_C),
      cast[clong](cstring("/proc/self")), cast[clong](addr buf[0]),
      clong(buf.len), 0, 0)
    if selfLen > 0 and cint(-n) == ENOENT_C:
      return 0                            # a kernel without pid namespaces
    if n < 0: cint(-n) else: ENOENT_C
{.pop.}

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
