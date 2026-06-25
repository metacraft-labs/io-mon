when not defined(macosx):
  {.error: "repro_monitor_shim/macos_interpose is macOS-only".}

import std/[locks, os, strutils, tables]
from io_mon/paths import extendedPath

import io_mon/hooks/macos_interpose_runtime
import io_mon/hooks/macos_bodypatch
import io_mon/types
import io_mon/writer

{.emit: """
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int repro_monitor_get_errno(void) {
  return errno;
}

static void repro_monitor_set_errno(int value) {
  errno = value;
}
""".}

const
  OAccMode = 0x0003.cint
  OWrOnly = 0x0001.cint
  ORdWr = 0x0002.cint
  OCreat = 0x0200.cint
  OTrunc = 0x0400.cint
  OAppend = 0x0008.cint

var
  initialized = false
  locksReady = false
  initLockVar: Lock
  recordLock: Lock
  fdLock: Lock
  dirLock: Lock
  fragmentDir: string
  nextProcessSeq: uint64 = 0
  fdPaths = initTable[cint, string]()
  dirPaths = initTable[uint, string]()

var disabled {.threadvar.}: int

proc c_getpid(): cint {.importc: "getpid", header: "<unistd.h>".}
proc c_getppid(): cint {.importc: "getppid", header: "<unistd.h>".}
proc pthread_threadid_np(thread: pointer; threadId: ptr uint64): cint
  {.importc: "pthread_threadid_np", header: "<pthread.h>".}
proc getErrno(): cint {.importc: "repro_monitor_get_errno", cdecl.}
proc setErrno(value: cint) {.importc: "repro_monitor_set_errno", cdecl.}

proc currentThreadId(): uint64 =
  var tid: uint64 = 0
  if pthread_threadid_np(nil, addr tid) == 0:
    result = tid

proc processSeq(): uint64 =
  acquire(recordLock)
  inc nextProcessSeq
  result = nextProcessSeq
  release(recordLock)

template withShimMuted(body: untyped) =
  inc disabled
  try:
    try:
      body
    except CatchableError:
      discard
  finally:
    dec disabled

proc baseRecord(kind: MonitorRecordKind; observationKind: MonitorObservationKind): MonitorRecord =
  MonitorRecord(
    kind: kind,
    observationKind: observationKind,
    seq: processSeq(),
    osPid: uint64(c_getpid()),
    parentOsPid: uint64(c_getppid()),
    threadId: currentThreadId(),
    probeResult: prUnknown)

proc emitRecord(record: MonitorRecord) {.raises: [].} =
  if not initialized or fragmentDir.len == 0 or disabled > 0:
    return
  withShimMuted:
    appendFragmentRecord(fragmentDir, record)

proc recordProcessStart() {.raises: [].} =
  var record = baseRecord(mrProcessStart, moProcessStart)
  record.detail = "shim-loaded"
  emitRecord(record)

proc observationForOpen(flags: cint): MonitorObservationKind =
  if (flags and (OCreat or OTrunc or OAppend)) != 0:
    moFileWrite
  else:
    let acc = flags and OAccMode
    if acc == OWrOnly or acc == ORdWr:
      moFileWrite
    else:
      moFileOpen

proc recordDirectoryEnumeration(path: cstring) {.raises: [].} =
  if path == nil or not ct_macos_interpose_path_is_dir(path):
    return
  var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
  record.path = $path
  record.result = 1
  record.detail = "directory-open"
  emitRecord(record)

proc updateFdPath(fd: cint; path: cstring) =
  if fd < 0 or path == nil:
    return
  acquire(fdLock)
  fdPaths[fd] = $path
  release(fdLock)

proc removeFdPath(fd: cint) =
  acquire(fdLock)
  fdPaths.del(fd)
  release(fdLock)

proc pathForFd(fd: cint): string =
  acquire(fdLock)
  result = fdPaths.getOrDefault(fd, "")
  release(fdLock)

proc dirKey(dirp: pointer): uint =
  cast[uint](dirp)

proc updateDirPath(dirp: pointer; path: cstring) =
  if dirp == nil or path == nil:
    return
  acquire(dirLock)
  dirPaths[dirKey(dirp)] = $path
  release(dirLock)

proc removeDirPath(dirp: pointer) =
  acquire(dirLock)
  dirPaths.del(dirKey(dirp))
  release(dirLock)

proc pathForDir(dirp: pointer): string =
  acquire(dirLock)
  result = dirPaths.getOrDefault(dirKey(dirp), "")
  release(dirLock)

proc probeFromResult(callResult: cint): ProbeResult =
  if callResult == 0:
    prExistingOther
  else:
    prAbsent

# --- Shared recording helpers (DRY, high fan-in) -------------------------
#
# Each syscall family has exactly ONE hook function (see "Unified hooks"
# below), and each hook builds its record through ONE of these helpers, so no
# record-building body is duplicated. The helpers take the already-computed
# call result + path/mode so the hook stays a thin "forward then record".

proc recordOpen(callResult: cint; path: cstring; flags: cint; detail: string) {.raises: [].} =
  ## Record an mrFileOpen observation. Shared by the open/openat hooks. The
  ## fd→path map update and directory-enumeration follow-up are done by the
  ## caller (they need the live fd/path before this record is emitted).
  var record = baseRecord(mrFileOpen, observationForOpen(flags))
  record.result = callResult.int64
  record.flags = uint32(flags)
  if path != nil:
    record.path = $path
  if detail.len > 0:
    record.detail = detail
  emitRecord(record)

proc recordPathProbe(callResult: cint; path: cstring; mode: cint; detail: string) {.raises: [].} =
  ## Record an mrPathProbe observation for the stat/lstat/fstatat/access family.
  ## `mode` is stored in `flags` (meaningful only for access(2); pass 0 for the
  ## stat family). Single source of truth for the probe record body.
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = callResult.int64
  record.probeResult = probeFromResult(callResult)
  record.flags = uint32(mode)
  if path != nil:
    record.path = $path
  if detail.len > 0:
    record.detail = detail
  emitRecord(record)

proc recordSpawn(childPid: PidT; callResult: cint; path: cstring; detail: string) {.raises: [].} =
  ## Record an mrProcessSpawn (moExecute) observation for fork/posix_spawn(p).
  ## Single source of truth for the spawn record body.
  var record = baseRecord(mrProcessSpawn, moExecute)
  record.childOsPid = uint64(childPid)
  record.result = callResult.int64
  if path != nil:
    record.path = $path
  if detail.len > 0:
    record.detail = detail
  emitRecord(record)

proc recordRename(callResult: cint; fromPath, toPath: cstring; detail: string) {.raises: [].} =
  ## Record a rename(2)/renameat(2) as an OUTPUT WRITE on the DESTINATION path.
  ##
  ## A rename is an output move: the build's atomic-write idiom
  ## (`chmod a-w $@t; mv $@t $@`, ubiquitous in gnulib/autotools makefiles) writes
  ## a temp file then rename(2)s it onto the final output path. For the §16.7.8
  ## coverage closure the dependency that matters is the DESTINATION (the output
  ## that materialises), so — consistent with the existing write/output handling
  ## (recordOpen's moFileWrite, repro_hook_write) — we classify it as an
  ## moFileWrite on the destination. The source temp path is preserved in `detail`
  ## for provenance (a rename also removes the source, but the source is a
  ## throwaway temp the build just created, so the destination write is the
  ## coverage-relevant fact). `result` carries the call outcome (only a
  ## successful rename, result == 0, actually materialises the destination).
  var record = baseRecord(mrFileWrite, moFileWrite)
  record.result = callResult.int64
  if toPath != nil:
    record.path = $toPath
  var d = detail
  if fromPath != nil:
    if d.len > 0: d.add ' '
    d.add "from=" & $fromPath
  if d.len > 0:
    record.detail = d
  emitRecord(record)

proc repro_monitor_shim_init*(configPath: cstring): cint {.exportc, dynlib.} =
  if not locksReady:
    initLock(initLockVar)
    initLock(recordLock)
    initLock(fdLock)
    initLock(dirLock)
    locksReady = true
  acquire(initLockVar)
  defer: release(initLockVar)
  if initialized:
    return 0
  withShimMuted:
    fragmentDir = getEnv("REPRO_MONITOR_FRAGMENT_DIR")
    if fragmentDir.len > 0:
      createDir(extendedPath(fragmentDir))
  initialized = true
  recordProcessStart()
  result = 0

proc repro_monitor_shim_flush*(): cint {.exportc, dynlib.} =
  ## Flush the calling thread's in-flight fragment batch to disk. The fragment
  ## writer batches frames into a per-thread buffer that is otherwise only
  ## flushed on overflow / 100 ms age / key change. A process that does a small
  ## amount of I/O and exits promptly (the common body-patch case — a tiny
  ## tool that opens a few files and returns) would otherwise lose its buffered
  ## records, so we flush explicitly here (and from the destructor below).
  withShimMuted:
    closeFragmentSlot()
  result = 0

proc repro_monitor_shim_shutdown*(): cint {.exportc, dynlib.} =
  ## Flush + close the calling thread's fragment slot on shutdown so no
  ## buffered records are dropped.
  withShimMuted:
    closeFragmentSlot()
  result = 0
proc repro_monitor_shim_disable_current_thread*() {.exportc, dynlib.} = inc disabled
proc repro_monitor_shim_enable_current_thread*() {.exportc, dynlib.} =
  if disabled > 0:
    dec disabled
proc repro_monitor_shim_version*(): cstring {.exportc, dynlib.} =
  "repro_monitor_shim_m11"

proc repro_hook_open*(path: cstring; flags, mode: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_open(path, flags, mode)
  result = ct_macos_interpose_real_open(path, flags, mode)
  let savedErrno = getErrno()
  updateFdPath(result, path)
  recordOpen(result, path, flags, "")
  if result >= 0:
    recordDirectoryEnumeration(path)
  setErrno(savedErrno)

proc repro_hook_openat*(dirfd: cint; path: cstring; flags, mode: cint): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_openat(dirfd, path, flags, mode)
  result = ct_macos_interpose_real_openat(dirfd, path, flags, mode)
  let savedErrno = getErrno()
  updateFdPath(result, path)
  recordOpen(result, path, flags, "dirfd=" & $dirfd)
  if result >= 0:
    recordDirectoryEnumeration(path)
  setErrno(savedErrno)

proc repro_hook_read*(fd: cint; buf: pointer; count: csize_t): int {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_read(fd, buf, count)
  result = ct_macos_interpose_real_read(fd, buf, count)
  if result >= 0:
    var record = baseRecord(mrFileRead, moFileRead)
    record.path = pathForFd(fd)
    record.result = result.int64
    record.flags = uint32(fd)
    emitRecord(record)

proc repro_hook_write*(fd: cint; buf: pointer; count: csize_t): int {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_write(fd, buf, count)
  result = ct_macos_interpose_real_write(fd, buf, count)
  if result >= 0 and fd > 2:
    var record = baseRecord(mrFileWrite, moFileWrite)
    record.path = pathForFd(fd)
    record.result = result.int64
    record.flags = uint32(fd)
    emitRecord(record)

proc repro_hook_close*(fd: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_close(fd)
  result = ct_macos_interpose_real_close(fd)
  removeFdPath(fd)

proc repro_hook_opendir*(path: cstring): pointer {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_opendir(path)
  inc disabled
  try:
    result = ct_macos_interpose_real_opendir(path)
  finally:
    dec disabled
  if result != nil:
    updateDirPath(result, path)

proc repro_hook_readdir*(dirp: pointer): pointer {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_readdir(dirp)
  let dirPath = pathForDir(dirp)
  inc disabled
  try:
    result = ct_macos_interpose_real_readdir(dirp)
  finally:
    dec disabled
  if result != nil:
    var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
    record.path = dirPath
    record.result = 1
    record.detail = "readdir"
    emitRecord(record)

proc repro_hook_closedir*(dirp: pointer): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_closedir(dirp)
  inc disabled
  try:
    result = ct_macos_interpose_real_closedir(dirp)
  finally:
    dec disabled
  removeDirPath(dirp)

# --- Unified stat-family hooks (interpose + body-patch share ONE hook) ---
#
# There is exactly ONE hook per stat-family call, used by BOTH the static
# __DATA,__interpose tuples AND the body-patch install. Each forwards to the
# kernel via the RAW stat64/lstat64/fstatat64/access syscall
# (ct_macos_bodypatch_real_*), NOT via the named symbol / dlsym.
#
# WHY the forward MUST bypass the named entry: under the default `both` backend
# the body-patch has REPLACED the named stat/lstat/fstatat/access entry points.
# If this hook forwarded via the by-name real (ct_macos_interpose_real_stat,
# which resolves the symbol with dlsym / NSLookupSymbolInImage), the resolved
# address would BE the body-patched entry → the call would re-enter THIS hook →
# the record would be emitted TWICE (the double-processing bug). Forwarding via
# the raw syscall reaches the kernel directly, so a given stat() records EXACTLY
# ONCE regardless of backend (interpose / bodypatch / both) and never re-enters.
# The *64 syscall variants fill the modern 64-bit-inode `struct stat` the caller
# expects (see macos_interpose_runtime.nim).

proc repro_hook_stat*(path: cstring; buf: pointer): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_stat(path, buf)
  result = ct_macos_bodypatch_real_stat(path, buf)
  let savedErrno = getErrno()
  recordPathProbe(result, path, 0, "")
  setErrno(savedErrno)

proc repro_hook_lstat*(path: cstring; buf: pointer): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_lstat(path, buf)
  result = ct_macos_bodypatch_real_lstat(path, buf)
  let savedErrno = getErrno()
  recordPathProbe(result, path, 0, "")
  setErrno(savedErrno)

proc repro_hook_fstatat*(dirfd: cint; path: cstring; buf: pointer;
    flag: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_fstatat(dirfd, path, buf, flag)
  result = ct_macos_bodypatch_real_fstatat(dirfd, path, buf, flag)
  let savedErrno = getErrno()
  recordPathProbe(result, path, 0, "fstatat dirfd=" & $dirfd)
  setErrno(savedErrno)

proc repro_hook_access*(path: cstring; mode: cint): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_access(path, mode)
  result = ct_macos_bodypatch_real_access(path, mode)
  let savedErrno = getErrno()
  recordPathProbe(result, path, mode, "")
  setErrno(savedErrno)

# --- Unified rename-family hooks (interpose + body-patch share ONE hook) ---
#
# gnulib/autotools makefiles materialise outputs atomically via the
# `chmod a-w $@t; mv $@t $@` idiom (e.g. lib/configmake.h, version.c) — an
# mv that issues rename(2)/renameat(2). Monitoring rename closes the §16.7.8
# coverage envelope for these output moves AND ensures the body-patch backend
# does not BREAK the move (the keystone failure was the body-patch corrupting
# subprocesses during exactly such a make). As with the stat family, each hook
# forwards to the kernel via the RAW rename/renameat syscall
# (ct_macos_real_rename*), NOT the named symbol, so a single rename records
# EXACTLY ONCE on every backend and never re-enters the (possibly patched) entry.

proc repro_hook_rename*(fromPath, toPath: cstring): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_rename(fromPath, toPath)
  result = ct_macos_real_rename(fromPath, toPath)
  let savedErrno = getErrno()
  recordRename(result, fromPath, toPath, "rename")
  setErrno(savedErrno)

proc repro_hook_renameat*(fromfd: cint; fromPath: cstring; tofd: cint;
    toPath: cstring): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_renameat(fromfd, fromPath, tofd, toPath)
  result = ct_macos_real_renameat(fromfd, fromPath, tofd, toPath)
  let savedErrno = getErrno()
  recordRename(result, fromPath, toPath,
    "renameat fromfd=" & $fromfd & " tofd=" & $tofd)
  setErrno(savedErrno)

# --- Unified spawn-family hooks ------------------------------------------
#
# There is exactly ONE hook per spawn-family call, used by BOTH the static
# __DATA,__interpose tuples AND the body-patch install. They close the
# SHARED-CACHE-INTERNAL spawn blind spot (spec §16.7.8): a
# `system()`/`popen()`/`NSTask` launch issues its `posix_spawn`/`fork`+`execve`
# INSIDE libsystem, never through the program's own import stubs, so the static
# `__DATA,__interpose` section never sees it — the child (e.g. a SIP-protected
# `/bin/sh`) would get NEITHER re-propagation NOR SIP-rewrite, and its whole
# subtree would run unmonitored (a FALSE SKIP). Body-patching the spawn-family
# ENTRY points catches the internal caller and re-applies propagation + rewrite.
#
# Forwarding constraint (WHY each hook bypasses the named entry): under the
# default `both` backend the body-patch has REPLACED the named
# fork/execve/posix_spawn symbols. If a hook forwarded through the named symbol
# / dlsym (e.g. ct_macos_interpose_real_fork, which resolves via
# NSLookupSymbolInImage), that address would BE the body-patched entry → the
# call would re-enter THIS SAME hook → the record would be emitted TWICE and
# env-propagation / SIP-rewrite would be applied twice (the double-processing
# bug). So each hook forwards via a body-patch-SAFE path that reaches the kernel
# / original body WITHOUT going through the (possibly patched) named entry:
#   * execve     -> the raw-syscall forwarder (raw `SYS_execve`, which itself
#                   re-adds DYLD_INSERT_LIBRARIES + CT_SANDBOX_TOOLS_DIR and
#                   SIP-rewrites the path before the kernel call). execve does
#                   not return on success, so its record is emitted FIRST.
#   * fork       -> raw `SYS_fork` (a fork child inherits the loaded shim+env;
#                   only RECORDING is needed).
#   * posix_spawn-> rewrite env+path ONCE, then forward via a TRAMPOLINE into the
#                   original wrapper body so libsystem's own
#                   `_posix_spawn_args_desc` marshalling runs. When no trampoline
#                   was built (interpose-only backend, where the entry is NOT
#                   patched) the by-name real (ct_macos_interpose_real_posix_spawn)
#                   is re-entry-free and already rewrites, so it is used instead.

var bodypatchPosixSpawnTramp: pointer = nil
  ## Trampoline into the ORIGINAL posix_spawn body (set at install time, before
  ## the entry is patched). nil ⇒ trampoline build was skipped (non-relocatable
  ## prologue / failure) OR the body-patch backend is not installed
  ## (interpose-only), and the hook then degrades to the by-name forwarder (the
  ## named entry is NOT patched in that case, so by-name is re-entry-free).
var bodypatchPosixSpawnpTramp: pointer = nil

proc repro_hook_execve*(path: cstring; argv, envp: cstringArray): cint
    {.exportc, cdecl, dynlib.} =
  ## Unified execve hook (interpose + body-patch). Record the exec, then forward
  ## via the raw-syscall forwarder (raw `SYS_execve`, which re-adds the injection
  ## env vars and SIP-rewrites the path). The raw syscall bypasses the possibly
  ## body-patched named `execve` entry, so there is no re-entry under `both`.
  ##
  ## execve does not return on success — it REPLACES the process image — so the
  ## record must be both EMITTED *and* FLUSHED before the forward. Emitting only
  ## appends to the per-thread fragment BUFFER, which the new image never flushes
  ## (it loses the old image's in-flight batch); the buffered exec record would
  ## then be dropped, and with it the launched-binary dependency for this exec
  ## (§16.7.8). We therefore flush the in-flight batch to disk before forwarding.
  ## (The fork+exec case is the important one: a forked child's exec record lives
  ## only in that child's buffer, which exec would otherwise discard.)
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_execve(path, argv, envp)
  var record = baseRecord(mrProcessExec, moExecute)
  if path != nil:
    record.path = $path
  record.detail = "execve"
  emitRecord(record)
  discard repro_monitor_shim_flush()
  result = ct_macos_interpose_real_execve(path, argv, envp)

var bodypatchForkTramp: pointer = nil
  ## Trampoline into the ORIGINAL libsystem `fork` body (set at install time,
  ## before the entry is patched). The fork hook forwards through this so
  ## libsystem's `pthread_atfork` + malloc fork handlers run — WITHOUT it, a raw
  ## `SYS_fork` leaves the child's libsystem_malloc state inconsistent and the
  ## child SIGTRAPs (`brk`) on its first allocation (observed crashing bash/sh
  ## subshells during a monitored gnulib make on macOS 26). nil ⇒ the trampoline
  ## build was skipped (the C forwarder then falls back to the raw syscall) OR the
  ## body-patch backend is not installed (interpose-only — the named entry is NOT
  ## patched, so the by-name real is re-entry-free).

proc repro_hook_fork*(): PidT {.exportc, cdecl, dynlib.} =
  ## Unified fork hook (interpose + body-patch). Forward through the fork
  ## TRAMPOLINE into libsystem's own `fork` body so its `pthread_atfork` + malloc
  ## fork handlers run (resetting the allocator across the fork); the raw
  ## `SYS_fork` forwarder previously skipped that and crashed fork children in
  ## libsystem_malloc. The trampoline bypasses the (possibly body-patched) named
  ## `fork` entry, so there is no re-entry under `both`. A fork child inherits the
  ## already-loaded shim + env, so NO propagation is needed — only recording
  ## (spec §16.7.8 process-tree accounting). When no trampoline was built
  ## (interpose-only, or the build was skipped) the C forwarder falls back to a
  ## re-entry-free path (the named entry is not patched there).
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_call_fork(bodypatchForkTramp)
  result = ct_macos_bodypatch_call_fork(bodypatchForkTramp)
  if result > 0:
    recordSpawn(result, result, nil, "fork")
  elif result == 0:
    recordProcessStart()

var inSpawnForward {.threadvar.}: int
  ## Spawn-forward re-entrancy depth. The trampoline forward runs the ORIGINAL
  ## libsystem posix_spawn body, which on macOS re-invokes the public
  ## posix_spawn(p) symbol internally (the PATH-search / arg-desc wrapper funnels
  ## back through it). Because the SAME unified hook is installed on BOTH the
  ## body-patched entry AND the global __DATA,__interpose binding, that internal
  ## re-invocation lands back in this hook. If we forwarded through the
  ## trampoline AGAIN we would loop forever (the original body re-enters
  ## endlessly). So while a spawn forward is already in flight on this thread, a
  ## re-entry must reach the kernel via a DIFFERENT, re-entry-free path: the
  ## by-name real forwarder (ct_macos_interpose_real_posix_spawn). On macOS that
  ## resolves an image-local copy of the wrapper that is NOT the patched entry,
  ## breaking the loop while still completing the spawn. The re-entry is the
  ## SAME logical spawn, so it is NOT recorded again (recording happens only at
  ## the outermost, depth-0 forward) — preserving exactly-once recording.

proc spawnForward(tramp: pointer; pid: ptr PidT; path: cstring;
    fileActions, attrp: pointer; argv, envp: cstringArray;
    byName: proc(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                 argv, envp: cstringArray): cint {.nimcall.};
    detail: string): cint =
  ## Shared posix_spawn(p) forwarding core (DRY between the two variants).
  ##
  ## Apply env-propagation + SIP-rewrite EXACTLY ONCE, forward to the real
  ## implementation via a path that bypasses the possibly body-patched named
  ## entry, then record the spawn:
  ##   * tramp != nil (body-patch active), outermost call: the named entry IS
  ##     patched, so we pre-rewrite env+path here and forward through the
  ##     TRAMPOLINE into the original wrapper body (the trampoline does NOT
  ##     rewrite). The original body re-invokes the public symbol internally; see
  ##     `inSpawnForward` for why the re-entry must NOT re-use the trampoline.
  ##   * tramp == nil (interpose-only / trampoline build skipped) OR a re-entry
  ##     while a forward is already in flight: forward through the by-name real
  ##     (which itself rewrites once and is re-entry-free), WITHOUT pre-rewriting,
  ##     so the rewrite still happens exactly once.
  ## Recording the spawn once, at the OUTERMOST forward only, keeps a single
  ## source of truth for the record (no duplication, no double-record under
  ## `both`, and no spurious record for the internal re-invocation).
  let outermost = inSpawnForward == 0
  if tramp == nil or not outermost:
    result = byName(pid, path, fileActions, attrp, argv, envp)
  else:
    var effectiveEnvp: cstringArray = nil
    let effectivePath =
      ct_macos_bodypatch_spawn_rewrite(path, envp, addr effectiveEnvp)
    inc inSpawnForward
    try:
      result = ct_macos_bodypatch_call_posix_spawn(tramp, pid, effectivePath,
        fileActions, attrp, argv, effectiveEnvp)
    finally:
      dec inSpawnForward
  if outermost and result == 0 and pid != nil:
    recordSpawn(pid[], result, path, detail)

proc spawnForwardMuted(tramp: pointer; pid: ptr PidT; path: cstring;
    fileActions, attrp: pointer; argv, envp: cstringArray;
    byName: proc(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                 argv, envp: cstringArray): cint {.nimcall.}): cint =
  ## Forward a posix_spawn(p) WITHOUT recording (the shim is muted), reusing the
  ## SAME re-entry discipline as `spawnForward`. The trampoline path is taken
  ## only at the OUTERMOST forward and MUST bump `inSpawnForward` for its whole
  ## duration: libsystem's original body re-invokes the public symbol, which —
  ## because both the body-patched entry and the __interpose binding route here —
  ## lands back in this hook. Without the depth bump a muted spawn would re-enter
  ## the trampoline at depth 0 forever; with it, the re-entry sees depth>0 and
  ## takes the re-entry-free by-name path (mirrors the unmuted core, DRY).
  if tramp != nil and inSpawnForward == 0:
    inc inSpawnForward
    try:
      result = ct_macos_bodypatch_call_posix_spawn(tramp, pid, path,
        fileActions, attrp, argv, envp)
    finally:
      dec inSpawnForward
  else:
    result = byName(pid, path, fileActions, attrp, argv, envp)

proc repro_hook_posix_spawn*(pid: ptr PidT; path: cstring;
    fileActions, attrp: pointer; argv, envp: cstringArray): cint
    {.exportc, cdecl, dynlib.} =
  ## Unified posix_spawn hook (interpose + body-patch). Re-propagate injection +
  ## SIP-rewrite ONCE, forward via the trampoline (body-patch) or the by-name
  ## real (interpose-only / re-entry), record the spawn. The detail tag reflects
  ## which forward was taken so downstream can tell a body-patch-intercepted
  ## internal spawn from an interpose-visible one.
  if not initialized or disabled > 0:
    # Muted: forward only (no record), via the depth-guarded muted forwarder so
    # the trampoline path cannot re-enter itself at depth 0 (see
    # `spawnForwardMuted` / `inSpawnForward`).
    return spawnForwardMuted(bodypatchPosixSpawnTramp, pid, path, fileActions,
      attrp, argv, envp, ct_macos_interpose_real_posix_spawn)
  let detail =
    if bodypatchPosixSpawnTramp != nil and inSpawnForward == 0:
      "bodypatch-posix_spawn"
    else:
      "posix_spawn"
  spawnForward(bodypatchPosixSpawnTramp, pid, path, fileActions, attrp,
    argv, envp, ct_macos_interpose_real_posix_spawn, detail)

proc repro_hook_posix_spawnp*(pid: ptr PidT; path: cstring;
    fileActions, attrp: pointer; argv, envp: cstringArray): cint
    {.exportc, cdecl, dynlib.} =
  ## Unified posix_spawnp hook: as `repro_hook_posix_spawn` for the
  ## PATH-searching variant.
  if not initialized or disabled > 0:
    # Muted: forward only (no record), via the depth-guarded muted forwarder
    # (see `spawnForwardMuted` / `inSpawnForward`).
    return spawnForwardMuted(bodypatchPosixSpawnpTramp, pid, path, fileActions,
      attrp, argv, envp, ct_macos_interpose_real_posix_spawnp)
  let detail =
    if bodypatchPosixSpawnpTramp != nil and inSpawnForward == 0:
      "bodypatch-posix_spawnp"
    else:
      "posix_spawnp"
  spawnForward(bodypatchPosixSpawnpTramp, pid, path, fileActions, attrp,
    argv, envp, ct_macos_interpose_real_posix_spawnp, detail)

proc reproRuntimeInit() {.exportc.} =
  discard repro_monitor_shim_init(nil)

# --- Body-patch backend selection + installation -------------------------
#
# IO_MON_MACOS_BACKEND selects the macOS monitoring backend:
#   "both"      (default) — interpose stays installed (its static
#                __DATA,__interpose section is always present) AND body-patch
#                adds shared-cache-internal coverage.
#   "bodypatch" — interpose section is still present (it is static and cannot
#                be removed at runtime) but body-patch is also installed; in
#                practice this is identical to "both" for capture purposes.
#   "interpose" — legacy: skip the body-patch install entirely.
# Any unrecognised value is treated as the default ("both") and a warning is
# logged, so a typo degrades to MORE coverage, never less.

type BodypatchHookSpec = object
  names: seq[string]   ## libsystem symbol variants that share this ABI
  hook: pointer        ## the body-hook to branch to

proc shimLogToStderr(msg: string) {.raises: [].} =
  ## Emit a diagnostic line to stderr under the shim-muted guard so the
  ## diagnostic's own write() does not recurse into the (now body-patched)
  ## write hook. Best-effort: never raises, never aborts the constructor.
  withShimMuted:
    try:
      stderr.write(msg)
      stderr.write("\n")
      stderr.flushFile()
    except IOError:
      discard

proc bodypatchEnabled(): bool {.raises: [].} =
  ## Returns true if the body-patch backend should be installed.
  var backend = ""
  withShimMuted:
    backend = getEnv("IO_MON_MACOS_BACKEND", "both")
  case backend
  of "interpose":
    false
  of "both", "bodypatch":
    true
  else:
    shimLogToStderr("io-mon: unknown IO_MON_MACOS_BACKEND='" & backend &
      "', defaulting to 'both'")
    true

proc installBodypatchHooks() {.exportc: "repro_monitor_install_bodypatch", raises: [].} =
  ## Install every file-relevant libsystem syscall-wrapper body patch. Runs in
  ## the constructor, single-threaded (dyld runs constructors before main and
  ## before any monitored thread starts), so the patcher's registry is
  ## race-free. Every failure is non-fatal: a reduced/empty capture degrades to
  ## "re-run" downstream, never a false skip.
  if not bodypatchEnabled():
    shimLogToStderr("io-mon: macOS backend=interpose (body-patch skipped)")
    return

  # Each spec lists the distinct named entry points that share one ABI and
  # therefore one hook. open / open$NOCANCEL / __open_nocancel are DISTINCT
  # addresses (stdio's fopen/fread reach the $NOCANCEL variants), so all must
  # be patched. Symbols absent on this OS (dlsym → NULL) are skipped.
  let specs = @[
    BodypatchHookSpec(
      names: @["open", "open$NOCANCEL", "__open_nocancel"],
      hook: cast[pointer](repro_hook_open)),
    BodypatchHookSpec(
      names: @["openat", "openat$NOCANCEL", "__openat_nocancel"],
      hook: cast[pointer](repro_hook_openat)),
    BodypatchHookSpec(
      names: @["read", "read$NOCANCEL", "__read_nocancel"],
      hook: cast[pointer](repro_hook_read)),
    BodypatchHookSpec(
      names: @["write", "write$NOCANCEL", "__write_nocancel"],
      hook: cast[pointer](repro_hook_write)),
    BodypatchHookSpec(
      names: @["close", "close$NOCANCEL", "__close_nocancel"],
      hook: cast[pointer](repro_hook_close)),
    BodypatchHookSpec(
      names: @["stat", "stat64", "stat$INODE64"],
      hook: cast[pointer](repro_hook_stat)),
    BodypatchHookSpec(
      names: @["lstat", "lstat64", "lstat$INODE64"],
      hook: cast[pointer](repro_hook_lstat)),
    BodypatchHookSpec(
      names: @["fstatat", "fstatat64", "fstatat$INODE64"],
      hook: cast[pointer](repro_hook_fstatat)),
    BodypatchHookSpec(
      names: @["access"],
      hook: cast[pointer](repro_hook_access)),
    # rename / renameat: the gnulib/autotools atomic-output move
    # (`chmod a-w $@t; mv $@t $@`). These are thin syscall wrappers, so — like
    # open/read/stat — the hook forwards via the RAW rename/renameat syscall and
    # the PLAIN installer (no trampoline, no prologue copy) suffices. The plain
    # body patch overwrites the entry's first 16 bytes with the branch stub and
    # never needs a relocatable prologue, so rename/renameat ARE fully
    # body-patched (catching shared-cache-internal callers too), unlike the spawn
    # family whose trampoline DOES need relocatability.
    BodypatchHookSpec(
      names: @["rename"],
      hook: cast[pointer](repro_hook_rename)),
    BodypatchHookSpec(
      names: @["renameat"],
      hook: cast[pointer](repro_hook_renameat)),
    # Spawn family (spec §16.7.8): execve forwards via raw `SYS_execve` (it
    # replaces the process image and never returns on success, so no trampoline
    # and no malloc-fork concern); installed with the plain installer below.
    # `fork` is NOT installed here — it needs a TRAMPOLINE into the libsystem fork
    # body so the malloc/atfork handlers run (a raw `SYS_fork` left the child's
    # libsystem_malloc state inconsistent → `brk` SIGTRAP in fork children, which
    # broke a monitored gnulib make). fork is installed via the trampoline
    # installer below, alongside posix_spawn / posix_spawnp.
    BodypatchHookSpec(
      names: @["execve"],
      hook: cast[pointer](repro_hook_execve)),
  ]

  # Diagnostic gate: IO_MON_DEBUG_SKIP is a comma-separated list of body-patch
  # target names to SKIP installing (e.g. "posix_spawn,posix_spawnp,fork"). It
  # exists for root-causing host-specific body-patch faults; an empty/unset value
  # installs everything. It never relaxes safety (skipping only REDUCES capture,
  # which degrades to a fail-safe re-run, never a false skip).
  var debugSkip = ""
  withShimMuted:
    debugSkip = getEnv("IO_MON_DEBUG_SKIP", "")
  proc skipped(name: string): bool =
    debugSkip.len > 0 and (name in debugSkip.split(','))

  var installed, failed, absent: cint = 0
  for spec in specs:
    for name in spec.names:
      if skipped(name):
        continue
      reproMacosBodypatchInstallNamed(cstring(name), spec.hook,
        addr installed, addr failed, addr absent)

  # posix_spawn / posix_spawnp: the trampoline path. posix_spawn is NOT a thin
  # syscall wrapper (it marshals a private _posix_spawn_args_desc), so the hook
  # must forward into the ORIGINAL body via a trampoline rather than a raw
  # syscall. If the trampoline cannot be built (non-relocatable prologue) the
  # function is left interpose-only — a safe degradation (the trampoline pointer
  # stays nil, the hook falls back to the by-name forwarder, and the fail-safe
  # re-runs any unmonitored subtree). $NOCANCEL/`__` variants do not exist for
  # posix_spawn, so we patch just the two named entry points.
  # fork: TRAMPOLINE install. The fork hook MUST forward into the libsystem fork
  # body (via the trampoline) so the malloc/atfork child handlers run; a raw
  # `SYS_fork` corrupted the child allocator and crashed fork children. The fork
  # prologue (`pacibsp; stp; stp; add`) is relocatable, so the trampoline builds;
  # if it ever could not, fork is left interpose-only (the hook then forwards via
  # the re-entry-free by-name real) — a safe degradation.
  if not skipped("fork"):
    reproMacosBodypatchInstallNamedTramp(cstring("fork"),
      cast[pointer](repro_hook_fork), addr bodypatchForkTramp,
      addr installed, addr failed, addr absent)
  if not skipped("posix_spawn"):
    reproMacosBodypatchInstallNamedTramp(cstring("posix_spawn"),
      cast[pointer](repro_hook_posix_spawn), addr bodypatchPosixSpawnTramp,
      addr installed, addr failed, addr absent)
  if not skipped("posix_spawnp"):
    reproMacosBodypatchInstallNamedTramp(cstring("posix_spawnp"),
      cast[pointer](repro_hook_posix_spawnp), addr bodypatchPosixSpawnpTramp,
      addr installed, addr failed, addr absent)

  shimLogToStderr("io-mon: macOS body-patch installed=" & $installed &
    " failed=" & $failed & " absent=" & $absent &
    " fork_tramp=" & (if bodypatchForkTramp != nil: "ok" else: "skip") &
    " spawn_tramp=" & (if bodypatchPosixSpawnTramp != nil: "ok" else: "skip") &
    " spawnp_tramp=" &
      (if bodypatchPosixSpawnpTramp != nil: "ok" else: "skip"))

{.emit: """
static int repro_monitor_runtime_ready = 0;
extern void NimMain(void);
extern void repro_monitor_install_bodypatch(void);
extern int repro_monitor_shim_flush(void);

typedef DIR *(*repro_real_opendir_fn)(const char *);
typedef struct dirent *(*repro_real_readdir_fn)(DIR *);
typedef int (*repro_real_closedir_fn)(DIR *);
typedef pid_t (*repro_real_fork_fn)(void);
typedef int (*repro_real_posix_spawn_fn)(pid_t *, const char *,
  const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
  char *const [], char *const []);

static int repro_wrap_open(const char *path, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_open, path, flags, mode);
  }
  return repro_hook_open((char *)path, flags, mode);
}

static int repro_wrap_openat(int dirfd, const char *path, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
  }
  return repro_hook_openat(dirfd, (char *)path, flags, mode);
}

static ssize_t repro_wrap_read(int fd, void *buf, size_t count) {
  if (!repro_monitor_runtime_ready) {
    return syscall(SYS_read, fd, buf, count);
  }
  return repro_hook_read(fd, buf, count);
}

static ssize_t repro_wrap_write(int fd, const void *buf, size_t count) {
  if (!repro_monitor_runtime_ready) {
    return syscall(SYS_write, fd, buf, count);
  }
  return repro_hook_write(fd, (void *)buf, count);
}

static int repro_wrap_close(int fd) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_close, fd);
  }
  return repro_hook_close(fd);
}

static DIR *repro_wrap_opendir(const char *path) {
  if (!repro_monitor_runtime_ready) {
    repro_real_opendir_fn real_fn = (repro_real_opendir_fn)dlsym(RTLD_NEXT, "opendir");
    return real_fn(path);
  }
  return (DIR *)repro_hook_opendir((char *)path);
}

static struct dirent *repro_wrap_readdir(DIR *dirp) {
  if (!repro_monitor_runtime_ready) {
    repro_real_readdir_fn real_fn = (repro_real_readdir_fn)dlsym(RTLD_NEXT, "readdir");
    return real_fn(dirp);
  }
  return (struct dirent *)repro_hook_readdir(dirp);
}

static int repro_wrap_closedir(DIR *dirp) {
  if (!repro_monitor_runtime_ready) {
    repro_real_closedir_fn real_fn = (repro_real_closedir_fn)dlsym(RTLD_NEXT, "closedir");
    return real_fn(dirp);
  }
  return repro_hook_closedir(dirp);
}

static int repro_wrap_stat(const char *path, struct stat *buf) {
  if (!repro_monitor_runtime_ready) {
#ifdef SYS_stat64
    return (int)syscall(SYS_stat64, path, buf);
#else
    return (int)syscall(SYS_stat, path, buf);
#endif
  }
  return repro_hook_stat((char *)path, buf);
}

static int repro_wrap_lstat(const char *path, struct stat *buf) {
  if (!repro_monitor_runtime_ready) {
#ifdef SYS_lstat64
    return (int)syscall(SYS_lstat64, path, buf);
#else
    return (int)syscall(SYS_lstat, path, buf);
#endif
  }
  return repro_hook_lstat((char *)path, buf);
}

static pid_t repro_wrap_fork(void) {
  if (!repro_monitor_runtime_ready) {
    repro_real_fork_fn real_fn = (repro_real_fork_fn)dlsym(RTLD_NEXT, "fork");
    return real_fn();
  }
  return repro_hook_fork();
}

static int repro_wrap_rename(const char *from, const char *to) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_rename, from, to);
  }
  return repro_hook_rename((char *)from, (char *)to);
}

static int repro_wrap_renameat(int fromfd, const char *from, int tofd,
                               const char *to) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_renameat, fromfd, from, tofd, to);
  }
  return repro_hook_renameat(fromfd, (char *)from, tofd, (char *)to);
}

static int repro_wrap_execve(const char *path, char *const argv[], char *const envp[]) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_execve, path, argv, envp);
  }
  return repro_hook_execve((char *)path, (char **)argv, (char **)envp);
}

static int repro_wrap_posix_spawn(pid_t *pid, const char *path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *attrp,
  char *const argv[], char *const envp[]) {
  if (!repro_monitor_runtime_ready) {
    repro_real_posix_spawn_fn real_fn =
      (repro_real_posix_spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    return real_fn(pid, path, file_actions, attrp, argv, envp);
  }
  return repro_hook_posix_spawn(pid, (char *)path, (void *)file_actions,
    (void *)attrp, (char **)argv, (char **)envp);
}

static int repro_wrap_posix_spawnp(pid_t *pid, const char *path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *attrp,
  char *const argv[], char *const envp[]) {
  if (!repro_monitor_runtime_ready) {
    repro_real_posix_spawn_fn real_fn =
      (repro_real_posix_spawn_fn)dlsym(RTLD_NEXT, "posix_spawnp");
    return real_fn(pid, path, file_actions, attrp, argv, envp);
  }
  return repro_hook_posix_spawnp(pid, (char *)path, (void *)file_actions,
    (void *)attrp, (char **)argv, (char **)envp);
}

__attribute__((constructor))
static void repro_monitor_shim_constructor(void) {
  NimMain();
  reproRuntimeInit();
  repro_monitor_runtime_ready = 1;
  /*
   * Install the body-patch backend AFTER the runtime is ready: the unified
   * repro_hook_* functions (used by BOTH the __interpose tuples and the
   * body-patch install) require the recording runtime to be live, and
   * runtime_ready=1 ensures the interpose wrappers route through the hooks too.
   * Runs single-threaded here (dyld constructors execute before
   * main and before any monitored thread starts), so the patcher's registry is
   * race-free. A failed install is non-fatal — it logs and degrades to reduced
   * capture (the downstream runner re-runs; it never treats this as a skip).
   */
  repro_monitor_install_bodypatch();
}

/*
 * Flush the fragment batch buffer at process exit. The writer batches frames
 * per-thread and only flushes on overflow / 100 ms age / explicit flush; a
 * short-lived monitored process that opens a few files and exits would
 * otherwise lose its buffered records before the parent's mergeFragments runs.
 * Registering this as a dyld destructor closes that window for the common
 * fast-exit case. (It runs only for normal returns / exit(); it cannot run on
 * _exit/signal — those windows are bounded by the 100 ms age flush.)
 */
__attribute__((destructor))
static void repro_monitor_shim_destructor(void) {
  if (repro_monitor_runtime_ready) {
    repro_monitor_shim_flush();
  }
}

__attribute__((used))
static struct {
  const void *replacement;
  const void *replacee;
} repro_monitor_interposers[] __attribute__((section("__DATA,__interpose"))) = {
  { (const void *)repro_wrap_open, (const void *)open },
  { (const void *)repro_wrap_openat, (const void *)openat },
  { (const void *)repro_wrap_read, (const void *)read },
  { (const void *)repro_wrap_write, (const void *)write },
  { (const void *)repro_wrap_close, (const void *)close },
  { (const void *)repro_wrap_opendir, (const void *)opendir },
  { (const void *)repro_wrap_readdir, (const void *)readdir },
  { (const void *)repro_wrap_closedir, (const void *)closedir },
  { (const void *)repro_wrap_stat, (const void *)stat },
  { (const void *)repro_wrap_lstat, (const void *)lstat },
  { (const void *)repro_wrap_fork, (const void *)fork },
  { (const void *)repro_wrap_rename, (const void *)rename },
  { (const void *)repro_wrap_renameat, (const void *)renameat },
  { (const void *)repro_wrap_execve, (const void *)execve },
  { (const void *)repro_wrap_posix_spawn, (const void *)posix_spawn },
  { (const void *)repro_wrap_posix_spawnp, (const void *)posix_spawnp }
};
""".}
