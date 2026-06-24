when not defined(macosx):
  {.error: "repro_monitor_shim/macos_interpose is macOS-only".}

import std/[locks, os, tables]
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
  var record = baseRecord(mrFileOpen, observationForOpen(flags))
  record.result = result.int64
  record.flags = uint32(flags)
  if path != nil:
    record.path = $path
  emitRecord(record)
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
  var record = baseRecord(mrFileOpen, observationForOpen(flags))
  record.result = result.int64
  record.flags = uint32(flags)
  if path != nil:
    record.path = $path
  record.detail = "dirfd=" & $dirfd
  emitRecord(record)
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

proc repro_hook_stat*(path: cstring; buf: pointer): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_stat(path, buf)
  result = ct_macos_interpose_real_stat(path, buf)
  let savedErrno = getErrno()
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = result.int64
  record.probeResult = probeFromResult(result)
  if path != nil:
    record.path = $path
  emitRecord(record)
  setErrno(savedErrno)

proc repro_hook_lstat*(path: cstring; buf: pointer): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_lstat(path, buf)
  result = ct_macos_interpose_real_lstat(path, buf)
  let savedErrno = getErrno()
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = result.int64
  record.probeResult = probeFromResult(result)
  if path != nil:
    record.path = $path
  emitRecord(record)
  setErrno(savedErrno)

# --- Body-patch stat-family hooks ----------------------------------------
#
# These mirror repro_hook_stat/lstat but forward to the kernel via the RAW
# stat64 syscall (ct_macos_bodypatch_real_*), NOT via the named symbol — the
# body-patch backend has replaced the named stat/lstat/fstatat entry points, so
# forwarding through them (or through dlsym) would re-enter infinitely. open /
# openat / read / write / close are NOT duplicated here: their existing
# repro_hook_* recorders already forward via the raw syscall
# (ct_macos_interpose_real_* → *_syscall), so the body patch reuses them
# directly (high fan-in, DRY).

proc repro_bodyhook_stat*(path: cstring; buf: pointer): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_stat(path, buf)
  result = ct_macos_bodypatch_real_stat(path, buf)
  let savedErrno = getErrno()
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = result.int64
  record.probeResult = probeFromResult(result)
  if path != nil:
    record.path = $path
  emitRecord(record)
  setErrno(savedErrno)

proc repro_bodyhook_lstat*(path: cstring; buf: pointer): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_lstat(path, buf)
  result = ct_macos_bodypatch_real_lstat(path, buf)
  let savedErrno = getErrno()
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = result.int64
  record.probeResult = probeFromResult(result)
  if path != nil:
    record.path = $path
  emitRecord(record)
  setErrno(savedErrno)

proc repro_bodyhook_fstatat*(dirfd: cint; path: cstring; buf: pointer;
    flag: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_fstatat(dirfd, path, buf, flag)
  result = ct_macos_bodypatch_real_fstatat(dirfd, path, buf, flag)
  let savedErrno = getErrno()
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = result.int64
  record.probeResult = probeFromResult(result)
  if path != nil:
    record.path = $path
  record.detail = "fstatat dirfd=" & $dirfd
  emitRecord(record)
  setErrno(savedErrno)

proc repro_bodyhook_access*(path: cstring; mode: cint): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_access(path, mode)
  result = ct_macos_bodypatch_real_access(path, mode)
  let savedErrno = getErrno()
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = result.int64
  record.probeResult = probeFromResult(result)
  record.flags = uint32(mode)
  if path != nil:
    record.path = $path
  emitRecord(record)
  setErrno(savedErrno)

proc repro_hook_fork*(): PidT {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_fork()
  result = ct_macos_interpose_real_fork()
  if result > 0:
    var record = baseRecord(mrProcessSpawn, moExecute)
    record.childOsPid = uint64(result)
    record.result = result.int64
    record.detail = "fork"
    emitRecord(record)
  elif result == 0:
    recordProcessStart()

proc repro_hook_execve*(path: cstring; argv, envp: cstringArray): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_execve(path, argv, envp)
  var record = baseRecord(mrProcessExec, moExecute)
  if path != nil:
    record.path = $path
  emitRecord(record)
  result = ct_macos_interpose_real_execve(path, argv, envp)

proc repro_hook_posix_spawn*(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
    argv, envp: cstringArray): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_posix_spawn(pid, path, fileActions, attrp, argv, envp)
  result = ct_macos_interpose_real_posix_spawn(pid, path, fileActions, attrp, argv, envp)
  if result == 0 and pid != nil:
    var record = baseRecord(mrProcessSpawn, moExecute)
    record.childOsPid = uint64(pid[])
    record.result = result.int64
    if path != nil:
      record.path = $path
    record.detail = "posix_spawn"
    emitRecord(record)

proc repro_hook_posix_spawnp*(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
    argv, envp: cstringArray): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_posix_spawnp(pid, path, fileActions, attrp, argv, envp)
  result = ct_macos_interpose_real_posix_spawnp(pid, path, fileActions, attrp, argv, envp)
  if result == 0 and pid != nil:
    var record = baseRecord(mrProcessSpawn, moExecute)
    record.childOsPid = uint64(pid[])
    record.result = result.int64
    if path != nil:
      record.path = $path
    record.detail = "posix_spawnp"
    emitRecord(record)

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
      hook: cast[pointer](repro_bodyhook_stat)),
    BodypatchHookSpec(
      names: @["lstat", "lstat64", "lstat$INODE64"],
      hook: cast[pointer](repro_bodyhook_lstat)),
    BodypatchHookSpec(
      names: @["fstatat", "fstatat64", "fstatat$INODE64"],
      hook: cast[pointer](repro_bodyhook_fstatat)),
    BodypatchHookSpec(
      names: @["access"],
      hook: cast[pointer](repro_bodyhook_access)),
  ]

  var installed, failed, absent: cint = 0
  for spec in specs:
    for name in spec.names:
      reproMacosBodypatchInstallNamed(cstring(name), spec.hook,
        addr installed, addr failed, addr absent)

  shimLogToStderr("io-mon: macOS body-patch installed=" & $installed &
    " failed=" & $failed & " absent=" & $absent)

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
   * Install the body-patch backend AFTER the runtime is ready: the body-patch
   * hooks (repro_hook_* / repro_bodyhook_*) require the recording runtime to
   * be live, and runtime_ready=1 ensures the interpose wrappers route through
   * the hooks too. Runs single-threaded here (dyld constructors execute before
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
  { (const void *)repro_wrap_execve, (const void *)execve },
  { (const void *)repro_wrap_posix_spawn, (const void *)posix_spawn },
  { (const void *)repro_wrap_posix_spawnp, (const void *)posix_spawnp }
};
""".}
