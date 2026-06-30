when not defined(linux):
  {.error: "repro_monitor_shim/linux_preload is Linux-only".}

import std/[locks, os, sets, strutils, tables]
from io_mon/paths import extendedPath

import io_mon/types
import io_mon/writer
import io_mon/hooks/linux_preload_runtime
import stackable_hooks/platform/linux_raw_syscalls

const
  OAccMode = 0x0003.cint
  OWrOnly = 0x0001.cint
  ORdWr = 0x0002.cint
  OCreat = 0x0040.cint
  OTrunc = 0x0200.cint
  OAppend = 0x0400.cint
  LinuxAtFdcwd = -100.cint
  LinuxSysRead = 0.clong
  LinuxSysOpen = 2.clong
  LinuxSysClose = 3.clong
  LinuxSysStat = 4.clong
  LinuxSysLstat = 6.clong
  LinuxSysAccess = 21.clong
  LinuxSysReadlink = 89.clong
  LinuxSysOpenat = 257.clong
  LinuxSysNewfstatat = 262.clong
  LinuxSysReadlinkat = 267.clong
  LinuxSysFaccessat = 269.clong
  LinuxSysStatx = 332.clong
  LinuxSysOpenat2 = 437.clong
  LinuxEfault = 14.clong

type
  LinuxOpenHow = object
    flags: uint64
    mode: uint64
    resolve: uint64

var
  initialized = false
  locksReady = false
  initLockVar: Lock
  recordLock: Lock
  fdLock: Lock
  dirLock: Lock
  streamLock: Lock
  observedLock: Lock
  fragmentDir: string
  nextProcessSeq: uint64 = 0
  fdPaths = initTable[cint, string]()
  dirPaths = initTable[uint, string]()
  streamPaths = initTable[uint, string]()
  observedNonFileInputs = initHashSet[string]()
  rawSyscallCoverageRecorded = false
  inlineSyscallCoverageRecorded = false
  inlineSyscallTrapCoverageRecorded = false
  # Thread id of the thread that ran the preload constructor (the process
  # main thread). Its fragment batch is flushed by the process-exit
  # destructor; worker threads flush eagerly per record (see emitRecord),
  # mirroring the macOS shim, because a pthread-key thread-exit destructor
  # cannot safely touch Nim TLS during teardown.
  mainThreadId: uint64 = 0

var
  disabled {.threadvar.}: int
  inForkChild {.threadvar.}: bool

{.emit: """
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

extern long stackable_linux_raw_syscall6(long nr, long a1, long a2, long a3,
                                         long a4, long a5, long a6);

long repro_linux_gettid(void) {
  return stackable_linux_raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
}

int repro_linux_get_errno(void) {
  return errno;
}

void repro_linux_set_errno(int value) {
  errno = value;
}

int repro_linux_errno_is_connect_in_progress(int value) {
  return value == EINPROGRESS || value == EALREADY || value == EWOULDBLOCK;
}

int repro_linux_sockaddr_family(void *addr, unsigned int addrlen) {
  if (addr == NULL || addrlen < sizeof(sa_family_t)) return 0;
  return ((struct sockaddr *)addr)->sa_family;
}

long repro_linux_socket_peer_pid(int fd) {
  struct ucred cred;
  socklen_t len = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
    return (long)cred.pid;
  return 0;
}

extern int repro_monitor_shim_init(char *configPath);
extern int repro_monitor_shim_shutdown(void);

__attribute__((constructor))
static void repro_linux_monitor_constructor(void) {
  repro_monitor_shim_init(NULL);
}

__attribute__((destructor))
static void repro_linux_monitor_destructor(void) {
  /* Flush the main thread's buffered fragment batch on process exit so a
     short-lived process (or the trailing batch of any process) does not
     drop its records — which would otherwise make a fast child look
     un-injected and downgrade completeness to mcIncomplete. */
  repro_monitor_shim_shutdown();
}
""".}

proc c_getpid(): cint {.importc: "getpid", header: "<unistd.h>".}
proc c_getppid(): cint {.importc: "getppid", header: "<unistd.h>".}
proc c_gettid(): clong {.importc: "repro_linux_gettid", raises: [].}
proc c_get_errno(): cint {.importc: "repro_linux_get_errno", raises: [].}
proc c_set_errno(value: cint) {.importc: "repro_linux_set_errno", raises: [].}
proc c_errno_is_connect_in_progress(value: cint): cint
  {.importc: "repro_linux_errno_is_connect_in_progress", raises: [].}
proc c_sockaddr_family(address: pointer; addrLen: uint32): cint
  {.importc: "repro_linux_sockaddr_family", raises: [].}
proc c_socket_peer_pid(fd: cint): clong
  {.importc: "repro_linux_socket_peer_pid", raises: [].}

proc currentThreadId(): uint64 =
  uint64(c_gettid())

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

proc shouldBypass(): bool {.inline, raises: [].} =
  disabled > 0 or inForkChild

proc baseRecord(kind: MonitorRecordKind;
                observationKind: MonitorObservationKind): MonitorRecord =
  MonitorRecord(
    kind: kind,
    observationKind: observationKind,
    seq: processSeq(),
    osPid: uint64(c_getpid()),
    parentOsPid: uint64(c_getppid()),
    threadId: currentThreadId(),
    probeResult: prUnknown)

proc emitRecord(record: MonitorRecord) {.raises: [].} =
  if not initialized or fragmentDir.len == 0 or shouldBypass():
    return
  withShimMuted:
    appendFragmentRecord(fragmentDir, record)
    # The main thread keeps the batching win (flushed by the process-exit
    # destructor); a worker thread that exits early cannot be reached by the
    # destructor and has no safe pthread-key flush, so flush its batch eagerly
    # per record. Mirrors the macOS shim's threaded-write handling.
    if mainThreadId != 0 and record.threadId != mainThreadId:
      flushFragmentBatch()

proc recordProcessStart() {.raises: [].} =
  var record = baseRecord(mrProcessStart, moProcessStart)
  record.detail = "linux-preload-hooks"
  emitRecord(record)

proc emitEventLoss(detail: string; result: int64 = 0) {.raises: [].} =
  var record = baseRecord(mrEventLoss, moEventLoss)
  record.detail = detail
  record.result = result
  emitRecord(record)

proc drainInlineRawSyscallEvents() {.raises: [].}

proc recordRawSyscallCoverage(status: RawSyscallPatchStatus) {.raises: [].} =
  if rawSyscallCoverageRecorded:
    return
  rawSyscallCoverageRecorded = true
  if status.installed:
    return
  emitEventLoss("linux raw-syscall wrapper patch unavailable diagnostic=" &
    $status.diagnostic & " stage=" & $status.stage &
    " errno=" & $status.osErrno)

proc recordInlineSyscallCoverage(status: InlineSyscallPatchStatus) {.raises: [].} =
  if inlineSyscallCoverageRecorded:
    return
  inlineSyscallCoverageRecorded = true
  if status.handlerInstalled and status.scanDiagnostic == lrsOk and
      status.firstPatchDiagnostic == lrsOk:
    return
  emitEventLoss("linux inline raw-syscall scanner unavailable scan=" &
    $status.scanDiagnostic & " install=" & $status.installDiagnostic &
    " patched-sites=" & $status.patchedSites &
    " first-patch=" & $status.firstPatchDiagnostic &
    " stage=" & $status.firstPatchStage &
    " errno=" & $status.firstPatchErrno)

proc recordLateInlineSyscallScanCoverage(status: InlineSyscallPatchStatus;
                                         source: string) {.raises: [].} =
  if status.handlerInstalled and status.scanDiagnostic == lrsOk and
      status.firstPatchDiagnostic == lrsOk:
    return
  emitEventLoss("linux late inline raw-syscall scanner unavailable source=" &
    source & " scan=" & $status.scanDiagnostic &
    " install=" & $status.installDiagnostic &
    " patched-sites=" & $status.patchedSites &
    " first-patch=" & $status.firstPatchDiagnostic &
    " stage=" & $status.firstPatchStage &
    " errno=" & $status.firstPatchErrno)

proc recordInlineSyscallTrapCoverage() {.raises: [].} =
  if inlineSyscallTrapCoverageRecorded:
    return
  let traps = inlineSyscallTrapCount()
  let failures = inlineSyscallFailureCount()
  if traps == 0 and failures == 0:
    return
  inlineSyscallTrapCoverageRecorded = true
  drainInlineRawSyscallEvents()
  if failures != 0:
    emitEventLoss("linux inline raw syscall replay failed nr=" &
      $inlineSyscallLastNumber() & " address=0x" &
      toHex(inlineSyscallLastAddress()) & " traps=" & $traps &
      " failures=" & $failures, int64(inlineSyscallLastNumber()))

proc repro_monitor_shim_init*(configPath: cstring): cint
    {.exportc, dynlib, raises: [].}

proc ensureInitialized() {.raises: [].} =
  if not initialized:
    discard repro_monitor_shim_init(nil)

proc ensureInitializedPreservingErrno() {.raises: [].} =
  let savedErrno = c_get_errno()
  ensureInitialized()
  c_set_errno(savedErrno)

proc observationForOpen(flags: cint): MonitorObservationKind =
  if (flags and (OCreat or OTrunc or OAppend)) != 0:
    moFileWrite
  else:
    let acc = flags and OAccMode
    if acc == OWrOnly or acc == ORdWr:
      moFileWrite
    else:
      moFileOpen

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

proc pathForAt(dirfd: cint; path: cstring): string {.raises: [].} =
  if path == nil:
    return ""
  let raw = $path
  if raw.len == 0 or raw.isAbsolute or dirfd == LinuxAtFdcwd:
    return raw
  let base = pathForFd(dirfd)
  if base.len == 0:
    return raw
  result = base / raw

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

proc streamKey(stream: pointer): uint =
  cast[uint](stream)

proc updateStreamPath(stream: pointer; path: cstring) =
  if stream == nil or path == nil:
    return
  acquire(streamLock)
  streamPaths[streamKey(stream)] = $path
  release(streamLock)

proc removeStreamPath(stream: pointer) =
  acquire(streamLock)
  streamPaths.del(streamKey(stream))
  release(streamLock)

proc pathForStream(stream: pointer): string =
  acquire(streamLock)
  result = streamPaths.getOrDefault(streamKey(stream), "")
  release(streamLock)

proc probeFromResult(callResult: cint): ProbeResult =
  if callResult == 0:
    prExistingOther
  else:
    prAbsent

proc repro_monitor_shim_init*(configPath: cstring): cint
    {.exportc, dynlib, raises: [].} =
  if not locksReady:
    initLock(initLockVar)
    initLock(recordLock)
    initLock(fdLock)
    initLock(dirLock)
    initLock(streamLock)
    initLock(observedLock)
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
  mainThreadId = currentThreadId()
  recordProcessStart()
  let rawStatus = installRawSyscallWrapperPatch()
  recordRawSyscallCoverage(rawStatus)
  let inlineStatus = installInlineSyscallPatches()
  recordInlineSyscallCoverage(inlineStatus)
  result = 0

proc repro_monitor_shim_flush*(): cint {.exportc, dynlib, raises: [].} =
  ## Flush + close the calling thread's fragment slot so no buffered records
  ## are dropped (previously a no-op, which lost the batched tail).
  withShimMuted:
    try: closeFragmentSlot()
    except CatchableError: discard
  result = 0
proc repro_monitor_shim_shutdown*(): cint {.exportc, dynlib, raises: [].} =
  ## Process/thread shutdown: flush + close the calling thread's fragment
  ## slot. Invoked by the process-exit destructor for the main thread.
  recordInlineSyscallTrapCoverage()
  withShimMuted:
    try: closeFragmentSlot()
    except CatchableError: discard
  result = 0
proc repro_monitor_shim_disable_current_thread*() {.exportc, dynlib, raises: [].} =
  inc disabled
proc repro_monitor_shim_enable_current_thread*() {.exportc, dynlib, raises: [].} =
  if disabled > 0:
    dec disabled
proc repro_monitor_shim_version*(): cstring {.exportc, dynlib, raises: [].} =
  "repro_monitor_shim_m11"

proc recordOpen(path: cstring; flags, mode, fd: cint) {.raises: [].} =
  updateFdPath(fd, path)
  var record = baseRecord(mrFileOpen, observationForOpen(flags))
  record.result = fd.int64
  record.flags = uint32(flags)
  if path != nil:
    record.path = $path
  emitRecord(record)

proc repro_hook_open*(ctx: var OpenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordOpen(ctx.path, ctx.flags, ctx.mode, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_open64*(ctx: var OpenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordOpen(ctx.path, ctx.flags, ctx.mode, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_openat*(ctx: var OpenatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordOpen(ctx.path, ctx.flags, ctx.mode, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_openat64*(ctx: var OpenatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordOpen(ctx.path, ctx.flags, ctx.mode, ctx.result)
  c_set_errno(savedErrno)

proc recordFdRead(fd: cint; bytes: clong) {.raises: [].} =
  if bytes >= 0:
    var record = baseRecord(mrFileRead, moFileRead)
    record.path = pathForFd(fd)
    record.result = bytes.int64
    record.flags = uint32(fd)
    emitRecord(record)

proc recordFdWrite(fd: cint; bytes: clong) {.raises: [].} =
  if bytes >= 0 and fd > 2:
    var record = baseRecord(mrFileWrite, moFileWrite)
    record.path = pathForFd(fd)
    record.result = bytes.int64
    record.flags = uint32(fd)
    emitRecord(record)

proc repro_hook_read*(ctx: var ReadContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordFdRead(ctx.fd, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_pread*(ctx: var PreadContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordFdRead(ctx.fd, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_readv*(ctx: var ReadvContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordFdRead(ctx.fd, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_preadv*(ctx: var PreadvContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordFdRead(ctx.fd, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_write*(ctx: var WriteContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordFdWrite(ctx.fd, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_close*(ctx: var CloseContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  callNext(ctx)
  let savedErrno = c_get_errno()
  removeFdPath(ctx.fd)
  c_set_errno(savedErrno)

proc emitProbe(path: cstring; callResult: cint) {.raises: [].} =
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = callResult.int64
  record.probeResult = probeFromResult(callResult)
  if path != nil:
    record.path = $path
  emitRecord(record)

proc cstringArg(value: clong): cstring {.inline, raises: [].} =
  if value == 0:
    nil
  else:
    cast[cstring](cast[pointer](value))

proc resultLooksFaulted(callResult: clong): bool {.inline, raises: [].} =
  callResult == -LinuxEfault

proc probeResultFromRaw(callResult: clong): cint {.inline, raises: [].} =
  if callResult >= 0:
    0.cint
  else:
    (-1).cint

proc recordRawRead(fd: cint; callResult: clong): bool {.raises: [].} =
  if callResult < 0:
    return true
  if fd <= 2:
    return true
  let path = pathForFd(fd)
  if path.len == 0:
    return false
  var record = baseRecord(mrFileRead, moFileRead)
  record.path = path
  record.result = callResult.int64
  record.flags = uint32(fd)
  emitRecord(record)
  true

proc openHowFlags(howArg, callResult: clong; flags, mode: var cint): bool
    {.raises: [].} =
  if callResult < 0 or howArg == 0:
    return false
  let how = cast[ptr LinuxOpenHow](cast[pointer](howArg))
  flags = cint(how.flags)
  mode = cint(how.mode)
  true

proc rawSyscallSourceName(inlineTrap: cint): string {.raises: [].} =
  if inlineTrap != 0:
    "inline raw syscall"
  else:
    "libc raw syscall"

proc classifyRawFileSyscall(number, a1, a2, a3, a4, a5, a6, callResult: clong;
                            inlineTrap: cint): bool {.raises: [].} =
  case number
  of LinuxSysOpen:
    if callResult < 0 or resultLooksFaulted(callResult):
      return true
    recordOpen(cstringArg(a1), cint(a2), cint(a3), cint(callResult))
    true
  of LinuxSysOpenat:
    if callResult < 0 or resultLooksFaulted(callResult):
      return true
    recordOpen(cstringArg(a2), cint(a3), cint(a4), cint(callResult))
    true
  of LinuxSysOpenat2:
    var flags, mode: cint
    if not openHowFlags(a3, callResult, flags, mode):
      return false
    recordOpen(cstringArg(a2), flags, mode, cint(callResult))
    true
  of LinuxSysRead:
    recordRawRead(cint(a1), callResult)
  of LinuxSysClose:
    if callResult >= 0:
      removeFdPath(cint(a1))
    true
  of LinuxSysStat, LinuxSysLstat, LinuxSysAccess, LinuxSysReadlink:
    if resultLooksFaulted(callResult):
      return false
    emitProbe(cstringArg(a1), probeResultFromRaw(callResult))
    true
  of LinuxSysNewfstatat, LinuxSysFaccessat, LinuxSysReadlinkat, LinuxSysStatx:
    if resultLooksFaulted(callResult):
      return false
    emitProbe(cstringArg(a2), probeResultFromRaw(callResult))
    true
  else:
    false

proc recordRawSyscallClassification(number, a1, a2, a3, a4, a5, a6,
                                    callResult: clong; inlineTrap: cint)
    {.raises: [].} =
  if classifyRawFileSyscall(number, a1, a2, a3, a4, a5, a6, callResult,
                            inlineTrap):
    return
  emitEventLoss(rawSyscallSourceName(inlineTrap) &
    " unsupported nr=" & $number, int64(number))

proc drainInlineRawSyscallEvents() {.raises: [].} =
  if rawSyscallEventOverflowed():
    emitEventLoss("inline raw syscall event buffer overflow")
  let count = rawSyscallEventCount()
  for i in 0 ..< count:
    let event = rawSyscallEventAt(i)
    if not event.ok:
      emitEventLoss("inline raw syscall event read failed index=" & $i)
      continue
    recordRawSyscallClassification(event.number, event.a1, event.a2, event.a3,
      event.a4, event.a5, event.a6, event.result, event.source)

proc repro_hook_stat*(ctx: var StatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  emitProbe(ctx.path, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_lstat*(ctx: var StatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  emitProbe(ctx.path, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_opendir*(ctx: var OpendirContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  updateDirPath(ctx.result, ctx.path)
  c_set_errno(savedErrno)

proc repro_hook_readdir*(ctx: var ReaddirContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  let dirPath = pathForDir(ctx.dirp)
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != nil:
    var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
    record.path = dirPath
    record.result = 1
    record.detail = "readdir"
    emitRecord(record)
  c_set_errno(savedErrno)

proc repro_hook_closedir*(ctx: var ClosedirContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  callNext(ctx)
  let savedErrno = c_get_errno()
  removeDirPath(ctx.dirp)
  c_set_errno(savedErrno)

proc modeLooksReadable(mode: cstring): bool =
  if mode == nil or mode[0] == '\0':
    return true
  if mode[0] == 'r':
    return true
  var i = 0
  while mode[i] != '\0':
    if mode[i] == '+':
      return true
    inc i
  result = false

proc recordFopen(path, mode: cstring; stream: pointer) {.raises: [].} =
  if stream != nil:
    updateStreamPath(stream, path)
  var record = baseRecord(mrFileOpen,
    if modeLooksReadable(mode): moFileOpen else: moFileWrite)
  record.result = cast[int64](stream)
  if path != nil:
    record.path = $path
  if mode != nil:
    record.detail = "stdio:" & $mode
  emitRecord(record)

proc repro_hook_fopen*(ctx: var FopenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordFopen(ctx.path, ctx.mode, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_fopen64*(ctx: var FopenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordFopen(ctx.path, ctx.mode, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_fread*(ctx: var FreadContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result > 0:
    var record = baseRecord(mrFileRead, moFileRead)
    record.path = pathForStream(ctx.stream)
    record.result = int64(ctx.result * ctx.size)
    emitRecord(record)
  c_set_errno(savedErrno)

proc repro_hook_fclose*(ctx: var FcloseContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  callNext(ctx)
  let savedErrno = c_get_errno()
  removeStreamPath(ctx.stream)
  c_set_errno(savedErrno)

proc recordIpcConnect(fd: cint; address: pointer; addrLen: uint32) {.raises: [].} =
  let family = c_sockaddr_family(address, addrLen)
  if family == 0:
    return
  var peerPid: uint64 = 0
  var familyName = "af_other"
  case family
  of 1: # AF_UNIX
    familyName = "af_unix"
    let pid = c_socket_peer_pid(fd)
    if pid > 0:
      peerPid = uint64(pid)
  of 2, 10: # AF_INET / AF_INET6
    familyName = "af_inet"
  else:
    discard

  var record = baseRecord(mrIpcConnect, moIpcConnect)
  record.childOsPid = peerPid
  record.result = int64(fd)
  record.detail = "connect " & familyName &
    (if peerPid == 0: " peer=unknown" else: " peer=" & $peerPid)
  emitRecord(record)

proc repro_hook_connect*(ctx: var ConnectContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0 or c_errno_is_connect_in_progress(savedErrno) != 0:
    recordIpcConnect(ctx.fd, ctx.address, ctx.addrLen)
  c_set_errno(savedErrno)

proc repro_hook_sendfile*(ctx: var SendfileContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result > 0:
    recordFdRead(ctx.inFd, ctx.result)
    recordFdWrite(ctx.outFd, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_copy_file_range*(ctx: var CopyFileRangeContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result > 0:
    recordFdRead(ctx.inFd, ctx.result)
    recordFdWrite(ctx.outFd, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_splice*(ctx: var SpliceContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result > 0:
    recordFdRead(ctx.fdIn, ctx.result)
    recordFdWrite(ctx.fdOut, ctx.result)
  c_set_errno(savedErrno)

proc recordPathRead(path, detail: string) {.raises: [].} =
  if path.len == 0:
    return
  var record = baseRecord(mrFileRead, moFileRead)
  record.path = path
  record.result = 0
  record.detail = detail
  emitRecord(record)

proc recordPathRead(path: cstring; detail: string) {.raises: [].} =
  if path == nil:
    return
  recordPathRead($path, detail)

proc recordPathWrite(path, detail: string) {.raises: [].} =
  if path.len == 0:
    return
  var record = baseRecord(mrFileWrite, moFileWrite)
  record.path = path
  record.result = 0
  record.detail = detail
  emitRecord(record)

proc recordPathWrite(path: cstring; detail: string) {.raises: [].} =
  if path == nil:
    return
  recordPathWrite($path, detail)

proc recordLinkMutation(resultCode: cint; oldPath, newPath: cstring;
                        detail: string) {.raises: [].} =
  if resultCode != 0:
    return
  recordPathRead(oldPath, detail & " source")
  recordPathWrite(newPath, detail & " alias")

proc recordRenameMutation(resultCode: cint; oldPath, newPath: cstring;
                          detail: string) {.raises: [].} =
  if resultCode != 0:
    return
  recordPathRead(oldPath, detail & " source")
  recordPathWrite(newPath, detail & " destination")

proc repro_hook_link*(ctx: var LinkContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordLinkMutation(ctx.result, ctx.oldPath, ctx.newPath, "link")
  c_set_errno(savedErrno)

proc repro_hook_linkat*(ctx: var LinkatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    let oldPath = pathForAt(ctx.oldDirfd, ctx.oldPath)
    let newPath = pathForAt(ctx.newDirfd, ctx.newPath)
    let detail = "linkat olddirfd=" & $ctx.oldDirfd & " newdirfd=" &
      $ctx.newDirfd & " flags=" & $ctx.flags
    recordPathRead(oldPath, detail & " source")
    recordPathWrite(newPath, detail & " alias")
  c_set_errno(savedErrno)

proc repro_hook_rename*(ctx: var RenameContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordRenameMutation(ctx.result, ctx.oldPath, ctx.newPath, "rename")
  c_set_errno(savedErrno)

proc repro_hook_renameat*(ctx: var RenameatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    let oldPath = pathForAt(ctx.oldDirfd, ctx.oldPath)
    let newPath = pathForAt(ctx.newDirfd, ctx.newPath)
    let detail = "renameat olddirfd=" & $ctx.oldDirfd & " newdirfd=" &
      $ctx.newDirfd
    recordPathRead(oldPath, detail & " source")
    recordPathWrite(newPath, detail & " destination")
  c_set_errno(savedErrno)

proc repro_hook_renameat2*(ctx: var RenameatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    let oldPath = pathForAt(ctx.oldDirfd, ctx.oldPath)
    let newPath = pathForAt(ctx.newDirfd, ctx.newPath)
    let detail = "renameat2 olddirfd=" & $ctx.oldDirfd & " newdirfd=" &
      $ctx.newDirfd & " flags=" & $ctx.flags
    recordPathRead(oldPath, detail & " source")
    recordPathWrite(newPath, detail & " destination")
  c_set_errno(savedErrno)

proc repro_hook_dlopen*(ctx: var DlopenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != nil:
    let status = scanInlineSyscallPatchesForNewMappings()
    recordLateInlineSyscallScanCoverage(status, "dlopen")
  c_set_errno(savedErrno)

proc repro_hook_dlmopen*(ctx: var DlmopenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != nil:
    let status = scanInlineSyscallPatchesForNewMappings()
    recordLateInlineSyscallScanCoverage(status, "dlmopen")
  c_set_errno(savedErrno)

proc repro_hook_mmap*(ctx: var MmapContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if isAnonymousPrivateMmap(ctx.flags, ctx.fd):
    recordAnonymousPrivateMmap(ctx.result, ctx.length)
    if protIncludesExec(ctx.prot):
      if protIncludesWrite(ctx.prot):
        emitEventLoss("linux anonymous executable mmap is writable; " &
          "raw syscall scan requires a later mprotect transition " &
          "source=mmap-anonymous-exec")
      let status = scanInlineSyscallPatchesForOwnedAnonymousRange(
        ctx.result, ctx.length)
      recordLateInlineSyscallScanCoverage(status, "mmap-anonymous-exec")
  c_set_errno(savedErrno)

proc repro_hook_mprotect*(ctx: var MprotectContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0 and protIncludesExec(ctx.prot):
    let coverage = liveAnonymousExecutableCoverage(ctx.address, ctx.length)
    if coverage.liveIntersects and coverage.mapsAvailable and
        coverage.fullyTracked:
      let status = scanInlineSyscallPatchesForTrackedMprotectRange(
        ctx.address, ctx.length)
      recordLateInlineSyscallScanCoverage(status, "mprotect-anonymous-exec")
    elif coverage.liveIntersects:
      emitEventLoss("linux anonymous executable mprotect is not owned by " &
        "the preload mmap lifecycle source=mprotect-anonymous-untracked")
  c_set_errno(savedErrno)

proc repro_hook_munmap*(ctx: var MunmapContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    removeAnonymousPrivateRange(ctx.address, ctx.length)
  c_set_errno(savedErrno)

proc repro_hook_mremap*(ctx: var MremapContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  let oldWasTracked = anonymousPrivateRangeFullyTracked(
    ctx.oldAddress, ctx.oldSize)
  let oldHadTrackedOverlap = anonymousPrivateRangeIntersects(
    ctx.oldAddress, ctx.oldSize)
  callNext(ctx)
  let savedErrno = c_get_errno()
  if isSuccessfulMmapResult(ctx.result):
    var movedPrecisely = false
    if oldWasTracked:
      movedPrecisely = remapAnonymousPrivateRange(
        ctx.oldAddress, ctx.oldSize, ctx.result, ctx.newSize)
      if not movedPrecisely:
        emitEventLoss("linux anonymous executable mremap could not preserve " &
          "precise mmap lifecycle ownership source=mremap-anonymous")
    elif oldHadTrackedOverlap:
      removeAnonymousPrivateRange(ctx.oldAddress, ctx.oldSize)
      emitEventLoss("linux anonymous executable mremap touched only part of " &
        "a preload-owned mapping source=mremap-anonymous")
    if movedPrecisely and liveAnonymousExecutableMappingIntersects(
        ctx.result, ctx.newSize):
      let status = scanInlineSyscallPatchesForTrackedMprotectRange(
        ctx.result, ctx.newSize)
      recordLateInlineSyscallScanCoverage(status, "mremap-anonymous-exec")
  c_set_errno(savedErrno)

proc recordObservedNonFile(kind: MonitorRecordKind;
                           observationKind: MonitorObservationKind;
                           path, detail: string) {.raises: [].} =
  if path.len == 0:
    return
  let key = $ord(kind) & ":" & path
  var shouldEmit = false
  acquire(observedLock)
  if not observedNonFileInputs.contains(key):
    observedNonFileInputs.incl(key)
    shouldEmit = true
  release(observedLock)
  if not shouldEmit:
    return
  var record = baseRecord(kind, observationKind)
  record.path = path
  record.detail = detail
  emitRecord(record)

proc recordEnvRead(name: cstring) {.raises: [].} =
  if name == nil:
    return
  recordObservedNonFile(mrEnvRead, moEnvRead, $name, "linux getenv")

proc recordSysconfRead(name: cint) {.raises: [].} =
  recordObservedNonFile(mrSysctlRead, moSysctlRead, "sysconf:" & $name,
    "linux sysconf")

proc recordUnameRead() {.raises: [].} =
  recordObservedNonFile(mrSysctlRead, moSysctlRead, "uname", "linux uname")

proc recordTimeRead(source: string) {.raises: [].} =
  recordObservedNonFile(mrTimeRead, moTimeRead, source, "linux time")

proc recordNonDeterministic(source: string) {.raises: [].} =
  var record = baseRecord(mrNonDeterministic, moNonDeterministic)
  record.path = source
  record.detail = "linux non-deterministic source"
  emitRecord(record)

proc repro_hook_getenv*(ctx: var GetenvContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordEnvRead(ctx.name)
  c_set_errno(savedErrno)

proc repro_hook_uname*(ctx: var UnameContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    recordUnameRead()
  c_set_errno(savedErrno)

proc repro_hook_sysconf*(ctx: var SysconfContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordSysconfRead(ctx.name)
  c_set_errno(savedErrno)

proc repro_hook_clock_gettime*(ctx: var ClockGettimeContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    recordTimeRead("clock_gettime:" & $ctx.clockId)
  c_set_errno(savedErrno)

proc repro_hook_gettimeofday*(ctx: var GettimeofdayContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    recordTimeRead("gettimeofday")
  c_set_errno(savedErrno)

proc repro_hook_time*(ctx: var TimeContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != -1:
    recordTimeRead("time")
  c_set_errno(savedErrno)

proc repro_hook_getrandom*(ctx: var GetrandomContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result >= 0:
    recordNonDeterministic("getrandom")
  c_set_errno(savedErrno)

proc repro_hook_raw_syscall*(number, a1, a2, a3, a4, a5, a6,
                             callResult: clong; inlineTrap: cint)
    {.raises: [].} =
  if shouldBypass():
    return
  let savedErrno = c_get_errno()
  recordRawSyscallClassification(number, a1, a2, a3, a4, a5, a6, callResult,
    inlineTrap)
  c_set_errno(savedErrno)

proc processIsSingleThreaded(): bool {.raises: [].} =
  ## True iff the current process has exactly one thread. Read in the PARENT
  ## BEFORE fork so the child — which inherits the answer copy-on-write — knows
  ## whether the parent was single-threaded. That is the safety precondition for
  ## the child to keep recording: with no sibling threads, none could have held
  ## a Nim lock across the fork, so the child can do monitor bookkeeping without
  ## deadlock. Conservatively returns false (treat as multi-threaded) on any
  ## read error.
  var content: string
  try:
    withShimMuted:
      content = readFile("/proc/self/status")
  except CatchableError:
    return false
  const key = "Threads:"
  let idx = content.find(key)
  if idx < 0:
    return false
  var i = idx + key.len
  while i < content.len and content[i] in {' ', '\t'}:
    inc i
  var n = 0
  var sawDigit = false
  while i < content.len and content[i] in {'0' .. '9'}:
    n = n * 10 + (ord(content[i]) - ord('0'))
    sawDigit = true
    inc i
  result = sawDigit and n == 1

proc repro_hook_fork*(ctx: var ForkContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  # Sampled in the parent, before the fork, and inherited by the child.
  let parentSingleThreaded = processIsSingleThreaded()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result > 0:
    var record = baseRecord(mrProcessSpawn, moExecute)
    record.childOsPid = uint64(ctx.result)
    record.result = ctx.result.int64
    record.detail = "fork"
    emitRecord(record)
  elif ctx.result == 0:
    if parentSingleThreaded:
      # Single-threaded parent ⇒ no sibling thread could hold a Nim lock across
      # the fork, so the child can safely keep recording. Reset the inherited
      # (copy-on-write) fragment slot so the child writes its OWN fragment, then
      # emit the child's process-start. This stops a fork-WITHOUT-exec child
      # (e.g. a nix cc/clang-wrapper command-substitution subshell) from being
      # flagged as an un-monitored subtree, and captures its I/O too. It only
      # ADDS evidence — a later exec re-runs the constructor (a second
      # process-start is expected and harmless; see t0-completeness).
      withShimMuted:
        discardFragmentSlotAfterFork()
      recordProcessStart()
    else:
      # Multi-threaded parent: another thread may have held a Nim lock at fork,
      # so the child must avoid monitor bookkeeping until exec loads a fresh
      # image and re-runs the preload constructor.
      inForkChild = true
  c_set_errno(savedErrno)

proc repro_hook_execve*(ctx: var ExecveContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  var record = baseRecord(mrProcessExec, moExecute)
  if ctx.path != nil:
    record.path = $ctx.path
  emitRecord(record)
  ctx.envp = envWithPreload(ctx.envp)
  callNext(ctx)

proc repro_hook_posix_spawn*(ctx: var PosixSpawnContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  ctx.envp = envWithPreload(ctx.envp)
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0 and ctx.pid != nil:
    var record = baseRecord(mrProcessSpawn, moExecute)
    record.childOsPid = uint64(ctx.pid[])
    record.result = ctx.result.int64
    if ctx.path != nil:
      record.path = $ctx.path
    record.detail = "posix_spawn"
    emitRecord(record)
  c_set_errno(savedErrno)

proc repro_hook_posix_spawnp*(ctx: var PosixSpawnContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  ctx.envp = envWithPreload(ctx.envp)
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0 and ctx.pid != nil:
    var record = baseRecord(mrProcessSpawn, moExecute)
    record.childOsPid = uint64(ctx.pid[])
    record.result = ctx.result.int64
    if ctx.path != nil:
      record.path = $ctx.path
    record.detail = "posix_spawnp"
    emitRecord(record)
  c_set_errno(savedErrno)

setPreloadShimEnvVar("REPRO_MONITOR_SHIM_LIB")
registerOpenHook(repro_hook_open)
registerOpen64Hook(repro_hook_open64)
registerOpenatHook(repro_hook_openat)
registerOpenat64Hook(repro_hook_openat64)
registerReadHook(repro_hook_read)
registerPreadHook(repro_hook_pread)
registerReadvHook(repro_hook_readv)
registerPreadvHook(repro_hook_preadv)
registerWriteHook(repro_hook_write)
registerCloseHook(repro_hook_close)
registerStatHook(repro_hook_stat)
registerLstatHook(repro_hook_lstat)
registerOpendirHook(repro_hook_opendir)
registerReaddirHook(repro_hook_readdir)
registerClosedirHook(repro_hook_closedir)
registerFopenHook(repro_hook_fopen)
registerFopen64Hook(repro_hook_fopen64)
registerFreadHook(repro_hook_fread)
registerFcloseHook(repro_hook_fclose)
registerConnectHook(repro_hook_connect)
registerSendfileHook(repro_hook_sendfile)
registerCopyFileRangeHook(repro_hook_copy_file_range)
registerSpliceHook(repro_hook_splice)
registerLinkHook(repro_hook_link)
registerLinkatHook(repro_hook_linkat)
registerRenameHook(repro_hook_rename)
registerRenameatHook(repro_hook_renameat)
registerRenameat2Hook(repro_hook_renameat2)
registerDlopenHook(repro_hook_dlopen)
registerDlmopenHook(repro_hook_dlmopen)
registerMmapHook(repro_hook_mmap)
registerMprotectHook(repro_hook_mprotect)
registerMunmapHook(repro_hook_munmap)
registerMremapHook(repro_hook_mremap)
registerGetenvHook(repro_hook_getenv)
registerUnameHook(repro_hook_uname)
registerSysconfHook(repro_hook_sysconf)
registerClockGettimeHook(repro_hook_clock_gettime)
registerGettimeofdayHook(repro_hook_gettimeofday)
registerTimeHook(repro_hook_time)
registerGetrandomHook(repro_hook_getrandom)
registerForkHook(repro_hook_fork)
registerExecveHook(repro_hook_execve)
registerPosixSpawnHook(repro_hook_posix_spawn)
registerPosixSpawnpHook(repro_hook_posix_spawnp)
registerRawSyscallHook(repro_hook_raw_syscall)
