when not defined(macosx):
  {.error: "repro_monitor_shim/macos_interpose is macOS-only".}

import std/[locks, os, sets, strutils, tables]
from io_mon/paths import extendedPath

import io_mon/hooks/macos_interpose_runtime
import stackable_hooks/platform/macos_bodypatch
import io_mon/types
import io_mon/writer

{.emit: """
#include <copyfile.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/xattr.h>
#include <time.h>
#include <mach/mach_time.h>
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
  # Darwin address-family + errno constants used by the IPC-connect hook (T3a).
  # AF_UNIX=1, AF_INET=2, AF_INET6=30, EINPROGRESS=36 on macOS/arm64 (stable
  # ABI values in <sys/socket.h> / <sys/errno.h>); inlined here so the Nim hook
  # need not pull the headers into its own scope.
  AfUnix = 1.cint
  AfInet = 2.cint
  AfInet6 = 30.cint
  EInProgress = 36.cint
  # ROUND-2 R4 — `fstatat`'s AT_FDCWD sentinel (<fcntl.h>, -2 on Darwin). The
  # fstatat canonicalisation is applied only for ABSOLUTE paths or AT_FDCWD, since
  # realpath resolves a relative path against the CWD, not an arbitrary `dirfd`.
  AtFdCwd = -2.cint
  # ROUND-3 S2d — fcntl(2) fd-duplication commands (<fcntl.h>, stable Darwin ABI:
  # F_DUPFD=0, F_DUPFD_CLOEXEC=67). Both return a NEW fd that refers to the SAME
  # open file as the source fd (so a read/write via it must be attributed to the
  # source's path). Every OTHER fcntl command is passed through untouched.
  FDupFd = 0.cint
  FDupFdCloexec = 67.cint
  # ROUND-2 R4 — cap on the canonical-path memo; cleared wholesale when exceeded
  # (a crude but O(1)-amortised, memory-bounded eviction — the working set of a
  # build's probed inputs is far below this).
  CanonicalCacheCap = 8192
  # ROUND-2 R-D — cap on the per-process observed-input dedup set
  # (`seenObservedInputs`). getenv/clock_gettime are HOT; the dedup records each
  # DISTINCT key once, so the set's working size is tiny (a few dozen env-var
  # names + a handful of sysctl/clock sources). Cleared wholesale when exceeded —
  # the same O(1)-amortised, memory-bounded eviction as CanonicalCacheCap.
  ObservedInputCacheCap = 8192
  # ROUND-2 R9 — mmap classification constants (<sys/mman.h>, stable Darwin ABI).
  # A MAP_SHARED|PROT_WRITE FILE mapping changes the file's CONTENT with NO
  # write(2) syscall (ld64 writes its output executable this way; r2_mmap probeC),
  # so the open alone does not convey the write. PROT_READ/MAP_PRIVATE/MAP_ANON
  # mappings are NOT recorded (a read mapping is already covered by the open; a
  # private/anon mapping never reaches the backing file).
  ProtRead = 0x01.cint
  ProtWrite = 0x02.cint
  MapShared = 0x0001.cint
  MapAnon = 0x1000.cint

  # ROUND-3 S1b — SYSTEM POSIX shm objects the OS/libsystem maps on essentially
  # every process (the notification center, cfprefsd, …). These are NOT build
  # inputs — a build's output never depends on the notification-center contents —
  # so recording them as out-of-tree content channels would DOWNGRADE EVERY
  # cc/clang/tool run (the cardinal sin, observed: a trivial `cc -c` attaches
  # `apple.shm.notification_center`). We exempt shm names under the Apple system
  # namespaces from the downgrade, exactly as the round-2 R-D arm excludes the
  # libsystem entropy baseline and the round-3 S0 arm excludes SIP-declared Apple
  # services. The names are checked after stripping a leading '/'. RESIDUAL (the
  # round-3 S0 lesson): a prefix exemption is in principle bypassable by an attacker
  # naming their shm `apple.shm.evil`; that narrow residual (fail-safe: a missed
  # dep, the structural endgame is the ES backend) is strictly preferable to a
  # false downgrade of every real compile.
  SystemShmPrefixes = ["apple.shm.", "com.apple."]
  # ROUND-3 S1a — the macOS resource-fork access path. A read of
  # `<file>/..namedfork/rsrc` (FILE_FLAGS_OFFSET) opens the file's resource fork
  # (the com.apple.ResourceFork extended attribute) under a NON-CANONICAL path
  # whose fd carries the FORK's inode, so the dependency would be attributed to an
  # opaque fork path rather than the underlying file. We normalise it to the base
  # `<file>` (research/adversarial-2026-06-round3/r3_xattr/rsrc_read.c).
  ResourceForkSuffix = "/..namedfork/rsrc"

  # ROUND-3 S0 — Mach/XPC service-name discrimination (close the round-2 R-C
  # `com.apple.*` prefix-filter break, see machServiceRecordable). Every Apple
  # service name begins with this prefix.
  AppleServicePrefix = "com.apple."
  # SIP-protected launchd plist directories. System Integrity Protection forbids
  # ANY process (even root) from creating or modifying files here, so the set of
  # `com.apple.*` MachServices DECLARED by these Apple-signed plists is an
  # ATTACKER-UNFORGEABLE allowlist of genuine system services. The round-3 S0
  # finding (research/adversarial-2026-06-round3/r3_residual): the round-2 blunt
  # `com.apple.*` name-prefix exemption let ANY unsigned process
  # `bootstrap_register` an UNUSED `com.apple.<custom>` name and serve a monitored
  # client a delegated file read with NO downgrade (verified: bootstrap_register
  # of an arbitrary com.apple.* name succeeds from an unsigned binary). We now
  # exempt a `com.apple.*` lookup ONLY when its name is declared in these
  # SIP-protected plists — a real system service the attacker cannot impersonate.
  SipLaunchdDirs = [
    "/System/Library/LaunchDaemons",
    "/System/Library/LaunchAgents"]
  # Cap on the per-process Mach-service decision memo; cleared wholesale when
  # exceeded (the same O(1)-amortised, memory-bounded eviction as the other caps).
  # The working set is tiny: a build's DIRECT com.apple.* lookups are rare (the
  # pervasive system lookups are libsystem-INTERNAL and never reach this
  # interpose-only hook), so this is essentially never hit.
  MachServiceCacheCap = 4096

var
  initialized = false
  locksReady = false
  initLockVar: Lock
  recordLock: Lock
  fdLock: Lock
  dirLock: Lock
  # ROUND-2 R4 — a bounded per-process realpath MEMO for the path-probe-family
  # canonicalisation. Maps a raw probe path → its realpath (the empty string when
  # realpath failed). Bounds the cost of canonicalising successful stat/lstat/
  # access probes: a repeated probe of the same file (ubiquitous in builds — make
  # re-stats the same inputs many times) is then O(1) instead of paying realpath
  # (a per-component lstat chain) every time. See `canonicalPathFor`.
  canonicalLock: Lock
  canonicalCache = initTable[string, string]()
  # ROUND-2 R-D (break R10) — per-process DEDUP set for the observed non-file
  # determinism inputs (env-var / sysctl / uname names, entropy sources, time
  # sources). getenv is HOT (a build re-reads PATH/HOME/etc thousands of times),
  # so the recorder records each DISTINCT key once and bails on a repeat — bounding
  # the perf. Keys are category-prefixed ("env:NAME", "sysctl:NAME", "nd:SOURCE",
  # "time:SOURCE") so one structure dedupes all four categories. Guarded by
  # `observedLock`; cleared wholesale at ObservedInputCacheCap.
  observedLock: Lock
  seenObservedInputs = initHashSet[string]()
  # ROUND-3 S0 — guards the lazily-built SIP-declared Apple-service set and the
  # per-name decision memo used by machServiceRecordable / isDeclaredAppleService.
  machServiceLock: Lock
  # The concatenated raw bytes of every SIP-protected launchd plist (binary or
  # XML), built ONCE lazily on the first DIRECT `com.apple.*` lookup that reaches
  # the interpose hook (normal builds make none, so this stays empty and costs
  # nothing). A service name present as a whole token in these bytes is a genuine,
  # SIP-declared Apple system service. See buildAppleServiceBlob.
  appleServiceBlobBuilt = false
  appleServiceBlob: string = ""
  # Per-name decision memo (name → "is a genuine SIP-declared Apple service"),
  # bounded by MachServiceCacheCap.
  appleServiceDecision = initTable[string, bool]()
  fragmentDir: string
  nextProcessSeq: uint64 = 0
  fdPaths = initTable[cint, string]()
  dirPaths = initTable[uint, string]()
  # ROUND-3 S1b — fds returned by shm_open, mapped to their shm object name. Lets
  # recordMmap record a CONTENT READ for a read-only MAP_SHARED mapping of an
  # shm-backed fd (a plain memory load, no read(2)). Guarded by `fdLock` (same
  # critical sections as fdPaths/the empty-fd set — all fd-keyed shim state).
  shmFds = initTable[cint, string]()
  # ROUND-3 S1c — fds whose EMPTY-PATH read has already been classified as an
  # out-of-tree opaque source (socket / pipe). Once flagged we emit the downgrade
  # signal ONCE and then skip the fstat/F_GETPATH on every subsequent read of that
  # fd — keeping the hot read path a single set lookup. A regular-file empty-path
  # fd is instead given its resolved path via updateFdPath, so it naturally takes
  # the fast (non-empty) path thereafter. Guarded by `fdLock`.
  classifiedEmptyFds = initHashSet[cint]()
  # The OS thread id of the thread that ran the dyld constructor (the "main"
  # thread). Captured once at init. The fragment writer batches a thread's
  # records into a per-thread buffer that is otherwise flushed only on overflow /
  # 100 ms age / explicit flush; the dyld process-exit destructor flushes ONLY
  # the main thread's batch. A WORKER thread (pthread_create'd by the monitored
  # program) that emits a few records and then exits BEFORE process teardown
  # would lose its buffered tail — and crucially we CANNOT flush it from a
  # pthread-key thread-exit destructor, because macOS tears down a non-Nim
  # thread's Nim runtime TLS before pthread destructors run, so any Nim call from
  # there faults. We therefore flush a worker thread's batch SYNCHRONOUSLY on
  # every emit (see emitRecord): the main thread keeps the batching win (the
  # millions of single-threaded configure probes the optimization targeted),
  # while worker threads trade a little batching for guaranteed capture of their
  # reads AND writes regardless of when they exit. This closes the threaded-write
  # capture gap without a teardown-time Nim call.
  mainThreadId: uint64 = 0
  # ROUND-2 R8 — this invocation's RUN ID, read once from REPRO_MONITOR_SESSION at
  # init. Stamped (as a `run=` token) onto every process-start and IPC-connect
  # record so the merge can scope trusted-daemon breakaway reports to THIS run and
  # reject stale / cross-run reports. Empty when the launcher set no session.
  runId: string = ""

var disabled {.threadvar.}: int
  ## Global shim-mute depth (suppresses ALL recording while > 0; emitRecord bails).
var inMmapHook {.threadvar.}: int
  ## ROUND-2 R9 — mmap-hook re-entrancy depth. The mmap recording path allocates
  ## (and malloc mmaps), which would re-enter the hook; while > 0 a nested mmap
  ## takes the plain forward without recording. Separate from `disabled` because
  ## the OUTER call must still record (emitRecord bails on disabled>0). See
  ## repro_hook_mmap.

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
    # Threaded-write capture fix: if this record was emitted from a WORKER thread
    # (not the main/constructor thread), flush its per-thread fragment batch
    # synchronously. The batch is otherwise flushed only on overflow / 100 ms age
    # / process-exit, and the process-exit destructor flushes only the MAIN
    # thread's batch — a worker thread that exits early would lose its buffered
    # tail (the threaded-write gap). We must flush here (while the thread is
    # alive) rather than from a pthread thread-exit destructor, because macOS
    # tears down a non-Nim thread's Nim-runtime TLS before pthread destructors
    # run, so a Nim flush call from there faults. The main thread keeps the
    # batching win (the single-threaded configure probe storm the optimization
    # targeted); worker-thread I/O is comparatively rare, so per-record flushing
    # there is an acceptable trade for guaranteed capture of its reads AND writes.
    if record.threadId != mainThreadId:
      flushFragmentBatch()

proc runIdToken(): string {.raises: [].} =
  ## ROUND-2 R8 — the ` run=<id>` detail suffix (empty when no run id). Single
  ## source of truth so process-start and IPC-connect stamp it identically.
  if runId.len > 0: " run=" & runId else: ""

proc recordProcessStart() {.raises: [].} =
  var record = baseRecord(mrProcessStart, moProcessStart)
  # ROUND-2 R7/R8 — stamp this process's (pid, kernel-start-time) identity and the
  # invocation run id. The merge keys monitored-process matching on (pid,
  # start-time) so a wrapped/recycled pid cannot false-match a stale process-start,
  # and scopes trusted-daemon reports to `run`.
  record.detail = "shim-loaded start=" &
    $ct_macos_proc_start_usec(c_getpid()) & runIdToken()
  emitRecord(record)

proc observationForOpen(flags: cint): MonitorObservationKind =
  ## Classify an open's PRIMARY observation.
  ##
  ## ROUND-2 R3 — a pure `O_RDWR` open (no O_CREAT/O_TRUNC/O_APPEND) is classified
  ## as an INPUT (`moFileOpen`), NOT a write. The round-1 code collapsed ANY
  ## O_RDWR/O_WRONLY/O_CREAT/O_TRUNC/O_APPEND open to `moFileWrite`, so a file
  ## opened O_RDWR but only READ (SQLite opens its DB O_RDWR even read-only;
  ## lockfiles; editors; the defensive lock-then-read idiom) was recorded purely as
  ## an OUTPUT — and a downstream "inputs = read AND NOT written" fold then EXCLUDED
  ## a genuine input that changes ⇒ a false cache hit (demonstrated in
  ## research/.../r2_mmap probeA/probeB). The DANGEROUS direction is dropping it
  ## from INPUTS, so a plain O_RDWR is an input by default; an ACTUAL write on the
  ## fd — a `write(2)` (recorded by repro_hook_write) or a MAP_SHARED|PROT_WRITE
  ## mmap (recorded by repro_hook_mmap, R9) — is what marks the path WRITTEN, so a
  ## genuine in-place O_RDWR edit is still an output. O_CREAT/O_TRUNC/O_APPEND and a
  ## pure O_WRONLY remain unambiguous OUTPUTS.
  if (flags and (OCreat or OTrunc or OAppend)) != 0:
    moFileWrite
  else:
    let acc = flags and OAccMode
    if acc == OWrOnly:
      moFileWrite
    else:
      # O_RDONLY and pure O_RDWR are both inputs (the latter writable only if an
      # actual write/mmap-write is later observed on the fd — see above).
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
  # ROUND-3 S1 — drop any shm / empty-fd-classification state on close so a
  # recycled fd number never inherits a stale shm name or opaque classification.
  shmFds.del(fd)
  classifiedEmptyFds.excl fd
  release(fdLock)

proc pathForFd(fd: cint): string =
  acquire(fdLock)
  result = fdPaths.getOrDefault(fd, "")
  release(fdLock)

proc copyFdPath(oldfd, newfd: cint) =
  ## ROUND-3 S2d — after a successful dup/dup2/fcntl(F_DUPFD*), mirror the source
  ## fd's recorded path (and shm name) onto the NEW fd, so a read/write through the
  ## duplicate is attributed to the SAME file as the source (round-3 r3_fd
  ## p_dup/p_dup2/p_fdupfd: a read via a dup'd fd otherwise had no path).
  ##
  ## CRITICAL for dup2/dup3-style reuse (p_dup2swap): `dup2(A, B)` where B is
  ## already open makes B refer to A AND closes the OLD B INTERNALLY in the kernel —
  ## that internal close NEVER reaches the hooked `close`, so the stale `fdPaths[B]`
  ## (pointing at B's old file) would otherwise persist and MISATTRIBUTE a read of A
  ## via B to B's old file. We therefore CLEAR all stale destination state first,
  ## then copy the source's. The source is read BEFORE the clear so the dup2(fd, fd)
  ## no-op (oldfd == newfd) preserves the entry. All under the single fdLock
  ## critical section so a concurrent close/read sees a consistent table.
  if newfd < 0:
    return
  acquire(fdLock)
  let srcPath = fdPaths.getOrDefault(oldfd, "")
  let srcShm = shmFds.getOrDefault(oldfd, "")
  # Drop any stale destination state left by the kernel's internal close of an
  # already-open destination fd (the hooked close never saw it).
  fdPaths.del(newfd)
  shmFds.del(newfd)
  classifiedEmptyFds.excl newfd
  if srcPath.len > 0:
    fdPaths[newfd] = srcPath
  if srcShm.len > 0:
    shmFds[newfd] = srcShm
  release(fdLock)

proc addShmFd(fd: cint; name: string) =
  ## ROUND-3 S1b — remember that `fd` is backed by the POSIX shm object `name`,
  ## so a later read-only MAP_SHARED mmap of it is recorded as a content read.
  if fd < 0:
    return
  acquire(fdLock)
  shmFds[fd] = name
  release(fdLock)

proc shmNameForFd(fd: cint): string =
  ## The shm object name `fd` was shm_open'd against, or "" if `fd` is not shm.
  acquire(fdLock)
  result = shmFds.getOrDefault(fd, "")
  release(fdLock)

proc markEmptyFdClassified(fd: cint) =
  ## ROUND-3 S1c — record that `fd`'s empty-path read was classified opaque, so
  ## subsequent reads skip the (re-)classification on the hot path.
  if fd < 0:
    return
  acquire(fdLock)
  classifiedEmptyFds.incl fd
  release(fdLock)

proc emptyFdAlreadyClassified(fd: cint): bool =
  acquire(fdLock)
  result = fd in classifiedEmptyFds
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

proc devInoSuffix(detail: string; dev, ino: uint64): string {.raises: [].} =
  ## Append a ` dev=<n> ino=<n>` token pair to `detail` (ROUND-2 R4 hardlink
  ## identity). The tokens are whitespace-separated `key=value` pairs read back via
  ## writer.detailToken, exactly like the round-2 R7/R8 start/peer tokens — so no
  ## wire-format field is added (RMDF stays byte-stable). realpath collapses two
  ## NAMES of one file to one canonical path, but it CANNOT collapse a HARDLINK
  ## (distinct directory entries, same inode); the (dev, ino) lets a consumer match
  ## that alternate-name case by inode identity.
  result = detail
  if result.len > 0: result.add ' '
  result.add "dev=" & $dev & " ino=" & $ino

proc statDetail(detail: string; buf: pointer; ok: bool): string {.raises: [].} =
  ## `detail` with the stat buffer's (dev, ino) appended when the probe succeeded
  ## and a buffer is available (ROUND-2 R4). Single source of truth for the
  ## stat-family hooks.
  if not ok or buf == nil:
    return detail
  var dev, ino: uint64
  if not ct_macos_stat_dev_ino(buf, addr dev, addr ino):
    return detail
  devInoSuffix(detail, dev, ino)

proc canonicalPathFor(rawPath: string): string {.raises: [].} =
  ## ROUND-2 R4 — the realpath of `rawPath`, memoised in a bounded per-process LRU
  ## (canonicalCache). Returns "" when realpath failed OR the path is already
  ## canonical. realpath's internal lstat is body-patched, so the resolution runs
  ## with the shim MUTED (disabled>0) to avoid recursing into recording. The memo
  ## bounds cost: a build re-stats the same inputs many times, and each repeat is
  ## then O(1); the first touch of a distinct successful path pays one realpath.
  ## (Failed/ENOENT probes never reach here — see recordCanonicalPathProbe — so the
  ## configure/find_program probe storm, dominated by absent paths, costs nothing.)
  if rawPath.len == 0:
    return ""
  # Cache representation: the stored value is the realpath when it DIFFERS from the
  # raw path, otherwise `rawPath` itself — a self-sentinel meaning "already
  # canonical / unresolvable, no companion needed". getOrDefault("") therefore
  # cleanly distinguishes a MISS ("") from a stored skip (== rawPath), without the
  # KeyError-raising `[]` (illegal in this raises:[] proc).
  acquire(canonicalLock)
  let cached = canonicalCache.getOrDefault(rawPath, "")
  release(canonicalLock)
  if cached.len > 0:
    return (if cached == rawPath: "" else: cached)
  var buf: array[1024, char]
  # Mute the shim around realpath: its internal lstat is body-patched and would
  # otherwise record a path-probe for every component (and risk recursion). Manual
  # inc/dec (not the withShimMuted template) keeps this value-returning raises:[]
  # proc free of an enclosing try/finally.
  inc disabled
  let ok = ct_macos_canonical_path(cstring(rawPath), addr buf[0],
    csize_t(buf.len)) != 0
  dec disabled
  let canonical = if ok: $cast[cstring](addr buf[0]) else: ""
  let stored = if canonical.len > 0 and canonical != rawPath: canonical
               else: rawPath
  acquire(canonicalLock)
  if canonicalCache.len >= CanonicalCacheCap:
    canonicalCache.clear()
  canonicalCache[rawPath] = stored
  release(canonicalLock)
  if stored == rawPath: "" else: stored

proc recordExternalContent(chan, role, path: string; fd: cint) {.raises: [].} =
  ## ROUND-3 S1 — emit one `mrExternalContent` describing a content-channel event.
  ## `chan` is the channel class (shm/fifo/opaque), `role` the side
  ## (create/attach/write/read), `path` the channel identity (shm name / FIFO path
  ## / "" for an anonymous socket-pipe). The fd is stamped into `flags` so the merge
  ## can dedup an anonymous source by (pid, fd). The merge — NOT the shim — decides
  ## whether this downgrades (the in-tree-provenance pairing is cross-process); the
  ## shim only reports the observed fact, so a self-produced channel stays
  ## mcComplete. See writer.externalContentLossCount.
  var record = baseRecord(mrExternalContent, moExternalContent)
  record.path = path
  record.flags = uint32(fd)
  record.detail = "chan=" & chan & " role=" & role
  emitRecord(record)

proc recordFifoChannel(fd: cint; path: cstring; flags: cint) {.raises: [].} =
  ## ROUND-3 S1d — a hooked open whose target is a FIFO. A FIFO read open consumes
  ## content from a WRITER: if the writer is an out-of-tree process the real input
  ## is invisible. We record the open's DIRECTION (read/write) keyed on the FIFO
  ## path; the merge downgrades a FIFO READ whose path has NO in-tree WRITE open
  ## (an out-of-tree feeder) and leaves an entirely in-tree pipeline alone (the
  ## cardinal-sin guard). `path` is the as-opened path; an empty path is skipped.
  if path == nil:
    return
  let p = $path
  if p.len == 0:
    return
  let acc = flags and OAccMode
  # A FIFO opened O_WRONLY (or O_RDWR — the writer end) is the in-tree feeder; any
  # other access (O_RDONLY) is a read/consume that may pull out-of-tree content.
  let role = if acc == OWrOnly or acc == ORdWr: "write" else: "read"
  recordExternalContent("fifo", role, p, fd)

proc recordResourceForkBase(path: cstring) {.raises: [].} =
  ## ROUND-3 S1a — when a hooked open targets `<file>/..namedfork/rsrc`, ALSO record
  ## a content read on the underlying `<file>` (the resource fork is the
  ## com.apple.ResourceFork extended attribute of that file). Without this the
  ## dependency is attributed only to the opaque fork path carrying the fork's
  ## inode, so editing the resource fork would not match a consumer keyed on the
  ## real file. No-op for any other path.
  if path == nil:
    return
  let raw = $path
  if not raw.endsWith(ResourceForkSuffix):
    return
  let base = raw[0 ..< raw.len - ResourceForkSuffix.len]
  if base.len == 0:
    return
  let canonical = canonicalPathFor(base)
  let p = if canonical.len > 0: canonical else: base
  var record = baseRecord(mrFileRead, moFileRead)
  record.path = p
  record.result = 0
  record.detail = "resource-fork com.apple.ResourceFork"
  emitRecord(record)

proc recordOpen(callResult: cint; path: cstring; flags: cint; detail: string) {.raises: [].} =
  ## Record an mrFileOpen observation. Shared by the open/openat hooks. The
  ## fd→path map update and directory-enumeration follow-up are done by the
  ## caller (they need the live fd/path before this record is emitted).
  var d = detail
  # ROUND-2 R4 — stamp the opened file's (dev, ino) via a raw fstat
  # (reentrancy-free) so a hardlink-alternate-name open is matchable by inode
  # identity (realpath cannot collapse a hardlink). ROUND-3 S1d — the SAME fstat
  # also classifies the fd so a FIFO open is detected with NO extra syscall on the
  # hot open path. Only on a successful open.
  var isFifo = false
  if callResult >= 0:
    var dev, ino: uint64
    var kind: FdKind
    if ct_macos_fd_dev_ino_kind(callResult, addr dev, addr ino, addr kind):
      d = devInoSuffix(d, dev, ino)
      isFifo = kind == fkFifo
  var record = baseRecord(mrFileOpen, observationForOpen(flags))
  record.result = callResult.int64
  record.flags = uint32(flags)
  if path != nil:
    record.path = $path
  if d.len > 0:
    record.detail = d
  emitRecord(record)
  if callResult >= 0:
    # ROUND-3 S1d — a FIFO open: record its direction so the merge can downgrade a
    # read whose out-of-tree feeder is invisible (an entirely in-tree pipeline is
    # paired and left alone — the cardinal-sin guard).
    if isFifo:
      recordFifoChannel(callResult, path, flags)
    # ROUND-3 S1a — a `<file>/..namedfork/rsrc` open is a resource-fork read; also
    # record the dependency against the underlying file (com.apple.ResourceFork).
    recordResourceForkBase(path)

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
  var d = detail
  # ROUND-2 R7 — stamp the CHILD's kernel start time so the merge matches the
  # spawn against the child's own process-start by (pid, start-time), not bare
  # pid. The child pid exists the instant posix_spawn/fork returns, so its start
  # time is queryable now. A recycled child pid whose start time differs from a
  # stale monitored process-start is then correctly seen as un-monitored.
  if childPid > 0:
    let childStart = ct_macos_proc_start_usec(cint(childPid))
    if childStart != 0:
      if d.len > 0: d.add ' '
      d.add "childstart=" & $childStart
  if d.len > 0:
    record.detail = d
  emitRecord(record)
  # ROUND-3 S2c — for posix_spawn(p) ALSO record the SYMLINK/realpath-RESOLVED
  # launched binary's BYTES as a CONTENT read (the same path-fidelity hole as
  # execve): the verbatim `path` may name a wrapper symlink whose real target's
  # bytes the build truly depends on. canonicalPathFor realpath-resolves it (returns
  # "" for a nil path — fork —, an already-canonical path, or a PATH-searched bare
  # name realpath cannot resolve from the CWD, so posix_spawnp's PATH search is never
  # mis-resolved here).
  #
  # Recorded as mrFileRead/moFileRead (a CONTENT dependency, like recordLibraryLoad),
  # DELIBERATELY NOT a second mrProcessSpawn: a duplicate spawn naming the same
  # `childOsPid` would look like an unmatched child to the merge
  # (writer.unmonitoredSubtreeLossCount case (a)) and FALSELY downgrade a normal
  # compile to mcIncomplete (the cardinal sin — observed: a real cc compile that
  # posix_spawns its subprocesses). A content read participates in no process-tree
  # check, so completeness is unchanged while the binary bytes bust the cache on a
  # content swap.
  if path != nil:
    let canonical = canonicalPathFor($path)
    if canonical.len > 0:
      var resolved = baseRecord(mrFileRead, moFileRead)
      resolved.result = 0
      resolved.path = canonical
      resolved.detail = "spawn resolved-target"
      emitRecord(resolved)

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

proc recordIpcConnect(fd: cint; address: pointer; addrLen: uint32;
    callResult: cint) {.raises: [].} =
  ## Record a successful (or in-flight non-blocking) connect(2) to an
  ## AF_UNIX / AF_INET(6) peer — the DAEMON-OVER-SOCKET breakaway hook (T3a,
  ## findings-doc break #1; see the runtime C doc for the full threat model).
  ##
  ## `childOsPid` carries the PEER PID (AF_UNIX via LOCAL_PEERPID; 0/unknown for
  ## INET). This deliberately mirrors `recordSpawn`'s use of `childOsPid` so the
  ## SAME merge-time peer-set machinery (writer.unmonitoredSubtreeLossCount) can
  ## decide INSIDE-vs-OUTSIDE the injected tree: a peer pid with a matching
  ## `mrProcessStart` is a monitored in-tree process (FINE — no downgrade, the
  ## cardinal-sin guard for legitimate intra-tree IPC); a peer pid NOT in the set,
  ## or an UNKNOWN peer, is an out-of-tree breakaway that may have read files on
  ## our behalf ⇒ the merge injects an event-loss ⇒ mcIncomplete (a conservative
  ## RE-RUN, never a false skip — Monitor-Hook-Shim.md §Failure Semantics).
  if address == nil:
    return
  var dest: array[1024, char]
  dest[0] = '\0'
  var peerPid: cint = 0
  let family = ct_macos_socket_describe(fd, address, addrLen,
    addr dest[0], csize_t(dest.len), addr peerPid)
  # Only socket families that can carry a file-serving peer are interesting:
  # AF_UNIX (local build daemons) and AF_INET/INET6 (remote/loopback services).
  # Other families (AF_ROUTE, AF_SYSTEM, …) and bad-arg (-1) returns are skipped.
  if family != AfUnix and family != AfInet and family != AfInet6:
    return
  var record = baseRecord(mrIpcConnect, moIpcConnect)
  record.result = callResult.int64
  record.flags = uint32(family)
  record.childOsPid = uint64(peerPid)        # peer pid (0 ⇒ unobtainable)
  record.path = $cast[cstring](addr dest[0]) # socket path or "ip:port"
  # ROUND-2 R7 — stamp the PEER's (pid, start-time) so the merge matches an
  # in-tree peer by identity, not bare pid (a recycled peer pid with a different
  # start time is correctly out-of-tree). ROUND-2 R8 — stamp the run id (report
  # scoping) and an unguessable per-connection nonce (recorded so the merge can
  # reject a trusted-daemon report whose nonce does not match an OBSERVED
  # connection). See writer.unmonitoredSubtreeLossCount / loadBreakawayReports.
  var d =
    (if family == AfUnix: "connect af_unix" else: "connect af_inet") &
    (if peerPid != 0: " peer=" & $peerPid else: " peer=unknown")
  if peerPid != 0:
    let peerStart = ct_macos_proc_start_usec(peerPid)
    if peerStart != 0:
      d.add " peerstart=" & $peerStart
  d.add runIdToken()
  # ROUND-2 R-D — the shim's OWN nonce randomness must NEVER be recorded as the
  # program's non-determinism (it would self-downgrade this capture — the cardinal
  # sin). repro_macos_random_u64 already resolves the genuine arc4random_buf
  # (bypassing the interpose wrapper); muting here is the belt-and-suspenders guard
  # against the wrapper being hit during dlsym's one-time internal resolution.
  inc disabled
  let nonce = ct_macos_random_u64()
  dec disabled
  d.add " nonce=" & $nonce
  record.detail = d
  emitRecord(record)

# --- ROUND-3 S0 — Mach/XPC service-name discrimination ----------------------
#
# Close the round-2 R-C CRITICAL regression: the blunt `com.apple.*` name-prefix
# exemption (the round-2 "system baseline" filter) is trivially bypassable. ANY
# unsigned third-party process can `bootstrap_register` an arbitrary UNUSED
# `com.apple.<custom>` name (verified on macOS 26: bootstrap_register of e.g.
# `com.apple.r3residual.<pid>` returns KERN_SUCCESS from an unsigned binary). A
# monitored client that looks that name up, and to which the registering daemon
# serves a delegated file read over Mach IPC, produced NO `mrIpcConnect` record
# (the com.apple.* prefix exempted it) → a false `mcComplete` with the secret
# input absent. (research/adversarial-2026-06-round3/r3_residual.)
#
# THE DISCRIMINATOR (owner-identity vs allowlist — both evaluated):
#  * OWNER IDENTITY is the gold standard but is NOT cheaply obtainable in-process
#    for EITHER path: a `bootstrap_look_up` returns only a bare Mach SEND port,
#    and `pid_for_task` on a service port fails (KERN_FAILURE, verified) — launchd
#    brokers the connection and never exposes the server pid; `csops`/
#    CS_PLATFORM_BINARY needs that pid. The XPC create entry is LAZY (no peer, no
#    audit token until a message round-trips, which we must not force). So neither
#    path yields the owner cheaply.
#  * DATA-DRIVEN ALLOWLIST (chosen): a GENUINE `com.apple.*` service is DECLARED
#    (as a MachServices key) inside an Apple-signed launchd plist under a
#    SIP-protected directory (SipLaunchdDirs). System Integrity Protection forbids
#    even root from writing those directories, so the attacker's runtime-registered
#    name is provably ABSENT from them. We therefore exempt a `com.apple.*` lookup
#    iff its name occurs as a WHOLE TOKEN in those plists' bytes. This is strictly
#    more robust than a hand-curated allowlist (it auto-covers every real Apple
#    launchd service and cannot be evaded by choosing an allowlisted prefix).
#
# WHY THIS DOES NOT FALSE-DOWNGRADE NORMAL BUILDS (the cardinal sin): the hooks
# are INTERPOSE-ONLY (not body-patched), so they see ONLY the program's OWN direct
# `bootstrap_look_up` / `xpc_connection_create_mach_service` calls crossing an
# import stub — NEVER the pervasive libsystem-INTERNAL `com.apple.*` lookups every
# process performs at startup (those are shared-cache-internal). Empirically a
# trivial program, a normal file-reading program, and a real `cc`/`clang` compile
# make ZERO direct `com.apple.*` lookups reaching this hook, so the SIP set is
# never even built for them. The set is consulted only on the RARE deliberate
# direct lookup (e.g. a tool that talks to cfprefsd / the notification center),
# where it keeps the genuine Apple service exempt while catching the attacker's
# undeclared name.
#
# RESIDUAL (documented): the SIP set covers the launchd LaunchDaemons/LaunchAgents
# MachServices. A genuine Apple service declared ONLY in a framework XPCServices
# bundle (not in those two dirs) and looked up DIRECTLY by a program would be
# conservatively recorded → a redundant re-run (the FAIL-SAFE direction), never a
# false skip. The structural endgame remains the EndpointSecurity backend (T3c).

proc isSvcContinuationByte(c: char): bool {.inline.} =
  ## True if `c` can continue a Mach service-name token to the RIGHT. Service
  ## names use the reverse-DNS charset `[A-Za-z0-9._-]`; a binary-plist length/
  ## type marker or a separator (NUL, tab, `<`, …) is NOT in it and ends a token.
  c in {'A'..'Z', 'a'..'z', '0'..'9', '.', '_', '-'}

proc isSvcLeftBoundaryByte(c: char): bool {.inline.} =
  ## True if `c` extends a Mach service-name token to the LEFT (so the candidate
  ## is a SUFFIX of a longer token, e.g. `com.apple.cfprefsd` inside
  ## `…cfprefsd.daemon` — which must NOT count as a whole-token match). `_` is
  ## DELIBERATELY excluded: the binary-plist ASCII-string marker is 0x5f (`_`) and
  ## legitimately immediately precedes a stored service name, so it is a boundary.
  c in {'A'..'Z', 'a'..'z', '0'..'9', '.', '-'}

proc blobContainsWholeToken(blob, name: string): bool {.raises: [].} =
  ## True iff `name` occurs in `blob` as a WHOLE service-name token — i.e. not as a
  ## sub-token of a longer name. The byte before the match must not extend the
  ## token left (isSvcLeftBoundaryByte) and the byte after must not extend it right
  ## (isSvcContinuationByte). This prevents an attacker's `com.apple.cfprefsd`
  ## (a prefix of the real `com.apple.cfprefsd.daemon`) from being falsely exempted
  ## by a bare substring hit, and tolerates the binary-plist framing around a
  ## genuine name.
  if name.len == 0 or blob.len < name.len:
    return false
  var i = 0
  while i <= blob.len - name.len:
    let idx = blob.find(name, i)
    if idx < 0:
      break
    let beforeOk = idx == 0 or not isSvcLeftBoundaryByte(blob[idx - 1])
    let afterIdx = idx + name.len
    let afterOk = afterIdx >= blob.len or not isSvcContinuationByte(blob[afterIdx])
    if beforeOk and afterOk:
      return true
    i = idx + 1
  false

proc buildAppleServiceBlob() {.raises: [].} =
  ## Lazily read every SIP-protected launchd plist into the cached `appleServiceBlob`
  ## byte buffer, with the shim MUTED so the scan's OWN file I/O is not recorded as a
  ## build dependency (and cannot recurse into recording). SIP guarantees an attacker
  ## cannot inject a plist here, so a `com.apple.*` whole-token present in these bytes
  ## is a genuine system service. Called ONCE, under `machServiceLock`. A per-file /
  ## per-dir failure is swallowed (a missing/unreadable plist must never break the
  ## decision — at worst a name is treated as undeclared ⇒ a conservative re-run).
  # Capacity for the concatenated SIP plist bytes. The two launchd dirs hold
  # ~1.3 MB of plist content today; 8 MB leaves generous headroom and is allocated
  # ONLY when a direct com.apple.* lookup first reaches the hook (normal builds
  # make none, so this is never allocated for them). A name truncated at the cap is
  # treated as undeclared ⇒ a conservative re-run, never a false skip.
  const SipBlobCap = 8 * 1024 * 1024
  var buf = newString(SipBlobCap)
  var pos: csize_t = 0
  # The C helper enumerates + reads via PURE RAW SYSCALLS (SYS_open(O_DIRECTORY) +
  # SYS_getdirentries64 + SYS_open/read/close), bypassing libsystem opendir/readdir
  # entirely — under the shim BOTH dlsym and the image walk resolve a `readdir`
  # whose record layout is off by one (drops d_name's first byte), and raw syscalls
  # never fire a file-I/O hook. We still mute around the call as belt-and-suspenders.
  withShimMuted:
    for dir in SipLaunchdDirs:
      pos = ct_macos_concat_sip_plists(cstring(dir), addr buf[0],
        csize_t(SipBlobCap), pos)
  buf.setLen(int(pos))
  appleServiceBlob = buf
  appleServiceBlobBuilt = true

proc isDeclaredAppleService(name: string): bool {.raises: [].} =
  ## True if `name` is a GENUINE `com.apple.*` system service declared (as a whole
  ## token) in the SIP-protected launchd plists — and therefore EXEMPT from the
  ## breakaway downgrade. The SIP set is built once, lazily; the decision is memoised
  ## per name (bounded by MachServiceCacheCap). All under `machServiceLock`.
  acquire(machServiceLock)
  defer: release(machServiceLock)
  if appleServiceDecision.hasKey(name):
    return appleServiceDecision.getOrDefault(name, false)
  if not appleServiceBlobBuilt:
    buildAppleServiceBlob()
  result = blobContainsWholeToken(appleServiceBlob, name)
  if appleServiceDecision.len >= MachServiceCacheCap:
    appleServiceDecision.clear()
  appleServiceDecision[name] = result

proc machServiceRecordable(serviceName: cstring): bool {.raises: [].} =
  ## ROUND-3 S0 — decide whether a `bootstrap_look_up` / XPC connection to
  ## `serviceName` must be RECORDED as a potential out-of-tree breakaway:
  ##  * a NON-`com.apple.*` name is ALWAYS recorded (the round-2 behaviour:
  ##    sccache/distcc/icecc/custom build daemons + the r2_xpc `com.example.*`
  ##    break) — a normal compile/link/make never resolves one directly.
  ##  * a `com.apple.*` name is recorded ONLY when it is NOT a genuine, SIP-declared
  ##    Apple system service (isDeclaredAppleService). This closes the round-3 S0
  ##    break: the attacker's unsigned-process `bootstrap_register`-ed
  ##    `com.apple.<custom>` name is absent from the SIP-protected plists ⇒ recorded
  ##    ⇒ downgrade; the real `com.apple.*` baseline stays exempt ⇒ no false
  ##    downgrade. See the threat-model block above.
  if serviceName == nil or serviceName[0] == '\0':
    return false
  let n = $serviceName
  if not n.startsWith(AppleServicePrefix):
    return true
  not isDeclaredAppleService(n)

proc recordMachLookup(serviceName: cstring; callResult: cint) {.raises: [].} =
  ## ROUND-2 R-C — record a successful `bootstrap_look_up` / XPC mach-service
  ## connection-establishment to an OUT-OF-TREE service as an `mrIpcConnect`
  ## breakaway, the XPC/Mach-port analog of the connect(2) daemon-over-socket hook
  ## (findings-doc break #1). XPC and raw Mach RPC never issue connect(2) — they
  ## resolve a service name to a send port via bootstrap + mach_msg — so the
  ## connect hook is blind to them; a monitored client that delegates a file read
  ## to an out-of-tree service (the confirmed r2_xpc break) otherwise produces a
  ## false `mcComplete`. See the runtime C doc for the full threat model.
  ##
  ## We REUSE the `mrIpcConnect` record kind so the SAME merge-time downgrade
  ## machinery (`writer.unmonitoredSubtreeLossCount` case (c)) fires with ZERO
  ## merge changes and NO wire-format change: a Mach peer pid is launchd-brokered
  ## and NOT knowable from the send port, so `childOsPid` is 0 (unknown peer) and
  ## the merge keys the downgrade on the destination (the service name). An
  ## unknown peer is treated conservatively as out-of-tree ⇒ one event-loss ⇒
  ## `mcIncomplete` (a conservative RE-RUN, never a false skip) — the same
  ## downgrade-on-uncertainty stance as the INET-peer-unknown connect(2) case.
  ##
  ## The CARDINAL-SIN guard lives in `machServiceRecordable` (ROUND-3 S0): a
  ## NON-`com.apple.*` service, OR a `com.apple.*` name NOT declared in the
  ## SIP-protected launchd plists (the attacker's forged name), is recorded; the
  ## genuine SIP-declared `com.apple.*` baseline is exempt, so a normal build —
  ## which makes NO direct `com.apple.*` lookups through this interpose-only hook —
  ## is NEVER downgraded. Pre-init / muted lookups never reach here (the hooks bail
  ## on `not initialized` / `disabled > 0`).
  if serviceName == nil or serviceName[0] == '\0':
    return
  if not machServiceRecordable(serviceName):
    return
  var record = baseRecord(mrIpcConnect, moIpcConnect)
  record.result = callResult.int64
  record.flags = 0                              # no socket family (Mach lookup)
  record.childOsPid = 0                         # launchd-brokered peer ⇒ unknown
  record.path = $serviceName                    # the mach service name
  # ROUND-2 R8 — stamp the run id (report scoping) and an unguessable
  # per-connection nonce, mirroring recordIpcConnect, so a future cooperating
  # daemon could authenticate a breakaway report for this lookup. `peer=unknown`
  # documents that the Mach peer pid is not obtainable from the send port.
  var d = "connect mach-service peer=unknown service=" & $serviceName
  d.add runIdToken()
  # ROUND-2 R-D — mute the shim's own nonce randomness (see recordIpcConnect).
  inc disabled
  let nonce = ct_macos_random_u64()
  dec disabled
  d.add " nonce=" & $nonce
  record.detail = d
  emitRecord(record)

proc recordLibraryLoad(path: cstring) {.raises: [].} =
  ## Record a dyld-mapped DEPENDENT DYLIB (or a dlopen'd image) as a CONTENT
  ## (read) dependency — findings-doc break #4 (a real clang/ld64 link mmaps ~620
  ## toolchain dylibs — libLLVM, libclang-cpp, … — that NEVER pass through the
  ## hooked open) plus the dlopen arm of break #7. dyld maps these via low-level
  ## kernel mmap, bypassing every open/openat hook, so the ONLY way to see them is
  ## the `_dyld` add-image callback (see `repro_hook_dyld_add_image`).
  ##
  ## The record carries the dylib's REAL on-disk path and uses `observationKind ==
  ## moFileRead` so that an existing read-dependency consumer fingerprints the
  ## dylib BYTES — directly closing the stale-cache hole (an in-place
  ## libclang.dylib upgrade beside a stable driver path MUST bust the cache). The
  ## distinct `mrLibraryLoad` record kind keeps it identifiable for inspection and
  ## for the no-flooding tests. The aggressive FILTER (the runtime C helper) has
  ## already dropped the ~600-image system baseline, so this fires only for real
  ## non-system on-disk dylibs — no gratuitous noise.
  if path == nil or path[0] == '\0':
    return
  var record = baseRecord(mrLibraryLoad, moFileRead)
  record.path = $path
  record.detail = "library-load dyld-image"
  emitRecord(record)

proc repro_hook_dyld_add_image*(mh: pointer; slide: int)
    {.exportc, cdecl, dynlib.} =
  ## dyld add-image callback (T3b). Registered via
  ## `_dyld_register_func_for_add_image` in the shim constructor: dyld invokes it
  ## ONCE for every image already loaded at registration time (the executable's
  ## full dependent-dylib closure — complete here because dyld maps all static
  ## dependencies BEFORE running initializers/this constructor) AND again for
  ## every future `dlopen`. A single code path therefore covers BOTH break #4 (the
  ## static toolchain-dylib closure) and the dlopen arm of break #7.
  ##
  ## SAFETY (this runs in dyld's image-loading context, dyld holding its loader
  ## lock):
  ##   * fail-safe: bail before the recording runtime is live (`initialized`).
  ##   * reentrancy: if a record-emit ever re-entered dyld (it should not — it does
  ##     only file I/O), `emitRecord` raises `disabled` for its append, so a nested
  ##     callback sees `disabled > 0` and bails — no loop.
  ##   * deadlock: all work is MINIMAL and dyld-free — the C classifier uses dladdr
  ##     + a raw stat (never the `_dyld` image walk), and the emit is plain file
  ##     I/O. No heavy work, no dlopen, no symbol resolution here.
  if not initialized or disabled > 0:
    return
  var buf: array[1024, char]
  buf[0] = '\0'
  # ROUND-2 R6 — the filter now realpath-CANONICALISES the candidate path (so a
  # `..`-laden or /private/var/…/usr/lib/… path cannot dodge/falsely-trip the
  # baseline prefix tests). realpath's internal lstat is body-patched, so we MUTE
  # the shim around the C call: a muted lstat forwards without recording (no
  # recursion), and we un-mute before recordLibraryLoad so the library-load record
  # is actually emitted.
  inc disabled
  let recordable = ct_macos_dyld_image_dep_path(mh, addr buf[0], csize_t(buf.len)) != 0
  dec disabled
  if recordable:
    recordLibraryLoad(cast[cstring](addr buf[0]))
    # ROUND-3 S3b — this image is NON-SYSTEM (it passed the same /usr/lib + /System
    # + shared-cache + shim filter the library-load record uses). Register its slid
    # __TEXT range for entropy caller-attribution ONLY when it is a DLOPEN'd image
    # (the initial link-time burst is done): a dlopen'd compiler pass-plugin is the
    # res1_dylib_entropy threat, while the program's LINK-TIME runtime dylibs (a Nix
    # clang's libLLVM/libc++) draw BENIGN temp-name/hash entropy that must NOT
    # downgrade a normal compile (the cardinal-sin guard). The entropy hooks then
    # flag an arc4random/getentropy call made by THIS dlopen'd plugin; recordLibraryLoad
    # above still records EVERY non-system image as a content dep (break #4).
    # getsegmentdata is a lock-free memory walk, safe in the dyld add-image callback.
    if ct_macos_addimage_burst_done():
      ct_macos_register_nonsystem_image(mh)

proc repro_monitor_shim_init*(configPath: cstring): cint {.exportc, dynlib.} =
  if not locksReady:
    initLock(initLockVar)
    initLock(recordLock)
    initLock(fdLock)
    initLock(dirLock)
    initLock(canonicalLock)   # ROUND-2 R4 — guards the realpath memo
    initLock(observedLock)    # ROUND-2 R-D — guards the observed-input dedup set
    initLock(machServiceLock) # ROUND-3 S0 — guards the SIP Apple-service set/memo
    locksReady = true
  acquire(initLockVar)
  defer: release(initLockVar)
  if initialized:
    return 0
  withShimMuted:
    fragmentDir = getEnv("REPRO_MONITOR_FRAGMENT_DIR")
    if fragmentDir.len > 0:
      createDir(extendedPath(fragmentDir))
    # ROUND-2 R8 — capture the invocation run id for report authentication.
    runId = getEnv("REPRO_MONITOR_SESSION")
  # Record the constructor thread as the "main" thread. Its fragment batch is
  # flushed by the dyld process-exit destructor; worker threads (which the
  # destructor cannot reach safely) flush eagerly per record in emitRecord. Init
  # runs in the dyld constructor, single-threaded, so this captures the main
  # thread id before any worker thread can emit.
  mainThreadId = currentThreadId()
  # ROUND-2 R6 — capture the shim's OWN (mach_header, realpath) NOW, single-threaded
  # at init and BEFORE the body-patch install / add-image registration, so the
  # library-load filter excludes our shim by unspoofable identity (header pointer /
  # exact realpath) rather than the round-1 substring test that false-dropped
  # genuine dependency dylibs whose path merely contained "librepro_monitor_shim".
  # realpath here reaches genuine libsystem (body-patch is not yet installed and the
  # interpose wrappers passthrough while runtime_ready is 0), so it cannot recurse.
  ct_macos_capture_shim_image()
  # ROUND-2 R-D — capture the main executable's __TEXT range NOW (single-threaded,
  # before runtime_ready) so the entropy hooks can attribute a caller to the
  # program's OWN code by a pure pointer-range compare — the crash-safe
  # cardinal-sin guard (see ct_macos_addr_in_program).
  ct_macos_capture_main_image()
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

# --- T2 content/metadata recording helpers (findings doc breaks #3/#5/#7) ---
#
# Each new hook family routes through ONE of these helpers, mirroring the
# recordOpen/recordPathProbe/recordSpawn pattern (DRY: one record-builder per
# record classification).

proc recordContentCopy(callResult: cint; src, dst, detail: string) {.raises: [].} =
  ## Classify a clonefile/link/copyfile-CLONE as a CONTENT (read) dependency on
  ## the SOURCE plus an output WRITE on the DESTINATION. An APFS clonefile clone
  ## reads ZERO source bytes (copy-on-write) and a hardlink merely aliases the
  ## inode, so the call itself is the ONLY evidence the source content is a
  ## dependency (findings doc break #3). Only a successful call (result == 0)
  ## consumes the source / materialises the destination; the result is recorded
  ## so the consumer can tell. Empty path components (e.g. an unmapped fd) are
  ## skipped rather than recording a blank dependency.
  if src.len > 0:
    var rd = baseRecord(mrFileRead, moFileRead)
    rd.path = src
    rd.result = callResult.int64
    if detail.len > 0: rd.detail = detail & " src"
    emitRecord(rd)
  if dst.len > 0:
    var wr = baseRecord(mrFileWrite, moFileWrite)
    wr.path = dst
    wr.result = callResult.int64
    if detail.len > 0: wr.detail = detail & " dst"
    emitRecord(wr)

proc recordDirEnumByFd(fd: cint; detail: string) {.raises: [].} =
  ## Record a directory enumeration keyed on an OPEN dir fd (getattrlistbulk /
  ## getdirentries). opendir/readdir are already hooked, but these bulk-scan a
  ## dir via a plain open()ed fd with no readdir call; the dir open IS captured
  ## (so pathForFd resolves the dir), and we add a directory-enumerate record to
  ## match the opendir/readdir granularity. Per-child name extraction from the
  ## packed attribute buffer is deferred (findings doc T2: "per-entry … partial").
  let p = pathForFd(fd)
  if p.len == 0:
    return
  var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
  record.path = p
  record.result = 1
  record.detail = detail
  emitRecord(record)

proc recordCanonicalTarget(fd: cint; original: cstring;
    obs: MonitorObservationKind) {.raises: [].} =
  ## After a successful open, resolve the fd's canonical real path via
  ## fcntl(F_GETPATH). When it differs from the caller-supplied path the open
  ## traversed a SYMLINK, a /.vol/<dev>/<inode> firmlink, OR — ROUND-3 S2a/S2b — a
  ## `dirfd`-relative (`openat`) or cwd-relative path that names the file only by a
  ## bare/relative component: record an ADDITIONAL file dependency on the resolved
  ## ABSOLUTE target and re-point the fd→path map at it, so subsequent reads/writes
  ## — and the dependency set — name the REAL canonical file, not the opaque
  ## link/inode or unmatchable relative path. fcntl is not hooked (raw syscall), so
  ## this is reentrancy-free.
  ##
  ## ROUND-3 S2b — this now runs for ALL successful opens (READ and WRITE), not only
  ## read-ish opens. A WRITE open via `openat(dirfd, "rel/out", …)` or a relative
  ## cwd path otherwise recorded its OUTPUT under a bare/relative path that no
  ## consumer's canonical cache key matches (a false cache hit / stale artifact).
  ## The companion carries the open's OWN observation kind (`obs`) so a write
  ## target's canonical companion stays a WRITE (moFileWrite) and a read target's an
  ## INPUT (moFileOpen) — the canonicalisation is ADDITIVE and never reclassifies.
  ## F_GETPATH is a single cheap raw fcntl (no realpath cost on this hot path).
  if fd < 0:
    return
  var buf: array[1024, char]
  if ct_macos_fd_real_path(fd, addr buf[0], csize_t(buf.len)) == 0:
    return
  let canonical = $cast[cstring](addr buf[0])
  if canonical.len == 0 or (original != nil and canonical == $original):
    return
  updateFdPath(fd, cstring(canonical))
  var record = baseRecord(mrFileOpen, obs)
  record.path = canonical
  record.result = fd.int64
  record.detail = "resolved-target"
  emitRecord(record)

proc recordCanonicalProbe(callResult: cint; path: cstring) {.raises: [].} =
  ## For a successful lstat of a SYMLINK, ALSO record a path-probe on the
  ## realpath-resolved target (findings doc break #7 / mcapSymlink): editing the
  ## target while the link is unchanged must remain a visible dependency.
  ## realpath's internal lstat calls are body-patched, so the canonicalisation is
  ## done with the shim MUTED (disabled>0) to avoid recursion; the probe is then
  ## emitted with the shim un-muted.
  if callResult != 0 or path == nil:
    return
  var buf: array[1024, char]
  var ok = false
  withShimMuted:
    ok = ct_macos_canonical_path(path, addr buf[0], csize_t(buf.len)) != 0
  if not ok:
    return
  let canonical = $cast[cstring](addr buf[0])
  if canonical.len == 0 or canonical == $path:
    return
  recordPathProbe(callResult, cstring(canonical), 0, "resolved-target")

proc recordCanonicalPathProbe(callResult: cint; path: cstring; mode: cint;
    detail: string) {.raises: [].} =
  ## ROUND-2 R4 — for a SUCCESSFUL stat/lstat/fstatat/access probe whose raw path
  ## is NON-CANONICAL, ALSO record a path-probe on the realpath-canonical form, so
  ## a metadata-only dependency (existence/mtime — HUGE in builds: make/ninja mtime
  ## checks, compiler include-search via access/stat, `configure`'s `test -f`)
  ## stays matchable when the consumer keys on the canonical path. Round 1
  ## canonicalised OPENS (the F_GETPATH companion) but the PATH-PROBE family
  ## recorded the RAW path verbatim, so `/dir/./file`, a case-folded `FILE.TXT` on
  ## case-insensitive APFS, a mid-path symlink, or a relative-after-chdir path never
  ## matched a canonical cache key ⇒ a changed dependency was MISSED → a false skip
  ## (research/.../r2_path). We record BOTH the as-passed (recordPathProbe in the
  ## caller) AND the canonical path here, mirroring the open #7/#8 dual record, so a
  ## consumer keyed on EITHER matches.
  ##
  ## Perf is bounded (stat storms are large): only on SUCCESS (callResult == 0 — the
  ## ENOENT probe storm is skipped) and via the realpath memo in canonicalPathFor.
  ## `detail` carries the as-passed probe's (dev, ino) so the canonical companion is
  ## inode-matchable too.
  if callResult != 0 or path == nil:
    return
  let raw = $path
  let canonical = canonicalPathFor(raw)
  if canonical.len == 0 or canonical == raw:
    return
  recordPathProbe(callResult, cstring(canonical), mode,
    (if detail.len > 0: detail & " resolved-target" else: "resolved-target"))

proc recordCanonicalAtProbe(callResult: cint; dirfd: cint; path: cstring;
    mode: cint; detail: string) {.raises: [].} =
  ## ROUND-3 S2a — canonical companion for the `*at` PROBE family (fstatat,
  ## getattrlistat). Closes the round-2 dirfd-relative residual: round 2 only
  ## canonicalised a probe whose path was ABSOLUTE or relative to AT_FDCWD (realpath
  ## resolves against the CWD, not an arbitrary `dirfd`), so `fstatat(dirfd,
  ## "rel/file", …)` with a REAL dirfd recorded only the BARE RELATIVE component —
  ## unmatchable against a consumer's canonical cache key, and (unlike an open)
  ## there is no fd to F_GETPATH and no open fallback, so a changed metadata
  ## dependency was INVISIBLE → a false skip (r3_fd p_fstat).
  ##
  ##  * ABSOLUTE path or AT_FDCWD → defer to recordCanonicalPathProbe (realpath
  ##    against the CWD is correct), exactly as round 2.
  ##  * dirfd-RELATIVE → resolve the dirfd to its real directory via F_GETPATH (a
  ##    raw fcntl, reentrancy-free), join the relative component, and record the
  ##    realpath-canonical ABSOLUTE companion (memoised via canonicalPathFor, so the
  ##    realpath cost is bounded on a probe storm).
  if callResult != 0 or path == nil:
    return
  let raw = $path
  if raw.len == 0:
    return
  if raw[0] == '/' or dirfd == AtFdCwd:
    recordCanonicalPathProbe(callResult, path, mode, detail)
    return
  # dirfd-relative: recover the directory's real path, then realpath the join.
  var dbuf: array[1024, char]
  if ct_macos_fd_real_path(dirfd, addr dbuf[0], csize_t(dbuf.len)) == 0:
    return
  let dir = $cast[cstring](addr dbuf[0])
  if dir.len == 0:
    return
  let joined = dir & "/" & raw
  let canonical = canonicalPathFor(joined)
  # Prefer the realpath-canonical form; fall back to the absolute join when
  # realpath fails (e.g. a broken-symlink leaf an lstat-style probe still describes)
  # so the companion is at worst absolute, never the bare relative component.
  let p = if canonical.len > 0: canonical else: joined
  recordPathProbe(callResult, cstring(p), mode,
    (if detail.len > 0: detail & " resolved-target" else: "resolved-target"))

proc recordMmap(callResult: pointer; prot, flags, fd: cint) {.raises: [].} =
  ## ROUND-2 R9 — classify an `mmap` of a FILE-backed fd. A MAP_SHARED|PROT_WRITE
  ## mapping changes the file's CONTENT with NO write(2)/pwrite(2) syscall (ld64
  ## writes its output executable this way; r2_mmap probeC), so the open alone does
  ## not convey the write → the output is INVISIBLE to a write-only-via-syscall
  ## monitor. We record an output WRITE on the mapped fd's path at mmap time
  ## (write-INTENT — conservative: a mapped-writable-but-never-written file is
  ## over-recorded as an output, the SAFE direction, never a missed output).
  ##
  ## A read-only / private / anonymous mapping is NOT recorded: the round-1 finding
  ## showed mmap-AFTER-open is already covered by the captured open (the file is in
  ## the input set), so recording a read mapping would be a gratuitous double-record
  ## (and an O_RDWR-then-PROT_READ-mmap input is already captured as an input by the
  ## R3 open classification). Only the MAP_SHARED|PROT_WRITE content write is a
  ## genuine fact the open does not carry.
  if callResult == cast[pointer](-1) or fd < 0:   # MAP_FAILED or no backing fd
    return
  if (flags and MapAnon) != 0:                    # anonymous: no file backing
    return
  if (flags and MapShared) == 0:                  # private: writes don't hit disk
    return
  # ROUND-3 S1b — a read-only MAP_SHARED mapping of an shm-backed fd IS a content
  # read (the consumer reads the producer's bytes via a plain memory load, no
  # read(2)). For a regular FILE a read mapping is already covered by the open, but
  # an shm object is NOT a file the open hook saw, so without this the consumed
  # content is invisible (research/.../r3_channel/probeC_shm_consumer.c). Record it
  # as a content read on the shm name; the shm_open already emitted the out-of-tree
  # provenance signal that the merge downgrades on.
  if (prot and ProtWrite) == 0:                   # read-only mapping
    let shm = shmNameForFd(fd)
    if shm.len > 0:
      var rd = baseRecord(mrFileRead, moFileRead)
      rd.path = "shm:" & shm
      rd.result = 0
      rd.flags = uint32(fd)
      rd.detail = "shm-mmap MAP_SHARED|PROT_READ"
      emitRecord(rd)
    return                                        # read-only file: open covers it
  let p = pathForFd(fd)
  if p.len == 0:
    return
  var record = baseRecord(mrFileWrite, moFileWrite)
  record.path = p
  record.result = 0
  record.flags = uint32(fd)
  record.detail = "mmap-write MAP_SHARED|PROT_WRITE"
  emitRecord(record)

proc recordSetexecExec(attrp: pointer; path: cstring) {.raises: [].} =
  ## If a posix_spawn(p) sets POSIX_SPAWN_SETEXEC it REPLACES the calling
  ## process image and NEVER returns on success — so (mirroring repro_hook_execve
  ## exactly) emit the exec record AND FLUSH it BEFORE the forward, else the
  ## record dies with the old image's in-flight fragment batch and the launched
  ## binary's dependency is lost (findings doc break #2). `childOsPid` is set to
  ## this pid: a SETEXEC re-images THIS process, and T0's exec-coverage check
  ## (writer.unmonitoredSubtreeLossCount) then downgrades completeness to a
  ## conservative re-run if the new image is un-injectable (no post-exec
  ## process-start), while an injectable child re-loads the shim and is captured.
  if not ct_macos_spawnattr_has_setexec(attrp):
    return
  var record = baseRecord(mrProcessExec, moExecute)
  if path != nil:
    record.path = $path
  record.childOsPid = uint64(c_getpid())
  record.detail = "posix_spawn-setexec"
  emitRecord(record)
  discard repro_monitor_shim_flush()

const
  # copyfile(3) clone-mode flags (<copyfile.h>): these clone via the APFS CoW
  # path and issue NO internal open/read on the source, so the source dependency
  # is invisible unless recorded. The DATA/ALL data modes DO open+read
  # internally (already captured), so we record only for the clone modes to avoid
  # double-counting (findings doc §"Coverage wins").
  CopyfileClone = 1'u32 shl 24
  CopyfileCloneForce = 1'u32 shl 25

# --- ROUND-3 S1 — content-channel recorders ---------------------------------
#
# Close the round-3 S1 false negatives (research/adversarial-2026-06-round3):
# CONTENT that reaches a build WITHOUT a hooked read(2) of a named file —
# extended-attribute values (S1a), POSIX shared memory (S1b), inherited
# socket/pipe fds (S1c), FIFOs and the sendfile/pread/readv zero-copy/positioned
# reads (S1d). Two response classes, mirroring the round-2 split:
#   * RECORD (no downgrade): an xattr read is a precise, attributable dependency
#     (resolved path + attr name) and a sendfile/pread/readv is a normal content
#     read on a NAMED in-tree file — these are added to the dependency set exactly
#     like a read(2), never downgraded.
#   * DOWNGRADE (reuse the IPC-breakaway machinery): a shm object / FIFO / inherited
#     socket-pipe whose producer is OUT OF THE MONITORED TREE is an INVISIBLE input
#     ⇒ emit an `mrExternalContent` the merge pairs against the in-tree create/write
#     side; an UNPAIRED consume injects one event-loss ⇒ `mcIncomplete` (a
#     conservative re-run). The CARDINAL-SIN GUARD is the pairing: an shm/FIFO a
#     monitored process itself created+fed is fully accounted for and NEVER
#     downgrades (see writer.externalContentLossCount).

proc isSystemShmName(name: string): bool {.raises: [].} =
  ## ROUND-3 S1b — true for a SYSTEM shm object the OS/libsystem maps on every
  ## process (apple.shm.* / com.apple.*). Exempted from the out-of-tree downgrade
  ## so a normal build is never falsely flagged (the cardinal-sin guard). A leading
  ## '/' is stripped first (shm names are conventionally `/name`).
  let n = if name.len > 0 and name[0] == '/': name[1 .. ^1] else: name
  for prefix in SystemShmPrefixes:
    if n.startsWith(prefix):
      return true
  false

proc recordShmOpen(fd: cint; name: cstring; flags: cint) {.raises: [].} =
  ## ROUND-3 S1b — record a POSIX `shm_open`. An shm_open WITH O_CREAT is the
  ## CREATE side (in-tree provenance evidence; the cardinal-sin guard data); WITHOUT
  ## O_CREAT it is an ATTACH/consume side. The fd→name map lets a subsequent
  ## read-only MAP_SHARED mmap of the object be recorded as a content read
  ## (recordMmap). Only a successful open (fd >= 0) is recorded. A SYSTEM shm
  ## (apple.shm.* / com.apple.*) is NOT recorded as a content channel at all (it is
  ## not a build input — see isSystemShmName), so it neither downgrades nor adds a
  ## spurious content read.
  if fd < 0 or name == nil:
    return
  let shmName = $name
  if isSystemShmName(shmName):
    return
  addShmFd(fd, shmName)
  let role = if (flags and OCreat) != 0: "create" else: "attach"
  recordExternalContent("shm", role, "shm:" & shmName, fd)

proc recordXattr(callResult: int; path: cstring; attrName: cstring;
    valueLen: int; isList, isWrite: bool; detail: string) {.raises: [].} =
  ## ROUND-3 S1a — record an extended-attribute access as a DEPENDENCY keyed on the
  ## (resolved path, attribute name). An xattr VALUE is build-relevant content the
  ## round-2 hook set missed entirely (getxattr never even open(2)s the file), so a
  ## build that reads a dep from an xattr produced ZERO records → a proven false
  ## cache hit (research/.../r3_xattr). We classify it as a PATH-PROBE on the file
  ## with the attr name (and the value LENGTH for content sensitivity) in `detail`,
  ## so a consumer folds the attr's value into its cache key. A READ xattr
  ## (getxattr/listxattr) is a probe/input; a WRITE (setxattr/removexattr) is
  ## additionally recorded as an output write on the file. Only a successful read
  ## (callResult >= 0) / successful write (callResult == 0) is recorded.
  if path == nil:
    return
  let raw = $path
  if raw.len == 0:
    return
  # Normalise to the realpath so the dependency matches a consumer keyed on the
  # canonical path (mirrors the round-2 path-probe canonicalisation). Muted inside
  # canonicalPathFor; falls back to the raw path when realpath cannot resolve it.
  let canonical = canonicalPathFor(raw)
  let p = if canonical.len > 0: canonical else: raw
  var d = detail
  if isList:
    if d.len > 0: d.add ' '
    d.add "xattr-list"
  elif attrName != nil and ($attrName).len > 0:
    if d.len > 0: d.add ' '
    d.add "xattr=" & $attrName
  if valueLen >= 0:
    d.add " vlen=" & $valueLen
  if isWrite and callResult == 0:
    var wr = baseRecord(mrFileWrite, moFileWrite)
    wr.path = p
    wr.result = callResult.int64
    wr.detail = d
    emitRecord(wr)
  else:
    recordPathProbe(cint(if callResult >= 0: 0 else: -1), cstring(p), 0, d)

proc classifyEmptyFdRead(fd: cint) {.raises: [].} =
  ## ROUND-3 S1c — a read on an fd with NO in-tree open record (`pathForFd` empty):
  ## an inherited / dup'd fd the monitored process never open(2)'d (e.g. `tool <
  ## input` redirected by an out-of-tree launcher, or process substitution).
  ## Resolve the fd:
  ##   * a REGULAR file or a CHAR/BLOCK device (stdin redirected from a file, a
  ##     dup'd fd, /dev/null, a tty) → recover the backing path via F_GETPATH,
  ##     record a CONTENT READ on it, and re-point the fd→path map so subsequent
  ##     reads take the fast path. NO downgrade — the real input is now named.
  ##   * a SOCKET / PIPE (FIFO/anonymous) → the source cannot be named. We emit an
  ##     opaque `mrExternalContent` marker (RECORD-not-downgrade): socket provenance
  ##     is owned by the IPC-connect machinery, which keeps intra-tree socket IPC
  ##     mcComplete and downgrades only an out-of-tree breakaway peer — so flagging
  ##     a downgrade here too would FALSE-FLAG every intra-tree socket/pipe exchange
  ##     (the cardinal sin). See writer.externalContentLossCount. Flagged ONCE per
  ##     fd so the hot read path stays cheap.
  ## The fstat + F_GETPATH are raw syscalls (reentrancy-free) and run ONLY on the
  ## empty-path branch (never on a normal in-tree read), so the hot path is intact.
  if fd < 0 or emptyFdAlreadyClassified(fd):
    return
  var dev, ino: uint64
  var kind: FdKind
  if not ct_macos_fd_dev_ino_kind(fd, addr dev, addr ino, addr kind):
    # fstat failed: cannot classify. Flag once so we do not retry per read.
    markEmptyFdClassified(fd)
    return
  case kind
  of fkRegular, fkCharDevice, fkBlockDevice:
    var buf: array[1024, char]
    if ct_macos_fd_real_path(fd, addr buf[0], csize_t(buf.len)) != 0:
      let resolved = $cast[cstring](addr buf[0])
      if resolved.len > 0:
        updateFdPath(fd, cstring(resolved))   # future reads take the fast path
        var record = baseRecord(mrFileRead, moFileRead)
        record.path = resolved
        record.result = 0
        record.flags = uint32(fd)
        record.detail = "inherited-fd"
        emitRecord(record)
        return
    # Unresolvable regular/device fd: flag once (do not re-stat every read).
    markEmptyFdClassified(fd)
  of fkSocket, fkFifo, fkOther:
    # Genuine out-of-tree content channel (an inherited socket or pipe whose peer
    # is outside the monitored tree). A named FIFO opened in-tree goes through the
    # open hook (recordFifoChannel) with its path, so reaching here means the fd
    # was INHERITED with no in-tree open — out-of-tree. Emit once.
    recordExternalContent("opaque", "read", "", fd)
    markEmptyFdClassified(fd)
  of fkDirectory:
    markEmptyFdClassified(fd)

proc recordFdRead(fd: cint; nbytes: int) {.raises: [].} =
  ## ROUND-3 S1c/S1d — shared content-read recorder for read/pread/preadv/readv/
  ## sendfile. When the fd has an in-tree open path, record a normal mrFileRead
  ## (the round-2 behaviour, now reused by the positioned/zero-copy reads so
  ## pread/readv/sendfile carry a file-READ, not just the file-open). When the path
  ## is EMPTY, classify the inherited/dup'd fd (resolve a real file, else downgrade
  ## an opaque source). Hot path: a single table lookup for the common in-tree fd.
  let p = pathForFd(fd)
  if p.len > 0:
    var record = baseRecord(mrFileRead, moFileRead)
    record.path = p
    record.result = nbytes.int64
    record.flags = uint32(fd)
    emitRecord(record)
  else:
    classifyEmptyFdRead(fd)

# --- ROUND-2 R-D (break R10) non-file determinism recorders -----------------
#
# THE NON-FILE OBSERVATION SPLIT (the crux — io-mon records evidence and leaves
# invalidation policy to callers). All four categories route through ONE shared
# per-process DEDUP
# (`recordObservedOnce`) so a HOT source (getenv, clock_gettime) records each
# DISTINCT key ONCE — cheap, bounded, muted:
#   1. env vars / sysctl / uname → OBSERVED DECLARED INPUTS (record, do NOT
#      downgrade). The consumer folds the queried value into its cache key
#      (BuildXL observed-environment model). Closes SOURCE_DATE_EPOCH / $CFLAGS /
#      hw.ncpu / uname PRECISELY — a benign PATH read just adds PATH to the key.
#   2. randomness (getentropy/arc4random*) → OBSERVED ENTROPY evidence. Caller
#      attribution avoids reporting the system-library startup baseline.
#   3. wall clock (clock_gettime/gettimeofday/time/mach_absolute_time) → OBSERVED
#      TIME evidence.

const
  # The shim's OWN monitoring / injection environment variables are NOT build
  # inputs (they are control vars the launcher sets per-run). Recording them as
  # observed inputs would fold a per-run injection path into the consumer's cache
  # key, busting the cache on EVERY run — effectively the cardinal sin via the
  # consumer. We therefore DENYLIST them (BuildXL likewise excludes its sandbox's
  # own control variables). A program legitimately reading DYLD_INSERT_LIBRARIES is
  # excluded too (our injection must never leak into the build's cache key).
  ObservedEnvDenylistPrefixes = [
    "REPRO_MONITOR_", "CT_SANDBOX_TOOLS_DIR", "IO_MON_",
    "DYLD_INSERT_LIBRARIES"]

proc isDenylistedEnvName(name: string): bool {.raises: [].} =
  for prefix in ObservedEnvDenylistPrefixes:
    if name.startsWith(prefix):
      return true
  false

proc recordObservedOnce(kind: MonitorRecordKind; obs: MonitorObservationKind;
    dedupKey, namePath, detail: string) {.raises: [].} =
  ## Shared per-process DEDUP + emit for the R-D records (DRY: one builder for all
  ## four categories). Records `dedupKey` ONCE per process; a repeat bails before
  ## emit (bounding the cost of a HOT source like getenv). The dedup set is bounded
  ## (ObservedInputCacheCap, cleared wholesale). The dedup lookup is done OUTSIDE
  ## emit so the emit's own muting does not interfere.
  if not initialized or fragmentDir.len == 0 or disabled > 0:
    return
  var fresh = false
  acquire(observedLock)
  if dedupKey notin seenObservedInputs:
    if seenObservedInputs.len >= ObservedInputCacheCap:
      seenObservedInputs.clear()
    seenObservedInputs.incl dedupKey
    fresh = true
  release(observedLock)
  if not fresh:
    return
  var record = baseRecord(kind, obs)
  record.path = namePath
  record.detail = detail
  emitRecord(record)

proc recordEnvRead(name: cstring) {.raises: [].} =
  ## Record a getenv query as an OBSERVED DECLARED INPUT (do NOT downgrade). The
  ## env-var NAME is recorded (deduped) so the CONSUMER folds the var's VALUE (or
  ## its absence) into the cache key — closing the SOURCE_DATE_EPOCH / $CFLAGS
  ## breaks precisely without over-re-running. The shim's own injection vars are
  ## denylisted (see ObservedEnvDenylistPrefixes).
  if name == nil or name[0] == '\0':
    return
  let n = $name
  if isDenylistedEnvName(n):
    return
  recordObservedOnce(mrEnvRead, moEnvRead, "env:" & n, n, "env-read")

proc recordSysctlRead(name: string) {.raises: [].} =
  ## Record a sysctl/uname/gethostname/gethostuuid query as an OBSERVED DECLARED
  ## INPUT (do NOT downgrade). `name` is the sysctl name ("hw.ncpu"), the integer
  ## MIB identity ("mib:6.5"), or the source ("uname"/"gethostname"/"gethostuuid").
  if name.len == 0:
    return
  recordObservedOnce(mrSysctlRead, moSysctlRead, "sysctl:" & name, name,
    "sysctl-read")

proc recordNonDeterministic(source: string) {.raises: [].} =
  ## Record the program's consumption of ENTROPY (getentropy/arc4random*) as
  ## policy evidence. This does not mean monitoring was incomplete; callers decide
  ## whether their cache/build policy invalidates on this observation.
  if source.len == 0:
    return
  recordObservedOnce(mrNonDeterministic, moNonDeterministic, "nd:" & source,
    source, "non-deterministic entropy source")

proc recordTimeRead(source: string) {.raises: [].} =
  ## Record a WALL-CLOCK read (clock_gettime/gettimeofday/time/mach_absolute_time)
  ## as a marker but DO NOT downgrade — almost every program reads a clock for
  ## benign timing whose value never reaches the output, so auto-downgrading would
  ## re-run everything (the cardinal sin). Deduped per process per source.
  if source.len == 0:
    return
  recordObservedOnce(mrTimeRead, moTimeRead, "time:" & source, source, "time-read")

# ROUND-2 R-D CARDINAL-SIN FIX — a /dev/urandom / /dev/random OPEN is DELIBERATELY
# NOT recorded as mrNonDeterministic. The original R-D flagged it on the premise
# that opening it signals intent to consume entropy. Measured against a real
# toolchain that premise is unsafe: a normal `cc`/`clang` compile opens /dev/urandom
# via `mktemp` (coreutils) to pick a RANDOM TEMP-FILE NAME — a build intermediate
# whose name never reaches the output — so treating a /dev/urandom open as an
# entropy observation would pollute essentially every build that uses a temp file.
# Caller-image attribution does not help here (mktemp is a non-system /nix/store
# binary opening it from its OWN code). The /dev/urandom open/read is STILL captured
# as a normal file dependency; we just do not treat it as a non-determinism
# downgrade. A program that embeds /dev/urandom bytes in its output is therefore a
# documented observation gap (it should use getentropy/arc4random, which ARE
# flagged, or declare the dependency) — far cheaper than the false positive.

proc repro_hook_open*(path: cstring; flags, mode: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_open(path, flags, mode)
  result = ct_macos_interpose_real_open(path, flags, mode)
  let savedErrno = getErrno()
  updateFdPath(result, path)
  recordOpen(result, path, flags, "")
  if result >= 0:
    recordDirectoryEnumeration(path)
    # ROUND-3 S2b — canonicalise EVERY successful open (read AND write) via
    # F_GETPATH, so a symlink/.vol target OR a relative-cwd OUTPUT is recorded
    # under its canonical absolute path and the fd→path map names the real file.
    # One cheap raw fcntl per open; the companion carries the open's own
    # observation kind so the write/read classification is preserved.
    recordCanonicalTarget(result, path, observationForOpen(flags))
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
    # ROUND-3 S2a/S2b — F_GETPATH on the resulting fd yields the canonical ABSOLUTE
    # path regardless of `dirfd`, closing the round-2 dirfd-relative residual for
    # BOTH read and write openat (r3_fd p_oat / p_oatw / p_normw): a dirfd-relative
    # input or output is now recorded under, and its fd mapped to, the real file.
    recordCanonicalTarget(result, path, observationForOpen(flags))
  setErrno(savedErrno)

proc repro_hook_read*(fd: cint; buf: pointer; count: csize_t): int {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_interpose_real_read(fd, buf, count)
  result = ct_macos_interpose_real_read(fd, buf, count)
  let savedErrno = getErrno()
  if result >= 0:
    # ROUND-3 S1c — recordFdRead names an in-tree fd's read normally and resolves /
    # downgrades an inherited empty-path fd (the F_GETPATH work runs ONLY on the
    # empty-path branch, so the common in-tree read stays a single table lookup).
    recordFdRead(fd, result)
  setErrno(savedErrno)

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

proc repro_hook_dup*(fd: cint): cint {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S2d — dup(2): the new fd refers to the SAME open file as `fd`. Mirror
  ## the source's path onto it so a read/write via the duplicate is attributed to
  ## the right file (r3_fd p_dup). Errno is preserved across the bookkeeping.
  if not initialized or disabled > 0:
    return ct_macos_real_dup(fd)
  result = ct_macos_real_dup(fd)
  let savedErrno = getErrno()
  if result >= 0:
    copyFdPath(fd, result)
  setErrno(savedErrno)

proc repro_hook_dup2*(oldfd, newfd: cint): cint {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S2d — dup2(2): `newfd` is closed (INTERNALLY in the kernel, bypassing
  ## the hooked close) and made to refer to `oldfd`'s file. copyFdPath clears the
  ## stale destination entry first, so a read of A via a swapped fd B is attributed
  ## to A, not B's old file (r3_fd p_dup2 / p_dup2swap). On success result == newfd.
  if not initialized or disabled > 0:
    return ct_macos_real_dup2(oldfd, newfd)
  result = ct_macos_real_dup2(oldfd, newfd)
  let savedErrno = getErrno()
  if result >= 0:
    copyFdPath(oldfd, result)
  setErrno(savedErrno)

proc repro_hook_fcntl*(fd, cmd: cint; arg: pointer): cint
    {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S2d — fcntl(2): hooked ONLY to catch the fd-DUPLICATION commands
  ## F_DUPFD / F_DUPFD_CLOEXEC (which return a NEW fd referring to `fd`'s file —
  ## r3_fd p_fdupfd). EVERY other command is forwarded and PASSED THROUGH untouched
  ## (the raw fcntl forwarder is faithful for all commands). The variadic third
  ## argument is read as a void* by the interpose thunk and forwarded verbatim.
  if not initialized or disabled > 0:
    return ct_macos_real_fcntl(fd, cmd, arg)
  result = ct_macos_real_fcntl(fd, cmd, arg)
  let savedErrno = getErrno()
  if result >= 0 and (cmd == FDupFd or cmd == FDupFdCloexec):
    copyFdPath(fd, result)
  setErrno(savedErrno)

# --- ROUND-3 S1 content-channel hooks (interpose-only, like connect/copyfile) ---
#
# These are thin libsystem wrappers over their syscalls, so each forwards via the
# RAW syscall (reentrancy-free, never re-enters its own interpose wrapper) and
# then records. They are INTERPOSE-only: build tools call getxattr/shm_open/
# sendfile/pread/readv DIRECTLY (not via shared-cache-internal libsystem paths the
# way fopen reaches read), so the interpose tuple captures the program's own calls
# and body-patching them would add early-init risk for no coverage gain — the same
# rationale as the connect / R-D hooks.

proc repro_hook_getxattr*(path, name: cstring; value: pointer; size: csize_t;
    position: uint32; options: cint): int {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a — getxattr(2): reads an extended-attribute VALUE (codesign /
  ## quarantine / ditto / custom build metadata). Recorded as a (resolved path,
  ## attr name, value length) dependency so a consumer folds the value into its key.
  if not initialized or disabled > 0:
    return ct_macos_real_getxattr(path, name, value, size, position, options)
  result = ct_macos_real_getxattr(path, name, value, size, position, options)
  let savedErrno = getErrno()
  recordXattr(result, path, name, (if result >= 0: result else: -1),
    isList = false, isWrite = false, detail = "")
  setErrno(savedErrno)

proc repro_hook_fgetxattr*(fd: cint; name: cstring; value: pointer;
    size: csize_t; position: uint32; options: cint): int
    {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a — fgetxattr(2): the fd variant. Resolve fd→path (the open's
  ## recorded path, else F_GETPATH) so the dependency names the real file.
  if not initialized or disabled > 0:
    return ct_macos_real_fgetxattr(fd, name, value, size, position, options)
  result = ct_macos_real_fgetxattr(fd, name, value, size, position, options)
  let savedErrno = getErrno()
  var p = pathForFd(fd)
  if p.len == 0:
    var buf: array[1024, char]
    if ct_macos_fd_real_path(fd, addr buf[0], csize_t(buf.len)) != 0:
      p = $cast[cstring](addr buf[0])
  if p.len > 0:
    recordXattr(result, cstring(p), name, (if result >= 0: result else: -1),
      isList = false, isWrite = false, detail = "fd")
  setErrno(savedErrno)

proc repro_hook_listxattr*(path: cstring; namebuf: pointer; size: csize_t;
    options: cint): int {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a — listxattr(2): a NAMESET dependency on the file (the output may
  ## branch on whether an attr is present, as in r3_xattr/list_read.c).
  if not initialized or disabled > 0:
    return ct_macos_real_listxattr(path, namebuf, size, options)
  result = ct_macos_real_listxattr(path, namebuf, size, options)
  let savedErrno = getErrno()
  recordXattr(result, path, nil, (if result >= 0: result else: -1),
    isList = true, isWrite = false, detail = "")
  setErrno(savedErrno)

proc repro_hook_flistxattr*(fd: cint; namebuf: pointer; size: csize_t;
    options: cint): int {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a — flistxattr(2): the fd variant of the nameset dependency.
  if not initialized or disabled > 0:
    return ct_macos_real_flistxattr(fd, namebuf, size, options)
  result = ct_macos_real_flistxattr(fd, namebuf, size, options)
  let savedErrno = getErrno()
  var p = pathForFd(fd)
  if p.len == 0:
    var buf: array[1024, char]
    if ct_macos_fd_real_path(fd, addr buf[0], csize_t(buf.len)) != 0:
      p = $cast[cstring](addr buf[0])
  if p.len > 0:
    recordXattr(result, cstring(p), nil, (if result >= 0: result else: -1),
      isList = true, isWrite = false, detail = "fd")
  setErrno(savedErrno)

proc repro_hook_setxattr*(path, name: cstring; value: pointer; size: csize_t;
    position: uint32; options: cint): cint {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a (output side) — setxattr(2) writes an xattr VALUE: an OUTPUT write
  ## on the file keyed on the attr name (so a build that emits a dep into an xattr
  ## is matchable too).
  if not initialized or disabled > 0:
    return ct_macos_real_setxattr(path, name, value, size, position, options)
  result = ct_macos_real_setxattr(path, name, value, size, position, options)
  let savedErrno = getErrno()
  recordXattr(int(result), path, name, int(size), isList = false,
    isWrite = true, detail = "xattr-set")
  setErrno(savedErrno)

proc repro_hook_fsetxattr*(fd: cint; name: cstring; value: pointer;
    size: csize_t; position: uint32; options: cint): cint
    {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a (output side) — fsetxattr(2): the fd variant.
  if not initialized or disabled > 0:
    return ct_macos_real_fsetxattr(fd, name, value, size, position, options)
  result = ct_macos_real_fsetxattr(fd, name, value, size, position, options)
  let savedErrno = getErrno()
  var p = pathForFd(fd)
  if p.len == 0:
    var buf: array[1024, char]
    if ct_macos_fd_real_path(fd, addr buf[0], csize_t(buf.len)) != 0:
      p = $cast[cstring](addr buf[0])
  if p.len > 0:
    recordXattr(int(result), cstring(p), name, int(size), isList = false,
      isWrite = true, detail = "xattr-set fd")
  setErrno(savedErrno)

proc repro_hook_removexattr*(path, name: cstring; options: cint): cint
    {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a (output side) — removexattr(2): an OUTPUT mutation of the file.
  if not initialized or disabled > 0:
    return ct_macos_real_removexattr(path, name, options)
  result = ct_macos_real_removexattr(path, name, options)
  let savedErrno = getErrno()
  recordXattr(int(result), path, name, -1, isList = false, isWrite = true,
    detail = "xattr-remove")
  setErrno(savedErrno)

proc repro_hook_fremovexattr*(fd: cint; name: cstring; options: cint): cint
    {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1a (output side) — fremovexattr(2): the fd variant.
  if not initialized or disabled > 0:
    return ct_macos_real_fremovexattr(fd, name, options)
  result = ct_macos_real_fremovexattr(fd, name, options)
  let savedErrno = getErrno()
  var p = pathForFd(fd)
  if p.len == 0:
    var buf: array[1024, char]
    if ct_macos_fd_real_path(fd, addr buf[0], csize_t(buf.len)) != 0:
      p = $cast[cstring](addr buf[0])
  if p.len > 0:
    recordXattr(int(result), cstring(p), name, -1, isList = false,
      isWrite = true, detail = "xattr-remove fd")
  setErrno(savedErrno)

proc repro_hook_shm_open*(name: cstring; oflag, mode: cint): cint
    {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1b — shm_open(3). An shm object NOT created in-tree (no in-tree
  ## shm_open(O_CREAT) for that name) is an OUT-OF-TREE content source the merge
  ## downgrades on; a self-produced shm (create AND consume in-tree) is paired and
  ## stays mcComplete (the cardinal-sin guard). See recordShmOpen.
  if not initialized or disabled > 0:
    return ct_macos_real_shm_open(name, oflag, mode)
  result = ct_macos_real_shm_open(name, oflag, mode)
  let savedErrno = getErrno()
  recordShmOpen(result, name, oflag)
  setErrno(savedErrno)

proc repro_hook_sendfile*(fd, s: cint; offset: int64; len: ptr int64;
    hdtr: pointer; flags: cint): cint {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1d — sendfile(2) zero-copy: the kernel reads the SOURCE fd's content
  ## (arg 1) and writes it to the socket with NO read(2). Record a content read on
  ## the source so its classification matches a normal read (today the source left
  ## only its open record). research/.../r3_channel/probeB_sendfile.c.
  if not initialized or disabled > 0:
    return ct_macos_real_sendfile(fd, s, offset, len, hdtr, flags)
  result = ct_macos_real_sendfile(fd, s, offset, len, hdtr, flags)
  let savedErrno = getErrno()
  if result == 0:
    let moved = if len != nil: int(len[]) else: 0
    recordFdRead(fd, moved)
  setErrno(savedErrno)

proc repro_hook_pread*(fd: cint; buf: pointer; count: csize_t;
    offset: int64): int {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1d — pread(2) positioned read: content via the source fd with NO
  ## read(2). Record an mrFileRead on the fd's path (probeA_pread.c).
  if not initialized or disabled > 0:
    return ct_macos_real_pread(fd, buf, count, offset)
  result = ct_macos_real_pread(fd, buf, count, offset)
  let savedErrno = getErrno()
  if result >= 0:
    recordFdRead(fd, result)
  setErrno(savedErrno)

proc repro_hook_preadv*(fd: cint; iov: pointer; iovcnt: cint;
    offset: int64): int {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1d — preadv(2): positioned scatter read.
  if not initialized or disabled > 0:
    return ct_macos_real_preadv(fd, iov, iovcnt, offset)
  result = ct_macos_real_preadv(fd, iov, iovcnt, offset)
  let savedErrno = getErrno()
  if result >= 0:
    recordFdRead(fd, result)
  setErrno(savedErrno)

proc repro_hook_readv*(fd: cint; iov: pointer; iovcnt: cint): int
    {.exportc, cdecl, dynlib.} =
  ## ROUND-3 S1d — readv(2): scatter read (NOT the hooked read(2)). probeA_pread.c.
  if not initialized or disabled > 0:
    return ct_macos_real_readv(fd, iov, iovcnt)
  result = ct_macos_real_readv(fd, iov, iovcnt)
  let savedErrno = getErrno()
  if result >= 0:
    recordFdRead(fd, result)
  setErrno(savedErrno)

proc repro_hook_mmap*(adr: pointer; length: csize_t; prot, flags, fd: cint;
    offset: int64): pointer {.exportc, cdecl, dynlib.} =
  ## ROUND-2 R9 — the output-via-memory blind spot. A file modified through a
  ## MAP_SHARED|PROT_WRITE mapping changes content with NO write(2) syscall, so the
  ## round-1 hook set saw only the open. We forward via the inline-asm BSD mmap
  ## syscall (full 64-bit return, allocation-free) then classify the mapping (see
  ## recordMmap): a MAP_SHARED|PROT_WRITE file mapping is recorded as a content
  ## WRITE on the fd's path; read-only/private/anonymous mappings are intentionally
  ## NOT recorded (the open already covers a read mapping — no double-record).
  ##
  ## mmap is INTERPOSE-only (not body-patched): build tools call mmap directly, so
  ## the __interpose tuple sees the program's own MAP_SHARED writes; mmap is also a
  ## very hot, early-init libsystem entry (dyld/malloc map heavily before main), so
  ## body-patching it would add early-init risk for no coverage gain.
  ##
  ## RE-ENTRANCY (critical): the recording path (recordMmap → baseRecord/emitRecord)
  ## ALLOCATES, and malloc mmaps, so a naive hook would re-enter itself and recurse
  ## to a stack-overflow crash. `inMmapHook` (a thread-local depth) makes any mmap
  ## issued WHILE recording take the plain forward (no record), so the outer call
  ## records exactly once and the inner allocations just map. The global `disabled`
  ## guard is NOT reused for this because emitRecord bails when disabled>0 (it would
  ## suppress the very record we want); `inMmapHook` gates ONLY the re-entry.
  if not initialized or disabled > 0 or inMmapHook > 0:
    return ct_macos_real_mmap(adr, length, prot, flags, fd, offset)
  inc inMmapHook
  result = ct_macos_real_mmap(adr, length, prot, flags, fd, offset)
  let savedErrno = getErrno()
  recordMmap(result, prot, flags, fd)
  setErrno(savedErrno)
  dec inMmapHook

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
# WHY the forward MUST bypass the named entry: body-patch (always installed by
# default) REPLACES the named stat/lstat/fstatat/access entry points. If this
# hook forwarded via the by-name real (ct_macos_interpose_real_stat, which
# resolves the symbol with dlsym / NSLookupSymbolInImage), the resolved address
# would BE the body-patched entry → the call would re-enter THIS hook → the
# record would be emitted TWICE (the double-processing bug). Forwarding via the
# raw syscall reaches the kernel directly, so a given stat() records EXACTLY ONCE
# regardless of which mechanism's entry it arrived through and never re-enters.
# The *64 syscall variants fill the modern 64-bit-inode `struct stat` the caller
# expects (see macos_interpose_runtime.nim).

proc repro_hook_stat*(path: cstring; buf: pointer): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_stat(path, buf)
  result = ct_macos_bodypatch_real_stat(path, buf)
  let savedErrno = getErrno()
  # ROUND-2 R4 — record the as-passed probe (with (dev, ino)) AND, when the raw
  # path is non-canonical, a companion probe on the realpath form. stat()'s path
  # resolves against the CWD, exactly as realpath does, so both absolute and
  # relative (post-chdir) paths canonicalise correctly.
  let dino = statDetail("", buf, result == 0)
  recordPathProbe(result, path, 0, dino)
  recordCanonicalPathProbe(result, path, 0, dino)
  setErrno(savedErrno)

proc repro_hook_lstat*(path: cstring; buf: pointer): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_lstat(path, buf)
  result = ct_macos_bodypatch_real_lstat(path, buf)
  let savedErrno = getErrno()
  let dino = statDetail("", buf, result == 0)
  recordPathProbe(result, path, 0, dino)
  # If the lstat'd object IS a symlink, also record its resolved target so
  # editing the target (while the link is unchanged) stays a visible dependency
  # (findings doc break #7 / mcapSymlink). Gated on S_ISLNK so realpath is only
  # paid for actual symlinks, never the stat-probe storm.
  if result == 0 and ct_macos_stat_is_symlink(buf):
    recordCanonicalProbe(result, path)
  else:
    # ROUND-2 R4 — for a non-symlink lstat, the canonical-companion (a mid-path
    # symlink, case-fold, `.`/`..`) is still relevant; recordCanonicalProbe already
    # covered the symlink-leaf case above, so avoid emitting it twice.
    recordCanonicalPathProbe(result, path, 0, dino)
  setErrno(savedErrno)

proc repro_hook_fstatat*(dirfd: cint; path: cstring; buf: pointer;
    flag: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_fstatat(dirfd, path, buf, flag)
  result = ct_macos_bodypatch_real_fstatat(dirfd, path, buf, flag)
  let savedErrno = getErrno()
  let dino = statDetail("fstatat dirfd=" & $dirfd, buf, result == 0)
  recordPathProbe(result, path, 0, dino)
  # ROUND-3 S2a — canonicalise for ABSOLUTE / AT_FDCWD paths (realpath against the
  # CWD) AND for the dirfd-RELATIVE case (resolve the dirfd via F_GETPATH, join,
  # realpath), closing the round-2 residual where a dirfd-relative fstatat recorded
  # only the bare relative component.
  recordCanonicalAtProbe(result, dirfd, path, 0, dino)
  setErrno(savedErrno)

proc repro_hook_access*(path: cstring; mode: cint): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_bodypatch_real_access(path, mode)
  result = ct_macos_bodypatch_real_access(path, mode)
  let savedErrno = getErrno()
  # access has no stat buffer, so no (dev, ino) is available — record the raw
  # probe and, on success, the canonical companion (ROUND-2 R4).
  recordPathProbe(result, path, mode, "")
  recordCanonicalPathProbe(result, path, mode, "")
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

# --- Unified clonefile / link / copyfile hooks (content dependency, #3) ---
#
# Each forwards via the body-patch-safe path (raw syscall for clonefile/link;
# the resolved genuine libsystem entry for copyfile — copyfile is interpose-only
# and never body-patched, see its forwarder doc) and classifies the SOURCE as a
# content read + the DESTINATION as an output write.

proc repro_hook_clonefile*(src, dst: cstring; flags: cint): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_clonefile(src, dst, flags)
  result = ct_macos_real_clonefile(src, dst, flags)
  let savedErrno = getErrno()
  recordContentCopy(result, $src, $dst, "clonefile")
  setErrno(savedErrno)

proc repro_hook_clonefileat*(srcfd: cint; src: cstring; dstfd: cint;
    dst: cstring; flags: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_clonefileat(srcfd, src, dstfd, dst, flags)
  result = ct_macos_real_clonefileat(srcfd, src, dstfd, dst, flags)
  let savedErrno = getErrno()
  recordContentCopy(result, $src, $dst,
    "clonefileat srcfd=" & $srcfd & " dstfd=" & $dstfd)
  setErrno(savedErrno)

proc repro_hook_fclonefileat*(srcfd, dstfd: cint; dst: cstring;
    flags: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_fclonefileat(srcfd, dstfd, dst, flags)
  result = ct_macos_real_fclonefileat(srcfd, dstfd, dst, flags)
  let savedErrno = getErrno()
  # The source is named only by fd; record its mapped path (empty ⇒ skipped).
  recordContentCopy(result, pathForFd(srcfd), $dst, "fclonefileat srcfd=" & $srcfd)
  setErrno(savedErrno)

proc repro_hook_link*(src, dst: cstring): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_link(src, dst)
  result = ct_macos_real_link(src, dst)
  let savedErrno = getErrno()
  recordContentCopy(result, $src, $dst, "link")
  setErrno(savedErrno)

proc repro_hook_linkat*(fd1: cint; src: cstring; fd2: cint; dst: cstring;
    flag: cint): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_linkat(fd1, src, fd2, dst, flag)
  result = ct_macos_real_linkat(fd1, src, fd2, dst, flag)
  let savedErrno = getErrno()
  recordContentCopy(result, $src, $dst, "linkat fd1=" & $fd1 & " fd2=" & $fd2)
  setErrno(savedErrno)

proc repro_hook_copyfile*(src, dst: cstring; state: pointer;
    flags: uint32): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_copyfile(src, dst, state, flags)
  result = ct_macos_real_copyfile(src, dst, state, flags)
  let savedErrno = getErrno()
  if (flags and (CopyfileClone or CopyfileCloneForce)) != 0:
    recordContentCopy(result, $src, $dst, "copyfile-clone")
  setErrno(savedErrno)

proc repro_hook_fcopyfile*(srcfd, dstfd: cint; state: pointer;
    flags: uint32): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_fcopyfile(srcfd, dstfd, state, flags)
  result = ct_macos_real_fcopyfile(srcfd, dstfd, state, flags)
  let savedErrno = getErrno()
  if (flags and (CopyfileClone or CopyfileCloneForce)) != 0:
    recordContentCopy(result, pathForFd(srcfd), pathForFd(dstfd),
      "fcopyfile srcfd=" & $srcfd & " dstfd=" & $dstfd)
  setErrno(savedErrno)

# --- Unified getattrlist-family hooks (path-probe, break #5) -------------
# getattrlist/getattrlistat/fgetattrlist are an existence+metadata probe with NO
# stat record, so a tool that checks "does this exist / what is its mtime" via
# them hides the dependency. Classify as a path-probe (like stat). Each forwards
# via the RAW syscall, bypassing any body-patched named entry.

proc repro_hook_getattrlist*(path: cstring; al, buf: pointer; size: csize_t;
    opts: culong): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_getattrlist(path, al, buf, size, opts)
  result = ct_macos_real_getattrlist(path, al, buf, size, opts)
  let savedErrno = getErrno()
  recordPathProbe(result, path, 0, "getattrlist")
  setErrno(savedErrno)

proc repro_hook_getattrlistat*(fd: cint; path: cstring; al, buf: pointer;
    size: csize_t; opts: culong): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_getattrlistat(fd, path, al, buf, size, opts)
  result = ct_macos_real_getattrlistat(fd, path, al, buf, size, opts)
  let savedErrno = getErrno()
  let d = "getattrlistat dirfd=" & $fd
  recordPathProbe(result, path, 0, d)
  # ROUND-3 S2a — same canonical companion as fstatat (absolute/AT_FDCWD via the
  # CWD, dirfd-relative via F_GETPATH+realpath), so a dirfd-relative getattrlistat
  # metadata probe is matchable against a canonical cache key.
  recordCanonicalAtProbe(result, fd, path, 0, d)
  setErrno(savedErrno)

proc repro_hook_fgetattrlist*(fd: cint; al, buf: pointer; size: csize_t;
    opts: culong): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_fgetattrlist(fd, al, buf, size, opts)
  result = ct_macos_real_fgetattrlist(fd, al, buf, size, opts)
  let savedErrno = getErrno()
  let p = pathForFd(fd)
  if p.len > 0:
    recordPathProbe(result, cstring(p), 0, "fgetattrlist fd=" & $fd)
  setErrno(savedErrno)

# --- Per-entry directory enumeration (getattrlistbulk / getdirentries) ---
# The libsystem-wrapper call sites are reachable; a program issuing the RAW
# getdirentries64 syscall inline is the structurally-unfixable raw-syscall gap
# (#6). Records the dir as enumerated (per-child parsing deferred — see
# recordDirEnumByFd).

proc repro_hook_getattrlistbulk*(dirfd: cint; al, buf: pointer; size: csize_t;
    opts: uint64): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_getattrlistbulk(dirfd, al, buf, size, opts)
  result = ct_macos_real_getattrlistbulk(dirfd, al, buf, size, opts)
  if result > 0:
    recordDirEnumByFd(dirfd, "getattrlistbulk")

proc repro_hook_getdirentries*(fd: cint; buf: pointer; nbytes: cint;
    basep: ptr clong): cint {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_getdirentries(fd, buf, nbytes, basep)
  result = ct_macos_real_getdirentries(fd, buf, nbytes, basep)
  if result > 0:
    recordDirEnumByFd(fd, "getdirentries")

# --- Unified connect hook (IPC / breakaway detection, T3a / break #1) -----
# There is exactly ONE connect hook, used by BOTH the static __DATA,__interpose
# tuple AND the body-patch install. connect is a thin syscall wrapper, so — like
# the stat/rename/clonefile families — the hook forwards via the RAW SYS_connect
# syscall (ct_macos_real_connect), bypassing any body-patched libsystem `connect`
# entry so a single connect records EXACTLY ONCE and never re-enters the patch.

proc repro_hook_connect*(fd: cint; address: pointer; addrLen: uint32): cint
    {.exportc, cdecl, dynlib.} =
  if not initialized or disabled > 0:
    return ct_macos_real_connect(fd, address, addrLen)
  result = ct_macos_real_connect(fd, address, addrLen)
  let savedErrno = getErrno()
  # Record an ESTABLISHED connection (result == 0 — the blocking daemon/sccache
  # case) or an in-flight NON-BLOCKING one (result < 0 && EINPROGRESS — the
  # connection will complete asynchronously; the peer pid may not be resolvable
  # yet, which the merge treats conservatively as out-of-tree). A hard failure
  # (ECONNREFUSED, …) reached no peer and is NOT recorded.
  if result == 0 or (result < 0 and savedErrno == EInProgress):
    recordIpcConnect(fd, address, addrLen, result)
  setErrno(savedErrno)

# --- XPC / Mach-port breakaway hooks (R-C, round-2 break R2) --------------
# XPC and raw Mach RPC bottom out in mach_msg to launchd's bootstrap port and
# NEVER call connect(2), so the connect hook above is blind to a monitored
# client that delegates a file read to an out-of-tree Mach/XPC service (the
# confirmed r2_xpc break). We hook the cheap connection-establishment boundary —
# bootstrap_look_up (raw-Mach clients) and xpc_connection_create_mach_service
# (the XPC client entry) — NOT the hot mach_msg send path. Both are
# INTERPOSE-ONLY (not body-patched): the program's own direct call to either is
# caught by the __interpose tuple; a shared-cache-INTERNAL bootstrap_look_up
# (e.g. a framework that internally brokers an XPC connection) is a documented
# residual for the EndpointSecurity backend (T3c). Each forwards via the GENUINE
# libsystem entry (resolved through the shim-skipping image walk), never a
# by-name call that could re-enter the shim's own interpose binding.

proc repro_hook_bootstrap_look_up*(bp: uint32; serviceName: cstring;
    sp: ptr uint32): cint {.exportc, cdecl, dynlib.} =
  ## bootstrap_look_up hook (R-C): a raw-Mach client resolving a service name to a
  ## send port. Record only a SUCCESSFUL lookup (KERN_SUCCESS == 0 and a non-null
  ## returned port) of a NON-`com.apple.*` service as an out-of-tree breakaway
  ## (see recordMachLookup / the cardinal-sin filter). A failed lookup reached no
  ## peer and is not recorded.
  if not initialized or disabled > 0:
    return ct_macos_real_bootstrap_look_up(bp, serviceName, sp)
  result = ct_macos_real_bootstrap_look_up(bp, serviceName, sp)
  let savedErrno = getErrno()
  if result == 0 and sp != nil and sp[] != 0'u32:
    recordMachLookup(serviceName, result)
  setErrno(savedErrno)

const
  # XPC_CONNECTION_MACH_SERVICE_LISTENER (<xpc/connection.h>, 1<<0): the SERVER
  # side — a monitored process OFFERING a mach service, not delegating a read to
  # one. A listener is not a breakaway-via-delegation, so it is NOT recorded
  # (recording it could falsely downgrade a monitored tool that hosts a service).
  XpcMachServiceListener = 1'u64

proc repro_hook_xpc_connection_create_mach_service*(name: cstring;
    targetq: pointer; flags: uint64): pointer {.exportc, cdecl, dynlib.} =
  ## xpc_connection_create_mach_service hook (R-C): the XPC CLIENT entry. XPC sits
  ## on Mach, but modern libxpc resolves the service via an internal
  ## (shared-cache) lookup path that the interposed `bootstrap_look_up` does not
  ## see, so we hook the XPC create entry directly. We record the INTENT to talk
  ## to a non-system mach service at connection-create time (the connection is
  ## lazy; recording at create is conservative — write-intent style — and cannot
  ## miss a later send). A successful create returns a non-nil xpc_connection_t.
  ## A LISTENER connection (the server role) is skipped (see XpcMachServiceListener).
  if not initialized or disabled > 0:
    return ct_macos_real_xpc_create_mach_service(name, targetq, flags)
  result = ct_macos_real_xpc_create_mach_service(name, targetq, flags)
  if result != nil and (flags and XpcMachServiceListener) == 0:
    recordMachLookup(name, 0)

# --- ROUND-2 R-D (break R10) non-file determinism hooks -------------------
#
# All INTERPOSE-ONLY (NOT body-patched). This is DELIBERATE and is the heart of
# the cardinal-sin guard for the randomness arm: interpose sees ONLY the
# program's OWN direct call (an import-stub crossing), never a libsystem-INTERNAL
# one. So malloc's internal arc4random (zone cookies), stack-guard setup, mktemp,
# and DNS query-id randomness — all direct intra-dylib calls inside libsystem —
# are NEVER misattributed to the program. Each hook forwards via the genuine
# libsystem entry (ct_macos_real_*, resolved shim-skipping) so it never re-enters
# its own wrapper, then routes through the deduped recorder. errno is preserved
# around the recording for the functions that report via errno.

proc repro_hook_getenv*(name: cstring): cstring {.exportc, cdecl, dynlib.} =
  ## Observed declared input (env). Forwards via the genuine getenv (environ walk)
  ## then records the queried NAME (deduped, denylisted). Does NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_getenv(name)
  result = ct_macos_real_getenv(name)
  let savedErrno = getErrno()
  recordEnvRead(name)
  setErrno(savedErrno)

proc repro_hook_sysctlbyname*(name: cstring; oldp: pointer; oldlenp: ptr csize_t;
    newp: pointer; newlen: csize_t): cint {.exportc, cdecl, dynlib.} =
  ## Observed declared input (sysctl by name, e.g. "hw.ncpu"). Does NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_sysctlbyname(name, oldp, oldlenp, newp, newlen)
  result = ct_macos_real_sysctlbyname(name, oldp, oldlenp, newp, newlen)
  let savedErrno = getErrno()
  if name != nil:
    recordSysctlRead($name)
  setErrno(savedErrno)

proc repro_hook_sysctl*(name: ptr cint; namelen: cuint; oldp: pointer;
    oldlenp: ptr csize_t; newp: pointer; newlen: csize_t): cint
    {.exportc, cdecl, dynlib.} =
  ## Observed declared input (integer-MIB sysctl form). The MIB ints are rendered
  ## to a stable "mib:6.5" identity for the cache key. Does NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
  result = ct_macos_real_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
  let savedErrno = getErrno()
  var buf: array[128, char]
  if ct_macos_sysctl_mib_describe(name, namelen, addr buf[0],
      csize_t(buf.len)) > 0:
    recordSysctlRead($cast[cstring](addr buf[0]))
  setErrno(savedErrno)

proc repro_hook_uname*(buf: pointer): cint {.exportc, cdecl, dynlib.} =
  ## Observed declared input (machine config). Does NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_uname(buf)
  result = ct_macos_real_uname(buf)
  let savedErrno = getErrno()
  recordSysctlRead("uname")
  setErrno(savedErrno)

proc repro_hook_gethostname*(name: cstring; namelen: csize_t): cint
    {.exportc, cdecl, dynlib.} =
  ## Observed declared input (host identity). Does NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_gethostname(name, namelen)
  result = ct_macos_real_gethostname(name, namelen)
  let savedErrno = getErrno()
  recordSysctlRead("gethostname")
  setErrno(savedErrno)

proc repro_hook_gethostuuid*(uuid: pointer; timeout: pointer): cint
    {.exportc, cdecl, dynlib.} =
  ## Observed declared input (host uuid). Does NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_gethostuuid(uuid, timeout)
  result = ct_macos_real_gethostuuid(uuid, timeout)
  let savedErrno = getErrno()
  recordSysctlRead("gethostuuid")
  setErrno(savedErrno)

# ROUND-2 R-D CARDINAL-SIN FIX — the entropy hooks emit policy evidence, so false
# positives still matter. The original "interpose only sees the
# program's own call" premise was WRONG: /usr/lib/libobjc, /usr/lib/swift,
# /usr/lib/system/libsystem_malloc / _trace call arc4random_buf and
# /usr/lib/system/libcorecrypto calls getentropy on EVERY process startup, all
# cross-dylib (so they DO cross the interpose stub) — which downgraded every real
# program. We therefore
# ATTRIBUTE each entropy call to its CALLER (the `caller` return address the C
# wrapper passes via __builtin_return_address) and flag ONLY when the caller lies in
# a NON-SYSTEM image's __TEXT. The benign libsystem/libobjc/libswift baseline lands
# in a system dylib and is excluded; the program's own (or its plugins'/toolchain
# dylibs') direct arc4random/getentropy is still recorded. The check is a pure
# pointer-range scan (ct_macos_addr_in_nonsystem) — these hooks fire UNDER dyld's
# loader lock during image init, where a dladdr-based check would risk re-entering
# dyld; a range scan touches no dyld/malloc/lock and is re-entry-safe.
#
# ROUND-3 S3b — the attribution was WIDENED from main-exe-only
# (ct_macos_addr_in_program) to ANY NON-SYSTEM image (ct_macos_addr_in_nonsystem):
# a dlopen'd compiler pass-plugin or a non-system toolchain dylib that draws entropy
# and bakes it into output (research/.../res1_dylib_entropy) is now flagged too,
# closing the round-2 documented false-negative. The non-system image __TEXT ranges
# are pre-registered from the dyld add-image hook (the SAME classification the
# library-load filter uses), so the hot path stays a pure range scan.

proc repro_hook_getentropy*(buf: pointer; len: csize_t; caller: pointer): cint
    {.exportc, cdecl, dynlib.} =
  ## NON-DETERMINISM (entropy) evidence, but ONLY for the program's own use
  ## (ROUND-3 S3b: caller in ANY non-system image — the main exe OR a dylib/plugin).
  ## Forward genuine, conditionally flag.
  if not initialized or disabled > 0:
    return ct_macos_real_getentropy(buf, len)
  result = ct_macos_real_getentropy(buf, len)
  let savedErrno = getErrno()
  if ct_macos_addr_in_nonsystem(caller):
    recordNonDeterministic("getentropy")
  setErrno(savedErrno)

proc repro_hook_arc4random*(caller: pointer): cuint {.exportc, cdecl, dynlib.} =
  ## NON-DETERMINISM (entropy) evidence for the program's own use only.
  if not initialized or disabled > 0:
    return ct_macos_real_arc4random()
  result = ct_macos_real_arc4random()
  if ct_macos_addr_in_nonsystem(caller):
    recordNonDeterministic("arc4random")

proc repro_hook_arc4random_buf*(buf: pointer; n: csize_t; caller: pointer)
    {.exportc, cdecl, dynlib.} =
  ## NON-DETERMINISM (entropy) evidence for the program's own use only. The
  ## shim's OWN nonce randomness bypasses this wrapper (repro_macos_random_u64
  ## resolves the genuine entry); the libsystem/libobjc/libswift startup baseline is
  ## excluded by the caller-image check (its caller is in /usr/lib).
  if not initialized or disabled > 0:
    ct_macos_real_arc4random_buf(buf, n)
    return
  ct_macos_real_arc4random_buf(buf, n)
  if ct_macos_addr_in_nonsystem(caller):
    recordNonDeterministic("arc4random_buf")

proc repro_hook_arc4random_uniform*(upper: cuint; caller: pointer): cuint
    {.exportc, cdecl, dynlib.} =
  ## NON-DETERMINISM (entropy) evidence for the program's own use only.
  if not initialized or disabled > 0:
    return ct_macos_real_arc4random_uniform(upper)
  result = ct_macos_real_arc4random_uniform(upper)
  if ct_macos_addr_in_nonsystem(caller):
    recordNonDeterministic("arc4random_uniform")

proc repro_hook_clock_gettime*(clk: cint; ts: pointer): cint
    {.exportc, cdecl, dynlib.} =
  ## WALL-CLOCK read — RECORD but do NOT downgrade (the cardinal-sin guard: almost
  ## every program times a loop benignly). The shim's own monoNowNs clock reads run
  ## under `disabled` (during emit), so they forward without recording.
  if not initialized or disabled > 0:
    return ct_macos_real_clock_gettime(clk, ts)
  result = ct_macos_real_clock_gettime(clk, ts)
  let savedErrno = getErrno()
  recordTimeRead("clock_gettime")
  setErrno(savedErrno)

proc repro_hook_gettimeofday*(tp: pointer; tzp: pointer): cint
    {.exportc, cdecl, dynlib.} =
  ## WALL-CLOCK read — RECORD but do NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_gettimeofday(tp, tzp)
  result = ct_macos_real_gettimeofday(tp, tzp)
  let savedErrno = getErrno()
  recordTimeRead("gettimeofday")
  setErrno(savedErrno)

proc repro_hook_time*(tloc: pointer): clonglong {.exportc, cdecl, dynlib.} =
  ## WALL-CLOCK read — RECORD but do NOT downgrade.
  if not initialized or disabled > 0:
    return ct_macos_real_time(tloc)
  result = ct_macos_real_time(tloc)
  let savedErrno = getErrno()
  recordTimeRead("time")
  setErrno(savedErrno)

# NOTE: mach_absolute_time is intentionally NOT hooked — libdispatch calls it
# cross-dylib during early libSystem init (a not-ready forward hazard with no safe
# raw-syscall path), and it is a monotonic tick counter rather than a wall clock,
# so it is almost never baked into a build's output. See the runtime C note (R-D).

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
# Forwarding constraint (WHY each hook bypasses the named entry): body-patch
# (always installed by default) has REPLACED the named
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
  # ROUND-3 S2c — ALSO record the SYMLINK/realpath-RESOLVED launched binary's BYTES
  # as a CONTENT read. execve records `path` verbatim, so `execve("/dir/tool_link",
  # …)` where tool_link→tool named only the LINK; swapping the real binary's bytes
  # (toolchain wrapper symlinks, busybox-style multi-call dispatch, /usr/bin
  # symlinks) was invisible → a false skip (r3_fd p_symexec). canonicalPathFor
  # realpath-resolves the path (returns "" when already canonical or unresolvable —
  # e.g. a non-existent / PATH-searched name — so no spurious companion).
  #
  # It is recorded as mrFileRead/moFileRead (the launched binary's CONTENT is the
  # dependency — mirroring recordLibraryLoad), DELIBERATELY NOT a second
  # mrProcessExec: a duplicate process-exec for this pid would inflate the merge's
  # exec-coverage count (writer.unmonitoredSubtreeLossCount case (b)) and FALSELY
  # downgrade a normal compile to mcIncomplete (the cardinal sin — observed). A
  # content read participates in no process-tree check, so completeness is unchanged
  # while the binary's bytes bust the cache on a content swap. Emitted BEFORE the
  # flush below because execve does not return on success. (fexecve/execveat do not
  # exist on macOS and /dev/fd/N exec fails natively, so the symlink is the live
  # Darwin vector.)
  if path != nil:
    let canonical = canonicalPathFor($path)
    if canonical.len > 0:
      var resolved = baseRecord(mrFileRead, moFileRead)
      resolved.result = 0
      resolved.path = canonical
      resolved.detail = "execve resolved-target"
      emitRecord(resolved)
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
  ## re-invocation lands back in this hook.
  ##
  ## Under the body-patch backend the re-entry MUST forward through the TRAMPOLINE
  ## (which holds the relocated original prologue and jumps PAST the patch) — the
  ## only genuinely re-entry-free path. The by-name "real" forwarder
  ## (ct_macos_interpose_real_posix_spawn) is NOT safe here: body-patch overwrites
  ## the libsystem posix_spawn body IN PLACE, so a by-name forward resolves the
  ## patched entry and loops back into this hook forever (observed as a
  ## spawn-hook <-> repro_macos_real_posix_spawn infinite recursion). The by-name
  ## path is reserved for the INTERPOSE-ONLY backend, where the named symbol is
  ## unpatched and dyld's __interpose tuples do not apply to the shim's own
  ## image-local lookup. The depth counter still gates env/path rewriting and the
  ## spawn record to the OUTERMOST (depth-0) forward, so the internal
  ## re-invocation is forwarded verbatim and recorded exactly once.

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
  if tramp == nil:
    # Interpose-only backend: the named ``posix_spawn`` symbol is NOT patched,
    # and dyld's __interpose tuples do not apply to the shim's OWN image-local
    # lookup, so the by-name real forwarder reaches the genuine libsystem entry
    # and is re-entry-free. (Pre-rewrite is skipped here: the by-name forwarder
    # rewrites env+path itself, exactly once.)
    result = byName(pid, path, fileActions, attrp, argv, envp)
  else:
    # Body-patch active (``both`` / ``bodypatch``). The libsystem ``posix_spawn``
    # body is patched IN PLACE, so the by-name "real" forwarder is NOT re-entry
    # free under this backend — it resolves the patched entry and loops back into
    # this hook forever (observed as a spawn-hook ↔ ``repro_macos_real_posix_spawn``
    # infinite recursion). The TRAMPOLINE (which holds the relocated original
    # prologue and jumps PAST the patch) is the only re-entry-free path into the
    # original marshalling body, so BOTH the outermost forward AND any in-flight
    # re-entry must go through it. The ``inSpawnForward`` depth still gates env+
    # path rewriting to EXACTLY ONCE (outermost only): the original body re-invokes
    # the public symbol internally, and that internal re-invocation must forward
    # the already-rewritten env/path verbatim rather than rewrite again.
    inc inSpawnForward
    try:
      if outermost:
        var effectiveEnvp: cstringArray = nil
        let effectivePath =
          ct_macos_bodypatch_spawn_rewrite(path, envp, addr effectiveEnvp)
        result = ct_macos_bodypatch_call_posix_spawn(tramp, pid, effectivePath,
          fileActions, attrp, argv, effectiveEnvp)
      else:
        # Internal re-invocation of the already-rewritten spawn: forward verbatim
        # through the trampoline (no second rewrite, no re-entry into the patch).
        result = ct_macos_bodypatch_call_posix_spawn(tramp, pid, path,
          fileActions, attrp, argv, envp)
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
  ## the trampoline at depth 0 forever; with it, the re-entry stays on the
  ## trampoline (the only re-entry-free path under body-patch — the by-name real
  ## resolves the IN-PLACE patched entry and would loop). Only the interpose-only
  ## backend (``tramp == nil``) uses the by-name path, where the named symbol is
  ## unpatched and the forward is genuinely re-entry-free (mirrors the unmuted
  ## core, DRY).
  if tramp != nil:
    let outermost = inSpawnForward == 0
    if outermost: inc inSpawnForward
    try:
      result = ct_macos_bodypatch_call_posix_spawn(tramp, pid, path,
        fileActions, attrp, argv, envp)
    finally:
      if outermost: dec inSpawnForward
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
  # A POSIX_SPAWN_SETEXEC spawn re-images THIS process and never returns on
  # success — record + flush the exec BEFORE forwarding (break #2).
  recordSetexecExec(attrp, path)
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
  recordSetexecExec(attrp, path)
  let detail =
    if bodypatchPosixSpawnpTramp != nil and inSpawnForward == 0:
      "bodypatch-posix_spawnp"
    else:
      "posix_spawnp"
  spawnForward(bodypatchPosixSpawnpTramp, pid, path, fileActions, attrp,
    argv, envp, ct_macos_interpose_real_posix_spawnp, detail)

proc reproRuntimeInit() {.exportc.} =
  discard repro_monitor_shim_init(nil)

# --- Monitoring mechanisms + DEBUG-ONLY per-mechanism diagnostic toggles ---
#
# On macOS the shim ALWAYS runs BOTH monitoring mechanisms by default — there is
# NO user-facing backend selector:
#   * interpose  — the static `__DATA,__interpose` section is linked into the
#                  shim unconditionally (it cannot be added or removed at
#                  runtime), so dyld always rebinds the monitored binary's own
#                  import stubs to the `repro_wrap_*` thunks.
#   * body-patch — the constructor ALWAYS runs `installBodypatchHooks`, which
#                  overwrites the libsystem syscall-wrapper entry points so that
#                  shared-cache-INTERNAL callers (which interpose never sees) are
#                  also captured.
# The two are additive: a given call is recorded by exactly one mechanism at its
# own layer, so the union is the full picture with no de-duplication needed.
#
# For DIAGNOSIS ONLY — and ONLY in NON-release (debug) builds — each mechanism
# has its own opt-in disable toggle. They let a developer perform a clean A/B to
# attribute a capture (or a regression) to a specific mechanism:
#   * IO_MON_DEBUG_DISABLE_BODYPATCH=1 → skip the body-patch install entirely
#     (→ interpose-only); proves which records come from interpose alone.
#   * IO_MON_DEBUG_DISABLE_INTERPOSE=1 → keep the static `__interpose` section
#     linked (it cannot be removed) but make the `repro_wrap_*` thunks STOP
#     RECORDING: instead of calling the recording `repro_hook_*`, they forward to
#     the REAL libsystem function via the (possibly body-patched) NAMED entry, so
#     body-patch records the call if it is active and nothing is recorded if it
#     is not. See `repro_interpose_disabled` in the C section for the exact
#     mechanism and re-entrancy handling.
#   * IO_MON_DEBUG_SKIP=<names> → comma-separated body-patch target names to skip
#     installing (finer-grained body-patch diagnosis).
# The clean A/B matrix these produce:
#   * neither disabled (DEFAULT)      — both mechanisms record at their own layer.
#   * body-patch disabled             — interpose only.
#   * interpose disabled              — body-patch only.
#   * both disabled                   — monitoring effectively off.
#
# RELEASE-vs-DEBUG GATING: every `IO_MON_DEBUG_*` env read is wrapped in
# `when not defined(release)`. In a RELEASE build the reads are not compiled in,
# the toggles are hard-wired off, and BOTH mechanisms are always on — so the
# diagnostic knobs can never weaken a production capture. Adding a future
# mechanism's toggle is a one-liner via `debugToggleEnabled` below.

type BodypatchHookSpec = object
  names: seq[string]   ## libsystem symbol variants that share this ABI
  hook: pointer        ## the body-hook to branch to

const BodypatchExcludeImage = "librepro_monitor_shim"

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

proc debugToggleEnabled(name: string): bool {.raises: [].} =
  ## Read a DEBUG-ONLY per-mechanism diagnostic toggle (`name` is the full env
  ## var, e.g. "IO_MON_DEBUG_DISABLE_BODYPATCH"). A toggle is honoured ONLY when
  ## its env var is exactly "1". Single source of truth for every `IO_MON_DEBUG_*`
  ## switch so adding a future mechanism's toggle is one call.
  ##
  ## RELEASE GATING: in a `-d:release` build the env read is NOT compiled in and
  ## this ALWAYS returns false — both mechanisms stay on, the diagnostic knobs
  ## have no effect, and a typo can never weaken a production capture.
  when not defined(release):
    var value = ""
    withShimMuted:
      value = getEnv(name)
    result = value == "1"
  else:
    discard name
    result = false

proc setInterposeDisabledC(disabled: cint)
  {.importc: "repro_macos_set_interpose_disabled", cdecl.}
  ## Publish the interpose-disable diagnostic state to the C interpose thunks
  ## (see `repro_interpose_disabled`). Called once from the constructor.

proc setInterposeDisabled(disabled: bool) =
  setInterposeDisabledC(if disabled: 1.cint else: 0.cint)

proc bodypatchEnabled(): bool {.raises: [].} =
  ## Returns true unless the body-patch mechanism is disabled for diagnosis via
  ## the DEBUG-only `IO_MON_DEBUG_DISABLE_BODYPATCH` toggle (always true in a
  ## release build — body-patch is unconditionally installed there).
  not debugToggleEnabled("IO_MON_DEBUG_DISABLE_BODYPATCH")

proc reproBodypatchOpenHookAddr(): pointer
    {.importc: "repro_macos_bodypatch_open_hook_addr_fn", cdecl.}
  ## Address of the VARIADIC `repro_wrap_open` thunk. The body-patch backend must
  ## branch the patched libsystem `open`/`open$NOCANCEL`/`__open_nocancel` entries
  ## here (NOT to the fixed-3-arg `repro_hook_open`): on the arm64 Apple ABI a
  ## variadic `mode` argument is passed on the STACK, so the fixed-arg hook would
  ## read garbage from x2 and create `O_CREAT` files with a corrupt permission
  ## mode (the `both`-backend nimcache EACCES defect). The thunk reads `mode` via
  ## `va_arg` only when the flags require it, matching the interpose path.

proc reproBodypatchOpenatHookAddr(): pointer
    {.importc: "repro_macos_bodypatch_openat_hook_addr_fn", cdecl.}
  ## Address of the VARIADIC `repro_wrap_openat` thunk (same rationale as
  ## `reproBodypatchOpenHookAddr`, for the `openat` family).

proc installBodypatchHooks() {.exportc: "repro_monitor_install_bodypatch", raises: [].} =
  ## Install every file-relevant libsystem syscall-wrapper body patch. Runs in
  ## the constructor, single-threaded (dyld runs constructors before main and
  ## before any monitored thread starts), so the patcher's registry is
  ## race-free. Every failure is non-fatal: a reduced/empty capture degrades to
  ## "re-run" downstream, never a false skip.
  #
  # Publish the interpose-disable diagnostic state to the C thunks FIRST, while
  # still single-threaded in the constructor (before main / any monitored
  # thread). In release this is always false (the toggle is compiled out), so the
  # interpose thunks always record. When true (debug + IO_MON_DEBUG_DISABLE_INTERPOSE)
  # the `repro_wrap_*` thunks forward to the named entry without recording, so
  # only body-patch (if installed) contributes records.
  setInterposeDisabled(debugToggleEnabled("IO_MON_DEBUG_DISABLE_INTERPOSE"))

  if not bodypatchEnabled():
    # DEBUG-only diagnostic state (IO_MON_DEBUG_DISABLE_BODYPATCH): body-patch is
    # skipped so only the static interpose mechanism records. In release builds
    # `bodypatchEnabled` is always true, so this branch is unreachable there.
    shimLogToStderr("io-mon: macOS body-patch not installed [debug] body-patch disabled")
    return

  # Each spec lists the distinct named entry points that share one ABI and
  # therefore one hook. open / open$NOCANCEL / __open_nocancel are DISTINCT
  # addresses (stdio's fopen/fread reach the $NOCANCEL variants), so all must
  # be patched. Symbols absent on this OS (dlsym → NULL) are skipped.
  # open/openat are VARIADIC libsystem entries (`open(const char *, int, ...)`).
  # The body-patch hook MUST be the variadic `repro_wrap_open(at)` thunk — which
  # reads `mode` from the stack via `va_arg` (the arm64 Apple ABI passes ALL
  # variadic args on the stack) ONLY when `O_CREAT` requires it — and NOT the
  # fixed-3-arg `repro_hook_open(at)`, which would read `mode` from register x2
  # (garbage) and create `O_CREAT` files with a corrupt permission mode. That
  # corruption is the body-patch nimcache `Permission denied`
  # defect: `fopen("...","w")` inside libsystem (a shared-cache-internal caller
  # interpose never sees) passes `mode=0666` on the stack, so the fixed-arg hook
  # mis-created the `.nim.c` `0404` and the compiler's later read got EACCES. The
  # accessors return the SAME thunks the interpose tuples use (DRY) so both
  # backends compute `mode` identically.
  let openHook = reproBodypatchOpenHookAddr()
  let openatHook = reproBodypatchOpenatHookAddr()
  let specs = @[
    BodypatchHookSpec(
      names: @["open", "open$NOCANCEL", "__open_nocancel"],
      hook: openHook),
    BodypatchHookSpec(
      names: @["openat", "openat$NOCANCEL", "__openat_nocancel"],
      hook: openatHook),
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
    # T2 content/metadata hooks (findings doc breaks #3/#5/#7). Like the
    # stat/rename family these are thin syscall wrappers, so the hook forwards
    # via the RAW syscall and the PLAIN body patch (no trampoline) suffices —
    # catching shared-cache-internal callers (e.g. ditto/cp internals) too. The
    # body-patch branches directly to the recording repro_hook_* (each forwards
    # via its raw-syscall forwarder, bypassing the patched entry). copyfile /
    # fcopyfile are DELIBERATELY absent: copyfile(3) is not a thin syscall (no
    # faithful raw forward), so it is interpose-only and forwards via the
    # resolved genuine libsystem entry — see its forwarder doc.
    BodypatchHookSpec(
      names: @["clonefile"],
      hook: cast[pointer](repro_hook_clonefile)),
    BodypatchHookSpec(
      names: @["clonefileat"],
      hook: cast[pointer](repro_hook_clonefileat)),
    BodypatchHookSpec(
      names: @["fclonefileat"],
      hook: cast[pointer](repro_hook_fclonefileat)),
    BodypatchHookSpec(
      names: @["link"],
      hook: cast[pointer](repro_hook_link)),
    BodypatchHookSpec(
      names: @["linkat"],
      hook: cast[pointer](repro_hook_linkat)),
    BodypatchHookSpec(
      names: @["getattrlist"],
      hook: cast[pointer](repro_hook_getattrlist)),
    BodypatchHookSpec(
      names: @["getattrlistat"],
      hook: cast[pointer](repro_hook_getattrlistat)),
    BodypatchHookSpec(
      names: @["fgetattrlist"],
      hook: cast[pointer](repro_hook_fgetattrlist)),
    BodypatchHookSpec(
      names: @["getattrlistbulk"],
      hook: cast[pointer](repro_hook_getattrlistbulk)),
    BodypatchHookSpec(
      names: @["getdirentries", "__getdirentries64"],
      hook: cast[pointer](repro_hook_getdirentries)),
    # T3a IPC-breakaway hook (findings doc break #1). connect is a thin syscall
    # wrapper, so the hook forwards via raw SYS_connect and the PLAIN body patch
    # (no trampoline) suffices — catching shared-cache-internal callers (e.g. a
    # daemon-client library that issues connect from inside a dylib) too. The
    # $NOCANCEL / __ variants are the cancellation-point entries stdio-ish code
    # reaches; all share the connect ABI and one hook.
    BodypatchHookSpec(
      names: @["connect", "connect$NOCANCEL", "__connect_nocancel"],
      hook: cast[pointer](repro_hook_connect)),
  ]

  # Diagnostic gate: IO_MON_DEBUG_SKIP is a comma-separated list of body-patch
  # target names to SKIP installing (e.g. "posix_spawn,posix_spawnp,fork"). It
  # exists for root-causing host-specific body-patch faults; an empty/unset value
  # installs everything. Like the other IO_MON_DEBUG_* knobs it is honoured ONLY
  # in NON-release builds (the read is compiled out under -d:release), so it can
  # never relax a production capture. Even in debug it never relaxes safety
  # (skipping only REDUCES capture, which degrades to a fail-safe re-run, never a
  # false skip).
  var debugSkip = ""
  when not defined(release):
    withShimMuted:
      debugSkip = getEnv("IO_MON_DEBUG_SKIP", "")
  proc skipped(name: string): bool =
    debugSkip.len > 0 and (name in debugSkip.split(','))

  var installed, failed, absent: cint = 0
  for spec in specs:
    for name in spec.names:
      if skipped(name):
        continue
      stackableMacosBodypatchInstallNamedExcluding(cstring(name), spec.hook,
        cstring(BodypatchExcludeImage), addr installed, addr failed, addr absent)

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
    stackableMacosBodypatchInstallNamedTrampExcluding(cstring("fork"),
      cast[pointer](repro_hook_fork), cstring(BodypatchExcludeImage),
      addr bodypatchForkTramp, addr installed, addr failed, addr absent)
  if not skipped("posix_spawn"):
    stackableMacosBodypatchInstallNamedTrampExcluding(cstring("posix_spawn"),
      cast[pointer](repro_hook_posix_spawn), cstring(BodypatchExcludeImage),
      addr bodypatchPosixSpawnTramp, addr installed, addr failed, addr absent)
  if not skipped("posix_spawnp"):
    stackableMacosBodypatchInstallNamedTrampExcluding(cstring("posix_spawnp"),
      cast[pointer](repro_hook_posix_spawnp), cstring(BodypatchExcludeImage),
      addr bodypatchPosixSpawnpTramp, addr installed, addr failed, addr absent)

  # In NON-release builds, if interpose has been disabled for diagnosis
  # (IO_MON_DEBUG_DISABLE_INTERPOSE), append a clear note so the A/B state is
  # visible in the banner. The static `__interpose` section stays linked; the
  # note means its `repro_wrap_*` thunks forward to the named entry WITHOUT
  # recording (body-patch records instead). In release builds the toggle is a
  # no-op and this note never appears.
  var interposeNote = ""
  when not defined(release):
    if debugToggleEnabled("IO_MON_DEBUG_DISABLE_INTERPOSE"):
      interposeNote = " [debug] interpose disabled"

  shimLogToStderr("io-mon: macOS body-patch installed=" & $installed &
    " failed=" & $failed & " absent=" & $absent &
    " fork_tramp=" & (if bodypatchForkTramp != nil: "ok" else: "skip") &
    " spawn_tramp=" & (if bodypatchPosixSpawnTramp != nil: "ok" else: "skip") &
    " spawnp_tramp=" &
      (if bodypatchPosixSpawnpTramp != nil: "ok" else: "skip") &
    interposeNote)

{.emit: """
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <xpc/xpc.h>

static int repro_monitor_runtime_ready = 0;
extern void NimMain(void);
extern void repro_monitor_install_bodypatch(void);
extern int repro_monitor_shim_flush(void);
extern void *repro_macos_resolve_libsystem_symbol(const char *symbol);
/* R-C: forwarders to the genuine libsystem bootstrap/XPC entries (defined in the
 * macos_interpose_runtime translation unit), used by the not-ready interpose
 * thunks below before the recording runtime is live. */
extern kern_return_t repro_macos_real_bootstrap_look_up_call(mach_port_t bp,
    char *name, mach_port_t *sp);
extern void *repro_macos_real_xpc_create_mach_service_call(char *name,
    void *targetq, unsigned long long flags);
/* ROUND-2 R-D: genuine-entry forwarders for the non-file-determinism hooks
 * (defined in the macos_interpose_runtime TU). The not-ready interpose thunks
 * forward through these before the recording runtime is live; the ready thunks
 * branch to the recording repro_hook_* (which forward through these too, so the
 * recording hook never re-enters its own wrapper). */
extern char *repro_macos_real_getenv(const char *name);
extern int repro_macos_real_sysctlbyname_call(const char *name, void *oldp,
    size_t *oldlenp, void *newp, size_t newlen);
extern int repro_macos_real_sysctl_call(int *name, unsigned int namelen,
    void *oldp, size_t *oldlenp, void *newp, size_t newlen);
extern int repro_macos_real_uname_call(void *buf);
extern int repro_macos_real_gethostname_call(char *name, size_t namelen);
extern int repro_macos_real_gethostuuid_call(unsigned char *uuid,
    const void *timeout);
extern int repro_macos_real_getentropy_call(void *buf, size_t len);
extern unsigned int repro_macos_real_arc4random_call(void);
extern void repro_macos_real_arc4random_buf_call(void *buf, size_t n);
extern unsigned int repro_macos_real_arc4random_uniform_call(unsigned int upper);
extern int repro_macos_real_clock_gettime_call(int clk, void *ts);
extern int repro_macos_real_gettimeofday_call(void *tp, void *tzp);
extern long long repro_macos_real_time_call(void *tloc);
/* ROUND-3 S3b — defined in the runtime module's emit; the constructor calls it the
 * instant the add-image registration's initial (link-time) burst finishes. */
extern void repro_macos_mark_addimage_burst_done(void);
/* T3b: the dyld add-image callback `repro_hook_dyld_add_image` is a Nim exportc
 * proc whose prototype is already emitted (N_LIB_EXPORT) earlier in this same
 * translation unit, so no re-declaration is needed here; we cast its function
 * pointer to dyld's expected signature when registering below. */

/*
 * Interpose-DISABLE diagnostic state (debug-only; see the Nim section's
 * `debugToggleEnabled` / IO_MON_DEBUG_DISABLE_INTERPOSE). When set, the
 * `repro_wrap_*` interpose thunks STOP RECORDING: instead of calling the
 * recording `repro_hook_*`, the OUTERMOST thunk invocation forwards to the REAL
 * libsystem function at its resolved entry ADDRESS (which body-patch overwrites
 * in place). Effect:
 *   * body-patch active  → the forward lands on the patched entry → body-patch
 *                          records the call (interpose contributes nothing).
 *   * body-patch disabled→ the forward lands on genuine libsystem → NO record
 *                          (monitoring effectively off for this call).
 * The static `__DATA,__interpose` section cannot be removed at runtime, so this
 * is how "interpose disabled" is realised: the section stays linked but its
 * thunks become non-recording pass-throughs. In RELEASE builds the toggle is
 * compiled out and this flag stays 0 (both mechanisms always record).
 *
 * `repro_wrap_reentry` is a per-thread guard that breaks the open-family loop:
 * for open/openat the body-patch hook IS `repro_wrap_open`/`repro_wrap_openat`,
 * so forwarding to the patched `_open` re-enters the SAME thunk. The guard makes
 * the re-entry (depth > 0) fall through to the recording `repro_hook_*` (that IS
 * the body-patch recording), so a single call records exactly once and never
 * loops. For the other families the body-patch hook is a distinct `repro_hook_*`
 * that never re-enters the wrapper, so the guard simply stays balanced.
 */
static int repro_interpose_disabled = 0;
static __thread int repro_wrap_reentry = 0;

void repro_macos_set_interpose_disabled(int value) {
  repro_interpose_disabled = value ? 1 : 0;
}

/*
 * Forward an interposed call to the REAL libsystem function via its resolved
 * entry ADDRESS (NOT the named symbol reference, which could be re-interposed,
 * and NOT a raw syscall, which would bypass the body-patch entry and so never
 * let body-patch record). Returns 1 if `*out_fn` was populated, 0 if the symbol
 * could not be resolved (the caller then degrades to the normal recording hook).
 * The resolved pointer is cached per symbol (resolution is a dyld image walk;
 * this path is debug-only, but caching keeps repeated calls cheap and the cache
 * is written single-threaded-equivalently — a benign racey re-resolve yields the
 * same address).
 */
#define REPRO_INTERPOSE_FORWARD_BEGIN \
  (repro_interpose_disabled && repro_wrap_reentry == 0)

/*
 * Threaded-write capture: why the flush is SYNCHRONOUS (in emitRecord), not a
 * pthread thread-exit destructor.
 *
 * The fragment writer (io_mon/writer.nim) batches a thread's records into a
 * per-thread (threadvar) buffer that is otherwise flushed only on overflow
 * (64 KiB), a 100 ms staleness age-check (LAZY — it only fires on the NEXT
 * emit), a fragment-key change, or an explicit flush. The dyld
 * `__attribute__((destructor))` at process exit flushes ONLY the calling (main)
 * thread's slot, because a threadvar names a DIFFERENT object per thread. So a
 * WORKER thread (a `pthread_create`d child of the monitored program) that emits
 * a few records and then EXITS before process teardown would leave its buffered
 * tail unflushed — its reads AND writes silently LOST. That is the tracked
 * "threaded-write capture gap".
 *
 * The obvious fix — a `pthread_key_t` whose destructor flushes on thread exit —
 * does NOT work here: a worker thread is a non-Nim thread, and macOS tears down
 * its Nim-runtime TLS BEFORE pthread key destructors run, so ANY Nim proc call
 * from such a destructor (even a trivial `raises: []` one) faults (verified
 * empirically on this host: the destructor ran but the Nim flush call never
 * entered its body). We therefore flush the worker thread's batch SYNCHRONOUSLY
 * inside `emitRecord` — while the thread is still alive and its Nim runtime is
 * intact — for every record whose `threadId` differs from the main/constructor
 * thread. The main thread keeps the full batching win (the single-threaded
 * configure probe storm the M9.R.15f.1 optimization targeted); worker-thread I/O
 * is comparatively rare, so per-record flushing there is an acceptable trade for
 * guaranteed capture. See `mainThreadId` / `emitRecord` in the Nim section.
 */

typedef DIR *(*repro_real_opendir_fn)(const char *);
typedef struct dirent *(*repro_real_readdir_fn)(DIR *);
typedef int (*repro_real_closedir_fn)(DIR *);
typedef pid_t (*repro_real_fork_fn)(void);
typedef int (*repro_real_posix_spawn_fn)(pid_t *, const char *,
  const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
  char *const [], char *const []);

/*
 * Cached libsystem entry-address resolvers for the interpose-disable forward.
 * Each returns the patched-in-place libsystem entry for its symbol (or NULL if
 * unresolved), via the shared shim-skipping resolver. Used ONLY on the debug-only
 * interpose-disabled path; the cache makes repeated calls cheap.
 */
typedef int (*repro_open_var_fn)(const char *, int, ...);
typedef ssize_t (*repro_rw_fn)(int, void *, size_t);
typedef int (*repro_close_fn)(int);

static repro_open_var_fn repro_libsystem_open(void) {
  static repro_open_var_fn fn = NULL;
  if (!fn) fn = (repro_open_var_fn)repro_macos_resolve_libsystem_symbol("_open");
  return fn;
}
static int (*repro_libsystem_openat_fn)(int, const char *, int, ...) = NULL;
static int repro_libsystem_openat_call(int dirfd, const char *p, int fl, int m) {
  if (!repro_libsystem_openat_fn)
    repro_libsystem_openat_fn = (int (*)(int, const char *, int, ...))
      repro_macos_resolve_libsystem_symbol("_openat");
  if (!repro_libsystem_openat_fn) return -1;
  return repro_libsystem_openat_fn(dirfd, p, fl, m);
}
static repro_rw_fn repro_libsystem_read(void) {
  static repro_rw_fn fn = NULL;
  if (!fn) fn = (repro_rw_fn)repro_macos_resolve_libsystem_symbol("_read");
  return fn;
}
static repro_rw_fn repro_libsystem_write(void) {
  static repro_rw_fn fn = NULL;
  if (!fn) fn = (repro_rw_fn)repro_macos_resolve_libsystem_symbol("_write");
  return fn;
}
static repro_close_fn repro_libsystem_close(void) {
  static repro_close_fn fn = NULL;
  if (!fn) fn = (repro_close_fn)repro_macos_resolve_libsystem_symbol("_close");
  return fn;
}

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
  /* Interpose disabled (debug A/B): forward to the libsystem open entry (which
   * body-patch may have replaced) WITHOUT recording here. Pass `mode` as a
   * variadic arg so the arm64 Apple ABI places it on the STACK exactly where a
   * va_arg reader expects it (see the open-mode rationale below). */
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    repro_open_var_fn fn = repro_libsystem_open();
    if (fn) {
      repro_wrap_reentry++;
      int r = fn(path, flags, mode);
      repro_wrap_reentry--;
      return r;
    }
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
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    repro_wrap_reentry++;
    int r = repro_libsystem_openat_call(dirfd, path, flags, mode);
    repro_wrap_reentry--;
    return r;
  }
  return repro_hook_openat(dirfd, (char *)path, flags, mode);
}

static ssize_t repro_wrap_read(int fd, void *buf, size_t count) {
  if (!repro_monitor_runtime_ready) {
    return syscall(SYS_read, fd, buf, count);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    repro_rw_fn fn = repro_libsystem_read();
    if (fn) {
      repro_wrap_reentry++;
      ssize_t r = fn(fd, buf, count);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_read(fd, buf, count);
}

static ssize_t repro_wrap_write(int fd, const void *buf, size_t count) {
  if (!repro_monitor_runtime_ready) {
    return syscall(SYS_write, fd, buf, count);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    repro_rw_fn fn = repro_libsystem_write();
    if (fn) {
      repro_wrap_reentry++;
      ssize_t r = fn(fd, (void *)buf, count);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_write(fd, (void *)buf, count);
}

static int repro_wrap_close(int fd) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_close, fd);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    repro_close_fn fn = repro_libsystem_close();
    if (fn) {
      repro_wrap_reentry++;
      int r = fn(fd);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_close(fd);
}

/*
 * ROUND-3 S2d — fd-duplication interpose thunks (dup/dup2/fcntl). Like the
 * connect / content-channel thunks these are INTERPOSE-ONLY (dup/dup2/fcntl are
 * thin syscall wrappers build tools call directly; never body-patched), so each
 * forwards via the RAW syscall before the recording runtime is live and then
 * branches to the recording repro_hook_*. They omit the debug-only
 * interpose-DISABLE A/B forward (moot for an interpose-only hook).
 */
static int repro_wrap_dup(int fd) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_dup, fd);
  }
  return repro_hook_dup(fd);
}

static int repro_wrap_dup2(int oldfd, int newfd) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_dup2, oldfd, newfd);
  }
  return repro_hook_dup2(oldfd, newfd);
}

/*
 * fcntl is VARIADIC (int fcntl(int, int, ...)). The optional third argument is an
 * int for some commands (F_DUPFD, F_SETFD, …) and a pointer for others (F_GETPATH,
 * F_PREALLOCATE, …); on the arm64 Apple ABI it lives on the STACK, so we read it
 * via va_arg as a void*-sized value (libsystem's own fcntl stub marshals it the
 * same way) and forward it verbatim — faithful for EVERY command. We hook fcntl
 * solely to observe F_DUPFD/F_DUPFD_CLOEXEC fd duplication; all other commands
 * pass straight through repro_hook_fcntl untouched.
 */
static int repro_wrap_fcntl(int fd, int cmd, ...) {
  va_list ap;
  va_start(ap, cmd);
  void *arg = va_arg(ap, void *);
  va_end(ap);
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_fcntl, fd, cmd, arg);
  }
  return repro_hook_fcntl(fd, cmd, arg);
}

/*
 * ROUND-2 R9 mmap interpose thunk. Like the T2/T3a thunks it forwards to the
 * kernel before the recording runtime is live, then branches to the recording
 * repro_hook_mmap (which forwards via the genuine libsystem mmap). It omits the
 * debug-only interpose-DISABLE A/B forward (REPRO_INTERPOSE_FORWARD_*): mmap is
 * interpose-only (never body-patched), and the knob attributes a capture to
 * interpose-vs-body-patch, which is moot for an interpose-only hook. The signature
 * matches `void *mmap(void *, size_t, int, int, int, off_t)`.
 */
extern void *repro_macos_real_mmap_syscall(void *addr, size_t len, int prot,
                                           int flags, int fd, long long offset);

static void *repro_wrap_mmap(void *addr, size_t len, int prot, int flags,
                             int fd, off_t offset) {
  if (!repro_monitor_runtime_ready) {
    /* Forward via the inline-asm BSD mmap syscall (full 64-bit return). MUST be
     * allocation-free here: the interpose tuple is live from image-load, so this
     * thunk fires for libsystem-internal mmaps BEFORE our constructor, and a
     * dlsym/resolve forward would malloc → mmap → re-enter this thunk → recurse.
     * NOT the libc syscall() shim either (it truncates the pointer → crash). */
    return repro_macos_real_mmap_syscall(addr, len, prot, flags, fd,
                                         (long long)offset);
  }
  return repro_hook_mmap(addr, len, prot, flags, fd, (long long)offset);
}

/* Cached libsystem entry-address resolvers for the remaining wrap families
 * (interpose-disable forward). Each lands on the patched-in-place body-patch
 * entry when body-patch is active, or genuine libsystem when it is not — both
 * bypassing the __interpose tuple. */
static DIR *(*repro_libsystem_opendir_fn)(const char *) = NULL;
static struct dirent *(*repro_libsystem_readdir_fn)(DIR *) = NULL;
static int (*repro_libsystem_closedir_fn)(DIR *) = NULL;
static int (*repro_libsystem_stat_fn)(const char *, struct stat *) = NULL;
static int (*repro_libsystem_lstat_fn)(const char *, struct stat *) = NULL;
static pid_t (*repro_libsystem_fork_fn)(void) = NULL;
static int (*repro_libsystem_rename_fn)(const char *, const char *) = NULL;
static int (*repro_libsystem_renameat_fn)(int, const char *, int,
                                          const char *) = NULL;
static int (*repro_libsystem_execve_fn)(const char *, char *const [],
                                        char *const []) = NULL;

static DIR *repro_wrap_opendir(const char *path) {
  if (!repro_monitor_runtime_ready) {
    repro_real_opendir_fn real_fn = (repro_real_opendir_fn)dlsym(RTLD_NEXT, "opendir");
    return real_fn(path);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_opendir_fn)
      repro_libsystem_opendir_fn = (DIR *(*)(const char *))
        repro_macos_resolve_libsystem_symbol("_opendir");
    if (repro_libsystem_opendir_fn) {
      repro_wrap_reentry++;
      DIR *r = repro_libsystem_opendir_fn(path);
      repro_wrap_reentry--;
      return r;
    }
  }
  return (DIR *)repro_hook_opendir((char *)path);
}

static struct dirent *repro_wrap_readdir(DIR *dirp) {
  if (!repro_monitor_runtime_ready) {
    repro_real_readdir_fn real_fn = (repro_real_readdir_fn)dlsym(RTLD_NEXT, "readdir");
    return real_fn(dirp);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_readdir_fn)
      repro_libsystem_readdir_fn = (struct dirent *(*)(DIR *))
        repro_macos_resolve_libsystem_symbol("_readdir");
    if (repro_libsystem_readdir_fn) {
      repro_wrap_reentry++;
      struct dirent *r = repro_libsystem_readdir_fn(dirp);
      repro_wrap_reentry--;
      return r;
    }
  }
  return (struct dirent *)repro_hook_readdir(dirp);
}

static int repro_wrap_closedir(DIR *dirp) {
  if (!repro_monitor_runtime_ready) {
    repro_real_closedir_fn real_fn = (repro_real_closedir_fn)dlsym(RTLD_NEXT, "closedir");
    return real_fn(dirp);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_closedir_fn)
      repro_libsystem_closedir_fn = (int (*)(DIR *))
        repro_macos_resolve_libsystem_symbol("_closedir");
    if (repro_libsystem_closedir_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_closedir_fn(dirp);
      repro_wrap_reentry--;
      return r;
    }
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
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_stat_fn)
      repro_libsystem_stat_fn = (int (*)(const char *, struct stat *))
        repro_macos_resolve_libsystem_symbol("_stat");
    if (repro_libsystem_stat_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_stat_fn(path, buf);
      repro_wrap_reentry--;
      return r;
    }
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
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_lstat_fn)
      repro_libsystem_lstat_fn = (int (*)(const char *, struct stat *))
        repro_macos_resolve_libsystem_symbol("_lstat");
    if (repro_libsystem_lstat_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_lstat_fn(path, buf);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_lstat((char *)path, buf);
}

static pid_t repro_wrap_fork(void) {
  if (!repro_monitor_runtime_ready) {
    repro_real_fork_fn real_fn = (repro_real_fork_fn)dlsym(RTLD_NEXT, "fork");
    return real_fn();
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_fork_fn)
      repro_libsystem_fork_fn = (pid_t (*)(void))
        repro_macos_resolve_libsystem_symbol("_fork");
    if (repro_libsystem_fork_fn) {
      repro_wrap_reentry++;
      pid_t r = repro_libsystem_fork_fn();
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_fork();
}

static int repro_wrap_rename(const char *from, const char *to) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_rename, from, to);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_rename_fn)
      repro_libsystem_rename_fn = (int (*)(const char *, const char *))
        repro_macos_resolve_libsystem_symbol("_rename");
    if (repro_libsystem_rename_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_rename_fn(from, to);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_rename((char *)from, (char *)to);
}

static int repro_wrap_renameat(int fromfd, const char *from, int tofd,
                               const char *to) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_renameat, fromfd, from, tofd, to);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_renameat_fn)
      repro_libsystem_renameat_fn = (int (*)(int, const char *, int,
        const char *))repro_macos_resolve_libsystem_symbol("_renameat");
    if (repro_libsystem_renameat_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_renameat_fn(fromfd, from, tofd, to);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_renameat(fromfd, (char *)from, tofd, (char *)to);
}

static int repro_wrap_execve(const char *path, char *const argv[], char *const envp[]) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_execve, path, argv, envp);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_execve_fn)
      repro_libsystem_execve_fn = (int (*)(const char *, char *const [],
        char *const []))repro_macos_resolve_libsystem_symbol("_execve");
    if (repro_libsystem_execve_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_execve_fn(path, argv, envp);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_execve((char *)path, (char **)argv, (char **)envp);
}

static repro_real_posix_spawn_fn repro_libsystem_posix_spawn_fn = NULL;
static repro_real_posix_spawn_fn repro_libsystem_posix_spawnp_fn = NULL;

static int repro_wrap_posix_spawn(pid_t *pid, const char *path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *attrp,
  char *const argv[], char *const envp[]) {
  if (!repro_monitor_runtime_ready) {
    repro_real_posix_spawn_fn real_fn =
      (repro_real_posix_spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    return real_fn(pid, path, file_actions, attrp, argv, envp);
  }
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_posix_spawn_fn)
      repro_libsystem_posix_spawn_fn = (repro_real_posix_spawn_fn)
        repro_macos_resolve_libsystem_symbol("_posix_spawn");
    if (repro_libsystem_posix_spawn_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_posix_spawn_fn(pid, path, file_actions, attrp,
        argv, envp);
      repro_wrap_reentry--;
      return r;
    }
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
  if (REPRO_INTERPOSE_FORWARD_BEGIN) {
    if (!repro_libsystem_posix_spawnp_fn)
      repro_libsystem_posix_spawnp_fn = (repro_real_posix_spawn_fn)
        repro_macos_resolve_libsystem_symbol("_posix_spawnp");
    if (repro_libsystem_posix_spawnp_fn) {
      repro_wrap_reentry++;
      int r = repro_libsystem_posix_spawnp_fn(pid, path, file_actions, attrp,
        argv, envp);
      repro_wrap_reentry--;
      return r;
    }
  }
  return repro_hook_posix_spawnp(pid, (char *)path, (void *)file_actions,
    (void *)attrp, (char **)argv, (char **)envp);
}

/*
 * T2 content/metadata interpose thunks (findings doc breaks #3/#5/#7).
 *
 * These are the __DATA,__interpose replacements for the clonefile/link/copyfile/
 * getattrlist families. They mirror the existing thunks' not-ready passthrough
 * (forward to the kernel/genuine entry before the recording runtime is live)
 * then branch to the recording repro_hook_*. UNLIKE the original thunks they do
 * NOT carry the debug-only interpose-DISABLE forward (REPRO_INTERPOSE_FORWARD_*):
 * that A/B knob attributes a capture to interpose-vs-body-patch, and these
 * Phase-1 hardening hooks are exercised only under the default `both` and the
 * `interpose` arms (where they correctly record via interpose). Omitting it
 * keeps them simple and cannot weaken a production capture (both mechanisms are
 * always on in release).
 */
static int repro_wrap_clonefile(const char *src, const char *dst, int flags) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_clonefileat, AT_FDCWD, src, AT_FDCWD, dst, flags);
  }
  return repro_hook_clonefile((char *)src, (char *)dst, flags);
}

static int repro_wrap_clonefileat(int srcfd, const char *src, int dstfd,
                                  const char *dst, int flags) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_clonefileat, srcfd, src, dstfd, dst, flags);
  }
  return repro_hook_clonefileat(srcfd, (char *)src, dstfd, (char *)dst, flags);
}

static int repro_wrap_fclonefileat(int srcfd, int dstfd, const char *dst,
                                   int flags) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_fclonefileat, srcfd, dstfd, dst, flags);
  }
  return repro_hook_fclonefileat(srcfd, dstfd, (char *)dst, flags);
}

static int repro_wrap_link(const char *src, const char *dst) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_link, src, dst);
  }
  return repro_hook_link((char *)src, (char *)dst);
}

static int repro_wrap_linkat(int fd1, const char *src, int fd2,
                             const char *dst, int flag) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_linkat, fd1, src, fd2, dst, flag);
  }
  return repro_hook_linkat(fd1, (char *)src, fd2, (char *)dst, flag);
}

static int repro_wrap_copyfile(const char *from, const char *to,
                               copyfile_state_t state, copyfile_flags_t flags) {
  if (!repro_monitor_runtime_ready) {
    int (*real)(const char *, const char *, copyfile_state_t, copyfile_flags_t)
      = (int (*)(const char *, const char *, copyfile_state_t,
                 copyfile_flags_t))dlsym(RTLD_NEXT, "copyfile");
    return real ? real(from, to, state, flags) : -1;
  }
  return repro_hook_copyfile((char *)from, (char *)to, (void *)state,
    (uint32_t)flags);
}

static int repro_wrap_fcopyfile(int from, int to, copyfile_state_t state,
                                copyfile_flags_t flags) {
  if (!repro_monitor_runtime_ready) {
    int (*real)(int, int, copyfile_state_t, copyfile_flags_t)
      = (int (*)(int, int, copyfile_state_t, copyfile_flags_t))
          dlsym(RTLD_NEXT, "fcopyfile");
    return real ? real(from, to, state, flags) : -1;
  }
  return repro_hook_fcopyfile(from, to, (void *)state, (uint32_t)flags);
}

static int repro_wrap_getattrlist(const char *path, void *al, void *buf,
                                  size_t size, unsigned long opts) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_getattrlist, path, al, buf, size, opts);
  }
  return repro_hook_getattrlist((char *)path, al, buf, size, opts);
}

static int repro_wrap_getattrlistat(int fd, const char *path, void *al,
                                    void *buf, size_t size, unsigned long opts) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_getattrlistat, fd, path, al, buf, size, opts);
  }
  return repro_hook_getattrlistat(fd, (char *)path, al, buf, size, opts);
}

static int repro_wrap_fgetattrlist(int fd, void *al, void *buf, size_t size,
                                   unsigned long opts) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_fgetattrlist, fd, al, buf, size, opts);
  }
  return repro_hook_fgetattrlist(fd, al, buf, size, opts);
}

static int repro_wrap_getattrlistbulk(int dirfd, void *al, void *buf,
                                      size_t size, uint64_t opts) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_getattrlistbulk, dirfd, al, buf, size, opts);
  }
  return repro_hook_getattrlistbulk(dirfd, al, buf, size, opts);
}

/*
 * T3a IPC-breakaway interpose thunk (findings doc break #1). Mirrors the T2
 * thunks: forward to the kernel before the recording runtime is live, then
 * branch to the recording repro_hook_connect (which itself forwards via raw
 * SYS_connect, bypassing any body-patched entry). It deliberately omits the
 * debug-only interpose-DISABLE A/B forward (REPRO_INTERPOSE_FORWARD_*) — this is
 * a hardening hook exercised under the default `both` and `interpose` arms, and
 * omitting the knob cannot weaken a production capture (both mechanisms are
 * always on in release).
 */
static int repro_wrap_connect(int fd, const struct sockaddr *addr,
                              socklen_t addrlen) {
  if (!repro_monitor_runtime_ready) {
    return (int)syscall(SYS_connect, fd, addr, addrlen);
  }
  return repro_hook_connect(fd, (void *)addr, (unsigned int)addrlen);
}

/*
 * R-C XPC / Mach-port breakaway interpose thunks (round-2 break R2). Mirror the
 * T3a connect thunk: forward to the GENUINE libsystem entry before the recording
 * runtime is live, then branch to the recording repro_hook_*. These are
 * INTERPOSE-ONLY (bootstrap_look_up / xpc_connection_create_mach_service are not
 * thin syscall wrappers and are not body-patched), so the not-ready forward uses
 * the shim-skipping genuine-entry forwarder (which itself falls back to
 * dlsym(RTLD_NEXT) so the program never breaks). Like the other hardening thunks
 * they omit the debug-only interpose-DISABLE A/B forward.
 */
static kern_return_t repro_wrap_bootstrap_look_up(mach_port_t bp,
    const char *name, mach_port_t *sp) {
  if (!repro_monitor_runtime_ready) {
    return repro_macos_real_bootstrap_look_up_call(bp, (char *)name, sp);
  }
  return repro_hook_bootstrap_look_up(bp, (char *)name, sp);
}

static xpc_connection_t repro_wrap_xpc_connection_create_mach_service(
    const char *name, dispatch_queue_t targetq, uint64_t flags) {
  if (!repro_monitor_runtime_ready) {
    return (xpc_connection_t)repro_macos_real_xpc_create_mach_service_call(
      (char *)name, (void *)targetq, (unsigned long long)flags);
  }
  return (xpc_connection_t)repro_hook_xpc_connection_create_mach_service(
    (char *)name, (void *)targetq, (unsigned long long)flags);
}

/*
 * ROUND-2 R-D (break R10) non-file-determinism interpose thunks. Each mirrors the
 * existing hardening thunks: forward to the GENUINE libsystem entry before the
 * recording runtime is live, then branch to the recording repro_hook_* (which
 * itself forwards via the genuine entry, so the recording hook never re-enters its
 * own wrapper). All are INTERPOSE-ONLY (not body-patched), so they see only the
 * monitored program's OWN direct call — the basis of the no-false-downgrade guard
 * for the randomness arm (libsystem-internal benign randomness is never seen).
 * Like the other hardening thunks they omit the debug-only interpose-DISABLE A/B
 * forward (it attributes a capture to interpose-vs-body-patch, moot here).
 */
static char *repro_wrap_getenv(const char *name) {
  if (!repro_monitor_runtime_ready) return repro_macos_real_getenv(name);
  return repro_hook_getenv((char *)name);
}

static int repro_wrap_sysctlbyname(const char *name, void *oldp,
    size_t *oldlenp, void *newp, size_t newlen) {
  if (!repro_monitor_runtime_ready)
    return repro_macos_real_sysctlbyname_call(name, oldp, oldlenp, newp, newlen);
  return repro_hook_sysctlbyname((char *)name, oldp, oldlenp, newp, newlen);
}

static int repro_wrap_sysctl(int *name, unsigned int namelen, void *oldp,
    size_t *oldlenp, void *newp, size_t newlen) {
  if (!repro_monitor_runtime_ready)
    return repro_macos_real_sysctl_call(name, namelen, oldp, oldlenp, newp, newlen);
  return repro_hook_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int repro_wrap_uname(struct utsname *buf) {
  if (!repro_monitor_runtime_ready) return repro_macos_real_uname_call(buf);
  return repro_hook_uname((void *)buf);
}

static int repro_wrap_gethostname(char *name, size_t namelen) {
  if (!repro_monitor_runtime_ready)
    return repro_macos_real_gethostname_call(name, namelen);
  return repro_hook_gethostname(name, namelen);
}

static int repro_wrap_gethostuuid(unsigned char *uuid,
    const struct timespec *timeout) {
  if (!repro_monitor_runtime_ready)
    return repro_macos_real_gethostuuid_call(uuid, (const void *)timeout);
  return repro_hook_gethostuuid((void *)uuid, (void *)timeout);
}

/* The entropy wrappers capture __builtin_return_address(0) — the address of the
 * instruction after the PROGRAM's call to the entropy API (the interpose binding
 * lands the program's call directly on this wrapper). It is passed to the recording
 * hook for CALLER-IMAGE ATTRIBUTION so only the program's OWN entropy use is flagged
 * (the /usr/lib libsystem/libobjc/libswift startup baseline is excluded) — the fix
 * for the cardinal-sin false downgrade of every real cc/clang/ld/bash run. */
static int repro_wrap_getentropy(void *buf, size_t len) {
  void *ra = __builtin_return_address(0);
  if (!repro_monitor_runtime_ready) return repro_macos_real_getentropy_call(buf, len);
  return repro_hook_getentropy(buf, len, ra);
}

static uint32_t repro_wrap_arc4random(void) {
  void *ra = __builtin_return_address(0);
  if (!repro_monitor_runtime_ready) return repro_macos_real_arc4random_call();
  return repro_hook_arc4random(ra);
}

static void repro_wrap_arc4random_buf(void *buf, size_t n) {
  void *ra = __builtin_return_address(0);
  if (!repro_monitor_runtime_ready) { repro_macos_real_arc4random_buf_call(buf, n); return; }
  repro_hook_arc4random_buf(buf, n, ra);
}

static uint32_t repro_wrap_arc4random_uniform(uint32_t upper) {
  void *ra = __builtin_return_address(0);
  if (!repro_monitor_runtime_ready) return repro_macos_real_arc4random_uniform_call(upper);
  return repro_hook_arc4random_uniform(upper, ra);
}

static int repro_wrap_clock_gettime(clockid_t clk, struct timespec *ts) {
  if (!repro_monitor_runtime_ready)
    return repro_macos_real_clock_gettime_call((int)clk, (void *)ts);
  return repro_hook_clock_gettime((int)clk, (void *)ts);
}

static int repro_wrap_gettimeofday(struct timeval *tp, void *tzp) {
  if (!repro_monitor_runtime_ready)
    return repro_macos_real_gettimeofday_call((void *)tp, tzp);
  return repro_hook_gettimeofday((void *)tp, tzp);
}

static time_t repro_wrap_time(time_t *tloc) {
  if (!repro_monitor_runtime_ready)
    return (time_t)repro_macos_real_time_call((void *)tloc);
  return (time_t)repro_hook_time((void *)tloc);
}

/* mach_absolute_time is intentionally NOT interposed (libdispatch early-init
 * hazard; monotonic counter, not a wall clock). See the Nim/runtime R-D notes. */

/*
 * ROUND-3 S1 content-channel interpose thunks. Each forwards to the GENUINE entry
 * (the raw-syscall forwarder) before the recording runtime is live, then branches
 * to the recording repro_hook_* (which itself forwards via the raw syscall, so it
 * never re-enters this wrapper). INTERPOSE-ONLY (see the Nim hook docs); like the
 * other hardening thunks they omit the debug-only interpose-DISABLE A/B forward.
 */
static ssize_t repro_wrap_getxattr(const char *path, const char *name,
    void *value, size_t size, uint32_t position, int options) {
  if (!repro_monitor_runtime_ready)
    return (ssize_t)syscall(SYS_getxattr, path, name, value, size, position,
      options);
  return repro_hook_getxattr((char *)path, (char *)name, value, size, position,
    options);
}
static ssize_t repro_wrap_fgetxattr(int fd, const char *name, void *value,
    size_t size, uint32_t position, int options) {
  if (!repro_monitor_runtime_ready)
    return (ssize_t)syscall(SYS_fgetxattr, fd, name, value, size, position,
      options);
  return repro_hook_fgetxattr(fd, (char *)name, value, size, position, options);
}
static ssize_t repro_wrap_listxattr(const char *path, char *namebuf,
    size_t size, int options) {
  if (!repro_monitor_runtime_ready)
    return (ssize_t)syscall(SYS_listxattr, path, namebuf, size, options);
  return repro_hook_listxattr((char *)path, namebuf, size, options);
}
static ssize_t repro_wrap_flistxattr(int fd, char *namebuf, size_t size,
    int options) {
  if (!repro_monitor_runtime_ready)
    return (ssize_t)syscall(SYS_flistxattr, fd, namebuf, size, options);
  return repro_hook_flistxattr(fd, namebuf, size, options);
}
static int repro_wrap_setxattr(const char *path, const char *name, void *value,
    size_t size, uint32_t position, int options) {
  if (!repro_monitor_runtime_ready)
    return (int)syscall(SYS_setxattr, path, name, value, size, position,
      options);
  return repro_hook_setxattr((char *)path, (char *)name, value, size, position,
    options);
}
static int repro_wrap_fsetxattr(int fd, const char *name, void *value,
    size_t size, uint32_t position, int options) {
  if (!repro_monitor_runtime_ready)
    return (int)syscall(SYS_fsetxattr, fd, name, value, size, position, options);
  return repro_hook_fsetxattr(fd, (char *)name, value, size, position, options);
}
static int repro_wrap_removexattr(const char *path, const char *name,
    int options) {
  if (!repro_monitor_runtime_ready)
    return (int)syscall(SYS_removexattr, path, name, options);
  return repro_hook_removexattr((char *)path, (char *)name, options);
}
static int repro_wrap_fremovexattr(int fd, const char *name, int options) {
  if (!repro_monitor_runtime_ready)
    return (int)syscall(SYS_fremovexattr, fd, name, options);
  return repro_hook_fremovexattr(fd, (char *)name, options);
}

/* shm_open is VARIADIC (int shm_open(const char *, int, ...)); mode is supplied
 * only with O_CREAT and — on the arm64 Apple ABI — lives on the STACK, so we read
 * it via va_arg (exactly like repro_wrap_open). */
static int repro_wrap_shm_open(const char *name, int oflag, ...) {
  int mode = 0;
  if (oflag & O_CREAT) {
    va_list ap;
    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  if (!repro_monitor_runtime_ready)
    return (int)syscall(SYS_shm_open, name, oflag, mode);
  return repro_hook_shm_open((char *)name, oflag, mode);
}

static int repro_wrap_sendfile(int fd, int s, off_t offset, off_t *len,
    void *hdtr, int flags) {
  if (!repro_monitor_runtime_ready)
    return (int)syscall(SYS_sendfile, fd, s, offset, len, hdtr, flags);
  return repro_hook_sendfile(fd, s, (long long)offset, (long long *)len, hdtr,
    flags);
}
static ssize_t repro_wrap_pread(int fd, void *buf, size_t count, off_t offset) {
  if (!repro_monitor_runtime_ready)
    return (ssize_t)syscall(SYS_pread, fd, buf, count, offset);
  return repro_hook_pread(fd, buf, count, (long long)offset);
}
static ssize_t repro_wrap_preadv(int fd, const struct iovec *iov, int iovcnt,
    off_t offset) {
  if (!repro_monitor_runtime_ready)
    return (ssize_t)syscall(SYS_preadv, fd, iov, iovcnt, offset);
  return repro_hook_preadv(fd, (void *)iov, iovcnt, (long long)offset);
}
static ssize_t repro_wrap_readv(int fd, const struct iovec *iov, int iovcnt) {
  if (!repro_monitor_runtime_ready)
    return (ssize_t)syscall(SYS_readv, fd, iov, iovcnt);
  return repro_hook_readv(fd, (void *)iov, iovcnt);
}

/*
 * Body-patch hook ADDRESS accessors for the VARIADIC open/openat wrappers.
 *
 * Why the body-patch backend MUST use the variadic repro_wrap_open(at) thunks --
 * and NOT the fixed-3-arg repro_hook_open(at) -- for the open family:
 *
 * Apple's libsystem open / open$NOCANCEL / openat / ... are VARIADIC entries
 * (open(const char *, int, ...)). On the arm64 Apple platform ABI, ALL variadic
 * arguments are passed on the STACK, never in argument registers (contrary to
 * the AAPCS64 default; see Apple's "Writing ARM64 Code for Apple Platforms" --
 * variadic args live at [sp], so x2 is NOT the mode). A caller that supplies
 * mode (e.g. libsystem_c's fopen, which emits movz w8,#0666; str x8,[sp]; bl
 * open$NOCANCEL) therefore places mode on the stack, while register x2 holds an
 * UNRELATED value.
 *
 * The body-patch overwrites the libsystem open$NOCANCEL entry so that ALL
 * callers -- including shared-cache-internal ones like fopen that interpose
 * never sees -- branch to our hook. If that hook is the fixed-3-arg
 * repro_hook_open(path, flags, mode), it reads mode from x2 (garbage) and
 * forwards open(path, flags, <garbage>) to the kernel. For an O_CREAT open that
 * CREATES the file with a corrupt permission mode (e.g. fopen(p,"w") yielding
 * 0404 instead of 0644), so the compiler's later read of its own just-written
 * nimcache .nim.c fails with EACCES ("Permission denied") -- the exact
 * body-patch defect. The interpose path never hit this because
 * repro_wrap_open already reads mode via va_arg (stack-correct); only the
 * body-patched shared-cache-internal callers were affected.
 *
 * The fix routes the body-patch open/openat hooks through the SAME variadic
 * repro_wrap_open(at) thunks the interpose tuples use (DRY): they read mode via
 * va_arg ONLY when O_CREAT requires it, then forward to repro_hook_open(at) with
 * the CORRECT mode. The thunks are static, so we expose their addresses through
 * these tiny accessor functions for the Nim-side body-patch installer.
 */
void *repro_macos_bodypatch_open_hook_addr_fn(void) {
  return (void *)repro_wrap_open;
}

void *repro_macos_bodypatch_openat_hook_addr_fn(void) {
  return (void *)repro_wrap_openat;
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
  /*
   * T3b (findings-doc break #4 + the dlopen arm of #7): capture the dyld IMAGE
   * SET — dependent dylibs that dyld maps via low-level kernel mmap (bypassing
   * every open/openat hook) plus future dlopen'd images.
   * _dyld_register_func_for_add_image invokes the callback ONCE for each image
   * ALREADY loaded (the executable's full dependent-dylib closure — complete at
   * this point because dyld maps all static dependencies before running
   * initializers/this constructor, so a separate _dyld_image_count() sweep would
   * only re-deliver the same images and risk double-recording) AND again for
   * every later dlopen — one path covers both breaks. Registered LAST so the
   * recording runtime (runtime_ready / shim_init) is fully live when the initial
   * burst of callbacks fires; the callback itself filters out the ~600-image
   * system baseline. The cast adapts the Nim proc's ABI to dyld's expected
   * `void(*)(const struct mach_header *, intptr_t)` (register-compatible).
   */
  _dyld_register_func_for_add_image(
    (void (*)(const struct mach_header *, intptr_t))repro_hook_dyld_add_image);
  /* ROUND-3 S3b — the register call above delivered the FULL link-time dependency
   * closure synchronously (one callback per already-loaded image). Mark the initial
   * burst done so every SUBSEQUENT callback is a dlopen'd image: the entropy
   * caller-attribution registers a non-system image's __TEXT range ONLY for those
   * dlopen'd extensions (a pass-plugin), never for the trusted link-time toolchain
   * runtime (libLLVM/libc++), keeping a normal cc/clang compile mcComplete. */
  repro_macos_mark_addimage_burst_done();
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
  { (const void *)repro_wrap_dup, (const void *)dup },
  { (const void *)repro_wrap_dup2, (const void *)dup2 },
  { (const void *)repro_wrap_fcntl, (const void *)fcntl },
  /* ROUND-2 R9 — mmap output-via-memory hook (MAP_SHARED|PROT_WRITE content
   * write with no write() syscall). Interpose-only (not body-patched). */
  { (const void *)repro_wrap_mmap, (const void *)mmap },
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
  { (const void *)repro_wrap_posix_spawnp, (const void *)posix_spawnp },
  /* T2 content/metadata hooks (findings doc breaks #3/#5/#7). */
  { (const void *)repro_wrap_clonefile, (const void *)clonefile },
  { (const void *)repro_wrap_clonefileat, (const void *)clonefileat },
  { (const void *)repro_wrap_fclonefileat, (const void *)fclonefileat },
  { (const void *)repro_wrap_link, (const void *)link },
  { (const void *)repro_wrap_linkat, (const void *)linkat },
  { (const void *)repro_wrap_copyfile, (const void *)copyfile },
  { (const void *)repro_wrap_fcopyfile, (const void *)fcopyfile },
  { (const void *)repro_wrap_getattrlist, (const void *)getattrlist },
  { (const void *)repro_wrap_getattrlistat, (const void *)getattrlistat },
  { (const void *)repro_wrap_fgetattrlist, (const void *)fgetattrlist },
  { (const void *)repro_wrap_getattrlistbulk, (const void *)getattrlistbulk },
  /* T3a IPC-breakaway hook (findings doc break #1). */
  { (const void *)repro_wrap_connect, (const void *)connect },
  /* R-C XPC / Mach-port breakaway hooks (round-2 break R2). bootstrap_look_up
   * (raw-Mach clients) + xpc_connection_create_mach_service (the XPC client
   * entry) — the connection-establishment boundary the connect(2) hook is blind
   * to. Interpose-only (see the thunks). */
  { (const void *)repro_wrap_bootstrap_look_up,
    (const void *)bootstrap_look_up },
  { (const void *)repro_wrap_xpc_connection_create_mach_service,
    (const void *)xpc_connection_create_mach_service },
  /* ROUND-2 R-D (break R10) non-file observation hooks. Env/sysctl/uname are
   * observed declared INPUTS; getentropy/arc4random* are entropy evidence;
   * clock_gettime/gettimeofday/time/mach_absolute_time are time evidence. */
  { (const void *)repro_wrap_getenv, (const void *)getenv },
  { (const void *)repro_wrap_clock_gettime, (const void *)clock_gettime },
  { (const void *)repro_wrap_gettimeofday, (const void *)gettimeofday },
  { (const void *)repro_wrap_time, (const void *)time },
  { (const void *)repro_wrap_sysctlbyname, (const void *)sysctlbyname },
  { (const void *)repro_wrap_sysctl, (const void *)sysctl },
  { (const void *)repro_wrap_uname, (const void *)uname },
  { (const void *)repro_wrap_gethostname, (const void *)gethostname },
  { (const void *)repro_wrap_gethostuuid, (const void *)gethostuuid },
  { (const void *)repro_wrap_getentropy, (const void *)getentropy },
  { (const void *)repro_wrap_arc4random, (const void *)arc4random },
  { (const void *)repro_wrap_arc4random_buf, (const void *)arc4random_buf },
  { (const void *)repro_wrap_arc4random_uniform,
    (const void *)arc4random_uniform },
  /* ROUND-3 S1 content-channel hooks. xattr family (S1a — metadata reads/writes),
   * shm_open (S1b — POSIX shared memory), and the sendfile/pread/preadv/readv
   * zero-copy/positioned reads (S1d — content classification). Interpose-only
   * (see the thunks). The FIFO (S1d) and inherited socket/pipe (S1c) downgrades
   * ride the existing open/read hooks, so they need no new tuple entry. */
  { (const void *)repro_wrap_getxattr, (const void *)getxattr },
  { (const void *)repro_wrap_fgetxattr, (const void *)fgetxattr },
  { (const void *)repro_wrap_listxattr, (const void *)listxattr },
  { (const void *)repro_wrap_flistxattr, (const void *)flistxattr },
  { (const void *)repro_wrap_setxattr, (const void *)setxattr },
  { (const void *)repro_wrap_fsetxattr, (const void *)fsetxattr },
  { (const void *)repro_wrap_removexattr, (const void *)removexattr },
  { (const void *)repro_wrap_fremovexattr, (const void *)fremovexattr },
  { (const void *)repro_wrap_shm_open, (const void *)shm_open },
  { (const void *)repro_wrap_sendfile, (const void *)sendfile },
  { (const void *)repro_wrap_pread, (const void *)pread },
  { (const void *)repro_wrap_preadv, (const void *)preadv },
  { (const void *)repro_wrap_readv, (const void *)readv }
  /* getdirentries is intentionally NOT in the interpose tuple: the SDK header
   * poisons the symbol under 64-bit inodes (`getdirentries_is_not_available…`),
   * so it cannot be referenced here. It is body-patched by string name instead
   * (see the BodypatchHookSpec list). The raw-syscall getdirentries call site is
   * the structurally-unfixable #6 gap regardless. */
};
""".}
