when not defined(linux):
  {.error: "repro_monitor_hooks/linux_preload_runtime is Linux-only".}

import std/[algorithm, locks, os, strutils]

import stackable_hooks/platform/linux_preload
import stackable_hooks/platform/linux_raw_syscalls
import ./linux_mapping_policy
import ../exec_image_header

export linux_mapping_policy

const linuxPreloadBackend* = "stackable_hooks/platform/linux_preload"
const
  linuxProtWrite = 0x2
  linuxProtExec = 0x4
  linuxMapPrivate = 0x02
  linuxMapAnonymous = 0x20
  linuxInlineAnonScanMaxBytes = 64 * 1024 * 1024
static:
  doAssert compiles(currentPreloadHookDepth())
  doAssert compiles(installAbsoluteJumpPatchTransaction(nil, nil))

type
  PidT* = int32

  LinuxHookSymbol = enum
    lhsOpen, lhsOpen64, lhsOpenat, lhsOpenat64, lhsClose, lhsRead, lhsWrite,
    lhsStat, lhsLstat, lhsOpendir, lhsReaddir, lhsClosedir, lhsFork,
    lhsExecve, lhsPosixSpawn, lhsPosixSpawnp, lhsFopen, lhsFopen64, lhsConnect,
    lhsDlopen, lhsDlmopen, lhsPread, lhsReadv, lhsPreadv, lhsSendfile,
    lhsCopyFileRange, lhsSplice, lhsLink, lhsLinkat, lhsRename, lhsRenameat,
    lhsRenameat2, lhsGetenv, lhsUname, lhsSysconf, lhsClockGettime,
    lhsGettimeofday, lhsTime, lhsGetrandom

  OpenContext* = object
    path*: cstring
    flags*: cint
    mode*: cint
    result*: cint
    symbol: LinuxHookSymbol
    nextIndex: int

  OpenatContext* = object
    dirfd*: cint
    path*: cstring
    flags*: cint
    mode*: cint
    result*: cint
    symbol: LinuxHookSymbol
    nextIndex: int

  CloseContext* = object
    fd*: cint
    result*: cint
    nextIndex: int

  ReadContext* = object
    fd*: cint
    buf*: pointer
    count*: csize_t
    result*: clong
    nextIndex: int

  PreadContext* = object
    fd*: cint
    buf*: pointer
    count*: csize_t
    offset*: clong
    result*: clong
    nextIndex: int

  ReadvContext* = object
    fd*: cint
    iov*: pointer
    iovcnt*: cint
    result*: clong
    nextIndex: int

  PreadvContext* = object
    fd*: cint
    iov*: pointer
    iovcnt*: cint
    offset*: clong
    result*: clong
    nextIndex: int

  WriteContext* = object
    fd*: cint
    buf*: pointer
    count*: csize_t
    result*: clong
    nextIndex: int

  StatContext* = object
    path*: cstring
    buf*: pointer
    result*: cint
    symbol: LinuxHookSymbol
    nextIndex: int

  OpendirContext* = object
    path*: cstring
    result*: pointer
    nextIndex: int

  ReaddirContext* = object
    dirp*: pointer
    result*: pointer
    nextIndex: int

  ClosedirContext* = object
    dirp*: pointer
    result*: cint
    nextIndex: int

  FopenContext* = object
    path*: cstring
    mode*: cstring
    result*: pointer
    symbol: LinuxHookSymbol
    nextIndex: int

  FreadContext* = object
    data*: pointer
    size*: csize_t
    nmemb*: csize_t
    stream*: pointer
    result*: csize_t
    nextIndex: int

  FcloseContext* = object
    stream*: pointer
    result*: cint
    nextIndex: int

  ConnectContext* = object
    fd*: cint
    address*: pointer
    addrLen*: uint32
    result*: cint
    nextIndex: int

  PipeContext* = object
    ## IM-3 — `pipe(2)`. `fds` points at the caller's `int[2]`, filled by the
    ## real call; a hook reads it only AFTER `callNext`/`callReal` returns 0.
    fds*: ptr cint
    result*: cint
    nextIndex: int

  Pipe2Context* = object
    ## IM-3 — `pipe2(2)`. Separate from `PipeContext` because the extra `flags`
    ## argument is part of the ABI; the observation logic is identical.
    fds*: ptr cint
    flags*: cint
    result*: cint
    nextIndex: int

  SocketpairContext* = object
    ## IM-3 — `socketpair(2)`. `sv` points at the caller's `int[2]`.
    domain*: cint
    typ*: cint
    protocol*: cint
    sv*: ptr cint
    result*: cint
    nextIndex: int

  SendfileContext* = object
    outFd*: cint
    inFd*: cint
    offset*: pointer
    count*: csize_t
    result*: clong
    nextIndex: int

  CopyFileRangeContext* = object
    inFd*: cint
    offIn*: pointer
    outFd*: cint
    offOut*: pointer
    length*: csize_t
    flags*: cuint
    result*: clong
    nextIndex: int

  SpliceContext* = object
    fdIn*: cint
    offIn*: pointer
    fdOut*: cint
    offOut*: pointer
    length*: csize_t
    flags*: cuint
    result*: clong
    nextIndex: int

  LinkContext* = object
    oldPath*: cstring
    newPath*: cstring
    result*: cint
    symbol: LinuxHookSymbol
    nextIndex: int

  LinkatContext* = object
    oldDirfd*: cint
    oldPath*: cstring
    newDirfd*: cint
    newPath*: cstring
    flags*: cint
    result*: cint
    nextIndex: int

  RenameContext* = object
    oldPath*: cstring
    newPath*: cstring
    result*: cint
    symbol: LinuxHookSymbol
    nextIndex: int

  RenameatContext* = object
    oldDirfd*: cint
    oldPath*: cstring
    newDirfd*: cint
    newPath*: cstring
    flags*: cuint
    result*: cint
    symbol: LinuxHookSymbol
    nextIndex: int

  DlopenContext* = object
    path*: cstring
    flags*: cint
    result*: pointer
    nextIndex: int

  DlmopenContext* = object
    namespaceId*: clong
    path*: cstring
    flags*: cint
    result*: pointer
    nextIndex: int

  DlsymContext* = object
    handle*: pointer
    name*: cstring
    result*: pointer
    nextIndex: int

  MmapContext* = object
    address*: pointer
    length*: csize_t
    prot*: cint
    flags*: cint
    fd*: cint
    offset*: clong
    result*: pointer
    nextIndex: int

  MprotectContext* = object
    address*: pointer
    length*: csize_t
    prot*: cint
    result*: cint
    nextIndex: int

  MunmapContext* = object
    address*: pointer
    length*: csize_t
    result*: cint
    nextIndex: int

  MremapContext* = object
    oldAddress*: pointer
    oldSize*: csize_t
    newSize*: csize_t
    flags*: cint
    newAddress*: pointer
    result*: pointer
    nextIndex: int

  GetenvContext* = object
    name*: cstring
    result*: cstring
    nextIndex: int

  UnameContext* = object
    buf*: pointer
    result*: cint
    nextIndex: int

  SysconfContext* = object
    name*: cint
    result*: clong
    nextIndex: int

  ClockGettimeContext* = object
    clockId*: cint
    timespecPtr*: pointer
    result*: cint
    nextIndex: int

  GettimeofdayContext* = object
    timevalPtr*: pointer
    timezonePtr*: pointer
    result*: cint
    nextIndex: int

  TimeContext* = object
    timePtr*: pointer
    result*: clong
    nextIndex: int

  GetrandomContext* = object
    buf*: pointer
    buflen*: csize_t
    flags*: cuint
    result*: clong
    nextIndex: int

  LinuxEntropySource* = enum
    ## The libc entropy entry points hooked BESIDES `getrandom` (which keeps its
    ## own context because it has three distinct entry paths: libc symbol, raw
    ## syscall and vDSO). The enum's string values are the exact names that go
    ## into the `mrNonDeterministic` record's `path`, so the recorded identity
    ## cannot drift from the symbol that was hooked.
    lesGetentropy = "getentropy"
    lesArc4random = "arc4random"
    lesArc4randomBuf = "arc4random_buf"
    lesArc4randomUniform = "arc4random_uniform"

  EntropyContext* = object
    ## One context for all four sources: they differ only in which fields are
    ## meaningful, and a hook that only records evidence reads `source` alone.
    source*: LinuxEntropySource
    buf*: pointer         ## getentropy / arc4random_buf destination
    length*: csize_t      ## getentropy / arc4random_buf byte count
    upper*: cuint         ## arc4random_uniform exclusive bound
    value*: cuint         ## arc4random / arc4random_uniform RESULT
    result*: cint         ## getentropy RESULT (0 on success, -1 on failure)
    nextIndex: int

  ForkContext* = object
    result*: PidT
    nextIndex: int

  ExecveContext* = object
    path*: cstring
    argv*: cstringArray
    envp*: cstringArray
    result*: cint
    nextIndex: int

  PosixSpawnContext* = object
    pid*: ptr PidT
    path*: cstring
    fileActions*: pointer
    attrp*: pointer
    argv*: cstringArray
    envp*: cstringArray
    result*: cint
    symbol: LinuxHookSymbol
    nextIndex: int

  ExitContext* = object
    status*: cint
    nextIndex: int

  RawSyscallPatchStatus* = object
    installed*: bool
    diagnostic*: LinuxRawSyscallDiagnostic
    stage*: LinuxPatchStage
    osErrno*: cint
    target*: pointer

  InlineSyscallPatchStatus* = object
    attempted*: bool
    handlerInstalled*: bool
    patchedSites*: int
    scanDiagnostic*: LinuxRawSyscallDiagnostic
    installDiagnostic*: LinuxRawSyscallDiagnostic
    firstPatchDiagnostic*: LinuxRawSyscallDiagnostic
    firstPatchStage*: LinuxPatchStage
    firstPatchErrno*: cint
    firstPatchAddress*: uint

  AnonymousExecutableRange = object
    start: uint
    stop: uint

  OpenHook* = proc(ctx: var OpenContext) {.raises: [].}
  OpenatHook* = proc(ctx: var OpenatContext) {.raises: [].}
  CloseHook* = proc(ctx: var CloseContext) {.raises: [].}
  ReadHook* = proc(ctx: var ReadContext) {.raises: [].}
  PreadHook* = proc(ctx: var PreadContext) {.raises: [].}
  ReadvHook* = proc(ctx: var ReadvContext) {.raises: [].}
  PreadvHook* = proc(ctx: var PreadvContext) {.raises: [].}
  WriteHook* = proc(ctx: var WriteContext) {.raises: [].}
  StatHook* = proc(ctx: var StatContext) {.raises: [].}
  OpendirHook* = proc(ctx: var OpendirContext) {.raises: [].}
  ReaddirHook* = proc(ctx: var ReaddirContext) {.raises: [].}
  ClosedirHook* = proc(ctx: var ClosedirContext) {.raises: [].}
  FopenHook* = proc(ctx: var FopenContext) {.raises: [].}
  FreadHook* = proc(ctx: var FreadContext) {.raises: [].}
  FcloseHook* = proc(ctx: var FcloseContext) {.raises: [].}
  ConnectHook* = proc(ctx: var ConnectContext) {.raises: [].}
  PipeHook* = proc(ctx: var PipeContext) {.raises: [].}
  Pipe2Hook* = proc(ctx: var Pipe2Context) {.raises: [].}
  SocketpairHook* = proc(ctx: var SocketpairContext) {.raises: [].}
  SendfileHook* = proc(ctx: var SendfileContext) {.raises: [].}
  CopyFileRangeHook* = proc(ctx: var CopyFileRangeContext) {.raises: [].}
  SpliceHook* = proc(ctx: var SpliceContext) {.raises: [].}
  LinkHook* = proc(ctx: var LinkContext) {.raises: [].}
  LinkatHook* = proc(ctx: var LinkatContext) {.raises: [].}
  RenameHook* = proc(ctx: var RenameContext) {.raises: [].}
  RenameatHook* = proc(ctx: var RenameatContext) {.raises: [].}
  DlopenHook* = proc(ctx: var DlopenContext) {.raises: [].}
  DlmopenHook* = proc(ctx: var DlmopenContext) {.raises: [].}
  DlsymHook* = proc(ctx: var DlsymContext) {.raises: [].}
  MmapHook* = proc(ctx: var MmapContext) {.raises: [].}
  MprotectHook* = proc(ctx: var MprotectContext) {.raises: [].}
  MunmapHook* = proc(ctx: var MunmapContext) {.raises: [].}
  MremapHook* = proc(ctx: var MremapContext) {.raises: [].}
  GetenvHook* = proc(ctx: var GetenvContext) {.raises: [].}
  UnameHook* = proc(ctx: var UnameContext) {.raises: [].}
  SysconfHook* = proc(ctx: var SysconfContext) {.raises: [].}
  ClockGettimeHook* = proc(ctx: var ClockGettimeContext) {.raises: [].}
  GettimeofdayHook* = proc(ctx: var GettimeofdayContext) {.raises: [].}
  TimeHook* = proc(ctx: var TimeContext) {.raises: [].}
  GetrandomHook* = proc(ctx: var GetrandomContext) {.raises: [].}
  EntropyHook* = proc(ctx: var EntropyContext) {.raises: [].}
  ForkHook* = proc(ctx: var ForkContext) {.raises: [].}
  ExecveHook* = proc(ctx: var ExecveContext) {.raises: [].}
  PosixSpawnHook* = proc(ctx: var PosixSpawnContext) {.raises: [].}
  ExitHook* = proc(ctx: var ExitContext) {.raises: [].}
  RawSyscallHook* = proc(number, a1, a2, a3, a4, a5, a6, result: clong;
                         inlineTrap: cint) {.raises: [].}

  OpenHookEntry = object
    priority: int
    callback: OpenHook
  OpenatHookEntry = object
    priority: int
    callback: OpenatHook
  CloseHookEntry = object
    priority: int
    callback: CloseHook
  ReadHookEntry = object
    priority: int
    callback: ReadHook
  PreadHookEntry = object
    priority: int
    callback: PreadHook
  ReadvHookEntry = object
    priority: int
    callback: ReadvHook
  PreadvHookEntry = object
    priority: int
    callback: PreadvHook
  WriteHookEntry = object
    priority: int
    callback: WriteHook
  StatHookEntry = object
    priority: int
    callback: StatHook
  OpendirHookEntry = object
    priority: int
    callback: OpendirHook
  ReaddirHookEntry = object
    priority: int
    callback: ReaddirHook
  ClosedirHookEntry = object
    priority: int
    callback: ClosedirHook
  FopenHookEntry = object
    priority: int
    callback: FopenHook
  FreadHookEntry = object
    priority: int
    callback: FreadHook
  FcloseHookEntry = object
    priority: int
    callback: FcloseHook
  ConnectHookEntry = object
    priority: int
    callback: ConnectHook
  PipeHookEntry = object
    priority: int
    callback: PipeHook
  Pipe2HookEntry = object
    priority: int
    callback: Pipe2Hook
  SocketpairHookEntry = object
    priority: int
    callback: SocketpairHook
  SendfileHookEntry = object
    priority: int
    callback: SendfileHook
  CopyFileRangeHookEntry = object
    priority: int
    callback: CopyFileRangeHook
  SpliceHookEntry = object
    priority: int
    callback: SpliceHook
  LinkHookEntry = object
    priority: int
    callback: LinkHook
  LinkatHookEntry = object
    priority: int
    callback: LinkatHook
  RenameHookEntry = object
    priority: int
    callback: RenameHook
  RenameatHookEntry = object
    priority: int
    callback: RenameatHook
  DlopenHookEntry = object
    priority: int
    callback: DlopenHook
  DlmopenHookEntry = object
    priority: int
    callback: DlmopenHook
  DlsymHookEntry = object
    priority: int
    callback: DlsymHook
  MmapHookEntry = object
    priority: int
    callback: MmapHook
  MprotectHookEntry = object
    priority: int
    callback: MprotectHook
  MunmapHookEntry = object
    priority: int
    callback: MunmapHook
  MremapHookEntry = object
    priority: int
    callback: MremapHook
  GetenvHookEntry = object
    priority: int
    callback: GetenvHook
  UnameHookEntry = object
    priority: int
    callback: UnameHook
  SysconfHookEntry = object
    priority: int
    callback: SysconfHook
  ClockGettimeHookEntry = object
    priority: int
    callback: ClockGettimeHook
  GettimeofdayHookEntry = object
    priority: int
    callback: GettimeofdayHook
  TimeHookEntry = object
    priority: int
    callback: TimeHook
  GetrandomHookEntry = object
    priority: int
    callback: GetrandomHook
  EntropyHookEntry = object
    priority: int
    callback: EntropyHook
  ForkHookEntry = object
    priority: int
    callback: ForkHook
  ExecveHookEntry = object
    priority: int
    callback: ExecveHook
  PosixSpawnHookEntry = object
    priority: int
    callback: PosixSpawnHook
  ExitHookEntry = object
    priority: int
    callback: ExitHook

{.emit: """
#define _GNU_SOURCE
#include <alloca.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
""".}

# The exec-target classifier shared with the consumer's root spawn: see that
# file's header comment and "AN EXEC INTO AN IMAGE THE SHIM CANNOT ENTER IS
# EVENT-LOSS" below. Included (all `static`) rather than linked, so this shim
# exports no symbol of it.
{.emit: execImageIncludeDirective.}

{.emit: """
typedef long ssize_like_t;
typedef int (*ct_open_hook_fn)(char *, int, int);
typedef int (*ct_openat_hook_fn)(int, char *, int, int);
typedef int (*ct_close_hook_fn)(int);
typedef ssize_like_t (*ct_read_hook_fn)(int, void *, size_t);
typedef ssize_like_t (*ct_pread_hook_fn)(int, void *, size_t, long);
typedef ssize_like_t (*ct_readv_hook_fn)(int, void *, int);
typedef ssize_like_t (*ct_preadv_hook_fn)(int, void *, int, long);
typedef ssize_like_t (*ct_write_hook_fn)(int, void *, size_t);
typedef int (*ct_stat_hook_fn)(char *, void *);
typedef void *(*ct_opendir_hook_fn)(char *);
typedef void *(*ct_readdir_hook_fn)(void *);
typedef int (*ct_closedir_hook_fn)(void *);
typedef void *(*ct_fopen_hook_fn)(char *, char *);
typedef size_t (*ct_fread_hook_fn)(void *, size_t, size_t, void *);
typedef int (*ct_fclose_hook_fn)(void *);
typedef int (*ct_connect_hook_fn)(int, void *, unsigned int);
typedef int (*ct_pipe_hook_fn)(void *);
typedef int (*ct_pipe2_hook_fn)(void *, int);
typedef int (*ct_socketpair_hook_fn)(int, int, int, void *);
typedef ssize_like_t (*ct_sendfile_hook_fn)(int, int, void *, size_t);
typedef ssize_like_t (*ct_copy_file_range_hook_fn)(int, void *, int, void *,
                                                   size_t, unsigned int);
typedef ssize_like_t (*ct_splice_hook_fn)(int, void *, int, void *, size_t,
                                          unsigned int);
typedef int (*ct_link_hook_fn)(char *, char *);
typedef int (*ct_linkat_hook_fn)(int, char *, int, char *, int);
typedef int (*ct_rename_hook_fn)(char *, char *);
typedef int (*ct_renameat_hook_fn)(int, char *, int, char *);
typedef int (*ct_renameat2_hook_fn)(int, char *, int, char *, unsigned int);
typedef void *(*ct_dlopen_hook_fn)(char *, int);
typedef void *(*ct_dlmopen_hook_fn)(long, char *, int);
typedef void *(*ct_dlsym_hook_fn)(void *, char *);
typedef void *(*ct_mmap_hook_fn)(void *, size_t, int, int, int, long);
typedef int (*ct_mprotect_hook_fn)(void *, size_t, int);
typedef int (*ct_munmap_hook_fn)(void *, size_t);
typedef void *(*ct_mremap_hook_fn)(void *, size_t, size_t, int, void *);
typedef char *(*ct_getenv_hook_fn)(char *);
typedef int (*ct_uname_hook_fn)(void *);
typedef long (*ct_sysconf_hook_fn)(int);
typedef int (*ct_clock_gettime_hook_fn)(int, void *);
typedef int (*ct_gettimeofday_hook_fn)(void *, void *);
typedef long (*ct_time_hook_fn)(void *);
typedef ssize_like_t (*ct_getrandom_hook_fn)(void *, size_t, unsigned int);
/* ENTROPY-PARITY — glibc >= 2.36 exports the BSD entropy set
   (getentropy since 2.25; arc4random/arc4random_buf/arc4random_uniform since
   2.36) and real programs use it in preference to getrandom(2). The macOS shim
   has always recorded these APIs; Linux hooked only getrandom, so the SAME
   program was flagged as an entropy consumer on macOS and invisible here.
   They are hooked as four distinct symbols (not folded into getrandom) so the
   record names the API the program actually called. */
typedef int (*ct_getentropy_hook_fn)(void *, size_t);
typedef unsigned int (*ct_arc4random_hook_fn)(void);
typedef void (*ct_arc4random_buf_hook_fn)(void *, size_t);
typedef unsigned int (*ct_arc4random_uniform_hook_fn)(unsigned int);
typedef pid_t (*ct_fork_hook_fn)(void);
typedef int (*ct_execve_hook_fn)(char *, char **, char **);
typedef int (*ct_posix_spawn_hook_fn)(pid_t *, char *, void *, void *,
                                      char **, char **);
typedef void (*ct_exit_hook_fn)(int);

typedef int (*ct_open_real_fn)(const char *, int, ...);
typedef int (*ct_openat_real_fn)(int, const char *, int, ...);
typedef int (*ct_close_real_fn)(int);
typedef ssize_t (*ct_read_real_fn)(int, void *, size_t);
typedef ssize_t (*ct_pread_real_fn)(int, void *, size_t, off_t);
typedef ssize_t (*ct_readv_real_fn)(int, const struct iovec *, int);
typedef ssize_t (*ct_preadv_real_fn)(int, const struct iovec *, int, off_t);
typedef ssize_t (*ct_write_real_fn)(int, const void *, size_t);
typedef int (*ct_stat_real_fn)(const char *, struct stat *);
typedef int (*ct_xstat_real_fn)(int, const char *, struct stat *);
typedef DIR *(*ct_opendir_real_fn)(const char *);
typedef struct dirent *(*ct_readdir_real_fn)(DIR *);
typedef int (*ct_closedir_real_fn)(DIR *);
typedef FILE *(*ct_fopen_real_fn)(const char *, const char *);
typedef size_t (*ct_fread_real_fn)(void *, size_t, size_t, FILE *);
typedef int (*ct_fclose_real_fn)(FILE *);
typedef int (*ct_connect_real_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*ct_pipe_real_fn)(int *);
typedef int (*ct_pipe2_real_fn)(int *, int);
typedef int (*ct_socketpair_real_fn)(int, int, int, int *);
typedef ssize_t (*ct_sendfile_real_fn)(int, int, off_t *, size_t);
typedef ssize_t (*ct_copy_file_range_real_fn)(int, off64_t *, int, off64_t *,
                                              size_t, unsigned int);
typedef ssize_t (*ct_splice_real_fn)(int, loff_t *, int, loff_t *, size_t,
                                     unsigned int);
typedef int (*ct_link_real_fn)(const char *, const char *);
typedef int (*ct_linkat_real_fn)(int, const char *, int, const char *, int);
typedef int (*ct_rename_real_fn)(const char *, const char *);
typedef int (*ct_renameat_real_fn)(int, const char *, int, const char *);
typedef int (*ct_renameat2_real_fn)(int, const char *, int, const char *,
                                    unsigned int);
typedef void *(*ct_dlopen_real_fn)(const char *, int);
typedef void *(*ct_dlmopen_real_fn)(Lmid_t, const char *, int);
typedef void *(*ct_dlsym_real_fn)(void *, const char *);
typedef void *(*ct_mmap_real_fn)(void *, size_t, int, int, int, off_t);
typedef int (*ct_mprotect_real_fn)(void *, size_t, int);
typedef int (*ct_munmap_real_fn)(void *, size_t);
typedef void *(*ct_mremap_real_fn)(void *, size_t, size_t, int, ...);
typedef char *(*ct_getenv_real_fn)(const char *);
typedef int (*ct_uname_real_fn)(struct utsname *);
typedef long (*ct_sysconf_real_fn)(int);
typedef int (*ct_clock_gettime_real_fn)(clockid_t, struct timespec *);
typedef int (*ct_gettimeofday_real_fn)(struct timeval *, void *);
typedef time_t (*ct_time_real_fn)(time_t *);
typedef ssize_t (*ct_getrandom_real_fn)(void *, size_t, unsigned int);
typedef int (*ct_getentropy_real_fn)(void *, size_t);
typedef unsigned int (*ct_arc4random_real_fn)(void);
typedef void (*ct_arc4random_buf_real_fn)(void *, size_t);
typedef unsigned int (*ct_arc4random_uniform_real_fn)(unsigned int);
typedef pid_t (*ct_fork_real_fn)(void);
typedef int (*ct_execve_real_fn)(const char *, char *const [], char *const []);
typedef int (*ct_execvp_real_fn)(const char *, char *const []);
typedef int (*ct_execvpe_real_fn)(const char *, char *const [], char *const []);
typedef int (*ct_fexecve_real_fn)(int, char *const [], char *const []);
typedef int (*ct_execveat_real_fn)(int, const char *, char *const [],
                                   char *const [], int);
typedef int (*ct_posix_spawn_real_fn)(pid_t *, const char *,
                                      const posix_spawn_file_actions_t *,
                                      const posix_spawnattr_t *,
                                      char *const [], char *const []);

static const char *ct_linux_preload_shim_env_name = NULL;

static ct_open_hook_fn ct_open_hook = NULL;
static ct_open_hook_fn ct_open64_hook = NULL;
static ct_openat_hook_fn ct_openat_hook = NULL;
static ct_openat_hook_fn ct_openat64_hook = NULL;
static ct_close_hook_fn ct_close_hook = NULL;
static ct_read_hook_fn ct_read_hook = NULL;
static ct_pread_hook_fn ct_pread_hook = NULL;
static ct_readv_hook_fn ct_readv_hook = NULL;
static ct_preadv_hook_fn ct_preadv_hook = NULL;
static ct_write_hook_fn ct_write_hook = NULL;
static ct_stat_hook_fn ct_stat_hook = NULL;
static ct_stat_hook_fn ct_lstat_hook = NULL;
static ct_opendir_hook_fn ct_opendir_hook = NULL;
static ct_readdir_hook_fn ct_readdir_hook = NULL;
static ct_closedir_hook_fn ct_closedir_hook = NULL;
static ct_fopen_hook_fn ct_fopen_hook = NULL;
static ct_fopen_hook_fn ct_fopen64_hook = NULL;
static ct_fread_hook_fn ct_fread_hook = NULL;
static ct_fclose_hook_fn ct_fclose_hook = NULL;
static ct_connect_hook_fn ct_connect_hook = NULL;
static ct_pipe_hook_fn ct_pipe_hook = NULL;
static ct_pipe2_hook_fn ct_pipe2_hook = NULL;
static ct_socketpair_hook_fn ct_socketpair_hook = NULL;
static ct_sendfile_hook_fn ct_sendfile_hook = NULL;
static ct_copy_file_range_hook_fn ct_copy_file_range_hook = NULL;
static ct_splice_hook_fn ct_splice_hook = NULL;
static ct_link_hook_fn ct_link_hook = NULL;
static ct_linkat_hook_fn ct_linkat_hook = NULL;
static ct_rename_hook_fn ct_rename_hook = NULL;
static ct_renameat_hook_fn ct_renameat_hook = NULL;
static ct_renameat2_hook_fn ct_renameat2_hook = NULL;
static ct_dlopen_hook_fn ct_dlopen_hook = NULL;
static ct_dlmopen_hook_fn ct_dlmopen_hook = NULL;
static ct_dlsym_hook_fn ct_dlsym_hook = NULL;
static ct_mmap_hook_fn ct_mmap_hook = NULL;
static ct_mprotect_hook_fn ct_mprotect_hook = NULL;
static ct_munmap_hook_fn ct_munmap_hook = NULL;
static ct_mremap_hook_fn ct_mremap_hook = NULL;
static ct_getenv_hook_fn ct_getenv_hook = NULL;
static ct_uname_hook_fn ct_uname_hook = NULL;
static ct_sysconf_hook_fn ct_sysconf_hook = NULL;
static ct_clock_gettime_hook_fn ct_clock_gettime_hook = NULL;
static ct_gettimeofday_hook_fn ct_gettimeofday_hook = NULL;
static ct_time_hook_fn ct_time_hook = NULL;
static ct_getrandom_hook_fn ct_getrandom_hook = NULL;
static ct_getentropy_hook_fn ct_getentropy_hook = NULL;
static ct_arc4random_hook_fn ct_arc4random_hook = NULL;
static ct_arc4random_buf_hook_fn ct_arc4random_buf_hook = NULL;
static ct_arc4random_uniform_hook_fn ct_arc4random_uniform_hook = NULL;
static ct_fork_hook_fn ct_fork_hook = NULL;
static ct_execve_hook_fn ct_execve_hook = NULL;
static ct_posix_spawn_hook_fn ct_posix_spawn_hook = NULL;
static ct_posix_spawn_hook_fn ct_posix_spawnp_hook = NULL;
static ct_exit_hook_fn ct_exit_hook = NULL;
typedef void (*ct_raw_syscall_hook_fn)(long, long, long, long, long, long, long,
                                       long, int);
static ct_raw_syscall_hook_fn ct_raw_syscall_hook = NULL;
/* A libc syscall patch is process-wide; hook state belongs to each loaded
 * monitor. Keep the installing monitor and compatible subscribers together. */
#define CT_RAW_OWNER_ABI_V2 0x4354524157303032ULL
#include <pthread.h>
#include <linux/futex.h>
#include <sched.h>
#define CT_RAW_SUBSCRIBER_CAP 16
typedef void (*ct_raw_enqueue_fn)(long, const long *, long, int, unsigned long);
typedef void (*ct_raw_flush_fn)(void);
typedef void (*ct_library_scan_fn)(const char *);
static ct_library_scan_fn ct_library_scan;
static ct_library_scan_fn ct_library_subscriber_scan[CT_RAW_SUBSCRIBER_CAP];
static ct_library_scan_fn ct_library_owner_scan;
static ct_raw_syscall_hook_fn ct_raw_subscribers[CT_RAW_SUBSCRIBER_CAP];
static ct_raw_enqueue_fn ct_raw_subscriber_enqueue[CT_RAW_SUBSCRIBER_CAP];
static ct_raw_flush_fn ct_raw_subscriber_flush[CT_RAW_SUBSCRIBER_CAP];
static int ct_raw_subscriber_lock = 0;
static void *ct_raw_owner_target = NULL;
static void *ct_raw_owner_handle = NULL;
static void *ct_raw_self_handle = NULL;
static char *ct_raw_owner_join_reason = "not-attempted";
static char ct_raw_owner_join_image[4096];
static char ct_raw_owner_refusal[64];
char *ct_linux_preload_raw_owner_join_reason(void) {
  return ct_raw_owner_join_reason;
}
char *ct_linux_preload_raw_owner_join_image(void) {
  return ct_raw_owner_join_image;
}

#define CT_RAW_SYSCALL_EVENT_CAP 4096
#define CT_RAW_SYSCALL_SOURCE_LIBC 0
#define CT_RAW_SYSCALL_SOURCE_INLINE 1
/* TRAP-TIME CAPTURE. A trapped inline syscall is CLASSIFIED later, outside
 * signal context (`drainInlineRawSyscallEvents` in linux_preload.nim), but
 * everything the classification reads through a pointer or a descriptor is
 * taken HERE, while the trapped call's arguments still mean what they meant
 * to the kernel: the path strings, the directory a relative path was resolved
 * against (the working directory, or the directory fd's /proc/self/fd link),
 * a symbolic link's target, openat2's open_how, and the file each descriptor
 * of a read/copy named. Read later, a path pointer may name freed or reused
 * memory, or unmapped memory (a crash at exit); the working directory and the
 * descriptors may have changed. Each capture is a raw syscall or a memcpy of
 * memory the kernel just read for the same call, so it is async-signal-safe
 * and touches no allocator. The strings go to a static bump arena; one that
 * does not fit marks the event CT_RAW_CAPTURE_FAILED, which the classifier
 * reports as event-loss.
 *
 * Slots are reserved atomically and published with a release store of
 * `state`, so concurrent traps on several threads never share a slot and the
 * drain never reads a half-written one. `pid` scopes an event to the process
 * that trapped it: a fork child inherits a copy of the buffer, and a vfork
 * child shares it, and neither may classify (or claim) the parent's events. */
#define CT_RAW_ARENA_CAP (2ul << 20)
#define CT_RAW_CAPTURE_PATH_MAX 4096
#define CT_RAW_CAP_BASE 0   /* directory a relative path was resolved against */
#define CT_RAW_CAP_PATH 1   /* the pathname argument, as passed */
#define CT_RAW_CAP_TARGET 2 /* symlink(at)'s target */
#define CT_RAW_CAP_FD0 3    /* /proc/self/fd link of the first descriptor */
#define CT_RAW_CAP_FD1 4    /* ... of the second (sendfile/copy/splice) */
#define CT_RAW_CAP_SLOTS 5
#define CT_RAW_CAPTURE_NONE 0
#define CT_RAW_CAPTURE_OK 1
#define CT_RAW_CAPTURE_FAILED 2
#define CT_RAW_EVENT_FREE 0
#define CT_RAW_EVENT_READY 1
#define CT_RAW_EVENT_DRAINED 2
struct ct_raw_syscall_event {
  long nr;
  long args[6];
  long result;
  int source;
  unsigned long address;
  int pid;
  int state;
  int capture;
  int cap_mask;
  unsigned long cap_off[CT_RAW_CAP_SLOTS];
  unsigned long cap_len[CT_RAW_CAP_SLOTS];
  int how_set;
  unsigned long long how_flags;
  unsigned long long how_mode;
};
static struct ct_raw_syscall_event ct_raw_syscall_events[CT_RAW_SYSCALL_EVENT_CAP];
static long ct_raw_syscall_event_reserved = 0;
static volatile sig_atomic_t ct_raw_syscall_event_overflow_value = 0;
static char ct_raw_capture_arena[CT_RAW_ARENA_CAP];
static unsigned long ct_raw_capture_arena_used = 0;

static ct_open_real_fn real_open_ptr = NULL;
static ct_open_real_fn real_open64_ptr = NULL;
static ct_openat_real_fn real_openat_ptr = NULL;
static ct_openat_real_fn real_openat64_ptr = NULL;
static ct_close_real_fn real_close_ptr = NULL;
static ct_read_real_fn real_read_ptr = NULL;
static ct_pread_real_fn real_pread_ptr = NULL;
static ct_pread_real_fn real_pread64_ptr = NULL;
static ct_readv_real_fn real_readv_ptr = NULL;
static ct_preadv_real_fn real_preadv_ptr = NULL;
static ct_preadv_real_fn real_preadv64_ptr = NULL;
static ct_write_real_fn real_write_ptr = NULL;
static ct_stat_real_fn real_stat_ptr = NULL;
static ct_stat_real_fn real_lstat_ptr = NULL;
static ct_xstat_real_fn real_xstat_ptr = NULL;
static ct_xstat_real_fn real_lxstat_ptr = NULL;
static ct_opendir_real_fn real_opendir_ptr = NULL;
static ct_readdir_real_fn real_readdir_ptr = NULL;
static ct_closedir_real_fn real_closedir_ptr = NULL;
static ct_fopen_real_fn real_fopen_ptr = NULL;
static ct_fopen_real_fn real_fopen64_ptr = NULL;
static ct_fread_real_fn real_fread_ptr = NULL;
static ct_fclose_real_fn real_fclose_ptr = NULL;
static ct_connect_real_fn real_connect_ptr = NULL;
static ct_pipe_real_fn real_pipe_ptr = NULL;
static ct_pipe2_real_fn real_pipe2_ptr = NULL;
static ct_socketpair_real_fn real_socketpair_ptr = NULL;
static ct_sendfile_real_fn real_sendfile_ptr = NULL;
static ct_copy_file_range_real_fn real_copy_file_range_ptr = NULL;
static ct_splice_real_fn real_splice_ptr = NULL;
static ct_link_real_fn real_link_ptr = NULL;
static ct_linkat_real_fn real_linkat_ptr = NULL;
static ct_rename_real_fn real_rename_ptr = NULL;
static ct_renameat_real_fn real_renameat_ptr = NULL;
static ct_renameat2_real_fn real_renameat2_ptr = NULL;
static ct_dlopen_real_fn real_dlopen_ptr = NULL;
static ct_dlmopen_real_fn real_dlmopen_ptr = NULL;
static ct_dlsym_real_fn real_dlsym_ptr = NULL;
static ct_mmap_real_fn real_mmap_ptr = NULL;
static ct_mprotect_real_fn real_mprotect_ptr = NULL;
static ct_munmap_real_fn real_munmap_ptr = NULL;
static ct_mremap_real_fn real_mremap_ptr = NULL;
static ct_getenv_real_fn real_getenv_ptr = NULL;
static ct_uname_real_fn real_uname_ptr = NULL;
static ct_sysconf_real_fn real_sysconf_ptr = NULL;
static ct_clock_gettime_real_fn real_clock_gettime_ptr = NULL;
static ct_gettimeofday_real_fn real_gettimeofday_ptr = NULL;
static ct_time_real_fn real_time_ptr = NULL;
static ct_getrandom_real_fn real_getrandom_ptr = NULL;
static ct_getentropy_real_fn real_getentropy_ptr = NULL;
static ct_arc4random_real_fn real_arc4random_ptr = NULL;
static ct_arc4random_buf_real_fn real_arc4random_buf_ptr = NULL;
static ct_arc4random_uniform_real_fn real_arc4random_uniform_ptr = NULL;
static ct_fork_real_fn real_fork_ptr = NULL;
static ct_execve_real_fn real_execve_ptr = NULL;
static ct_execvp_real_fn real_execvp_ptr = NULL;
static ct_execvpe_real_fn real_execvpe_ptr = NULL;
static ct_fexecve_real_fn real_fexecve_ptr = NULL;
static ct_execveat_real_fn real_execveat_ptr = NULL;
static ct_posix_spawn_real_fn real_posix_spawn_ptr = NULL;
static ct_posix_spawn_real_fn real_posix_spawnp_ptr = NULL;

/* Entry points that are only OBSERVED (no hook chain): the real call runs,
 * then one observer callback records what it means. See "OBSERVE-ONLY
 * INTERPOSITIONS" below. */
typedef int (*ct_access_real_fn)(const char *, int);
typedef int (*ct_faccessat_real_fn)(int, const char *, int, int);
typedef ssize_t (*ct_readlink_real_fn)(const char *, char *, size_t);
typedef ssize_t (*ct_readlinkat_real_fn)(int, const char *, char *, size_t);
typedef char *(*ct_realpath_real_fn)(const char *, char *);
typedef char *(*ct_canonicalize_real_fn)(const char *);
typedef int (*ct_scandir_real_fn)(const char *, void *, void *, void *);
typedef DIR *(*ct_fdopendir_real_fn)(int);
typedef int (*ct_statx_real_fn)(int, const char *, int, unsigned int, void *);
typedef int (*ct_fstatat_real_fn)(int, const char *, void *, int);
typedef int (*ct_pkey_mprotect_real_fn)(void *, size_t, int, int);
typedef char *(*ct_realpath_chk_real_fn)(const char *, char *, size_t);
typedef int (*ct_eventfd_real_fn)(unsigned int, int);
typedef int (*ct_timerfd_create_real_fn)(int, int);
typedef ssize_t (*ct_readlink_chk_real_fn)(const char *, char *, size_t, size_t);
typedef ssize_t (*ct_readlinkat_chk_real_fn)(int, const char *, char *, size_t,
                                             size_t);
static ct_access_real_fn real_access_ptr = NULL;
static ct_faccessat_real_fn real_faccessat_ptr = NULL;
static ct_readlink_real_fn real_readlink_ptr = NULL;
static ct_readlinkat_real_fn real_readlinkat_ptr = NULL;
static ct_realpath_real_fn real_realpath_ptr = NULL;
static ct_canonicalize_real_fn real_canonicalize_file_name_ptr = NULL;
static ct_scandir_real_fn real_scandir_ptr = NULL;
static ct_scandir_real_fn real_scandir64_ptr = NULL;
/* glob/glob64 (see the glob interposition below). On LP64 glibc glob_t and
 * glob64_t share one layout, so one pointer type serves both. */
typedef int (*ct_glob_real_fn)(const char *, int, int (*)(const char *, int),
                               glob_t *);
static ct_glob_real_fn real_glob_ptr = NULL;
static ct_glob_real_fn real_glob64_ptr = NULL;
static ct_fdopendir_real_fn real_fdopendir_ptr = NULL;
static ct_statx_real_fn real_statx_ptr = NULL;
static ct_fstatat_real_fn real_fstatat_ptr = NULL;
static ct_fstatat_real_fn real_fstatat64_ptr = NULL;
static ct_pkey_mprotect_real_fn real_pkey_mprotect_ptr = NULL;
static ct_realpath_chk_real_fn real_realpath_chk_ptr = NULL;
static ct_eventfd_real_fn real_eventfd_ptr = NULL;
static ct_timerfd_create_real_fn real_timerfd_create_ptr = NULL;
static ct_readlink_chk_real_fn real_readlink_chk_ptr = NULL;
static ct_readlinkat_chk_real_fn real_readlinkat_chk_ptr = NULL;
typedef int (*ct_unlink_real_fn)(const char *);
typedef int (*ct_unlinkat_real_fn)(int, const char *, int);
typedef int (*ct_mkdir_real_fn)(const char *, mode_t);
typedef int (*ct_mkdirat_real_fn)(int, const char *, mode_t);
typedef int (*ct_symlink_real_fn)(const char *, const char *);
typedef int (*ct_symlinkat_real_fn)(const char *, int, const char *);
typedef int (*ct_truncate_real_fn)(const char *, off_t);
typedef int (*ct_creat_real_fn)(const char *, mode_t);
static ct_unlink_real_fn real_unlink_ptr = NULL;
static ct_unlinkat_real_fn real_unlinkat_ptr = NULL;
static ct_unlink_real_fn real_rmdir_ptr = NULL;
static ct_unlink_real_fn real_remove_ptr = NULL;
static ct_mkdir_real_fn real_mkdir_ptr = NULL;
static ct_mkdirat_real_fn real_mkdirat_ptr = NULL;
static ct_symlink_real_fn real_symlink_ptr = NULL;
static ct_symlinkat_real_fn real_symlinkat_ptr = NULL;
static ct_truncate_real_fn real_truncate_ptr = NULL;
static ct_creat_real_fn real_creat_ptr = NULL;
typedef int (*ct_mkstemp_real_fn)(char *);
typedef int (*ct_mkostemp_real_fn)(char *, int);
typedef int (*ct_mkstemps_real_fn)(char *, int);
typedef int (*ct_mkostemps_real_fn)(char *, int, int);
typedef char *(*ct_mkdtemp_real_fn)(char *);
static ct_mkstemp_real_fn real_mkstemp_ptr = NULL;
static ct_mkostemp_real_fn real_mkostemp_ptr = NULL;
static ct_mkstemps_real_fn real_mkstemps_ptr = NULL;
static ct_mkostemps_real_fn real_mkostemps_ptr = NULL;
static ct_mkdtemp_real_fn real_mkdtemp_ptr = NULL;

#define CT_INLINE_SYSCALL_SITE_CAP 4096
static unsigned long ct_inline_syscall_sites[CT_INLINE_SYSCALL_SITE_CAP];
static volatile sig_atomic_t ct_inline_syscall_site_count_value = 0;
static volatile sig_atomic_t ct_inline_syscall_trap_count_value = 0;
static volatile sig_atomic_t ct_inline_syscall_failure_count_value = 0;
static volatile sig_atomic_t ct_inline_syscall_last_nr_value = -1;
static volatile sig_atomic_t ct_inline_syscall_overflow_value = 0;
static volatile unsigned long ct_inline_syscall_last_address_value = 0;

extern void *stackable_linux_preload_resolve_next(const char *name);
extern int stackable_linux_preload_hooks_allowed(void);
extern int stackable_linux_preload_current_depth(void);
extern void stackable_linux_preload_enter_hook(void);
extern void stackable_linux_preload_exit_hook(void);
/* The raw-syscall / INT3 substrate below lives in nim-stackable-hooks'
 * ``platform/linux_raw_syscalls.nim``, whose entire ``{.emit.}`` body is
 * guarded by ``when defined(linux) and defined(amd64)``. On any other Linux
 * architecture NONE of these symbols exist, and the same module's
 * ``linuxRawSyscallSupported()`` reports ``lrsUnsupportedArchitecture``.
 *
 * The Nim side of this file already honours that predicate:
 * ``installRawSyscallWrapperPatch`` and ``installInlineSyscallPatches`` both
 * return early when ``linuxRawSyscallSupported() != lrsOk``, so on aarch64 the
 * substrate is never *used*. But a runtime guard does not stop the C below from
 * being COMPILED and REFERENCING the symbols, and ``librepro_monitor_shim.so``
 * is consumed via ``LD_PRELOAD`` — which binds every undefined symbol eagerly.
 * The result on ``eph-linux-arm64`` was that the very first monitored process
 * died before ``main``:
 *
 *   repro: symbol lookup error: .../build/lib/librepro_monitor_shim.so:
 *     undefined symbol: stackable_linux_chain_sigtrap
 *
 * So the reference has to disappear at COMPILE time, not merely go untaken at
 * run time. ``__x86_64__`` is the C-preprocessor spelling of Nim's ``amd64``
 * define, keeping this guard byte-for-byte aligned with the producing module's.
 * Every entry point the Nim ``importc``s below still exists on non-x86_64 — the
 * stubs just never touch the absent substrate. */
#if defined(__x86_64__)
extern long stackable_linux_raw_syscall6(long nr, long a1, long a2, long a3,
                                         long a4, long a5, long a6);
struct stackable_linux_syscall_regs {
  long nr;
  long args[6];
  long result;
  unsigned long trap_rip;
  unsigned long syscall_address;
  unsigned long resume_rip;
};
extern int stackable_linux_capture_syscall_regs_from_ucontext(
    void *ucontext_ptr, struct stackable_linux_syscall_regs *out);
extern long stackable_linux_replay_syscall_regs(
    const struct stackable_linux_syscall_regs *regs);
extern int stackable_linux_write_syscall_result_to_ucontext(
    void *ucontext_ptr, long result, unsigned long resume_rip);
extern int stackable_linux_chain_sigtrap(int signum, void *siginfo_ptr,
                                         void *ucontext_ptr);
#endif /* __x86_64__ */

/* Provided by shim/linux_preload.nim. Async-signal-safe: writes the
 * batched read frames + the pre-encoded committed marker via raw
 * SYS_write, then fsync/close via raw syscalls, and marks the slot
 * closed. Safe to call from a SIGTRAP handler that is about to replay
 * an inline-asm SYS_exit_group / SYS_exit — retires the pending
 * read-tail sentinel so mergeFragments does not inject a synthetic
 * kill-before-flush event-loss (M9.R.63.3 wiring). No-op when the slot
 * is not open (e.g. shim not initialised) so the handler stays safe on
 * every code path. */
extern void repro_linux_sig_safe_flush(void);

/* A raw fork-like call (fork, or clone/clone3 without CLONE_VM) creates a
 * process that runs no atfork handlers: it inherits every shim lock another
 * thread held at that instant, and recording anything there can wait on such
 * a lock forever. The libc fork hook samples whether the parent is
 * single-threaded and, when it is not, makes the child skip monitor
 * bookkeeping until exec (repro_hook_fork). These callbacks, registered by
 * linux_preload.nim, give the raw path the same treatment. */
typedef int (*ct_raw_fork_sample_fn)(void);
typedef void (*ct_raw_fork_child_fn)(int parentSingleThreaded);
static ct_raw_fork_sample_fn ct_raw_fork_sample = NULL;
static ct_raw_fork_child_fn ct_raw_fork_child = NULL;
static long ct_raw_syscall6(long nr, long a1, long a2, long a3, long a4,
                            long a5, long a6);
static int ct_raw_fork_reset_pid = 0;
static int ct_raw_subscriber_fork_pid = 0;
void ct_linux_preload_register_raw_fork(ct_raw_fork_sample_fn sample,
                                        ct_raw_fork_child_fn child) {
  ct_raw_fork_sample = sample;
  ct_raw_fork_child = child;
}

static int ct_raw_call_forks_process(long nr, long a1) {
#ifdef SYS_fork
  if (nr == SYS_fork) return 1;
#endif
#ifdef SYS_clone
  if (nr == SYS_clone) return (a1 & CLONE_VM) == 0;
#endif
#ifdef SYS_clone3
  if (nr == SYS_clone3 && a1 != 0) {
    unsigned long long flags;
    memcpy(&flags, (void *)a1, sizeof(flags));
    return (flags & CLONE_VM) == 0;
  }
#endif
  (void)a1;
  return 0;
}

/* A child cannot inherit a registration lock held by a vanished thread.
 * No loader call runs under the lock; unpublished POD slots remain invisible.
 * libc fork registers this child reset, and raw fork replay invokes it below. */
static void ct_raw_owner_after_fork_child(void) {
  __atomic_store_n(&ct_raw_subscriber_lock, 0, __ATOMIC_RELAXED);
}

/* The shim's private heap (shim/linux_private_heap.c) reclaims class locks a
 * raw fork child inherited from threads that do not exist in it. Weak: the
 * heap is linked only into glibc shim builds. */
extern void repro_linux_private_heap_after_raw_fork_child(void)
    __attribute__((weak));

static void ct_raw_fork_child_reset(void) {
  ct_raw_owner_after_fork_child();
  if (repro_linux_private_heap_after_raw_fork_child != NULL)
    repro_linux_private_heap_after_raw_fork_child();
  ct_raw_fork_reset_pid = (int)ct_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
}

/* The process-wide syscall owner already notifies its own image, but V2
 * subscribers receive only the completed syscall. Its successful child
 * return is also a lifecycle notification: reset THIS image before its first
 * Nim callback or queued event can touch an inherited lock. The owner sampled
 * its parent's thread count, not ours, so an unnotified subscriber uses the
 * conservative multi-threaded path and reports any skipped evidence.
 *
 * PID is only a deduplication key after a proven private-address-space fork;
 * a new PID alone is not sufficient (vfork/CLONE_VM share the parent's heap).
 * This also works when the process-wide owner is an older V2 image. */
void ct_linux_preload_after_raw_fork_syscall(long nr, long a1, long result)
    __attribute__((visibility("hidden")));
void ct_linux_preload_after_raw_fork_syscall(long nr, long a1, long result) {
  if (result != 0 || !ct_raw_call_forks_process(nr, a1)) return;
  int saved_errno = errno;
  int pid = (int)ct_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
  if (ct_raw_fork_reset_pid == pid) return;
  ct_raw_fork_child_reset();
  ct_raw_subscriber_fork_pid = pid;
  if (ct_raw_fork_child != NULL) ct_raw_fork_child(0);
  errno = saved_errno;
}

static ct_raw_syscall_hook_fn ct_raw_user_hook = NULL;
static void ct_raw_dispatch(long nr, long a1, long a2, long a3, long a4,
                            long a5, long a6, long result, int source) {
  ct_linux_preload_after_raw_fork_syscall(nr, a1, result);
  ct_raw_syscall_hook_fn hook = __atomic_load_n(&ct_raw_user_hook,
                                               __ATOMIC_ACQUIRE);
  if (hook != NULL) hook(nr, a1, a2, a3, a4, a5, a6, result, source);
}

static void ct_raw_owner_after_raw_fork(long nr, long a1, long result) {
  if (result != 0) return;
#ifdef SYS_fork
  if (nr == SYS_fork) ct_raw_fork_child_reset();
#endif
#ifdef SYS_clone
  /* CLONE_VM children share the live parent lock, not an abandoned copy. */
  if (nr == SYS_clone && (a1 & CLONE_VM) == 0)
    ct_raw_fork_child_reset();
#endif
#ifdef SYS_clone3
  if (nr == SYS_clone3 && a1 != 0) {
    /* The kernel accepted clone_args before returning in this child. Its
     * first field is the 64-bit flags word, in this inherited address space. */
    unsigned long long flags;
    memcpy(&flags, (void *)a1, sizeof(flags));
    if ((flags & CLONE_VM) == 0) ct_raw_fork_child_reset();
  }
#endif
}

static void *ct_resolve(const char *name) {
  return stackable_linux_preload_resolve_next(name);
}

/* Reserve `max` bytes of the capture arena; -1 when they do not fit. */
static long ct_raw_arena_reserve(unsigned long max) {
  unsigned long off = __atomic_load_n(&ct_raw_capture_arena_used,
                                      __ATOMIC_RELAXED);
  for (;;) {
    if (off > CT_RAW_ARENA_CAP || max > CT_RAW_ARENA_CAP - off) return -1;
    if (__atomic_compare_exchange_n(&ct_raw_capture_arena_used, &off,
                                    off + max, 1, __ATOMIC_ACQ_REL,
                                    __ATOMIC_RELAXED))
      return (long)off;
  }
}

/* Give back the unused tail of a reservation when nothing was reserved after
 * it (the common case); otherwise the tail is simply not reused. */
static void ct_raw_arena_shrink(unsigned long off, unsigned long max,
                                unsigned long used) {
  unsigned long expected = off + max;
  __atomic_compare_exchange_n(&ct_raw_capture_arena_used, &expected,
                              off + used, 0, __ATOMIC_ACQ_REL,
                              __ATOMIC_RELAXED);
}

static void ct_raw_capture_set(struct ct_raw_syscall_event *event, int slot,
                               unsigned long off, unsigned long len) {
  event->cap_off[slot] = off;
  event->cap_len[slot] = len;
  event->cap_mask |= 1 << slot;
}

/* Copy a NUL-terminated argument the kernel just accepted. */
static int ct_raw_capture_string(struct ct_raw_syscall_event *event, int slot,
                                 long value) {
  const char *text = (const char *)value;
  if (text == NULL) return 0;
  size_t len = strnlen(text, CT_RAW_CAPTURE_PATH_MAX);
  if (len >= CT_RAW_CAPTURE_PATH_MAX) return 0;
  long off = ct_raw_arena_reserve(len + 1);
  if (off < 0) return 0;
  memcpy(ct_raw_capture_arena + off, text, len);
  ct_raw_capture_arena[off + len] = '\0';
  ct_raw_capture_set(event, slot, (unsigned long)off, len);
  return 1;
}

/* What a descriptor names, from its /proc/self/fd link (AT_FDCWD: the working
 * directory). `require_path`: the answer must be a live absolute path (a
 * directory relative paths were resolved against); otherwise a link that is
 * not one -- pipe:[N], socket:[N], a deleted file -- is captured as EMPTY,
 * which tells the classifier the descriptor names no path. */
static int ct_raw_capture_fd(struct ct_raw_syscall_event *event, int slot,
                             long fd, int require_path) {
  long off = ct_raw_arena_reserve(CT_RAW_CAPTURE_PATH_MAX);
  if (off < 0) return 0;
  char *dst = ct_raw_capture_arena + off;
  long n;
  if ((int)fd == AT_FDCWD) {
    n = ct_raw_syscall6(SYS_getcwd, (long)dst, CT_RAW_CAPTURE_PATH_MAX, 0, 0,
                        0, 0);
    if (n > 0) n = (long)strnlen(dst, CT_RAW_CAPTURE_PATH_MAX);
  } else {
    char link[32] = "/proc/self/fd/";
    char digits[16];
    int nd = 0;
    unsigned long v = (unsigned long)(unsigned int)fd;
    if ((int)fd < 0) {
      ct_raw_arena_shrink((unsigned long)off, CT_RAW_CAPTURE_PATH_MAX, 0);
      return 0;
    }
    do { digits[nd++] = (char)('0' + v % 10); v /= 10; } while (v != 0);
    size_t at = strlen(link);
    while (nd > 0) link[at++] = digits[--nd];
    link[at] = '\0';
    n = ct_raw_syscall6(SYS_readlinkat, AT_FDCWD, (long)link, (long)dst,
                        CT_RAW_CAPTURE_PATH_MAX - 1, 0, 0);
    if (n > 0) dst[n] = '\0';
  }
  static const char deleted[] = " (deleted)";
  const size_t deleted_len = sizeof(deleted) - 1;
  int is_path = n > 0 && dst[0] == '/' &&
    !((size_t)n >= deleted_len &&
      memcmp(dst + n - deleted_len, deleted, deleted_len) == 0);
  if (n <= 0 || (!is_path && require_path)) {
    ct_raw_arena_shrink((unsigned long)off, CT_RAW_CAPTURE_PATH_MAX, 0);
    return 0;
  }
  if (!is_path) n = 0;
  dst[n] = '\0';
  ct_raw_arena_shrink((unsigned long)off, CT_RAW_CAPTURE_PATH_MAX,
                      (unsigned long)n + 1);
  ct_raw_capture_set(event, slot, (unsigned long)off, (unsigned long)n);
  return 1;
}

/* A pathname argument, and for a relative one the directory it was resolved
 * against (an empty pathname needs none: it is AT_EMPTY_PATH or ENOENT). */
static int ct_raw_capture_at(struct ct_raw_syscall_event *event, long dirfd,
                             long path) {
  if (!ct_raw_capture_string(event, CT_RAW_CAP_PATH, path)) return 0;
  const char *text = (const char *)path;
  if (text[0] == '\0' || text[0] == '/') return 1;
  return ct_raw_capture_fd(event, CT_RAW_CAP_BASE, dirfd, 1);
}

/* Everything the deferred classification of `event` reads indirectly. The
 * set of syscalls here is exactly the set `classifyRawFileSyscall` reads a
 * pointer or a descriptor's path for; anything else needs no capture. */
static void ct_raw_capture_event(struct ct_raw_syscall_event *event) {
  const long *a = event->args;
  long r = event->result;
  int needed = 1;
  int ok = 1;
  event->capture = CT_RAW_CAPTURE_NONE;
  event->cap_mask = 0;
  event->how_set = 0;
  if (r == -EFAULT) return; /* the classifier treats a fault as loss */
  switch (event->nr) {
#ifdef SYS_open
  case SYS_open:
#endif
#ifdef SYS_creat
  case SYS_creat:
#endif
#ifdef SYS_unlink
  case SYS_unlink:
#endif
#ifdef SYS_rmdir
  case SYS_rmdir:
#endif
#ifdef SYS_mkdir
  case SYS_mkdir:
#endif
#ifdef SYS_stat
  case SYS_stat:
#endif
#ifdef SYS_lstat
  case SYS_lstat:
#endif
#ifdef SYS_access
  case SYS_access:
#endif
#ifdef SYS_readlink
  case SYS_readlink:
#endif
  case SYS_truncate:
    ok = ct_raw_capture_at(event, AT_FDCWD, a[0]);
    break;
  case SYS_openat:
  case SYS_unlinkat:
  case SYS_mkdirat:
#ifdef SYS_newfstatat
  case SYS_newfstatat:
#endif
  case SYS_faccessat:
  case SYS_readlinkat:
#ifdef SYS_statx
  case SYS_statx:
#endif
    ok = ct_raw_capture_at(event, a[0], a[1]);
    break;
#ifdef SYS_openat2
  case SYS_openat2:
    ok = ct_raw_capture_at(event, a[0], a[1]);
    if (ok && r >= 0 && a[2] != 0) {
      /* struct open_how { u64 flags; u64 mode; u64 resolve; } (openat2(2)) */
      memcpy(&event->how_flags, (const void *)a[2], sizeof(event->how_flags));
      memcpy(&event->how_mode, (const char *)a[2] + 8,
             sizeof(event->how_mode));
      event->how_set = 1;
    }
    break;
#endif
#ifdef SYS_symlink
  case SYS_symlink:
    ok = ct_raw_capture_string(event, CT_RAW_CAP_TARGET, a[0]) &&
         ct_raw_capture_at(event, AT_FDCWD, a[1]);
    break;
#endif
  case SYS_symlinkat:
    ok = ct_raw_capture_string(event, CT_RAW_CAP_TARGET, a[0]) &&
         ct_raw_capture_at(event, a[1], a[2]);
    break;
  /* Descriptors: whenever the call succeeded, even with 0 bytes, so the
   * classifier never falls back to the live descriptor table, which by then
   * may map the number to another file. */
  case SYS_read:
  case SYS_getdents64:
    if (r >= 0) ok = ct_raw_capture_fd(event, CT_RAW_CAP_FD0, a[0], 0);
    break;
  case SYS_sendfile: /* sendfile(out_fd, in_fd, ...) */
    if (r >= 0)
      ok = ct_raw_capture_fd(event, CT_RAW_CAP_FD0, a[1], 0) &&
           ct_raw_capture_fd(event, CT_RAW_CAP_FD1, a[0], 0);
    break;
  case SYS_copy_file_range: /* (fd_in, off_in, fd_out, ...) */
  case SYS_splice:
    if (r >= 0)
      ok = ct_raw_capture_fd(event, CT_RAW_CAP_FD0, a[0], 0) &&
           ct_raw_capture_fd(event, CT_RAW_CAP_FD1, a[2], 0);
    break;
  default:
    needed = 0;
    break;
  }
  if (needed)
    event->capture = ok ? CT_RAW_CAPTURE_OK : CT_RAW_CAPTURE_FAILED;
}

/* UNCLASSIFIED EVENTS ARE REPORTED, NEVER DROPPED SILENTLY.
 *
 * A trapped event is classified later, outside signal context, by a drain
 * that takes the shim's locks. Some image ends cannot run that drain: the
 * thread is inside a hook (a host signal handler interrupted one, so the
 * locks may be held), the process is a fork child skipping monitor
 * bookkeeping until exec, or the event arrived after the process's final
 * drain. Withholding a fragment's commit marker shows nothing on the
 * shared-memory transport, which has no such marker, so those paths used to
 * end with a capture that was complete in name and silently lacked the
 * events.
 *
 * Instead they write one pre-encoded event-loss frame to a fragment file of
 * their own, with raw syscalls only (openat, writev, close), so the merge
 * downgrades the capture to incomplete. The frame is encoded once by the
 * shim at init (`ct_linux_preload_arm_inline_loss_report`); only the pid and
 * thread id are filled in here. Async-signal-safe, lock-free, no
 * allocation, a few hundred bytes of stack, errno preserved. */
#define CT_INLINE_LOSS_DIR_CAP 4096
#define CT_INLINE_LOSS_FRAME_CAP 4096
static char ct_inline_loss_dir[CT_INLINE_LOSS_DIR_CAP];
static unsigned char ct_inline_loss_frame[CT_INLINE_LOSS_FRAME_CAP];
static long ct_inline_loss_frame_len = 0;   /* 0: not armed */
static long ct_inline_loss_pid_offset = -1;
static long ct_inline_loss_tid_offset = -1;
static int ct_inline_final_drain_pid = 0;
/* The last (pid, reserved-count) reported, so the paths that can report
 * more than once for the same events (glibc's PATH search tries one execve
 * per candidate) write one frame. A race only duplicates a frame. */
static int ct_inline_loss_reported_pid = 0;
static long ct_inline_loss_reported_count = -1;
static void ct_report_unclassified_inline_events(void);

/* Arm the report. `dir` must be absolute (a host may chdir before it ends);
 * `pid_offset`/`tid_offset` locate the frame's little-endian u64 pid and
 * thread id, or are -1 when the frame carries none. Returns 1 when armed;
 * the shim reports a failure to arm as event-loss itself, since nothing
 * could report a later unclassified event. */
int ct_linux_preload_arm_inline_loss_report(const char *dir,
                                            const unsigned char *frame,
                                            long frame_len, long pid_offset,
                                            long tid_offset)
    __attribute__((visibility("default")));
int ct_linux_preload_arm_inline_loss_report(const char *dir,
                                            const unsigned char *frame,
                                            long frame_len, long pid_offset,
                                            long tid_offset) {
  __atomic_store_n(&ct_inline_loss_frame_len, 0, __ATOMIC_RELEASE);
  if (dir == NULL || dir[0] != '/' || frame == NULL || frame_len <= 0 ||
      frame_len > CT_INLINE_LOSS_FRAME_CAP)
    return 0;
  size_t dir_len = strlen(dir);
  if (dir_len >= CT_INLINE_LOSS_DIR_CAP) return 0;
  if (pid_offset < 0 || pid_offset + 8 > frame_len ||
      tid_offset < 0 || tid_offset + 8 > frame_len ||
      (pid_offset < tid_offset ? pid_offset + 8 > tid_offset
                               : tid_offset + 8 > pid_offset)) {
    pid_offset = -1;
    tid_offset = -1;
  }
  memcpy(ct_inline_loss_dir, dir, dir_len + 1);
  memcpy(ct_inline_loss_frame, frame, (size_t)frame_len);
  ct_inline_loss_pid_offset = pid_offset;
  ct_inline_loss_tid_offset = tid_offset;
  __atomic_store_n(&ct_inline_loss_frame_len, frame_len, __ATOMIC_RELEASE);
  return 1;
}

static long ct_inline_loss_append_decimal(char *out, long at, long cap,
                                          unsigned long value) {
  char digits[24];
  int n = 0;
  do {
    digits[n++] = (char)('0' + value % 10);
    value /= 10;
  } while (value != 0 && n < (int)sizeof(digits));
  while (n > 0 && at < cap) out[at++] = digits[--n];
  return at;
}

static long ct_inline_loss_append_text(char *out, long at, long cap,
                                       const char *text) {
  while (*text != '\0' && at < cap) out[at++] = *text++;
  return at;
}

/* Append one pre-encoded loss frame, with `pid`/`tid` filled in at the
 * offsets given (-1: none), to "repro-monitor-<pid>-<tid><suffix>" in the
 * armed fragment directory. Raw syscalls only; async-signal-safe, no locks,
 * no allocation. Returns 1 when the whole frame was written. */
static int ct_write_loss_frame(const unsigned char *frame, long frame_len,
                               long po, long to, const char *suffix,
                               long pid, long tid) {
  /* The directory is opened first and the file created relative to it, so
   * only the short file name is built here, whatever the directory's
   * length. The name differs from the thread's ordinary fragment by its
   * suffix, and a reused pid/tid appends another whole frame to it
   * (O_APPEND), which the merge reads like any other. */
  char name[96];
  const long cap = (long)sizeof(name) - 1;
  long at = 0;
  at = ct_inline_loss_append_text(name, at, cap, "repro-monitor-");
  at = ct_inline_loss_append_decimal(name, at, cap, (unsigned long)pid);
  at = ct_inline_loss_append_text(name, at, cap, "-");
  at = ct_inline_loss_append_decimal(name, at, cap, (unsigned long)tid);
  at = ct_inline_loss_append_text(name, at, cap, suffix);
  name[at] = '\0';
  long dirfd = ct_raw_syscall6(SYS_openat, AT_FDCWD, (long)ct_inline_loss_dir,
                               O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
  long fd = -1;
  if (dirfd >= 0) {
    fd = ct_raw_syscall6(SYS_openat, dirfd, (long)name,
                         O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC |
                             O_NOFOLLOW,
                         0600, 0, 0);
    ct_raw_syscall6(SYS_close, dirfd, 0, 0, 0, 0, 0);
  }
  if (fd < 0) return 0;
  unsigned char pid_bytes[8], tid_bytes[8];
  for (int i = 0; i < 8; ++i) {
    pid_bytes[i] = (unsigned char)((unsigned long)pid >> (8 * i));
    tid_bytes[i] = (unsigned char)((unsigned long)tid >> (8 * i));
  }
  /* One writev, so the frame lands whole even if another thread appends
   * to the same file (O_APPEND). */
  struct iovec parts[5];
  int count = 0;
  if (po < 0) {
    parts[count].iov_base = (void *)frame;
    parts[count++].iov_len = (size_t)frame_len;
  } else {
    long first = po < to ? po : to, second = po < to ? to : po;
    unsigned char *first_bytes = po < to ? pid_bytes : tid_bytes;
    unsigned char *second_bytes = po < to ? tid_bytes : pid_bytes;
    parts[count].iov_base = (void *)frame;
    parts[count++].iov_len = (size_t)first;
    parts[count].iov_base = first_bytes;
    parts[count++].iov_len = 8;
    parts[count].iov_base = (void *)(frame + first + 8);
    parts[count++].iov_len = (size_t)(second - first - 8);
    parts[count].iov_base = second_bytes;
    parts[count++].iov_len = 8;
    parts[count].iov_base = (void *)(frame + second + 8);
    parts[count++].iov_len = (size_t)(frame_len - second - 8);
  }
  long written = ct_raw_syscall6(SYS_writev, fd, (long)parts, count, 0, 0, 0);
  ct_raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
  return written == frame_len;
}

static void ct_report_unclassified_inline_events(void) {
  long frame_len = __atomic_load_n(&ct_inline_loss_frame_len,
                                   __ATOMIC_ACQUIRE);
  if (frame_len <= 0) return;
  int saved_errno = errno;
  long pid = ct_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
  long tid = ct_raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
  long reserved = __atomic_load_n(&ct_raw_syscall_event_reserved,
                                  __ATOMIC_ACQUIRE);
  if (__atomic_load_n(&ct_inline_loss_reported_pid, __ATOMIC_ACQUIRE) ==
          (int)pid &&
      __atomic_load_n(&ct_inline_loss_reported_count, __ATOMIC_ACQUIRE) ==
          reserved) {
    errno = saved_errno;
    return;
  }
  if (ct_write_loss_frame(ct_inline_loss_frame, frame_len,
                          ct_inline_loss_pid_offset, ct_inline_loss_tid_offset,
                          "-inline-loss.iomon-frag", pid, tid)) {
    __atomic_store_n(&ct_inline_loss_reported_count, reserved,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&ct_inline_loss_reported_pid, (int)pid,
                     __ATOMIC_RELEASE);
  }
  errno = saved_errno;
}

/* EVIDENCE A FORK CHILD SKIPPED IS REPORTED, NEVER DROPPED SILENTLY.
 *
 * A child forked from a multi-threaded process whose shim state another
 * thread was updating at the fork instant (or created by a raw fork-like
 * system call, which resets no libc state at all) skips monitor bookkeeping
 * until it execs: recording could wait forever on a lock held by a thread
 * that does not exist in the child. A hook that would have produced
 * evidence there reports, once per process, a pre-encoded event-loss frame
 * through the same raw-syscall writer as the inline report, so the capture
 * is incomplete rather than complete without the child's reads. Armed by the
 * shim at init (`ct_linux_preload_arm_fork_skip_loss_report`), after the
 * inline report, whose fragment directory it shares. */
typedef struct ct_fork_loss_frame {
  unsigned char bytes[CT_INLINE_LOSS_FRAME_CAP];
  long len;   /* 0: not armed */
  long pid_offset, tid_offset;
} ct_fork_loss_frame;
static ct_fork_loss_frame ct_fork_skip_loss[2];
static int ct_fork_skip_loss_reported_pid = 0;

int ct_linux_preload_arm_fork_skip_loss_report(const unsigned char *frame,
                                               long frame_len, long pid_offset,
                                               long tid_offset)
    __attribute__((visibility("default")));
static int ct_arm_loss_frame(ct_fork_loss_frame *slot,
    const unsigned char *frame, long frame_len, long pid_offset, long tid_offset) {
  __atomic_store_n(&slot->len, 0, __ATOMIC_RELEASE);
  if (ct_inline_loss_dir[0] != '/' || frame == NULL || frame_len <= 0 ||
      frame_len > CT_INLINE_LOSS_FRAME_CAP)
    return 0;
  if (pid_offset < 0 || pid_offset + 8 > frame_len ||
      tid_offset < 0 || tid_offset + 8 > frame_len ||
      (pid_offset < tid_offset ? pid_offset + 8 > tid_offset
                               : tid_offset + 8 > pid_offset)) {
    pid_offset = -1;
    tid_offset = -1;
  }
  memcpy(slot->bytes, frame, (size_t)frame_len);
  slot->pid_offset = pid_offset;
  slot->tid_offset = tid_offset;
  __atomic_store_n(&slot->len, frame_len, __ATOMIC_RELEASE);
  return 1;
}
int ct_linux_preload_arm_fork_skip_loss_report(const unsigned char *frame,
    long frame_len, long pid_offset, long tid_offset) {
  return ct_arm_loss_frame(&ct_fork_skip_loss[0], frame, frame_len, pid_offset,
                           tid_offset);
}
int ct_linux_preload_arm_subscriber_fork_skip_loss_report(const unsigned char *frame,
    long frame_len, long pid_offset, long tid_offset)
    __attribute__((visibility("hidden")));
int ct_linux_preload_arm_subscriber_fork_skip_loss_report(const unsigned char *frame,
    long frame_len, long pid_offset, long tid_offset) {
  return ct_arm_loss_frame(&ct_fork_skip_loss[1], frame, frame_len, pid_offset,
                           tid_offset);
}

void ct_linux_report_fork_child_skipped_evidence(void)
    __attribute__((visibility("default")));
void ct_linux_report_fork_child_skipped_evidence(void) {
  int saved_errno = errno;
  long pid = ct_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
  ct_fork_loss_frame *slot = &ct_fork_skip_loss[ct_raw_subscriber_fork_pid == pid];
  long frame_len = __atomic_load_n(&slot->len, __ATOMIC_ACQUIRE);
  if (frame_len <= 0) { errno = saved_errno; return; }
  if (__atomic_load_n(&ct_fork_skip_loss_reported_pid, __ATOMIC_ACQUIRE) !=
      (int)pid) {
    long tid = ct_raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    if (ct_write_loss_frame(slot->bytes, frame_len,
                            slot->pid_offset, slot->tid_offset,
                            "-fork-loss.iomon-frag", pid, tid))
      __atomic_store_n(&ct_fork_skip_loss_reported_pid, (int)pid,
                       __ATOMIC_RELEASE);
  }
  errno = saved_errno;
}

/* AN EXEC INTO AN IMAGE THE SHIM CANNOT ENTER IS EVENT-LOSS.
 *
 * The loader drops LD_PRELOAD for an image of another ELF class or machine
 * ("wrong ELF class: ignored") and a static image has no loader at all, so
 * such an image runs with no shim and leaves no record. The merge's
 * process-tree accounting cannot tell: when that image later execs a
 * monitored one in the same pid, the monitored image emits the pid's
 * process-start and the unmonitored one emitted no exec, so starts and
 * execs balance. Only the monitored context that starts the image knows, so
 * every entry this shim sees classifies its target
 * (exec_image_injectability.h) and records event-loss naming the image:
 *   - the exec family, through the execve hook, which resolves what the
 *     kernel will run (the descriptor of fexecve/execveat, the caller's PATH
 *     for execvp): ct_linux_exec_hook_image_uninjectable;
 *   - posix_spawn/posix_spawnp, through their hooks, after a successful
 *     spawn: ct_linux_spawn_image_uninjectable;
 *   - a raw execve/execveat (syscall(2), its patched replacement, and an
 *     inline `syscall` instruction the trap handler replays), which reach no
 *     exec hook: ct_linux_check_raw_exec_entry, below.
 * Files are read with raw system calls, so the classification neither
 * re-enters this shim's hooks nor is recorded as an observation, and it is
 * async-signal-safe for the trap handler.
 *
 * The record is emitted by the shim (ct_uninjectable_exec_observer) when it
 * can record: this thread is not inside a hook. Otherwise -- a host signal
 * handler that interrupted a hook, or a fork child skipping bookkeeping until
 * exec -- a pre-encoded event-loss frame is written instead, with raw
 * syscalls, as for unclassified inline events; it cannot name the image, but
 * the capture is still graded incomplete. */
static long ct_exec_io_openat(int dirfd, const char *path, int flags) {
  return ct_raw_syscall6(SYS_openat, dirfd, (long)path, flags, 0, 0, 0);
}
static long ct_exec_io_pread(int fd, void *buf, unsigned long len,
                             long offset) {
  long n;
  do {
    n = ct_raw_syscall6(SYS_pread64, fd, (long)buf, (long)len, offset, 0, 0);
  } while (n == -EINTR);
  return n;
}
static long ct_exec_io_is_regular(int fd) {
  /* The kernel's struct stat is glibc's on x86_64 and on the generic ABI
   * (aarch64), so st_mode is where <sys/stat.h> says. */
  struct stat st;
  long rc = ct_raw_syscall6(SYS_fstat, fd, (long)&st, 0, 0, 0, 0);
  return rc < 0 ? rc : (S_ISREG(st.st_mode) ? 1 : 0);
}
static long ct_exec_io_access_x(int dirfd, const char *path) {
  return ct_raw_syscall6(SYS_faccessat, dirfd, (long)path, X_OK, 0, 0, 0);
}
static void ct_exec_io_close(int fd) {
  (void)ct_raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
}
static const iomon_exec_io ct_exec_raw_io = {
  ct_exec_io_openat, ct_exec_io_pread, ct_exec_io_is_regular,
  ct_exec_io_access_x, ct_exec_io_close
};

/* Room for the reason, an image path and a script path on the paths that
 * keep the detail on the stack (the trap handler may run on a small
 * alternate signal stack); a longer one is truncated, never overrun. */
#define CT_EXEC_DETAIL_CAP 1024

/* The shim's recorder (linux_preload.nim): emits the loss and flushes, and
 * returns 1, or returns 0 when it cannot record (then the frame is used). */
typedef int (*ct_uninjectable_exec_fn)(const char *entry, const char *detail);
static ct_uninjectable_exec_fn ct_uninjectable_exec_observer = NULL;
void ct_linux_preload_register_uninjectable_exec(ct_uninjectable_exec_fn fn)
    __attribute__((visibility("hidden")));
void ct_linux_preload_register_uninjectable_exec(ct_uninjectable_exec_fn fn) {
  __atomic_store_n(&ct_uninjectable_exec_observer, fn, __ATOMIC_RELEASE);
}

static ct_fork_loss_frame ct_uninjectable_exec_loss;
int ct_linux_preload_arm_uninjectable_exec_loss_report(
    const unsigned char *frame, long frame_len, long pid_offset,
    long tid_offset) __attribute__((visibility("hidden")));
int ct_linux_preload_arm_uninjectable_exec_loss_report(
    const unsigned char *frame, long frame_len, long pid_offset,
    long tid_offset) {
  return ct_arm_loss_frame(&ct_uninjectable_exec_loss, frame, frame_len,
                           pid_offset, tid_offset);
}

/* The unnamed fallback: one pre-encoded frame per uninjectable entry. */
void ct_linux_report_uninjectable_exec_frame(void)
    __attribute__((visibility("hidden")));
void ct_linux_report_uninjectable_exec_frame(void) {
  long frame_len = __atomic_load_n(&ct_uninjectable_exec_loss.len,
                                   __ATOMIC_ACQUIRE);
  if (frame_len <= 0) return;
  int saved_errno = errno;
  long pid = ct_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
  long tid = ct_raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
  (void)ct_write_loss_frame(ct_uninjectable_exec_loss.bytes, frame_len,
                            ct_uninjectable_exec_loss.pid_offset,
                            ct_uninjectable_exec_loss.tid_offset,
                            "-exec-loss.iomon-frag", pid, tid);
  errno = saved_errno;
}

/* Record that `entry` is about to start the uninjectable image `detail`
 * describes: through the shim when this thread is not inside a hook (the
 * recorder takes the shim's locks), else through the frame. */
static void ct_report_uninjectable_exec(const char *entry,
                                        const char *detail) {
  ct_uninjectable_exec_fn observer =
      __atomic_load_n(&ct_uninjectable_exec_observer, __ATOMIC_ACQUIRE);
  if (observer != NULL && stackable_linux_preload_current_depth() == 0) {
    int saved_errno = errno;
    stackable_linux_preload_enter_hook();
    int recorded = observer(entry, detail);
    stackable_linux_preload_exit_hook();
    if (recorded) {
      /* The exec discards this image: make a batched record durable first
       * (the shared-memory set needs no flush; the file fallback does). */
      repro_linux_sig_safe_flush();
      errno = saved_errno;
      return;
    }
    errno = saved_errno;
  }
  ct_linux_report_uninjectable_exec_frame();
}

/* A raw execve(path, ...) or execveat(dirfd, path, ..., flags) is about to
 * be issued (a1, a2, a5 are its first, second and fifth arguments). */
void ct_linux_check_raw_exec_entry(long nr, long a1, long a2, long a5)
    __attribute__((visibility("hidden")));
void ct_linux_check_raw_exec_entry(long nr, long a1, long a2, long a5) {
  int dirfd = AT_FDCWD, flags = 0;
  const char *path;
  const char *entry;
  if (nr == SYS_execve) {
    path = (const char *)a1;
    entry = "raw execve";
#ifdef SYS_execveat
  } else if (nr == SYS_execveat) {
    dirfd = (int)a1;
    path = (const char *)a2;
    flags = (int)a5;
    entry = "raw execveat";
#endif
  } else {
    return;
  }
  (void)a2;
  (void)a5;
  int saved_errno = errno;
  char detail[CT_EXEC_DETAIL_CAP];
  if (iomon_exec_image_classify(&ct_exec_raw_io, dirfd, path, flags, NULL,
                                detail, sizeof(detail)) !=
      IOMON_EXEC_INJECTABLE)
    ct_report_uninjectable_exec(entry, detail);
  errno = saved_errno;
}

static void ct_record_raw_syscall_event(long nr, const long args[6],
                                        long result, int source,
                                        unsigned long address) {
  for (int i = 0; i < CT_RAW_SUBSCRIBER_CAP; ++i) {
    if (__atomic_load_n(&ct_raw_subscribers[i], __ATOMIC_ACQUIRE) != NULL)
      ct_raw_subscriber_enqueue[i](nr, args, result, source, address);
  }
  long index = __atomic_fetch_add(&ct_raw_syscall_event_reserved, 1,
                                  __ATOMIC_ACQ_REL);
  if (index >= CT_RAW_SYSCALL_EVENT_CAP) {
    ct_raw_syscall_event_overflow_value = 1;
    return;
  }
  struct ct_raw_syscall_event *event = &ct_raw_syscall_events[index];
  /* Slots are never reused (reset happens only before any trap), so this one
   * is still FREE; its pid goes first so a drain in this process can tell an
   * event still being written here from one another process left behind. */
  __atomic_store_n(&event->pid,
                   (int)ct_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0),
                   __ATOMIC_RELAXED);
  event->nr = nr;
  for (int i = 0; i < 6; i++) event->args[i] = args[i];
  event->result = result;
  event->source = source;
  event->address = address;
  ct_raw_capture_event(event);
  __atomic_store_n(&event->state, CT_RAW_EVENT_READY, __ATOMIC_RELEASE);
  /* Trapped after this process's final drain (another thread still running
   * while the main thread exits, or a later finaliser): no drain is
   * guaranteed to run before the image ends, so report it now. The fence
   * pairs with the one in ct_linux_note_final_inline_drain: either this
   * load sees the final-drain pid, or that function's scan sees this event
   * (store-load ordering needs a full fence on both sides). */
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  if (__atomic_load_n(&ct_inline_final_drain_pid, __ATOMIC_RELAXED) ==
      event->pid)
    ct_report_unclassified_inline_events();
}

void ct_linux_preload_raw_enqueue_v1(long nr, const long *args,
    long result, int source, unsigned long address)
    __attribute__((visibility("default")));
void ct_linux_preload_raw_enqueue_v1(long nr, const long *args,
    long result, int source, unsigned long address) {
  ct_linux_preload_after_raw_fork_syscall(nr, args[0], result);
  ct_record_raw_syscall_event(nr, args, result, source, address);
}

/* CLASSIFY BEFORE THE IMAGE ENDS. Trapped events are classified at the
 * process-exit destructor and before a libc exec; an exit or exec that goes
 * around both (an inline or syscall(2) exit_group, execve or execveat) would
 * take every still-pending event with it, with no record and no loss. So
 * those paths drain first, through the observer linux_preload.nim registers.
 *
 * Only when this thread is not inside a hook: the classification takes the
 * shim's locks, and a thread already inside a hook (a host signal handler
 * that interrupted one) may hold them. Whenever events stay pending -- for
 * that reason, or because the drain itself skipped them (a fork child before
 * exec) -- they are reported as event-loss (see
 * ct_report_unclassified_inline_events) and this returns 0, so an exit_group
 * caller also withholds its commit marker; 1 when nothing is pending. */
static int ct_linux_raw_syscall_events_pending(int pid);
int ct_linux_raw_current_pid(void);
typedef void (*ct_inline_drain_fn)(void);
static ct_inline_drain_fn ct_inline_drain_observer = NULL;
void ct_linux_preload_register_inline_drain(ct_inline_drain_fn observer) {
  __atomic_store_n(&ct_inline_drain_observer, observer, __ATOMIC_RELEASE);
}

/* Events this process trapped and nobody classified, including any that did
 * not fit the buffer. */
static int ct_linux_inline_events_unclassified(int pid) {
  return ct_raw_syscall_event_overflow_value != 0 ||
         ct_linux_raw_syscall_events_pending(pid);
}

/* For an image end that runs no drain at all (a libc exec made from inside a
 * hook, or by a fork child skipping bookkeeping): report what is pending. */
void ct_linux_report_inline_events_if_pending(void)
    __attribute__((visibility("default")));
void ct_linux_report_inline_events_if_pending(void) {
  if (__atomic_load_n(&ct_inline_drain_observer, __ATOMIC_ACQUIRE) == NULL)
    return;
  if (ct_linux_inline_events_unclassified(ct_linux_raw_current_pid()))
    ct_report_unclassified_inline_events();
}

/* The process-exit destructor has run its drain: report anything it left,
 * and anything trapped from now on (ct_record_raw_syscall_event). */
void ct_linux_note_final_inline_drain(void)
    __attribute__((visibility("default")));
void ct_linux_note_final_inline_drain(void) {
  /* Mark first, then scan: an event recorded concurrently is either seen by
   * the scan or reports itself (see ct_record_raw_syscall_event). */
  __atomic_store_n(&ct_inline_final_drain_pid, ct_linux_raw_current_pid(),
                   __ATOMIC_RELAXED);
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  ct_linux_report_inline_events_if_pending();
}

int ct_linux_drain_inline_events_before_image_end(void)
    __attribute__((visibility("default")));
int ct_linux_drain_inline_events_before_image_end(void) {
  ct_inline_drain_fn observer =
      __atomic_load_n(&ct_inline_drain_observer, __ATOMIC_ACQUIRE);
  int pid = ct_linux_raw_current_pid();
  if (observer == NULL || !ct_linux_raw_syscall_events_pending(pid))
    return 1;
  if (stackable_linux_preload_current_depth() == 0) {
    int saved_errno = errno;
    stackable_linux_preload_enter_hook();
    observer();
    stackable_linux_preload_exit_hook();
    errno = saved_errno;
    if (!ct_linux_raw_syscall_events_pending(pid)) return 1;
  }
  ct_report_unclassified_inline_events();
  return 0;
}

static void ct_raw_flush_observers(void) {
  repro_linux_sig_safe_flush();
  for (int i = 0; i < CT_RAW_SUBSCRIBER_CAP; ++i) {
    if (__atomic_load_n(&ct_raw_subscribers[i], __ATOMIC_ACQUIRE) != NULL)
      ct_raw_subscriber_flush[i]();
  }
}

long ct_linux_raw_syscall_event_count(void) {
  long reserved = __atomic_load_n(&ct_raw_syscall_event_reserved,
                                  __ATOMIC_ACQUIRE);
  return reserved < CT_RAW_SYSCALL_EVENT_CAP ? reserved
                                             : CT_RAW_SYSCALL_EVENT_CAP;
}

int ct_linux_raw_current_pid(void) {
  return (int)ct_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
}

/* Take event `index` for classification by process `pid`: 1 when it is
 * ready, belongs to `pid` and nobody took it before; 0 when it belongs to
 * another process or was already taken; -1 when it is still being written. */
int ct_linux_raw_syscall_event_claim(long index, int pid) {
  if (index < 0 || index >= ct_linux_raw_syscall_event_count()) return 0;
  struct ct_raw_syscall_event *event = &ct_raw_syscall_events[index];
  int state = __atomic_load_n(&event->state, __ATOMIC_ACQUIRE);
  if (__atomic_load_n(&event->pid, __ATOMIC_RELAXED) != pid) return 0;
  if (state == CT_RAW_EVENT_FREE) return -1;
  if (state != CT_RAW_EVENT_READY) return 0;
  int expected = CT_RAW_EVENT_READY;
  return __atomic_compare_exchange_n(&event->state, &expected,
                                     CT_RAW_EVENT_DRAINED, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
           ? 1 : 0;
}

/* Whether any event of `pid` is still waiting to be classified, or still
 * being written. */
static int ct_linux_raw_syscall_events_pending(int pid) {
  long count = ct_linux_raw_syscall_event_count();
  for (long i = 0; i < count; ++i) {
    struct ct_raw_syscall_event *event = &ct_raw_syscall_events[i];
    int state = __atomic_load_n(&event->state, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&event->pid, __ATOMIC_RELAXED) == pid &&
        state != CT_RAW_EVENT_DRAINED)
      return 1;
  }
  return 0;
}

int ct_linux_raw_syscall_event_capture_state(long index) {
  if (index < 0 || index >= ct_linux_raw_syscall_event_count()) return 0;
  return ct_raw_syscall_events[index].capture;
}

/* Captured string `slot` of event `index` (see CT_RAW_CAP_*): 1 and its bytes
 * when it was captured, 0 otherwise. */
int ct_linux_raw_syscall_event_capture(long index, int slot, char **text,
                                       long *len) {
  if (index < 0 || index >= ct_linux_raw_syscall_event_count() || slot < 0 ||
      slot >= CT_RAW_CAP_SLOTS)
    return 0;
  struct ct_raw_syscall_event *event = &ct_raw_syscall_events[index];
  if ((event->cap_mask & (1 << slot)) == 0) return 0;
  *text = ct_raw_capture_arena + event->cap_off[slot];
  *len = (long)event->cap_len[slot];
  return 1;
}

int ct_linux_raw_syscall_event_open_how(long index, unsigned long long *flags,
                                        unsigned long long *mode) {
  if (index < 0 || index >= ct_linux_raw_syscall_event_count()) return 0;
  struct ct_raw_syscall_event *event = &ct_raw_syscall_events[index];
  if (!event->how_set) return 0;
  *flags = event->how_flags;
  *mode = event->how_mode;
  return 1;
}

int ct_linux_raw_syscall_event_overflowed(void) {
  return ct_raw_syscall_event_overflow_value != 0;
}

int ct_linux_raw_syscall_event_at(long index, long *nr, long *a1, long *a2,
                                  long *a3, long *a4, long *a5, long *a6,
                                  long *result, int *source,
                                  unsigned long *address) {
  if (index < 0 || index >= ct_linux_raw_syscall_event_count()) return -1;
  struct ct_raw_syscall_event *event = &ct_raw_syscall_events[index];
  if (nr) *nr = event->nr;
  if (a1) *a1 = event->args[0];
  if (a2) *a2 = event->args[1];
  if (a3) *a3 = event->args[2];
  if (a4) *a4 = event->args[3];
  if (a5) *a5 = event->args[4];
  if (a6) *a6 = event->args[5];
  if (result) *result = event->result;
  if (source) *source = event->source;
  if (address) *address = event->address;
  return 0;
}

static int ct_inline_syscall_site_index(unsigned long address) {
  sig_atomic_t count = ct_inline_syscall_site_count_value;
  for (sig_atomic_t i = 0; i < count; i++) {
    if (ct_inline_syscall_sites[i] == address) return (int)i;
  }
  return -1;
}

void ct_linux_inline_syscall_reset(void) {
  ct_inline_syscall_site_count_value = 0;
  ct_inline_syscall_trap_count_value = 0;
  ct_inline_syscall_failure_count_value = 0;
  ct_inline_syscall_last_nr_value = -1;
  ct_inline_syscall_overflow_value = 0;
  ct_inline_syscall_last_address_value = 0;
  for (int i = 0; i < CT_RAW_SYSCALL_EVENT_CAP; ++i)
    __atomic_store_n(&ct_raw_syscall_events[i].state, CT_RAW_EVENT_FREE,
                     __ATOMIC_RELAXED);
  __atomic_store_n(&ct_raw_syscall_event_reserved, 0, __ATOMIC_RELEASE);
  __atomic_store_n(&ct_raw_capture_arena_used, 0, __ATOMIC_RELEASE);
  ct_raw_syscall_event_overflow_value = 0;
}

int ct_linux_inline_syscall_record_site(unsigned long address) {
  if (address == 0) return -1;
  if (ct_inline_syscall_site_index(address) >= 0) return 0;
  sig_atomic_t count = ct_inline_syscall_site_count_value;
  if (count >= CT_INLINE_SYSCALL_SITE_CAP) {
    ct_inline_syscall_overflow_value = 1;
    return -2;
  }
  ct_inline_syscall_sites[count] = address;
  ct_inline_syscall_site_count_value = count + 1;
  return 0;
}

#if defined(__x86_64__)
/* Whether this process has exactly one thread, from field 20 (num_threads) of
 * /proc/self/stat. The inline-syscall trap handler runs in signal context, so
 * it cannot use the Nim sampler the syscall(2) replacement uses (that one
 * allocates); this reads with raw system calls into a stack buffer. Field 20
 * sits within the first ~420 bytes whatever the command name, because comm is
 * at most 16 bytes and the 17 fields before it are numbers. Any failure answers
 * "not single-threaded", the safe side. See proc(5). */
static int ct_raw_process_is_single_threaded(void) {
  char buf[512];
  long fd = stackable_linux_raw_syscall6(SYS_openat, AT_FDCWD,
                                         (long)"/proc/self/stat",
                                         O_RDONLY | O_CLOEXEC, 0, 0, 0);
  if (fd < 0) return 0;
  long n = stackable_linux_raw_syscall6(SYS_read, fd, (long)buf,
                                        (long)sizeof(buf) - 1, 0, 0, 0);
  stackable_linux_raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
  if (n <= 0) return 0;
  buf[n] = '\0';
  /* comm may contain spaces and parentheses; the fields resume after the
   * last ')'. That is field 2, so field 20 is the 18th field after it. */
  char *p = strrchr(buf, ')');
  if (p == NULL) return 0;
  for (int field = 2; field < 20; ++field) {
    p = strchr(p + 1, ' ');
    if (p == NULL) return 0;
  }
  return p[1] == '1' && p[2] == ' ';
}

static void ct_linux_inline_syscall_sigtrap_handler(
    int signum, siginfo_t *info, void *ucontext) {
  struct stackable_linux_syscall_regs regs;
  int rc = stackable_linux_capture_syscall_regs_from_ucontext(ucontext, &regs);
  if (rc != 0 || ct_inline_syscall_site_index(regs.syscall_address) < 0) {
    rc = stackable_linux_chain_sigtrap(signum, info, ucontext);
    if (rc != 0) {
      signal(signum, SIG_DFL);
      raise(signum);
    }
    return;
  }

  ct_inline_syscall_last_nr_value = (sig_atomic_t)regs.nr;
  ct_inline_syscall_last_address_value = regs.syscall_address;

  /* M9.R.63.3 — exit-family syscalls REPLAYED HERE never return; the
   * kernel tears the thread/process down inside
   * stackable_linux_replay_syscall_regs. If we did not flush the
   * fragment slot FIRST, the buffered read frames + the pre-encoded
   * committed marker would die with the process and mergeFragments
   * would inject a synthetic kill-before-flush event-loss. Mirrors the
   * M9.R.62.2b libc syscall(3) interposer contract: catch SYS_exit_group
   * / SYS_exit, run the async-signal-safe flush, then delegate. Every
   * other syscall replays normally so its result can be written back to
   * the trapped ucontext.
   *
   * The flush is async-signal-safe: it uses raw SYS_write / SYS_fsync /
   * SYS_close through stackable_linux_raw_syscall6 and no libc /
   * malloc / lock is entered. It is a no-op when the slot is not open
   * so the handler is safe from all pre-init trap paths too. */
#ifdef SYS_exit_group
  if (regs.nr == SYS_exit_group) {
    /* Events that could not be classified must not be covered by a commit
     * marker: leaving this thread's batch uncommitted makes the merge report
     * the loss instead of a capture that silently lacks them. */
    if (ct_linux_drain_inline_events_before_image_end())
      ct_raw_flush_observers();
  }
#endif
#ifdef SYS_exit
  if (regs.nr == SYS_exit) {
    ct_raw_flush_observers();
  }
#endif
  /* A successful execve replaces this image and its event buffer. */
  if (regs.nr == SYS_execve
#ifdef SYS_execveat
      || regs.nr == SYS_execveat
#endif
      ) {
    ct_linux_drain_inline_events_before_image_end();
    /* No exec hook runs for a replayed inline exec: classify its target. */
    ct_linux_check_raw_exec_entry(regs.nr, regs.args[0], regs.args[1],
                                  regs.args[4]);
  }

  /* A trapped fork-like call (an inline `syscall` issuing clone/clone3
   * without CLONE_VM, or fork) gets what the syscall(2) replacement gives the
   * same call: the child reclaims the locks it inherited and, when the parent
   * had other threads, skips monitor bookkeeping until exec. */
  int forks = ct_raw_call_forks_process(regs.nr, regs.args[0]) &&
              ct_raw_fork_child != NULL;
  int parent_single = forks ? ct_raw_process_is_single_threaded() : 1;
  long result = stackable_linux_replay_syscall_regs(&regs);
  ct_raw_owner_after_raw_fork(regs.nr, regs.args[0], result);
  if (forks && result == 0) ct_raw_fork_child(parent_single);
  ct_record_raw_syscall_event(regs.nr, regs.args, result,
                              CT_RAW_SYSCALL_SOURCE_INLINE,
                              regs.syscall_address);
  rc = stackable_linux_write_syscall_result_to_ucontext(
      ucontext, result, regs.resume_rip);
  if (rc == 0) {
    ct_inline_syscall_trap_count_value++;
  } else {
    ct_inline_syscall_failure_count_value++;
  }
}

void *ct_linux_inline_syscall_handler_address(void) {
  return (void *)&ct_linux_inline_syscall_sigtrap_handler;
}
#else /* !__x86_64__ */
/* No INT3 syscall-trap substrate on this architecture. Returning NULL is the
 * value ``installInlineSyscallPatches`` already treats as "no handler" — it
 * records ``lrsInvalidArgument`` and installs nothing. In practice that branch
 * is unreachable because the caller bails on
 * ``linuxRawSyscallSupported() != lrsOk`` first; this keeps the symbol defined
 * so the Nim ``importc`` binding resolves. */
void *ct_linux_inline_syscall_handler_address(void) { return NULL; }
#endif /* __x86_64__ */

long ct_linux_inline_syscall_site_count(void) {
  return (long)ct_inline_syscall_site_count_value;
}

long ct_linux_inline_syscall_trap_count(void) {
  return (long)ct_inline_syscall_trap_count_value;
}

long ct_linux_inline_syscall_failure_count(void) {
  return (long)ct_inline_syscall_failure_count_value;
}

long ct_linux_inline_syscall_last_nr(void) {
  return (long)ct_inline_syscall_last_nr_value;
}

unsigned long ct_linux_inline_syscall_last_address(void) {
  return ct_inline_syscall_last_address_value;
}

int ct_linux_inline_syscall_overflowed(void) {
  return ct_inline_syscall_overflow_value != 0;
}

/* vfork shares TLS with its suspended parent. A successful exec never returns
 * through CT_CALL_HOOK, leaving that parent's guard raised. Remember the
 * guard depth before an exec dispatch and restore it when the parent resumes.
 * Keep the guard during libc PATH lookup to suppress duplicate exec records.
 * Only an outstanding exec bracket needs the live PID check. */
static __thread pid_t ct_exec_guard_pid = 0;
static __thread int ct_exec_guard_resume_depth = 0;

/* The same holds for the environment an exec hook prepares on the shim's heap
 * (ct_linux_preload_exec_env_prepare): the hook frees it when the exec fails,
 * but after a successful exec in a vfork child nothing returns to free it, and
 * the child's heap is the suspended parent's. So the preparation is remembered
 * here, per thread, with the pid that made it; when the parent resumes it sees
 * a different pid and releases the orphan. At most one is outstanding per
 * thread, so a host looping vfork + exec does not grow. */
static __thread char **ct_exec_env_pending = NULL;
static __thread pid_t ct_exec_env_pending_pid = 0;
void ct_linux_preload_free_owned_env(char **entries, char *const original[]);

static void ct_release_orphaned_exec_env(void) {
  if (ct_exec_env_pending != NULL && ct_exec_env_pending_pid != getpid()) {
    char **orphan = ct_exec_env_pending;
    ct_exec_env_pending = NULL;
    ct_exec_env_pending_pid = 0;
    ct_linux_preload_free_owned_env(orphan, NULL);
  }
}

static void ct_restore_vfork_exec_guard(void) {
  if (ct_exec_env_pending != NULL) ct_release_orphaned_exec_env();
  if (ct_exec_guard_pid != 0 && ct_exec_guard_pid != getpid()) {
    while (stackable_linux_preload_current_depth() > ct_exec_guard_resume_depth)
      stackable_linux_preload_exit_hook();
    ct_exec_guard_pid = 0;
    ct_exec_guard_resume_depth = 0;
  }
}

static int ct_preload_hooks_allowed(void) {
  ct_restore_vfork_exec_guard();
  return stackable_linux_preload_hooks_allowed();
}

#define CT_BYPASS() (!ct_preload_hooks_allowed())
#define CT_CALL_HOOK(expr) ({ \
  stackable_linux_preload_enter_hook(); \
  __typeof__(expr) _ct_result = (expr); \
  stackable_linux_preload_exit_hook(); \
  _ct_result; \
})

#define CT_CALL_EXEC_HOOK(expr) ({ \
  ct_restore_vfork_exec_guard(); \
  pid_t _ct_previous_exec_pid = ct_exec_guard_pid; \
  int _ct_previous_exec_depth = ct_exec_guard_resume_depth; \
  if (ct_exec_guard_pid == 0) { \
    ct_exec_guard_pid = getpid(); \
    ct_exec_guard_resume_depth = stackable_linux_preload_current_depth(); \
  } \
  __typeof__(expr) _ct_exec_result = CT_CALL_HOOK(expr); \
  ct_exec_guard_pid = _ct_previous_exec_pid; \
  ct_exec_guard_resume_depth = _ct_previous_exec_depth; \
  _ct_exec_result; \
})

static int ct_starts_with(const char *value, const char *prefix) {
  return strncmp(value, prefix, strlen(prefix)) == 0;
}

static int ct_env_contains_shim(const char *entry, const char *shim) {
  const char *value = entry + strlen("LD_PRELOAD=");
  return strstr(value, shim) != NULL;
}

void ct_linux_preload_set_shim_env_name(const char *name) {
  ct_linux_preload_shim_env_name = name;
}

/* Only arrays returned as different from the supplied envp are owned.
 * Entry strings borrowed from envp/environ are never freed. */
typedef struct ct_owned_env {
  char *owned[8];
  size_t ownedCount;
  char **parent;
  char *entries[];
} ct_owned_env;
static char **ct_alloc_env(size_t count) {
  if (count > (SIZE_MAX - sizeof(ct_owned_env)) / sizeof(char *)) return NULL;
  ct_owned_env *owner = calloc(1, sizeof(ct_owned_env) + count * sizeof(char *));
  return owner != NULL ? owner->entries : NULL;
}
static ct_owned_env *ct_env_owner(char **entries) {
  return (ct_owned_env *)((char *)entries - offsetof(ct_owned_env, entries));
}
void ct_linux_preload_free_owned_env(char **entries, char *const original[]) {
  if (entries == NULL || entries == original) return;
  if (entries == ct_exec_env_pending) {
    ct_exec_env_pending = NULL;
    ct_exec_env_pending_pid = 0;
  }
  ct_owned_env *owner = ct_env_owner(entries);
  for (size_t i = 0; i < owner->ownedCount; ++i) free(owner->owned[i]);
  if (owner->parent != NULL) ct_linux_preload_free_owned_env(owner->parent, NULL);
  free(owner);
}

/* Explicit child routes are never combined with a parent's capture route. */
static const char *ct_capture_seed_names[] = {
  "REPRO_MONITOR_FRAGMENT_DIR", "REPRO_MONITOR_SESSION",
  "REPRO_MONITOR_SHIM_LIB", "REPRO_MONITOR_INTEREST",
  "REPRO_MONITOR_EVIDENCE", "REPRO_MONITOR_DEP_SHM",
  "REPRO_MONITOR_COLLECTION_EVIDENCE"
};

static int ct_child_env_has(char *const source[], const char *name) {
  size_t n = strlen(name);
  for (char *const *it = source; *it != NULL; ++it)
    if (strncmp(*it, name, n) == 0 && (*it)[n] == '=') return 1;
  return 0;
}

/* Report malformed routing to the active parent; application syscalls still
 * execute. Complete child routes are left to the existing nested handoff. */
int ct_linux_preload_child_capture_route_status(char *const envp[]) {
  if (ct_linux_preload_shim_env_name == NULL ||
      strcmp(ct_linux_preload_shim_env_name, "REPRO_MONITOR_SHIM_LIB") != 0) return 0;
  char *const *source = envp != NULL ? envp : environ;
  if (source == NULL) return 0;
  unsigned counts[7] = {0};
  const char *values[7] = {0};
  for (char *const *it = source; *it != NULL; ++it) {
    for (size_t i = 0; i < 7; ++i) {
      size_t n = strlen(ct_capture_seed_names[i]);
      if (strncmp(*it, ct_capture_seed_names[i], n) == 0 && (*it)[n] == '=') {
        if (++counts[i] > 1) return 1;
        values[i] = *it + n + 1;
      }
    }
  }
  if ((counts[0] != 0) != (counts[1] != 0)) return 2;
  if (counts[0] != 0) {
    if (values[0][0] == '\0' || values[1][0] == '\0') return 3;
    if (strpbrk(values[1], " \t\r\n") != NULL) return 4;
  } else {
    const char *fragment = getenv("REPRO_MONITOR_FRAGMENT_DIR");
    const char *session = getenv("REPRO_MONITOR_SESSION");
    int hasFragment = fragment != NULL && fragment[0] != '\0';
    int hasSession = session != NULL && session[0] != '\0';
    if (hasFragment != hasSession) return 5;
    if (hasFragment && hasSession) {
      for (size_t i = 2; i < 7; ++i) {
        const char *parent = getenv(ct_capture_seed_names[i]);
        if (counts[i] != 0 && (parent == NULL || strcmp(values[i], parent) != 0)) return 6;
      }
    }
  }
  return 0;
}

char **ct_linux_preload_env_with_preload(char *const envp[]) {
  if (ct_linux_preload_shim_env_name == NULL ||
      ct_linux_preload_shim_env_name[0] == '\0') return (char **)envp;
  const char *shim = getenv(ct_linux_preload_shim_env_name);
  if (shim == NULL || shim[0] == '\0') return (char **)envp;
  char *const *source = envp != NULL ? envp : environ;
  if (source == NULL) return (char **)envp;

  const char *existing = NULL;
  size_t count = 0;
  for (char *const *it = source; *it != NULL; ++it) {
    if (ct_starts_with(*it, "LD_PRELOAD=")) existing = *it;
    else ++count;
  }
  /* This helper also serves other shim families; only the monitor's declared
   * constructor may propagate its capture controls. An explicit route, even
   * partial, stays untouched and must pass the actual capture protocol. */
  int inherit = strcmp(ct_linux_preload_shim_env_name,
                       "REPRO_MONITOR_SHIM_LIB") == 0 &&
    !ct_child_env_has(source, "REPRO_MONITOR_FRAGMENT_DIR") &&
    !ct_child_env_has(source, "REPRO_MONITOR_SESSION");
  char *seeds[7] = {0};
  size_t seedCount = 0;
  if (inherit) {
    const char *fragment = getenv("REPRO_MONITOR_FRAGMENT_DIR");
    const char *session = getenv("REPRO_MONITOR_SESSION");
    inherit = fragment != NULL && fragment[0] != '\0' &&
              session != NULL && session[0] != '\0';
  }
  if (inherit) {
    for (size_t i = 0; i < 7; ++i) {
      const char *name = ct_capture_seed_names[i];
      const char *value = getenv(name);
      if (ct_child_env_has(source, name) || value == NULL) continue;
      size_t size = strlen(name) + strlen(value) + 2;
      seeds[seedCount] = (char *)malloc(size);
      if (seeds[seedCount] == NULL) goto seed_failure;
      snprintf(seeds[seedCount], size, "%s=%s", name, value);
      ++seedCount;
    }
  }
  if (existing != NULL && ct_env_contains_shim(existing, shim) &&
      seedCount == 0) return (char **)envp;
  const char *existingValue = existing != NULL ? existing + 11 : "";
  int already = existing != NULL && ct_env_contains_shim(existing, shim);
  size_t size = already ? strlen(existing) + 1 :
    strlen("LD_PRELOAD=") + strlen(shim) + strlen(existingValue) + 2;
  char *entry = (char *)malloc(size);
  if (entry == NULL) goto seed_failure;
  if (already) snprintf(entry, size, "%s", existing);
  else if (existingValue[0] != '\0')
    snprintf(entry, size, "LD_PRELOAD=%s:%s", shim, existingValue);
  else snprintf(entry, size, "LD_PRELOAD=%s", shim);
  char **result = ct_alloc_env(count + seedCount + 2);
  if (result == NULL) { free(entry); goto seed_failure; }
  ct_owned_env *owner = ct_env_owner(result);
  owner->owned[owner->ownedCount++] = entry;
  for (size_t i = 0; i < seedCount; ++i) owner->owned[owner->ownedCount++] = seeds[i];
  size_t index = 0;
  for (char *const *it = source; *it != NULL; ++it)
    if (!ct_starts_with(*it, "LD_PRELOAD=")) result[index++] = *it;
  result[index++] = entry;
  for (size_t i = 0; i < seedCount; ++i) result[index++] = seeds[i];
  result[index] = NULL;
  return result;
seed_failure:
  for (size_t i = 0; i < seedCount; ++i) free(seeds[i]);
  return (char **)envp;
}

/* io-mon Lossless-Event-Capture M3 (exec-generation identity) — build the
 * child environment for an exec: inject LD_PRELOAD=shim (exactly like
 * ct_linux_preload_env_with_preload) AND set REPRO_MONITOR_EXEC_GEN=<nextGen>,
 * REPLACING any value inherited from the current incarnation.
 *
 * The generation exists so that two consecutive process-starts on the SAME
 * pid whose /proc/self/exe is byte-identical (the Nix gcc/rustc bash-wrapper
 * that re-execs the real compiler in-place) land as DISTINCT dep-set elements.
 * Without it the second, byte-identical process-start is deduped at the source
 * and the completeness accounting sees execs>=starts -> mrEventLoss ->
 * mcIncomplete for every Nix-toolchain build. The child reads this value in
 * its preload constructor and appends it to its own set-element identity.
 *
 * It does NOT touch the process's own `environ`: the PATH-searching exec
 * family is handed the array this returns instead (see
 * ct_linux_preload_dispatch_execvp). A previous version bumped `environ` with
 * an array from the shim's private heap, which handed the host an `environ`
 * its own allocator never allocated.
 *
 * Returns a freshly malloc'd, NULL-terminated array (leaked into the exec —
 * the kernel reclaims the pages when the image is replaced) or the plain
 * preload array on allocation failure. A stale generation can only ever cause
 * an over-conservative mcIncomplete, never a false mcComplete. */
char **ct_linux_preload_env_with_exec_gen(char *const envp[], long nextGen) {
  /* A newly declared public capture root has a distinct complete route and
   * an explicit zero incarnation. Do not carry its enclosing observer's exec
   * generation into that new route. Same-route descendants still advance. */
  const char *child_session = NULL, *child_generation = NULL, *child_fragment = NULL;
  unsigned session_count = 0, generation_count = 0, fragment_count = 0;
  if (envp != NULL) for (char *const *it = envp; *it != NULL; ++it) {
    if (ct_starts_with(*it, "REPRO_MONITOR_FRAGMENT_DIR=")) {
      child_fragment = *it + strlen("REPRO_MONITOR_FRAGMENT_DIR="); ++fragment_count;
    }
    if (ct_starts_with(*it, "REPRO_MONITOR_SESSION=")) {
      child_session = *it + strlen("REPRO_MONITOR_SESSION="); ++session_count;
    }
    if (ct_starts_with(*it, "REPRO_MONITOR_EXEC_GEN=")) {
      child_generation = *it + strlen("REPRO_MONITOR_EXEC_GEN="); ++generation_count;
    }
  }
  const char *parent_session = getenv("REPRO_MONITOR_SESSION");
  if (ct_linux_preload_shim_env_name != NULL &&
      strcmp(ct_linux_preload_shim_env_name, "REPRO_MONITOR_SHIM_LIB") == 0 &&
      fragment_count == 1 && child_fragment[0] != '\0' &&
      session_count == 1 && generation_count == 1 &&
      child_session[0] != '\0' && parent_session != NULL &&
      strcmp(child_session, parent_session) != 0 &&
      strcmp(child_generation, "0") == 0 &&
      ct_linux_preload_child_capture_route_status(envp) == 0)
    nextGen = 0;
  char genValue[32];
  snprintf(genValue, sizeof(genValue), "%ld", nextGen);
  size_t genEntryLen = strlen("REPRO_MONITOR_EXEC_GEN=") + strlen(genValue) + 1;

  const char *shim = NULL;
  if (ct_linux_preload_shim_env_name != NULL &&
      ct_linux_preload_shim_env_name[0] != '\0') {
    const char *s = getenv(ct_linux_preload_shim_env_name);
    if (s != NULL && s[0] != '\0') shim = s;
  }

  char **prepared = ct_linux_preload_env_with_preload(envp);
  char *const *source = prepared != NULL ? prepared : environ;

  int count = 0;
  const char *existingPreload = NULL;
  if (source != NULL) {
    for (char *const *it = source; *it != NULL; it++) {
      if (ct_starts_with(*it, "LD_PRELOAD=")) {
        existingPreload = *it;
      } else if (ct_starts_with(*it, "REPRO_MONITOR_EXEC_GEN=")) {
        /* dropped — re-emitted with nextGen below */
      } else {
        count++;
      }
    }
  }

  /* LD_PRELOAD entry: keep the caller's value, prepend the shim if absent. */
  char *preloadEntry = NULL;
  if (shim != NULL) {
    const char *existingValue =
      existingPreload != NULL ? existingPreload + strlen("LD_PRELOAD=") : "";
    if (existingPreload != NULL && strstr(existingValue, shim) != NULL) {
      size_t n = strlen(existingPreload) + 1;
      preloadEntry = (char *)malloc(n);
      if (preloadEntry != NULL) memcpy(preloadEntry, existingPreload, n);
    } else {
      size_t entryLen = strlen("LD_PRELOAD=") + strlen(shim) + 1;
      if (existingValue[0] != '\0') entryLen += 1 + strlen(existingValue);
      preloadEntry = (char *)malloc(entryLen);
      if (preloadEntry != NULL) {
        if (existingValue[0] != '\0')
          snprintf(preloadEntry, entryLen, "LD_PRELOAD=%s:%s", shim, existingValue);
        else
          snprintf(preloadEntry, entryLen, "LD_PRELOAD=%s", shim);
      }
    }
  } else if (existingPreload != NULL) {
    size_t n = strlen(existingPreload) + 1;
    preloadEntry = (char *)malloc(n);
    if (preloadEntry != NULL) memcpy(preloadEntry, existingPreload, n);
  }

  char *genEntry = (char *)malloc(genEntryLen);
  if (genEntry != NULL)
    snprintf(genEntry, genEntryLen, "REPRO_MONITOR_EXEC_GEN=%s", genValue);

  if (genEntry == NULL || (existingPreload != NULL && preloadEntry == NULL)) {
    free(preloadEntry);
    free(genEntry);
    return prepared;
  }

  int extra = 1 /* gen */ + (preloadEntry != NULL ? 1 : 0);
  char **result =
    ct_alloc_env((size_t)count + (size_t)extra + 1);
  if (result == NULL) {
    free(preloadEntry);
    free(genEntry);
    return prepared;
  }
  ct_owned_env *owner = ct_env_owner(result);
  if (preloadEntry != NULL) owner->owned[owner->ownedCount++] = preloadEntry;
  owner->owned[owner->ownedCount++] = genEntry;
  if (prepared != NULL && prepared != envp) owner->parent = prepared;
  int index = 0;
  if (source != NULL) {
    /* Kept entries are borrowed pointers into `source`; only the entries
     * this function allocated are owned (and freed by
     * ct_linux_preload_free_owned_env if the exec fails). */
    for (char *const *it = source; *it != NULL; it++) {
      if (ct_starts_with(*it, "LD_PRELOAD=")) continue;
      if (ct_starts_with(*it, "REPRO_MONITOR_EXEC_GEN=")) continue;
      result[index++] = *it;
    }
  }
  if (preloadEntry != NULL) result[index++] = preloadEntry;
  result[index++] = genEntry;
  result[index] = NULL;
  return result;
}

/* ct_linux_preload_env_with_exec_gen for an exec hook: the preparation is
 * also remembered as outstanding until the hook frees it (exec failed) or the
 * process image is replaced; see ct_exec_env_pending. */
char **ct_linux_preload_exec_env_prepare(char *const envp[], long nextGen) {
  ct_release_orphaned_exec_env();
  char **prepared = ct_linux_preload_env_with_exec_gen(envp, nextGen);
  if (prepared != NULL && prepared != (char **)envp) {
    ct_exec_env_pending = prepared;
    ct_exec_env_pending_pid = getpid();
  }
  return prepared;
}

void ct_linux_preload_register_open_hook(ct_open_hook_fn hook) { ct_open_hook = hook; }
void ct_linux_preload_register_open64_hook(ct_open_hook_fn hook) { ct_open64_hook = hook; }
void ct_linux_preload_register_openat_hook(ct_openat_hook_fn hook) { ct_openat_hook = hook; }
void ct_linux_preload_register_openat64_hook(ct_openat_hook_fn hook) { ct_openat64_hook = hook; }
void ct_linux_preload_register_close_hook(ct_close_hook_fn hook) { ct_close_hook = hook; }
void ct_linux_preload_register_read_hook(ct_read_hook_fn hook) { ct_read_hook = hook; }
void ct_linux_preload_register_pread_hook(ct_pread_hook_fn hook) { ct_pread_hook = hook; }
void ct_linux_preload_register_readv_hook(ct_readv_hook_fn hook) { ct_readv_hook = hook; }
void ct_linux_preload_register_preadv_hook(ct_preadv_hook_fn hook) { ct_preadv_hook = hook; }
void ct_linux_preload_register_write_hook(ct_write_hook_fn hook) { ct_write_hook = hook; }
void ct_linux_preload_register_stat_hook(ct_stat_hook_fn hook) { ct_stat_hook = hook; }
void ct_linux_preload_register_lstat_hook(ct_stat_hook_fn hook) { ct_lstat_hook = hook; }
void ct_linux_preload_register_opendir_hook(ct_opendir_hook_fn hook) { ct_opendir_hook = hook; }
void ct_linux_preload_register_readdir_hook(ct_readdir_hook_fn hook) { ct_readdir_hook = hook; }
void ct_linux_preload_register_closedir_hook(ct_closedir_hook_fn hook) { ct_closedir_hook = hook; }
void ct_linux_preload_register_fopen_hook(ct_fopen_hook_fn hook) { ct_fopen_hook = hook; }
void ct_linux_preload_register_fopen64_hook(ct_fopen_hook_fn hook) { ct_fopen64_hook = hook; }
void ct_linux_preload_register_fread_hook(ct_fread_hook_fn hook) { ct_fread_hook = hook; }
void ct_linux_preload_register_fclose_hook(ct_fclose_hook_fn hook) { ct_fclose_hook = hook; }
void ct_linux_preload_register_connect_hook(ct_connect_hook_fn hook) { ct_connect_hook = hook; }
void ct_linux_preload_register_pipe_hook(ct_pipe_hook_fn hook) { ct_pipe_hook = hook; }
void ct_linux_preload_register_pipe2_hook(ct_pipe2_hook_fn hook) { ct_pipe2_hook = hook; }
void ct_linux_preload_register_socketpair_hook(ct_socketpair_hook_fn hook) { ct_socketpair_hook = hook; }
void ct_linux_preload_register_sendfile_hook(ct_sendfile_hook_fn hook) { ct_sendfile_hook = hook; }
void ct_linux_preload_register_copy_file_range_hook(ct_copy_file_range_hook_fn hook) { ct_copy_file_range_hook = hook; }
void ct_linux_preload_register_splice_hook(ct_splice_hook_fn hook) { ct_splice_hook = hook; }
void ct_linux_preload_register_link_hook(ct_link_hook_fn hook) { ct_link_hook = hook; }
void ct_linux_preload_register_linkat_hook(ct_linkat_hook_fn hook) { ct_linkat_hook = hook; }
void ct_linux_preload_register_rename_hook(ct_rename_hook_fn hook) { ct_rename_hook = hook; }
void ct_linux_preload_register_renameat_hook(ct_renameat_hook_fn hook) { ct_renameat_hook = hook; }
void ct_linux_preload_register_renameat2_hook(ct_renameat2_hook_fn hook) { ct_renameat2_hook = hook; }
void ct_linux_preload_register_dlopen_hook(ct_dlopen_hook_fn hook) { ct_dlopen_hook = hook; }
void ct_linux_preload_register_dlmopen_hook(ct_dlmopen_hook_fn hook) { ct_dlmopen_hook = hook; }
void ct_linux_preload_register_dlsym_hook(ct_dlsym_hook_fn hook) { ct_dlsym_hook = hook; }
void ct_linux_preload_register_mmap_hook(ct_mmap_hook_fn hook) { ct_mmap_hook = hook; }
void ct_linux_preload_register_mprotect_hook(ct_mprotect_hook_fn hook) { ct_mprotect_hook = hook; }
void ct_linux_preload_register_munmap_hook(ct_munmap_hook_fn hook) { ct_munmap_hook = hook; }
void ct_linux_preload_register_mremap_hook(ct_mremap_hook_fn hook) { ct_mremap_hook = hook; }
void ct_linux_preload_register_getenv_hook(ct_getenv_hook_fn hook) { ct_getenv_hook = hook; }
void ct_linux_preload_register_uname_hook(ct_uname_hook_fn hook) { ct_uname_hook = hook; }
void ct_linux_preload_register_sysconf_hook(ct_sysconf_hook_fn hook) { ct_sysconf_hook = hook; }
void ct_linux_preload_register_clock_gettime_hook(ct_clock_gettime_hook_fn hook) { ct_clock_gettime_hook = hook; }
void ct_linux_preload_register_gettimeofday_hook(ct_gettimeofday_hook_fn hook) { ct_gettimeofday_hook = hook; }
void ct_linux_preload_register_time_hook(ct_time_hook_fn hook) { ct_time_hook = hook; }
void ct_linux_preload_register_getrandom_hook(ct_getrandom_hook_fn hook) { ct_getrandom_hook = hook; }
void ct_linux_preload_register_getentropy_hook(ct_getentropy_hook_fn hook) { ct_getentropy_hook = hook; }
void ct_linux_preload_register_arc4random_hook(ct_arc4random_hook_fn hook) { ct_arc4random_hook = hook; }
void ct_linux_preload_register_arc4random_buf_hook(ct_arc4random_buf_hook_fn hook) { ct_arc4random_buf_hook = hook; }
void ct_linux_preload_register_arc4random_uniform_hook(ct_arc4random_uniform_hook_fn hook) { ct_arc4random_uniform_hook = hook; }
void ct_linux_preload_register_fork_hook(ct_fork_hook_fn hook) { ct_fork_hook = hook; }
void ct_linux_preload_register_execve_hook(ct_execve_hook_fn hook) { ct_execve_hook = hook; }
void ct_linux_preload_register_posix_spawn_hook(ct_posix_spawn_hook_fn hook) { ct_posix_spawn_hook = hook; }
void ct_linux_preload_register_posix_spawnp_hook(ct_posix_spawn_hook_fn hook) { ct_posix_spawnp_hook = hook; }
void ct_linux_preload_register_exit_hook(ct_exit_hook_fn hook) { ct_exit_hook = hook; }
void ct_linux_preload_register_raw_syscall_hook(ct_raw_syscall_hook_fn hook) {
  __atomic_store_n(&ct_raw_user_hook, hook, __ATOMIC_RELEASE);
  __atomic_store_n(&ct_raw_syscall_hook, hook != NULL ? ct_raw_dispatch : NULL,
                    __ATOMIC_RELEASE);
}

void ct_linux_preload_real_exit(int status) __attribute__((noreturn));
void ct_linux_preload_real_exit(int status) {
#ifdef SYS_exit_group
  syscall(SYS_exit_group, status);
#endif
  syscall(SYS_exit, status);
  __builtin_unreachable();
}

/* Raw (un-interposed) syscall entry. On x86_64 this is nim-stackable-hooks'
 * hand-written ``syscall`` instruction wrapper, which returns the kernel's
 * ``-errno`` convention directly. On other architectures that substrate does
 * not exist (see the ``__x86_64__`` note above the extern block), so fall back
 * to libc ``syscall(2)`` and re-encode its ``-1``/``errno`` convention into the
 * kernel convention the callers below expect.
 *
 * It must NOT fall back to libc ``syscall(2)``. ``shim/linux_preload.nim``
 * DEFINES ``long syscall(long, ...)`` with default visibility -- that is the
 * LD_PRELOAD interposer for libc's ``syscall``. Since this shim is preloaded it
 * is first in the lookup scope, so a call to ``syscall`` from anywhere inside
 * it binds back to that interposer: unbounded recursion in every monitored
 * process. The non-amd64 arm therefore issues the syscall instruction directly,
 * exactly as nim-stackable-hooks does for x86_64.
 *
 * aarch64 Linux ABI: number in x8, args in x0-x5, ``svc #0``, result in x0
 * under the kernel ``-errno`` convention -- which is already the convention the
 * callers below test against, so there is nothing to re-encode. */
static long ct_raw_syscall6(long nr, long a1, long a2, long a3, long a4,
                            long a5, long a6) {
#if defined(__x86_64__)
  return stackable_linux_raw_syscall6(nr, a1, a2, a3, a4, a5, a6);
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = a1;
  register long x1 __asm__("x1") = a2;
  register long x2 __asm__("x2") = a3;
  register long x3 __asm__("x3") = a4;
  register long x4 __asm__("x4") = a5;
  register long x5 __asm__("x5") = a6;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                   : "memory", "cc");
  return x0;
#else
#error "io-mon: no raw syscall primitive for this architecture. Add one here \
rather than routing through libc syscall(2) -- this shim interposes that \
symbol, so calling it would recurse forever."
#endif
}

static long ct_linux_preload_raw_syscall6(long nr, long a1, long a2, long a3,
                                          long a4, long a5, long a6) {
  long result = ct_raw_syscall6(nr, a1, a2, a3, a4, a5, a6);
  if (result < 0 && result >= -4095) {
    errno = (int)-result;
    return -1;
  }
  return result;
}

long ct_linux_preload_syscall_replacement(long nr, long a1, long a2, long a3,
                                          long a4, long a5, long a6)
    __attribute__((visibility("default")));
/* This protocol deliberately does not accept an arbitrary existing jump.
 * Both its destination and the owner ABI must resolve inside the same loaded
 * DSO; the owner then independently checks its live target/replacement pair. */
static int ct_raw_patch_matches(void *target, void *replacement) {
#if defined(__x86_64__)
  static const unsigned char prefix[6] = {0xff, 0x25, 0, 0, 0, 0};
  void *actual = NULL;
  if (target == NULL || replacement == NULL ||
      memcmp(target, prefix, sizeof(prefix)) != 0) return 0;
  memcpy(&actual, (unsigned char *)target + 6, sizeof(actual));
  return actual == replacement;
#else
  return 0;
#endif
}

/* Fixed source-owned POD lock: child reset has no opaque pthread layout.
 * Wait through a raw futex, not a CPU spin or a monitored libc syscall. */
static int ct_raw_subscribers_lock(void) {
  for (;;) {
    int empty = 0;
    if (__atomic_compare_exchange_n(&ct_raw_subscriber_lock, &empty, 1, 0,
          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return 1;
    long waited = ct_raw_syscall6(SYS_futex, (long)&ct_raw_subscriber_lock,
                                  FUTEX_WAIT_PRIVATE, 1, 0, 0, 0);
    if (waited < 0 && waited != -EINTR && waited != -EAGAIN) return 0;
  }
}

static void ct_raw_subscribers_unlock(void) {
  __atomic_store_n(&ct_raw_subscriber_lock, 0, __ATOMIC_RELEASE);
  (void)ct_raw_syscall6(SYS_futex, (long)&ct_raw_subscriber_lock,
                        FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
}

int ct_linux_preload_raw_owner_prepare(void) {
  if (__atomic_load_n(&ct_raw_self_handle, __ATOMIC_ACQUIRE) != NULL) return 1;
  Dl_info self;
  if (!dladdr((void *)ct_linux_preload_syscall_replacement, &self)) return 0;
  ct_dlopen_real_fn open_fn = (ct_dlopen_real_fn)ct_resolve("dlopen");
  if (open_fn == NULL) return 0;
  void *pin = open_fn(self.dli_fname, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  if (pin == NULL) return 0;
  if (pthread_atfork(NULL, NULL, ct_raw_owner_after_fork_child) != 0) {
    dlclose(pin);
    return 0;
  }
  void *empty = NULL;
  if (!__atomic_compare_exchange_n(&ct_raw_self_handle, &empty, pin, 0,
        __ATOMIC_RELEASE, __ATOMIC_RELAXED)) dlclose(pin);
  return 1;
}

void ct_linux_preload_raw_owner_commit(void *target) {
  __atomic_store_n(&ct_raw_owner_target, target, __ATOMIC_RELEASE);
}

typedef int (*ct_raw_owner_subscribe_fn)(unsigned long long, void *, void *,
                                        ct_raw_syscall_hook_fn,
                                        ct_raw_enqueue_fn, ct_raw_flush_fn, ct_library_scan_fn);
int ct_linux_preload_raw_owner_subscribe_v2(unsigned long long abi,
    void *target, void *replacement, ct_raw_syscall_hook_fn callback,
    ct_raw_enqueue_fn enqueue, ct_raw_flush_fn flush, ct_library_scan_fn scan)
    __attribute__((visibility("default")));
int ct_linux_preload_raw_owner_subscribe_v2(unsigned long long abi,
    void *target, void *replacement, ct_raw_syscall_hook_fn callback,
    ct_raw_enqueue_fn enqueue, ct_raw_flush_fn flush, ct_library_scan_fn scan) {
  Dl_info owner, subscriber, queue_image, flush_image, scan_image;
  if (abi != CT_RAW_OWNER_ABI_V2) return -1;
  if (callback == NULL || enqueue == NULL || flush == NULL || scan == NULL) return -2;
  if (target != __atomic_load_n(&ct_raw_owner_target, __ATOMIC_ACQUIRE)) return -3;
  if (replacement != (void *)ct_linux_preload_syscall_replacement) return -4;
  if (!ct_raw_patch_matches(target, replacement)) return -5;
  if (!dladdr(replacement, &owner) || !dladdr((void *)callback, &subscriber) ||
      !dladdr((void *)enqueue, &queue_image) ||
      !dladdr((void *)flush, &flush_image) ||
      !dladdr((void *)scan, &scan_image)) return -6;
  if (queue_image.dli_fbase != subscriber.dli_fbase ||
      flush_image.dli_fbase != subscriber.dli_fbase ||
      scan_image.dli_fbase != subscriber.dli_fbase) return -7;
  if (callback == __atomic_load_n(&ct_raw_syscall_hook, __ATOMIC_ACQUIRE))
    return 1;
  /* Resolve and pin outside the table lock: loader constructors may themselves
   * attach a monitor. The lock covers only bounded POD comparisons/publication. */
  ct_dlopen_real_fn open_fn = (ct_dlopen_real_fn)ct_resolve("dlopen");
  if (open_fn == NULL) return 0;
  void *pin = open_fn(subscriber.dli_fname, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  if (pin == NULL) return 0;
  if (!ct_raw_subscribers_lock()) {
    dlclose(pin);
    return 0;
  }
  int attached = 0;
  int published = 0;
  int empty = -1;
  for (int i = 0; i < CT_RAW_SUBSCRIBER_CAP; ++i) {
    ct_raw_syscall_hook_fn found = __atomic_load_n(&ct_raw_subscribers[i],
                                                  __ATOMIC_ACQUIRE);
    if (found == callback) {
      attached = ct_raw_subscriber_enqueue[i] == enqueue &&
                 ct_raw_subscriber_flush[i] == flush &&
                 ct_library_subscriber_scan[i] == scan;
      empty = -1;
      break;
    }
    if (found == NULL && empty == -1) empty = i;
  }
  if (!attached && empty != -1) {
    ct_raw_subscriber_enqueue[empty] = enqueue;
    ct_raw_subscriber_flush[empty] = flush;
    ct_library_subscriber_scan[empty] = scan;
    __atomic_store_n(&ct_raw_subscribers[empty], callback, __ATOMIC_RELEASE);
    attached = published = 1;
  }
  ct_raw_subscribers_unlock();
  if (!published) dlclose(pin);
  return attached;
}

/* Callbacks are published with their pinned subscriber record. No loader or
 * registration lock is held while an observer enumerates its own link map. */
void ct_linux_preload_library_scan_owner(const char *reason)
    __attribute__((visibility("default")));
void ct_linux_preload_library_scan_owner(const char *reason) {
  int saved_errno = errno;
  ct_library_scan_fn primary = __atomic_load_n(&ct_library_scan, __ATOMIC_ACQUIRE);
  if (primary != NULL) primary(reason);
  for (int i = 0; i < CT_RAW_SUBSCRIBER_CAP; ++i) {
    if (__atomic_load_n(&ct_raw_subscribers[i], __ATOMIC_ACQUIRE) != NULL)
      ct_library_subscriber_scan[i](reason);
  }
  errno = saved_errno;
}
void ct_linux_preload_library_scan_register(ct_library_scan_fn scan) {
  __atomic_store_n(&ct_library_scan, scan, __ATOMIC_RELEASE);
}
void ct_linux_preload_library_scan_all(const char *reason) {
  ct_library_scan_fn owner = __atomic_load_n(&ct_library_owner_scan, __ATOMIC_ACQUIRE);
  if (owner != NULL) owner(reason);
  else ct_linux_preload_library_scan_owner(reason);
}

int ct_linux_preload_raw_owner_join(void *target) {
#if defined(__x86_64__)
  void *replacement = NULL;
  Dl_info owner, api_image, scan_image;
  static const unsigned char prefix[6] = {0xff, 0x25, 0, 0, 0, 0};
  ct_raw_owner_join_reason = "target-not-absolute-jump";
  if (target == NULL || memcmp(target, prefix, sizeof(prefix)) != 0) return 0;
  memcpy(&replacement, (unsigned char *)target + 6, sizeof(replacement));
  ct_raw_owner_join_reason = "replacement-image-unavailable";
  if (replacement == NULL || !dladdr(replacement, &owner)) return 0;
  snprintf(ct_raw_owner_join_image, sizeof(ct_raw_owner_join_image), "%s",
           owner.dli_fname == NULL ? "" : owner.dli_fname);
  ct_dlopen_real_fn open_fn = (ct_dlopen_real_fn)ct_resolve("dlopen");
  ct_dlsym_real_fn symbol_fn = (ct_dlsym_real_fn)ct_resolve("dlsym");
  ct_raw_owner_join_reason = "loader-functions-unavailable";
  if (open_fn == NULL || symbol_fn == NULL) return 0;
  void *handle = open_fn(owner.dli_fname, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  ct_raw_owner_join_reason = "owner-handle-unavailable";
  if (handle == NULL) return 0;
  void *owner_replacement = symbol_fn(handle, "ct_linux_preload_syscall_replacement");
  void *api = symbol_fn(handle, "ct_linux_preload_raw_owner_subscribe_v2");
  void *scan_api = symbol_fn(handle, "ct_linux_preload_library_scan_owner");
  ct_raw_owner_join_reason = "owner-replacement-symbol-mismatch";
  if (owner_replacement != replacement) { dlclose(handle); return 0; }
  ct_raw_owner_join_reason = "owner-api-unavailable";
  if (api == NULL || scan_api == NULL) { dlclose(handle); return 0; }
  ct_raw_owner_join_reason = "owner-api-image-mismatch";
  if (!dladdr(api, &api_image) || api_image.dli_fbase != owner.dli_fbase ||
      !dladdr(scan_api, &scan_image) || scan_image.dli_fbase != owner.dli_fbase) {
    dlclose(handle); return 0;
  }
  ct_raw_owner_join_reason = "owner-rejected-subscription";
  int joined = ((ct_raw_owner_subscribe_fn)api)(CT_RAW_OWNER_ABI_V2, target,
          replacement, __atomic_load_n(&ct_raw_syscall_hook, __ATOMIC_ACQUIRE),
          ct_linux_preload_raw_enqueue_v1, repro_linux_sig_safe_flush,
          __atomic_load_n(&ct_library_scan, __ATOMIC_ACQUIRE));
  if (joined != 1) {
    snprintf(ct_raw_owner_refusal, sizeof(ct_raw_owner_refusal),
              "owner-rejected-subscription:%d", joined);
    ct_raw_owner_join_reason = ct_raw_owner_refusal;
    dlclose(handle); return 0;
  }
  ct_raw_owner_join_reason = "attached";
  ct_raw_owner_handle = handle;
  __atomic_store_n(&ct_library_owner_scan, (ct_library_scan_fn)scan_api, __ATOMIC_RELEASE);
  return 1;
#else
  return 0;
#endif
}

long ct_linux_preload_syscall_replacement(long nr, long a1, long a2, long a3,
                                          long a4, long a5, long a6) {
  int saved_errno = errno;
  /* Once installed, this replacement is what libc's syscall(2) -- and the
   * shim's own `syscall` interposer, whose body the same patch redirects --
   * runs, so the end-of-image work the interposer and the inline trap do
   * belongs here too: classify pending trapped events before an exit or
   * exec that bypasses the destructor and the exec hooks, and flush this
   * thread's batch before it exits (see the trap handler). */
#ifdef SYS_exit_group
  if (nr == SYS_exit_group) {
    if (ct_linux_drain_inline_events_before_image_end())
      ct_raw_flush_observers();
  }
#endif
#ifdef SYS_exit
  if (nr == SYS_exit) ct_raw_flush_observers();
#endif
  if (nr == SYS_execve
#ifdef SYS_execveat
      || nr == SYS_execveat
#endif
      ) {
    ct_linux_drain_inline_events_before_image_end();
    /* No exec hook runs for a raw exec: classify its target here. */
    ct_linux_check_raw_exec_entry(nr, a1, a2, a5);
  }
  int forks = ct_raw_call_forks_process(nr, a1) && !CT_BYPASS() &&
              ct_raw_fork_sample != NULL && ct_raw_fork_child != NULL;
  int parent_single = forks ? CT_CALL_HOOK(ct_raw_fork_sample()) : 1;
  long result = ct_raw_syscall6(nr, a1, a2, a3, a4, a5, a6);
  ct_raw_owner_after_raw_fork(nr, a1, result);
  if (forks && result == 0) ct_raw_fork_child(parent_single);
  ct_raw_syscall_hook_fn primary = __atomic_load_n(&ct_raw_syscall_hook, __ATOMIC_ACQUIRE);
  if (!CT_BYPASS() && primary != NULL) {
    CT_CALL_HOOK((primary(nr, a1, a2, a3, a4, a5, a6, result,
                                      CT_RAW_SYSCALL_SOURCE_LIBC), 0));
    for (int i = 0; i < CT_RAW_SUBSCRIBER_CAP; ++i) {
      ct_raw_syscall_hook_fn callback = __atomic_load_n(&ct_raw_subscribers[i],
                                                        __ATOMIC_ACQUIRE);
      if (callback != NULL)
        CT_CALL_HOOK((callback(nr, a1, a2, a3, a4, a5, a6, result,
                               CT_RAW_SYSCALL_SOURCE_LIBC), 0));
    }
  }
  if (result < 0 && result >= -4095) {
    errno = (int)-result;
    return -1;
  }
  errno = saved_errno;
  return result;
}

/* glibc's clone(3) wrapper issues the clone system call from inside libc,
 * where neither the syscall(2) replacement nor the inline-syscall trap sees it.
 * A child created without CLONE_VM is a process, not a thread, and is in the
 * position the raw paths above handle: it ran no atfork handlers and inherits
 * every shim lock another thread held at that instant. So the interposition
 * runs the child's function through a trampoline that first gives the child
 * the same treatment (reclaim inherited locks; skip monitor bookkeeping until
 * exec when the parent had other threads). The trampoline's argument lives in
 * the caller's frame, which the child receives a copy of. A CLONE_VM child
 * shares the parent's memory and live locks, so it is passed through as is.
 * glibc passes the three optional arguments to the kernel unconditionally
 * (sysdeps/unix/sysv/linux/x86_64/clone.S), so forwarding them is exact. See
 * clone(2). */
typedef int (*ct_clone_fn)(int (*)(void *), void *, int, void *, ...);
static ct_clone_fn real_clone_ptr = NULL;

struct ct_clone_trampoline {
  int (*fn)(void *);
  void *arg;
  int parent_single;
};

static int ct_clone_child_entry(void *opaque) {
  struct ct_clone_trampoline call = *(struct ct_clone_trampoline *)opaque;
  ct_raw_fork_child_reset();
  if (ct_raw_fork_child != NULL) ct_raw_fork_child(call.parent_single);
  return call.fn(call.arg);
}

int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...)
    __attribute__((visibility("default")));
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
  va_list ap;
  va_start(ap, arg);
  pid_t *parent_tid = va_arg(ap, pid_t *);
  void *tls = va_arg(ap, void *);
  pid_t *child_tid = va_arg(ap, pid_t *);
  va_end(ap);
  if (real_clone_ptr == NULL) real_clone_ptr = (ct_clone_fn)ct_resolve("clone");
  if (real_clone_ptr == NULL) { errno = ENOSYS; return -1; }
  if ((flags & CLONE_VM) != 0 || fn == NULL)
    return real_clone_ptr(fn, stack, flags, arg, parent_tid, tls, child_tid);
  int saved_errno = errno;
  struct ct_clone_trampoline call = {fn, arg, 1};
  if (!CT_BYPASS() && ct_raw_fork_sample != NULL)
    call.parent_single = CT_CALL_HOOK(ct_raw_fork_sample());
  errno = saved_errno;
  return real_clone_ptr(ct_clone_child_entry, stack, flags, &call,
                        parent_tid, tls, child_tid);
}

/* glibc 2.34's _Fork(3) is fork(2) without the atfork handlers, for code
 * that must fork from a signal handler. glibc's own fork() calls it
 * internally, never through this symbol, so only a program's direct call
 * lands here. Its child is in the position of a raw clone's: no atfork
 * handler ran, so neither the shim's nor the private heap's state was made
 * consistent, and a multi-threaded parent's other threads may have held any
 * shim lock. It gets the same treatment as glibc's clone(3) above (reclaim
 * the private heap's locks; skip monitor bookkeeping until exec, reporting
 * what it skips, when the parent had other threads). Without this, such a
 * child recorded straight through whatever state the fork caught. See
 * _Fork(3). */
typedef pid_t (*ct_underscore_fork_fn)(void);
static ct_underscore_fork_fn real_underscore_fork_ptr = NULL;

pid_t _Fork(void) __attribute__((visibility("default")));
pid_t _Fork(void) {
  ct_underscore_fork_fn real = __atomic_load_n(&real_underscore_fork_ptr,
                                               __ATOMIC_ACQUIRE);
  if (real == NULL) {
    /* Normally primed by ct_linux_preload_prime_real_functions; this lookup
     * covers a call made before the constructor ran. */
    real = (ct_underscore_fork_fn)ct_resolve("_Fork");
    __atomic_store_n(&real_underscore_fork_ptr, real, __ATOMIC_RELEASE);
  }
  if (real == NULL) { errno = ENOSYS; return -1; }
  int saved_errno = errno;
  int parent_single = 1;
  if (!CT_BYPASS() && ct_raw_fork_sample != NULL)
    parent_single = CT_CALL_HOOK(ct_raw_fork_sample());
  errno = saved_errno;
  pid_t pid = real();
  if (pid == 0) {
    saved_errno = errno;
    ct_raw_fork_child_reset();
    if (ct_raw_fork_child != NULL) ct_raw_fork_child(parent_single);
    errno = saved_errno;
  }
  return pid;
}

static int ct_open_flags_need_mode(int flags) {
  if ((flags & O_CREAT) != 0) return 1;
#ifdef O_TMPFILE
  if ((flags & O_TMPFILE) == O_TMPFILE) return 1;
#endif
  return 0;
}

static int ct_real_open_common(ct_open_real_fn *slot, const char *symbol,
                               char *path, int flags, int mode) {
  if (*slot == NULL) *slot = (ct_open_real_fn)ct_resolve(symbol);
  if (*slot == NULL && strcmp(symbol, "open64") == 0)
    *slot = (ct_open_real_fn)ct_resolve("open");
  if (*slot == NULL) { errno = ENOSYS; return -1; }
  return ct_open_flags_need_mode(flags) ? (*slot)(path, flags, mode) :
                                          (*slot)(path, flags);
}

int ct_linux_preload_real_open(char *path, int flags, int mode) {
  return ct_real_open_common(&real_open_ptr, "open", path, flags, mode);
}

int ct_linux_preload_real_open64(char *path, int flags, int mode) {
  return ct_real_open_common(&real_open64_ptr, "open64", path, flags, mode);
}

static int ct_real_openat_common(ct_openat_real_fn *slot, const char *symbol,
                                 int dirfd, char *path, int flags, int mode) {
  if (*slot == NULL) *slot = (ct_openat_real_fn)ct_resolve(symbol);
  if (*slot == NULL && strcmp(symbol, "openat64") == 0)
    *slot = (ct_openat_real_fn)ct_resolve("openat");
  if (*slot == NULL) { errno = ENOSYS; return -1; }
  return ct_open_flags_need_mode(flags) ? (*slot)(dirfd, path, flags, mode) :
                                          (*slot)(dirfd, path, flags);
}

int ct_linux_preload_real_openat(int dirfd, char *path, int flags, int mode) {
  return ct_real_openat_common(&real_openat_ptr, "openat", dirfd, path, flags, mode);
}

int ct_linux_preload_real_openat64(int dirfd, char *path, int flags, int mode) {
  return ct_real_openat_common(&real_openat64_ptr, "openat64", dirfd, path, flags, mode);
}

#define CT_REAL(name, slot, type) do { \
  if ((slot) == NULL) (slot) = (type)ct_resolve(name); \
  if ((slot) == NULL) { errno = ENOSYS; return -1; } \
} while (0)

ssize_like_t ct_linux_preload_real_read(int fd, void *buf, size_t count) {
  CT_REAL("read", real_read_ptr, ct_read_real_fn);
  return (ssize_like_t)real_read_ptr(fd, buf, count);
}

ssize_like_t ct_linux_preload_real_pread(int fd, void *buf, size_t count,
                                         long offset) {
  CT_REAL("pread", real_pread_ptr, ct_pread_real_fn);
  return (ssize_like_t)real_pread_ptr(fd, buf, count, (off_t)offset);
}

ssize_like_t ct_linux_preload_real_pread64(int fd, void *buf, size_t count,
                                           long offset) {
  if (real_pread64_ptr == NULL)
    real_pread64_ptr = (ct_pread_real_fn)ct_resolve("pread64");
  if (real_pread64_ptr == NULL)
    real_pread64_ptr = (ct_pread_real_fn)ct_resolve("pread");
  if (real_pread64_ptr == NULL) { errno = ENOSYS; return -1; }
  return (ssize_like_t)real_pread64_ptr(fd, buf, count, (off_t)offset);
}

ssize_like_t ct_linux_preload_real_readv(int fd, void *iov, int iovcnt) {
  CT_REAL("readv", real_readv_ptr, ct_readv_real_fn);
  return (ssize_like_t)real_readv_ptr(fd, (const struct iovec *)iov, iovcnt);
}

ssize_like_t ct_linux_preload_real_preadv(int fd, void *iov, int iovcnt,
                                          long offset) {
  CT_REAL("preadv", real_preadv_ptr, ct_preadv_real_fn);
  return (ssize_like_t)real_preadv_ptr(fd, (const struct iovec *)iov, iovcnt,
                                       (off_t)offset);
}

ssize_like_t ct_linux_preload_real_preadv64(int fd, void *iov, int iovcnt,
                                            long offset) {
  if (real_preadv64_ptr == NULL)
    real_preadv64_ptr = (ct_preadv_real_fn)ct_resolve("preadv64");
  if (real_preadv64_ptr == NULL)
    real_preadv64_ptr = (ct_preadv_real_fn)ct_resolve("preadv");
  if (real_preadv64_ptr == NULL) { errno = ENOSYS; return -1; }
  return (ssize_like_t)real_preadv64_ptr(fd, (const struct iovec *)iov, iovcnt,
                                         (off_t)offset);
}

ssize_like_t ct_linux_preload_real_write(int fd, void *buf, size_t count) {
  CT_REAL("write", real_write_ptr, ct_write_real_fn);
  return (ssize_like_t)real_write_ptr(fd, buf, count);
}

int ct_linux_preload_real_close(int fd) {
  CT_REAL("close", real_close_ptr, ct_close_real_fn);
  return real_close_ptr(fd);
}

/* Before glibc 2.33 the public stat/lstat entrypoints were header wrappers
 * around __xstat/__lxstat, not dynamically exported symbols. Newer build
 * headers no longer define _STAT_VER. Preserve the host libc's struct stat
 * ABI when forwarding into an older runtime. See glibc 2.31's
 * sysdeps/unix/sysv/linux/{x86,generic}/bits/stat.h. */
#if defined(_STAT_VER)
#define CT_STAT_VER _STAT_VER
#elif defined(__x86_64__)
#define CT_STAT_VER 1
#elif defined(__aarch64__)
#define CT_STAT_VER 0
#endif

int ct_linux_preload_real_stat(char *path, void *buf) {
  if (real_stat_ptr == NULL)
    real_stat_ptr = (ct_stat_real_fn)ct_resolve("stat");
  if (real_stat_ptr != NULL) return real_stat_ptr(path, (struct stat *)buf);
#ifdef CT_STAT_VER
  if (real_xstat_ptr == NULL)
    real_xstat_ptr = (ct_xstat_real_fn)ct_resolve("__xstat");
  if (real_xstat_ptr != NULL)
    return real_xstat_ptr(CT_STAT_VER, path, (struct stat *)buf);
#endif
  errno = ENOSYS;
  return -1;
}

int ct_linux_preload_real_lstat(char *path, void *buf) {
  if (real_lstat_ptr == NULL)
    real_lstat_ptr = (ct_stat_real_fn)ct_resolve("lstat");
  if (real_lstat_ptr != NULL) return real_lstat_ptr(path, (struct stat *)buf);
#ifdef CT_STAT_VER
  if (real_lxstat_ptr == NULL)
    real_lxstat_ptr = (ct_xstat_real_fn)ct_resolve("__lxstat");
  if (real_lxstat_ptr != NULL)
    return real_lxstat_ptr(CT_STAT_VER, path, (struct stat *)buf);
#endif
  errno = ENOSYS;
  return -1;
}

void *ct_linux_preload_real_opendir(char *path) {
  if (real_opendir_ptr == NULL) real_opendir_ptr = (ct_opendir_real_fn)ct_resolve("opendir");
  if (real_opendir_ptr == NULL) { errno = ENOSYS; return NULL; }
  return (void *)real_opendir_ptr(path);
}

void *ct_linux_preload_real_readdir(void *dirp) {
  if (real_readdir_ptr == NULL) real_readdir_ptr = (ct_readdir_real_fn)ct_resolve("readdir");
  if (real_readdir_ptr == NULL) { errno = ENOSYS; return NULL; }
  return (void *)real_readdir_ptr((DIR *)dirp);
}

int ct_linux_preload_real_closedir(void *dirp) {
  CT_REAL("closedir", real_closedir_ptr, ct_closedir_real_fn);
  return real_closedir_ptr((DIR *)dirp);
}

void *ct_linux_preload_real_fopen(char *path, char *mode) {
  if (real_fopen_ptr == NULL)
    real_fopen_ptr = (ct_fopen_real_fn)ct_resolve("fopen");
  if (real_fopen_ptr == NULL) { errno = ENOSYS; return NULL; }
  return real_fopen_ptr(path, mode);
}

void *ct_linux_preload_real_fopen64(char *path, char *mode) {
  if (real_fopen64_ptr == NULL)
    real_fopen64_ptr = (ct_fopen_real_fn)ct_resolve("fopen64");
  if (real_fopen64_ptr == NULL) { errno = ENOSYS; return NULL; }
  return real_fopen64_ptr(path, mode);
}

size_t ct_linux_preload_real_fread(void *buf, size_t size, size_t nmemb, void *stream) {
  if (real_fread_ptr == NULL)
    real_fread_ptr = (ct_fread_real_fn)ct_resolve("fread");
  if (real_fread_ptr == NULL) { errno = ENOSYS; return 0; }
  return real_fread_ptr(buf, size, nmemb, (FILE *)stream);
}

int ct_linux_preload_real_fclose(void *stream) {
  CT_REAL("fclose", real_fclose_ptr, ct_fclose_real_fn);
  return real_fclose_ptr((FILE *)stream);
}

/* Resolve before application dlopen constructors can start a worker while
 * holding another library's lock. The normal next-object resolver and all
 * connect dispatch/monitoring remain unchanged. */
void ct_linux_preload_prepare_real_connect(void) {
  if (real_connect_ptr == NULL)
    real_connect_ptr = (ct_connect_real_fn)ct_resolve("connect");
}

int ct_linux_preload_real_connect(int fd, void *addr, unsigned int addrlen) {
  CT_REAL("connect", real_connect_ptr, ct_connect_real_fn);
  return real_connect_ptr(fd, (const struct sockaddr *)addr, (socklen_t)addrlen);
}

/* IM-3 — genuine entries for the local-IPC-fd CREATE hooks. `pipe`/`pipe2`/
   `socketpair` are thin libc wrappers, but they are resolved through the same
   `ct_resolve` next-object walk as every other real forwarder so the shim never
   re-enters its own interposed symbol. */
int ct_linux_preload_real_pipe(void *fds) {
  CT_REAL("pipe", real_pipe_ptr, ct_pipe_real_fn);
  return real_pipe_ptr((int *)fds);
}

int ct_linux_preload_real_pipe2(void *fds, int flags) {
  CT_REAL("pipe2", real_pipe2_ptr, ct_pipe2_real_fn);
  return real_pipe2_ptr((int *)fds, flags);
}

int ct_linux_preload_real_socketpair(int domain, int type, int protocol,
                                     void *sv) {
  CT_REAL("socketpair", real_socketpair_ptr, ct_socketpair_real_fn);
  return real_socketpair_ptr(domain, type, protocol, (int *)sv);
}

ssize_like_t ct_linux_preload_real_sendfile(int out_fd, int in_fd, void *offset,
                                            size_t count) {
  CT_REAL("sendfile", real_sendfile_ptr, ct_sendfile_real_fn);
  return (ssize_like_t)real_sendfile_ptr(out_fd, in_fd, (off_t *)offset, count);
}

ssize_like_t ct_linux_preload_real_copy_file_range(int in_fd, void *off_in,
                                                   int out_fd, void *off_out,
                                                   size_t length,
                                                   unsigned int flags) {
  CT_REAL("copy_file_range", real_copy_file_range_ptr,
          ct_copy_file_range_real_fn);
  return (ssize_like_t)real_copy_file_range_ptr(in_fd, (off64_t *)off_in,
                                                out_fd, (off64_t *)off_out,
                                                length, flags);
}

ssize_like_t ct_linux_preload_real_splice(int fd_in, void *off_in, int fd_out,
                                          void *off_out, size_t length,
                                          unsigned int flags) {
  CT_REAL("splice", real_splice_ptr, ct_splice_real_fn);
  return (ssize_like_t)real_splice_ptr(fd_in, (loff_t *)off_in, fd_out,
                                       (loff_t *)off_out, length, flags);
}

int ct_linux_preload_real_link(char *oldpath, char *newpath) {
  CT_REAL("link", real_link_ptr, ct_link_real_fn);
  return real_link_ptr(oldpath, newpath);
}

int ct_linux_preload_real_linkat(int olddirfd, char *oldpath, int newdirfd,
                                 char *newpath, int flags) {
  CT_REAL("linkat", real_linkat_ptr, ct_linkat_real_fn);
  return real_linkat_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
}

int ct_linux_preload_real_rename(char *oldpath, char *newpath) {
  CT_REAL("rename", real_rename_ptr, ct_rename_real_fn);
  return real_rename_ptr(oldpath, newpath);
}

int ct_linux_preload_real_renameat(int olddirfd, char *oldpath, int newdirfd,
                                   char *newpath) {
  CT_REAL("renameat", real_renameat_ptr, ct_renameat_real_fn);
  return real_renameat_ptr(olddirfd, oldpath, newdirfd, newpath);
}

int ct_linux_preload_real_renameat2(int olddirfd, char *oldpath, int newdirfd,
                                    char *newpath, unsigned int flags) {
  CT_REAL("renameat2", real_renameat2_ptr, ct_renameat2_real_fn);
  return real_renameat2_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
}

void *ct_linux_preload_real_dlopen(char *path, int flags) {
  if (real_dlopen_ptr == NULL)
    real_dlopen_ptr = (ct_dlopen_real_fn)ct_resolve("dlopen");
  if (real_dlopen_ptr == NULL) { errno = ENOSYS; return NULL; }
  return real_dlopen_ptr(path, flags);
}

void *ct_linux_preload_real_dlmopen(long namespace_id, char *path, int flags) {
  if (real_dlmopen_ptr == NULL)
    real_dlmopen_ptr = (ct_dlmopen_real_fn)ct_resolve("dlmopen");
  if (real_dlmopen_ptr == NULL) { errno = ENOSYS; return NULL; }
  return real_dlmopen_ptr((Lmid_t)namespace_id, path, flags);
}

/* --- Monitor transparency: caller-scoped dlopen soname resolution -----------
 *
 * The shim interposes dlopen and forwards the real call to
 * dlsym(RTLD_NEXT, "dlopen"). glibc attributes the CALLING object by the
 * return address at the real dlopen call site — which is inside THIS shim —
 * and therefore resolves a bare-soname dlopen("libfoo.so.N") against the
 * SHIM's DT_RPATH/DT_RUNPATH instead of the monitored caller's. A program
 * that dlopens a library by soname relying on its OWN DT_RUNPATH then gets a
 * silent ENOENT under monitoring. That is a transparency violation: the
 * monitor must not change how the target resolves libraries.
 *
 * Fix: before entering the real dlopen, replicate glibc's caller-scoped
 * search order for a bare soname (no '/') using the ORIGINAL caller's
 * link_map (found from the wrapper's __builtin_return_address(0)):
 *   1. caller DT_RPATH   (only when the caller has NO DT_RUNPATH)
 *   2. LD_LIBRARY_PATH
 *   3. caller DT_RUNPATH
 * On a hit we hand the real dlopen an ABSOLUTE path, which glibc loads
 * verbatim independent of any object's search list. On a miss we return the
 * soname UNCHANGED so glibc's own ld.so.cache + default-path fallback (both
 * caller-independent) still apply. Any failure falls back to unmodified
 * behavior. $ORIGIN is expanded; $LIB / $PLATFORM dirs are left to glibc. */

static const char *ct_dlopen_dyn_paths(struct link_map *lm,
                                       const char **rpath,
                                       const char **runpath) {
  /* Extract the DT_RPATH / DT_RUNPATH strings for `lm` by walking its dynamic
     section (lm->l_ld). The PUBLIC struct link_map does NOT expose glibc's
     private l_info[] array, so we scan l_ld directly. On x86_64 glibc
     (!DL_RO_DYN_SECTION) the loader relocates DT_STRTAB's d_ptr in place, so
     it is an absolute pointer; DT_RPATH/DT_RUNPATH carry byte offsets into it.
     Returns the strtab base (or NULL) and sets *rpath / *runpath. */
  *rpath = NULL;
  *runpath = NULL;
  if (lm == NULL || lm->l_ld == NULL) return NULL;
  const char *strtab = NULL;
  ElfW(Sxword) rpath_off = -1, runpath_off = -1;
  for (ElfW(Dyn) *d = lm->l_ld; d->d_tag != DT_NULL; d++) {
    switch (d->d_tag) {
      case DT_STRTAB:  strtab = (const char *)d->d_un.d_ptr; break;
      case DT_RPATH:   rpath_off = (ElfW(Sxword))d->d_un.d_val; break;
      case DT_RUNPATH: runpath_off = (ElfW(Sxword))d->d_un.d_val; break;
      default: break;
    }
  }
  if (strtab == NULL) return NULL;
  if (rpath_off >= 0) *rpath = strtab + rpath_off;
  if (runpath_off >= 0) *runpath = strtab + runpath_off;
  return strtab;
}

/* Working storage for one caller-relative dlopen resolution. It lives on the
   C heap for the duration of one interposed dlopen/dlmopen call (see
   ct_dlopen_scratch_new), not on the stack: as four PATH_MAX stack arrays
   spread over the hook and three helpers it took ~16 KiB of the CALLING
   thread's stack, which a host may legally have created with
   PTHREAD_STACK_MIN (16 KiB on x86_64). */
typedef struct {
  char resolved[PATH_MAX]; /* the path handed to the real loader */
  char origin[PATH_MAX];   /* $ORIGIN of the calling object */
  char exe[PATH_MAX];      /* readlink("/proc/self/exe") for the main program */
  char expanded[PATH_MAX]; /* one search-list entry with $ORIGIN expanded */
} ct_dlopen_scratch;

static int ct_dlopen_origin_dir(struct link_map *lm, char *out, size_t cap,
                                char *path, size_t path_cap) {
  /* Directory used to expand $ORIGIN for object `lm`: dirname(l_name) for a
     normal library, or dirname(readlink("/proc/self/exe")) for the main
     executable (l_name == ""). `path` is working space for the latter.
     Returns 1 on success. */
  const char *src = NULL;
  if (lm != NULL && lm->l_name != NULL && lm->l_name[0] != '\0') {
    src = lm->l_name;
  } else {
    ssize_t n = readlink("/proc/self/exe", path, path_cap - 1);
    if (n <= 0) return 0;
    path[n] = '\0';
    src = path;
  }
  size_t len = strlen(src);
  while (len > 0 && src[len - 1] != '/') len--;
  if (len == 0) { if (cap < 2) return 0; out[0] = '.'; out[1] = '\0'; return 1; }
  size_t copy = (len > 1) ? len - 1 : len; /* strip trailing '/', keep root */
  if (copy >= cap) return 0;
  memcpy(out, src, copy);
  out[copy] = '\0';
  return 1;
}

static int ct_dlopen_has_other_elf_class(const char *path) {
  /* glibc's open_verify skips a different ELF class while searching, but
     treats short files and bad magic as real errors. An existence-only probe
     changes a search into an absolute dlopen of (for example) a 32-bit library
     in a 64-bit process. Inspect bytes without executing any candidate's
     constructors. Leave every other validation decision to the real loader. */
  int saved_errno = errno;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { errno = saved_errno; return 0; }
  ElfW(Ehdr) header;
  size_t used = 0;
  while (used < sizeof(header)) {
    ssize_t n = read(fd, (char *)&header + used, sizeof(header) - used);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    used += (size_t)n;
  }
  close(fd);
  int other = used == sizeof(header) &&
      memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
      header.e_ident[EI_CLASS] != (sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32);
  errno = saved_errno;
  return other;
}

static int ct_dlopen_try_dir(const char *dir, size_t dirlen,
                             const char *soname, const char *origin,
                             char *out, size_t cap, char *expanded,
                             size_t expanded_cap) {
  /* Expand $ORIGIN in `dir` into `expanded`; on an unsupported token
     ($LIB/$PLATFORM/unknown) return 0 (skip). Then test "dir/soname" for
     existence; on a hit copy the full path into `out` and return 1. */
  size_t pos = 0, i = 0;
  while (i < dirlen) {
    if (dir[i] == '$') {
      const char *tok = dir + i + 1;
      size_t rem = dirlen - i - 1;
      int brace = 0;
      if (rem > 0 && *tok == '{') { brace = 1; tok++; rem--; }
      if (rem >= 6 && strncmp(tok, "ORIGIN", 6) == 0) {
        size_t olen = strlen(origin);
        if (pos + olen >= expanded_cap) return 0;
        memcpy(expanded + pos, origin, olen); pos += olen;
        i += 1 + (brace ? 1 : 0) + 6 + (brace ? 1 : 0);
        continue;
      }
      return 0; /* $LIB / $PLATFORM / unknown — unsupported; skip this dir. */
    }
    if (pos + 1 >= expanded_cap) return 0;
    expanded[pos++] = dir[i++];
  }
  expanded[pos] = '\0';
  if (pos == 0) return 0;
  int n = snprintf(out, cap, "%s/%s", expanded, soname);
  if (n < 0 || (size_t)n >= cap) return 0;
  if (access(out, F_OK) != 0) return 0;
  return 1;
}

static int ct_dlopen_search_list(const char *list, const char *soname,
                                 const char *origin, ct_dlopen_scratch *s) {
  /* Preserve the loader's fallback past incompatible ELF classes. A malformed
     candidate still wins here so the real loader reports its genuine error. */
  if (list == NULL) return 0;
  const char *p = list;
  while (*p) {
    const char *sep = strchr(p, ':');
    size_t len = sep ? (size_t)(sep - p) : strlen(p);
    if (len > 0 &&
        ct_dlopen_try_dir(p, len, soname, origin, s->resolved,
                          sizeof(s->resolved), s->expanded,
                          sizeof(s->expanded)) &&
        !ct_dlopen_has_other_elf_class(s->resolved))
      return 1;
    if (!sep) break;
    p = sep + 1;
  }
  return 0;
}

/* Scratch for one resolution, or NULL when `path` needs none (absolute or
   relative-with-slash, which the loader opens as given) or when the
   allocation fails. In the failure case the resolver returns `path`
   unchanged, i.e. the loader searches with its own rules (this library's
   RUNPATH instead of the caller's) — only under memory exhaustion, in which
   case the dlopen that follows is unlikely to succeed either. The caller
   frees it with ct_dlopen_scratch_free AFTER the real loader call, because
   `resolved` is the path that call consumes.

   malloc here goes to the shim's private heap (linux_private_heap.c wraps
   this DSO's malloc/free), is per call and is freed on the same thread before the
   hook returns, so there is no shared buffer a nested or concurrent dlopen
   could clobber. */
static ct_dlopen_scratch *ct_dlopen_scratch_new(const char *path) {
  if (path == NULL || strchr(path, '/') != NULL) return NULL;
  return (ct_dlopen_scratch *)malloc(sizeof(ct_dlopen_scratch));
}

static void ct_dlopen_scratch_free(ct_dlopen_scratch *s) {
  int saved_errno = errno; /* dlopen/dlerror state must survive the free */
  free(s);
  errno = saved_errno;
}

/* Returns `path` itself, or `s->resolved` holding the caller-relative
   resolution. */
const char *ct_linux_preload_resolve_dlopen_caller_path(const char *path,
                                                        void *caller,
                                                        ct_dlopen_scratch *s) {
  if (path == NULL || strchr(path, '/') != NULL || caller == NULL || s == NULL)
    return path;
  /* Suppress our own interposed hooks (getenv/access/readlink) during
     resolution so it neither recurses nor records spurious dependencies. */
  stackable_linux_preload_enter_hook();
  const char *out = path;
  Dl_info info;
  struct link_map *lm = NULL;
  if (dladdr1(caller, &info, (void **)&lm, RTLD_DL_LINKMAP) != 0 &&
      lm != NULL) {
    if (!ct_dlopen_origin_dir(lm, s->origin, sizeof(s->origin), s->exe,
                              sizeof(s->exe)))
      s->origin[0] = '\0';
    const char *rpath = NULL;
    const char *runpath = NULL;
    ct_dlopen_dyn_paths(lm, &rpath, &runpath);
    /* glibc honors DT_RPATH only when DT_RUNPATH is absent. */
    if (runpath == NULL && rpath != NULL &&
        ct_dlopen_search_list(rpath, path, s->origin, s))
      out = s->resolved;
    else if (ct_dlopen_search_list(getenv("LD_LIBRARY_PATH"), path, s->origin,
                                   s))
      out = s->resolved;
    else if (runpath != NULL &&
             ct_dlopen_search_list(runpath, path, s->origin, s))
      out = s->resolved;
  }
  stackable_linux_preload_exit_hook();
  return out;
}

/* ---------------------------------------------------------------------------
 * LIBRARY-LOAD OBSERVATION — ask the loader, do not interpose it.
 *
 * THE DEFECT THIS CLOSES. ld.so maps a shared object with its own internal
 * __mmap / __open64_nocancel calls, which do NOT traverse LD_PRELOAD
 * symbol interposition. So none of this shim's open/openat/mmap hooks
 * ever fire for a loader-driven load, and the runtime shared-library closure of
 * a monitored process was captured NOWHERE. Measured on this repo before the
 * fix: a monitored gcc -c loads ten shared objects (libisl, libmpfr, libmpc,
 * libgmp, libbfd, libz, libsframe, libc, libdl, libm — strace -f ground
 * truth) and the depfile contained ZERO .so paths while reporting
 * completeness=mcComplete. An in-place upgrade of any of those libraries
 * changes what the compiler DOES and busts nothing: a content-addressed
 * consumer serves a stale result. That is the cardinal sin.
 *
 * WHY dl_iterate_phdr AND NOT AN EVENT HOOK. The macOS shim already solved the
 * same problem the right way: _dyld_register_func_for_add_image asks dyld for
 * its image set instead of hooking the calls that produce it. dl_iterate_phdr
 * is the Linux equivalent — it walks the loader's OWN link map, so what it
 * reports is what the loader actually has, regardless of which code path put it
 * there. Three consequences matter:
 *
 *   1. It is STATE, not EVENTS. Objects mapped before this shim's constructor
 *      ran — every DT_NEEDED of the executable, every other LD_PRELOAD, the
 *      loader itself — are all visible at the first scan, because ld.so maps
 *      the entire initial closure BEFORE running any ELF initializer. An
 *      event hook can only ever see what happens after it is installed; a
 *      state scan sees what is there. This is what makes "loaded before we
 *      were initialised" a covered case rather than a hole.
 *   2. It cannot perturb. It resolves nothing, opens nothing, and returns the
 *      loader's already-resolved dlpi_name. Contrast the interposed dlopen
 *      immediately below, which had to be taught to reconstruct the caller's
 *      RUNPATH precisely because interposing a resolution path CHANGES it.
 *   3. It is not privileged and adds no process. LD_AUDIT's la_objopen sees
 *      strictly more (it fires for loader-internal __libc_dlopen_mode too),
 *      but an audit library is loaded into its OWN link-map namespace with its
 *      own libc, so it cannot share this shim's recording state and would have
 *      to attach to the shm transport independently — a second injected copy of
 *      io-mon in every monitored process. That cost buys coverage of a case
 *      this design DETECTS instead (see the accounting below), so it stays the
 *      documented future direction, not this change.
 *
 * THE ACCOUNTING — why sampling is honest here. Scanning at chosen points
 * would normally leave the question "what about a library loaded and unloaded
 * BETWEEN two scans?" unanswerable, and an unanswerable question about input
 * coverage must not be answered with mcComplete. struct dl_phdr_info
 * carries dlpi_adds and dlpi_subs: the loader's own cumulative counts of
 * objects added and removed. That turns the question into arithmetic. Between
 * two scans, adds - lastAdds reports load operations. Scans immediately before
 * and after interposed loader calls distinguish ordinary unload/reload cycles:
 * a reloaded object appears in the current link map relative to the pre-call
 * snapshot. A short newly-active count plus an unload therefore identifies a
 * load that may have disappeared without a scan and requires a downgrade.
 *
 * SAFETY. The dl_iterate_phdr callback runs with the loader's
 * dl_load_write_lock held. It therefore does only memcpy into a
 * preallocated buffer: no allocation, no Nim, no locks, no recording. The sink
 * — which allocates and records — is invoked AFTER dl_iterate_phdr returns
 * and the loader lock is released. (This is stricter than the macOS arm, which
 * records from inside dyld's add-image callback; on glibc a shim hook can
 * allocate while the loader lock is held, so the lock-ordering risk is real
 * enough to design out rather than argue about.)
 *
 * The snapshot buffer is a single static, and callers serialise scans, so
 * there is no per-scan allocation on any path. Overflowing it is treated as an
 * observation failure, not silently truncated.
 * ------------------------------------------------------------------------- */
#define CT_LL_MAX_OBJECTS 512
#define CT_LL_NAME_BYTES (128 * 1024)
#define CT_LL_SEEN_MAX 2048
#define CT_LL_SEEN_NAME_BYTES (256 * 1024)

typedef void (*ct_ll_sink_fn)(char *name, unsigned long address, char *reason);

typedef struct {
  unsigned long long adds;
  unsigned long long subs;
  int counters_valid;
  int count;
  int overflow;
  unsigned long addrs[CT_LL_MAX_OBJECTS];
  int name_off[CT_LL_MAX_OBJECTS];
  int name_used;
  char names[CT_LL_NAME_BYTES];
} ct_ll_snapshot;

static ct_ll_snapshot ct_ll_snap;

/* The PERSISTENT state -- the set of link-map entries already enumerated, and
   the loader's cumulative load/unload counts as of the previous scan -- live
   HERE, in C, and not in a Nim seq.
   That is not a style preference. A scan can run on ANY thread (the interposed
   dlopen fires on whichever thread called it), so a Nim heap object that
   survives between scans would be allocated on one thread and freed or grown on
   another. That is precisely the FUP-C/FUP-H mechanism documented at the top of
   linux_preload.nim: an ORC chunk allocated on one thread and released on
   another corrupts the process allocator, and it crashed live-Vulkan replay in
   rawDealloc off updateFdPath. Keeping this state POD and C-owned removes the
   class rather than hoping the lock is enough -- the lock orders the accesses,
   it does not make the allocator cross-thread safe.
   Nim still allocates per RECORD, but those temporaries are created and
   released on the same thread inside one sink call, exactly like every other
   hook. */
static unsigned long ct_ll_seen_addr[CT_LL_SEEN_MAX];
static int ct_ll_seen_off[CT_LL_SEEN_MAX];
static char ct_ll_seen_names[CT_LL_SEEN_NAME_BYTES];
static int ct_ll_seen_count;
static int ct_ll_seen_used;
static unsigned long ct_ll_active_addr[CT_LL_MAX_OBJECTS];
static int ct_ll_active_off[CT_LL_MAX_OBJECTS];
static char ct_ll_active_names[CT_LL_NAME_BYTES];
static int ct_ll_active_count;
static unsigned long long ct_ll_last_adds;
static unsigned long long ct_ll_last_subs;

static int ct_ll_collect(struct dl_phdr_info *info, size_t size, void *data) {
  ct_ll_snapshot *s = (ct_ll_snapshot *)data;
  const char *name;
  size_t len;
  /* dlpi_adds/dlpi_subs are a later addition to the struct; a runtime whose
     struct stops short of them leaves counters_valid at 0, and the caller then
     treats coverage as UNPROVEN rather than assuming the counters were zero. */
  if (size >= offsetof(struct dl_phdr_info, dlpi_subs) +
                  sizeof(info->dlpi_subs)) {
    s->adds = (unsigned long long)info->dlpi_adds;
    s->subs = (unsigned long long)info->dlpi_subs;
    s->counters_valid = 1;
  }
  if (s->count >= CT_LL_MAX_OBJECTS) {
    s->overflow = 1;
    return 0;
  }
  name = (info->dlpi_name != NULL) ? info->dlpi_name : "";
  len = strlen(name);
  if (s->name_used + (int)len + 1 > CT_LL_NAME_BYTES) {
    s->overflow = 1;
    return 0;
  }
  s->addrs[s->count] = (unsigned long)info->dlpi_addr;
  s->name_off[s->count] = s->name_used;
  memcpy(s->names + s->name_used, name, len + 1);
  s->name_used += (int)len + 1;
  s->count++;
  return 0;
}

static int ct_ll_seen_has(unsigned long addr, const char *name) {
  int i;
  for (i = 0; i < ct_ll_seen_count; i++)
    if (ct_ll_seen_addr[i] == addr &&
        strcmp(ct_ll_seen_names + ct_ll_seen_off[i], name) == 0)
      return 1;
  return 0;
}

static int ct_ll_seen_add(unsigned long addr, const char *name) {
  size_t len = strlen(name);
  if (ct_ll_seen_count >= CT_LL_SEEN_MAX) return 0;
  if (ct_ll_seen_used + (int)len + 1 > CT_LL_SEEN_NAME_BYTES) return 0;
  ct_ll_seen_addr[ct_ll_seen_count] = addr;
  ct_ll_seen_off[ct_ll_seen_count] = ct_ll_seen_used;
  memcpy(ct_ll_seen_names + ct_ll_seen_used, name, len + 1);
  ct_ll_seen_used += (int)len + 1;
  ct_ll_seen_count++;
  return 1;
}

static int ct_ll_active_has(unsigned long addr, const char *name) {
  int i;
  for (i = 0; i < ct_ll_active_count; i++)
    if (ct_ll_active_addr[i] == addr &&
        strcmp(ct_ll_active_names + ct_ll_active_off[i], name) == 0)
      return 1;
  return 0;
}

static void ct_ll_replace_active_snapshot(void) {
  int i;
  ct_ll_active_count = ct_ll_snap.count;
  memcpy(ct_ll_active_names, ct_ll_snap.names, (size_t)ct_ll_snap.name_used);
  for (i = 0; i < ct_ll_snap.count; i++) {
    ct_ll_active_addr[i] = ct_ll_snap.addrs[i];
    ct_ll_active_off[i] = ct_ll_snap.name_off[i];
  }
}

/* Callers serialise scans with a lock on the Nim side, so no locking here. */
int ct_linux_library_scan(ct_ll_sink_fn sink, char *reason,
                          unsigned long long *performed,
                          unsigned long long *removed, int *newly_active,
                          int *newly_seen,
                          int *counters_valid, int *overflow) {
  int i, active_new = 0, seen_new = 0;
  ct_ll_snap.count = 0;
  ct_ll_snap.name_used = 0;
  ct_ll_snap.overflow = 0;
  ct_ll_snap.adds = 0;
  ct_ll_snap.subs = 0;
  ct_ll_snap.counters_valid = 0;
  dl_iterate_phdr(ct_ll_collect, &ct_ll_snap);

  /* Optional bounded loader diagnostics report identities/counters, never
   * environment values or captured file contents. Keep writes outside hooks. */
  const char *debug_scan = secure_getenv("IO_MON_DIAGNOSTIC_LIBRARY_SCAN");
  if (debug_scan != NULL && strcmp(debug_scan, "1") == 0) {
    /* static, not a stack array: even an untaken branch's array is part of
       this function's frame, and scans run in the dlopen hook on the host's
       thread. Scans are serialised by the caller's lock, so one buffer is
       never in use twice. */
    static char line[4096];
    Dl_info self;
    const char *image = dladdr((void *)ct_linux_library_scan, &self)
                          ? self.dli_fname : "unknown";
    int used = snprintf(line, sizeof(line),
      "IO_MON_LL image=%s reason=%s adds=%llu subs=%llu last=%llu/%llu active=%d count=%d\n",
      image, reason == NULL ? "" : reason, ct_ll_snap.adds, ct_ll_snap.subs,
      ct_ll_last_adds, ct_ll_last_subs, ct_ll_active_count, ct_ll_snap.count);
    if (used > 0 && used < (int)sizeof(line))
      (void)ct_raw_syscall6(SYS_write, 2, (long)line, used, 0, 0, 0);
    for (int j = 0; j < ct_ll_snap.count; ++j) {
      const char *name = ct_ll_snap.names + ct_ll_snap.name_off[j];
      if (ct_ll_active_has(ct_ll_snap.addrs[j], name)) continue;
      used = snprintf(line, sizeof(line), "IO_MON_LL new=%s\n", name);
      if (used > 0 && used < (int)sizeof(line))
        (void)ct_raw_syscall6(SYS_write, 2, (long)line, used, 0, 0, 0);
    }
  }

  /* Sink calls happen HERE, with the loader lock already released. */
  for (i = 0; i < ct_ll_snap.count; i++) {
    const char *name = ct_ll_snap.names + ct_ll_snap.name_off[i];
    unsigned long addr = ct_ll_snap.addrs[i];
    if (!ct_ll_active_has(addr, name)) active_new++;
    if (ct_ll_seen_has(addr, name)) continue;
    if (!ct_ll_seen_add(addr, name)) {
      /* The seen-set is full: further entries cannot be tracked, so coverage
         is no longer provable. Reported as an overflow, never truncated
         silently. */
      ct_ll_snap.overflow = 1;
      break;
    }
    seen_new++;
    if (sink != NULL) sink((char *)name, addr, reason);
  }

  if (performed != NULL) {
    *performed = (ct_ll_snap.counters_valid && ct_ll_snap.adds >= ct_ll_last_adds)
                     ? ct_ll_snap.adds - ct_ll_last_adds
                     : 0;
  }
  if (removed != NULL) {
    *removed = (ct_ll_snap.counters_valid && ct_ll_snap.subs >= ct_ll_last_subs)
                   ? ct_ll_snap.subs - ct_ll_last_subs
                   : 0;
  }
  if (ct_ll_snap.counters_valid && ct_ll_snap.adds >= ct_ll_last_adds)
    ct_ll_last_adds = ct_ll_snap.adds;
  if (ct_ll_snap.counters_valid && ct_ll_snap.subs >= ct_ll_last_subs)
    ct_ll_last_subs = ct_ll_snap.subs;
  if (!ct_ll_snap.overflow) ct_ll_replace_active_snapshot();
  if (newly_active != NULL) *newly_active = active_new;
  if (newly_seen != NULL) *newly_seen = seen_new;
  if (counters_valid != NULL) *counters_valid = ct_ll_snap.counters_valid;
  if (overflow != NULL) *overflow = ct_ll_snap.overflow;
  return ct_ll_snap.count;
}

#if defined(__aarch64__)
#define CT_DLSYM_GLIBC_BASE "GLIBC_2.17"
#else
#define CT_DLSYM_GLIBC_BASE "GLIBC_2.2.5"
#endif

void *ct_linux_preload_real_dlsym(void *handle, char *name) {
#ifdef __GLIBC__
  if (real_dlsym_ptr == NULL)
    real_dlsym_ptr = (ct_dlsym_real_fn)dlvsym(RTLD_NEXT, "dlsym", CT_DLSYM_GLIBC_BASE);
  /* Never retry through ct_resolve on glibc: that calls our interposed
   * dlsym again. ARM64's baseline is 2.17, not x86_64's 2.2.5. */
#else
  if (real_dlsym_ptr == NULL)
    real_dlsym_ptr = (ct_dlsym_real_fn)ct_resolve("dlsym");
#endif
  if (real_dlsym_ptr == NULL) { errno = ENOSYS; return NULL; }
  return real_dlsym_ptr(handle, name);
}

void *ct_linux_preload_real_mmap(void *addr, size_t length, int prot, int flags,
                                 int fd, long offset) {
  if (real_mmap_ptr == NULL)
    real_mmap_ptr = (ct_mmap_real_fn)ct_resolve("mmap");
  if (real_mmap_ptr == NULL) { errno = ENOSYS; return MAP_FAILED; }
  return real_mmap_ptr(addr, length, prot, flags, fd, (off_t)offset);
}

int ct_linux_preload_real_mprotect(void *addr, size_t length, int prot) {
  CT_REAL("mprotect", real_mprotect_ptr, ct_mprotect_real_fn);
  return real_mprotect_ptr(addr, length, prot);
}

int ct_linux_preload_real_munmap(void *addr, size_t length) {
  CT_REAL("munmap", real_munmap_ptr, ct_munmap_real_fn);
  return real_munmap_ptr(addr, length);
}

void *ct_linux_preload_real_mremap(void *old_addr, size_t old_size,
                                   size_t new_size, int flags,
                                   void *new_addr) {
  if (real_mremap_ptr == NULL)
    real_mremap_ptr = (ct_mremap_real_fn)ct_resolve("mremap");
  if (real_mremap_ptr == NULL) { errno = ENOSYS; return MAP_FAILED; }
  if ((flags & MREMAP_FIXED) != 0)
    return real_mremap_ptr(old_addr, old_size, new_size, flags, new_addr);
  return real_mremap_ptr(old_addr, old_size, new_size, flags);
}

char *ct_linux_preload_real_getenv(char *name) {
  if (real_getenv_ptr == NULL)
    real_getenv_ptr = (ct_getenv_real_fn)ct_resolve("getenv");
  if (real_getenv_ptr == NULL) return NULL;
  return real_getenv_ptr(name);
}

int ct_linux_preload_real_uname(void *buf) {
  CT_REAL("uname", real_uname_ptr, ct_uname_real_fn);
  return real_uname_ptr((struct utsname *)buf);
}

long ct_linux_preload_real_sysconf(int name) {
  if (real_sysconf_ptr == NULL)
    real_sysconf_ptr = (ct_sysconf_real_fn)ct_resolve("sysconf");
  if (real_sysconf_ptr == NULL) { errno = ENOSYS; return -1; }
  return real_sysconf_ptr(name);
}

int ct_linux_preload_real_clock_gettime(int clock_id, void *tp) {
  CT_REAL("clock_gettime", real_clock_gettime_ptr, ct_clock_gettime_real_fn);
  return real_clock_gettime_ptr((clockid_t)clock_id, (struct timespec *)tp);
}

int ct_linux_preload_real_gettimeofday(void *tv, void *tz) {
  CT_REAL("gettimeofday", real_gettimeofday_ptr, ct_gettimeofday_real_fn);
  return real_gettimeofday_ptr((struct timeval *)tv, tz);
}

long ct_linux_preload_real_time(void *tloc) {
  if (real_time_ptr == NULL)
    real_time_ptr = (ct_time_real_fn)ct_resolve("time");
  if (real_time_ptr == NULL) { errno = ENOSYS; return -1; }
  return (long)real_time_ptr((time_t *)tloc);
}

ssize_like_t ct_linux_preload_real_getrandom(void *buf, size_t buflen,
                                             unsigned int flags) {
  CT_REAL("getrandom", real_getrandom_ptr, ct_getrandom_real_fn);
  return (ssize_like_t)real_getrandom_ptr(buf, buflen, flags);
}

/* ENTROPY-PARITY forwarders.
 *
 * Each resolves the genuine libc entry with ct_resolve (dlsym(RTLD_NEXT)), so a
 * program that supplies its own arc4random from a DSO loaded after the shim
 * still reaches ITS implementation. If no successor definition exists at all,
 * we fall back to real getrandom(2) rather than returning a value: these are
 * ENTROPY primitives, and handing a caller predictable bytes because a MONITOR
 * could not resolve a symbol would be a security defect, not a monitoring one.
 * The fallback is unreachable on any glibc >= 2.36 (all four symbols exist);
 * it exists so the failure mode is "still random" instead of "silently weak".
 */
static void ct_entropy_fallback_bytes(void *buf, size_t n) {
  unsigned char *out = (unsigned char *)buf;
  size_t done = 0;
  while (done < n) {
    ssize_like_t got =
        ct_linux_preload_real_getrandom(out + done, n - done, 0);
    if (got <= 0) {
      if (errno == EINTR) continue;
      /* No entropy source at all. Returning would hand the caller
         uninitialised or predictable bytes; refuse instead. */
      abort();
    }
    done += (size_t)got;
  }
}

int ct_linux_preload_real_getentropy(void *buf, size_t len) {
  if (real_getentropy_ptr == NULL)
    real_getentropy_ptr = (ct_getentropy_real_fn)ct_resolve("getentropy");
  if (real_getentropy_ptr != NULL)
    return real_getentropy_ptr(buf, len);
  if (len > 256) { errno = EIO; return -1; }
  ct_entropy_fallback_bytes(buf, len);
  return 0;
}

unsigned int ct_linux_preload_real_arc4random(void) {
  unsigned int value = 0;
  if (real_arc4random_ptr == NULL)
    real_arc4random_ptr = (ct_arc4random_real_fn)ct_resolve("arc4random");
  if (real_arc4random_ptr != NULL)
    return real_arc4random_ptr();
  ct_entropy_fallback_bytes(&value, sizeof(value));
  return value;
}

void ct_linux_preload_real_arc4random_buf(void *buf, size_t n) {
  if (real_arc4random_buf_ptr == NULL)
    real_arc4random_buf_ptr =
        (ct_arc4random_buf_real_fn)ct_resolve("arc4random_buf");
  if (real_arc4random_buf_ptr != NULL) {
    real_arc4random_buf_ptr(buf, n);
    return;
  }
  ct_entropy_fallback_bytes(buf, n);
}

unsigned int ct_linux_preload_real_arc4random_uniform(unsigned int upper) {
  if (real_arc4random_uniform_ptr == NULL)
    real_arc4random_uniform_ptr =
        (ct_arc4random_uniform_real_fn)ct_resolve("arc4random_uniform");
  if (real_arc4random_uniform_ptr != NULL)
    return real_arc4random_uniform_ptr(upper);
  if (upper < 2) return 0;
  {
    /* Same modulo-bias rejection the BSD/glibc implementation uses. */
    unsigned int min = (unsigned int)(-upper) % upper;
    for (;;) {
      unsigned int r = ct_linux_preload_real_arc4random();
      if (r >= min) return r % upper;
    }
  }
}

pid_t ct_linux_preload_real_fork(void) {
  CT_REAL("fork", real_fork_ptr, ct_fork_real_fn);
  return real_fork_ptr();
}

/* Set while the PATH-searching exec family runs the execve hook for a file
 * name without a slash. The hook records the exec and then calls the real
 * execve on the path it was given; for such a name that would resolve it
 * against the CURRENT DIRECTORY, which execvp never does (it searches PATH
 * only), and would run `./name` when one exists. The leaf below fails that
 * call with ENOENT instead, which is what it does whenever no `./name`
 * exists, and glibc's execvpe then runs the PATH search. See
 * ct_linux_preload_dispatch_execvp. */
static __thread int ct_exec_announce_only = 0;

/* Set while fexecve or execveat runs the execve hook (see
 * ct_linux_preload_dispatch_execveat). The hook records the exec, prepares
 * the environment, drains and flushes like for any execve, and its real
 * execve then performs THIS call, with the prepared environment, instead of
 * an execve of the path it was given (which only names the image for the
 * record). Matched on the identity of that path buffer, which only the
 * dispatcher has, and on the pid, so neither an execve from a signal handler
 * nor a parent resuming after a vfork child's exec can take it. Kept by
 * value: after vfork the thread's TLS is shared with the child. */
struct ct_exec_redirect {
  int active;
  pid_t pid;
  const char *announced;
  int fd;
  const char *path;
  int flags;
  int fexecve;
};
static __thread struct ct_exec_redirect ct_exec_redirect_state;
int ct_linux_preload_real_fexecve(int fd, char **argv, char **envp);
int ct_linux_preload_real_execveat(int dirfd, const char *path, char **argv,
                                   char **envp, int flags);

int ct_linux_preload_real_execve(char *path, char **argv, char **envp) {
  if (ct_exec_announce_only) {
    errno = ENOENT;
    return -1;
  }
  if (ct_exec_redirect_state.active &&
      ct_exec_redirect_state.announced == path &&
      ct_exec_redirect_state.pid == getpid()) {
    struct ct_exec_redirect redirect = ct_exec_redirect_state;
    if (redirect.fexecve)
      return ct_linux_preload_real_fexecve(redirect.fd, argv, envp);
    return ct_linux_preload_real_execveat(redirect.fd, redirect.path, argv,
                                          envp, redirect.flags);
  }
  CT_REAL("execve", real_execve_ptr, ct_execve_real_fn);
  return real_execve_ptr(path, argv, envp);
}

int ct_linux_preload_real_execvp(char *file, char **argv) {
  CT_REAL("execvp", real_execvp_ptr, ct_execvp_real_fn);
  return real_execvp_ptr(file, argv);
}

int ct_linux_preload_real_execvpe(char *file, char **argv, char **envp) {
  CT_REAL("execvpe", real_execvpe_ptr, ct_execvpe_real_fn);
  return real_execvpe_ptr(file, argv, envp);
}

int ct_linux_preload_real_fexecve(int fd, char **argv, char **envp) {
  CT_REAL("fexecve", real_fexecve_ptr, ct_fexecve_real_fn);
  return real_fexecve_ptr(fd, argv, envp);
}

/* glibc has an execveat wrapper only since 2.34; before that, and in a libc
 * without one, the system call itself (execveat(2), Linux 3.19+). */
int ct_linux_preload_real_execveat(int dirfd, const char *path, char **argv,
                                   char **envp, int flags) {
  if (real_execveat_ptr == NULL)
    real_execveat_ptr = (ct_execveat_real_fn)ct_resolve("execveat");
  if (real_execveat_ptr != NULL)
    return real_execveat_ptr(dirfd, path, argv, envp, flags);
#ifdef SYS_execveat
  long rc = ct_raw_syscall6(SYS_execveat, dirfd, (long)path, (long)argv,
                            (long)envp, flags, 0);
  if (rc < 0 && rc > -4096) {
    errno = (int)-rc;
    return -1;
  }
  return (int)rc;
#else
  errno = ENOSYS;
  return -1;
#endif
}

/* The caller's PATH, as glibc's execvpe and posix_spawnp read it
 * (getenv("PATH") of the process, never the envp passed to the call),
 * scanned from `environ` directly so the shim's getenv hook is not entered.
 * NULL when unset. */
static const char *ct_exec_caller_path(void) {
  if (environ == NULL) return NULL;
  for (char **entry = environ; *entry != NULL; entry++)
    if (strncmp(*entry, "PATH=", 5) == 0) return *entry + 5;
  return NULL;
}

/* Classify what a PATH-searching exec of `file`, run in the directory
 * `dirfd`, would run. */
static int ct_exec_classify_searched(int dirfd, const char *file,
                                     char *detail, size_t cap) {
  char resolved[PATH_MAX];
  if (!iomon_exec_search_path(&ct_exec_raw_io, dirfd, file,
                              ct_exec_caller_path(), resolved,
                              sizeof(resolved)))
    return IOMON_EXEC_INJECTABLE;
  return iomon_exec_image_classify(&ct_exec_raw_io, dirfd, resolved, 0,
                                   NULL, detail, cap);
}

/* For the execve hook: 1, with `detail` filled, when the exec it is about
 * to perform on `path` enters an image the shim cannot enter. The hook's
 * `path` is not always what the kernel runs, and this resolves the same
 * target the hook's real execve will:
 *   - fexecve/execveat (ct_exec_redirect_state): the descriptor and path of
 *     THAT call; `path` is only its label (ct_exec_image_label), kept for
 *     the detail;
 *   - execvp/execvpe/execlp of a name without a slash
 *     (ct_exec_announce_only): glibc's PATH search over the caller's PATH;
 *   - otherwise `path` itself, relative to the working directory.
 * errno is preserved. */
int ct_linux_exec_hook_image_uninjectable(const char *path, char *detail,
                                          size_t cap)
    __attribute__((visibility("hidden")));
int ct_linux_exec_hook_image_uninjectable(const char *path, char *detail,
                                          size_t cap) {
  int saved_errno = errno;
  int verdict;
  if (ct_exec_redirect_state.active &&
      ct_exec_redirect_state.announced == path &&
      ct_exec_redirect_state.pid == getpid()) {
    struct ct_exec_redirect redirect = ct_exec_redirect_state;
    verdict = iomon_exec_image_classify(&ct_exec_raw_io, redirect.fd,
                                        redirect.path, redirect.flags, path,
                                        detail, cap);
  } else if (ct_exec_announce_only && path != NULL &&
             strchr(path, '/') == NULL) {
    verdict = ct_exec_classify_searched(AT_FDCWD, path, detail, cap);
  } else {
    verdict = iomon_exec_image_classify(&ct_exec_raw_io, AT_FDCWD, path, 0,
                                        NULL, detail, cap);
  }
  errno = saved_errno;
  return verdict != IOMON_EXEC_INJECTABLE;
}

/* The execve hook's entry when it cannot record (a fork child skipping
 * bookkeeping until exec): classify, and report through the unnamed frame. */
void ct_linux_report_exec_hook_entry_unrecorded(const char *path)
    __attribute__((visibility("hidden")));
void ct_linux_report_exec_hook_entry_unrecorded(const char *path) {
  char detail[CT_EXEC_DETAIL_CAP];
  if (ct_linux_exec_hook_image_uninjectable(path, detail, sizeof(detail)))
    ct_linux_report_uninjectable_exec_frame();
}

/* Whether what a spawn of `file` runs depends on the directory it is
 * resolved in: a relative name with a slash, or a PATH search (`use_path`,
 * no slash) over a PATH holding a relative or empty element. */
static int ct_exec_name_depends_on_cwd(const char *file, int use_path) {
  if (file == NULL || file[0] == '\0') return 0;
  if (!use_path || strchr(file, '/') != NULL) return file[0] != '/';
  const char *p = ct_exec_caller_path();
  if (p == NULL) p = "/bin:/usr/bin";
  for (;;) {
    if (*p != '/') return 1;   /* empty (`::`, leading/trailing `:`) or relative */
    const char *end = strchr(p, ':');
    if (end == NULL) return 0;
    p = end + 1;
  }
}

/* "/proc/<pid>/<leaf>" into `out[cap]`. */
static void ct_proc_pid_path(char *out, size_t cap, long pid,
                             const char *leaf) {
  size_t at = iomon_exec_append(out, 0, cap, "/proc/");
  at = iomon_exec_append_dec(out, at, cap, (unsigned long)pid);
  at = iomon_exec_append(out, at, cap, "/");
  iomon_exec_append(out, at, cap, leaf);
}

/* For the posix_spawn/posix_spawnp hooks: 1, with `detail` filled, when the
 * spawn starts an image the shim cannot enter. posix_spawnp (`use_path`)
 * searches the caller's PATH as glibc's __spawni does.
 *
 * With `child_pid` 0 a relative `file` (or a candidate from a relative PATH
 * element) is looked up in the caller's working directory, which is right
 * unless a file action changed the child's directory first
 * (posix_spawn_file_actions_addchdir_np / addfchdir_np). For that case the
 * hook calls again after a successful spawn with the child's pid; glibc
 * returns only once the child has exec'd, so the kernel's answer is there:
 *   - /proc/<pid>/exe, the image the exec actually loaded (for a `#!` script,
 *     its interpreter), is classified first;
 *   - then the name is resolved in /proc/<pid>/cwd, which catches an
 *     uninjectable image that already exec'd on into a monitored one (the
 *     shape this whole check exists for), whose exe no longer names it;
 *   - when neither can be read (the child already exited) and the name
 *     depends on the directory, the entry cannot be verified and is flagged
 *     (fail closed), as an execute-only image is.
 * errno is preserved. */
int ct_linux_spawn_image_uninjectable(const char *file, int use_path,
                                      long child_pid, char *detail,
                                      size_t cap)
    __attribute__((visibility("hidden")));
int ct_linux_spawn_image_uninjectable(const char *file, int use_path,
                                      long child_pid, char *detail,
                                      size_t cap) {
  int saved_errno = errno;
  int verdict;
  if (cap > 0) detail[0] = '\0';
  if (child_pid <= 0) {
    verdict = use_path
        ? ct_exec_classify_searched(AT_FDCWD, file, detail, cap)
        : iomon_exec_image_classify(&ct_exec_raw_io, AT_FDCWD, file, 0, NULL,
                                    detail, cap);
    errno = saved_errno;
    return verdict != IOMON_EXEC_INJECTABLE;
  }
  char proc_path[48];
  ct_proc_pid_path(proc_path, sizeof(proc_path), child_pid, "exe");
  long exe = ct_raw_syscall6(SYS_openat, AT_FDCWD, (long)proc_path,
                             O_PATH | O_CLOEXEC, 0, 0, 0);
  int exe_readable = exe >= 0;
  if (exe_readable) (void)ct_raw_syscall6(SYS_close, exe, 0, 0, 0, 0, 0);
  verdict = exe_readable
      ? iomon_exec_image_classify(&ct_exec_raw_io, AT_FDCWD, proc_path, 0,
                                  file, detail, cap)
      : IOMON_EXEC_INJECTABLE;
  if (verdict == IOMON_EXEC_INJECTABLE) {
    ct_proc_pid_path(proc_path, sizeof(proc_path), child_pid, "cwd");
    long dirfd = ct_raw_syscall6(SYS_openat, AT_FDCWD, (long)proc_path,
                                 O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
    if (dirfd >= 0) {
      verdict = use_path
          ? ct_exec_classify_searched((int)dirfd, file, detail, cap)
          : iomon_exec_image_classify(&ct_exec_raw_io, (int)dirfd, file, 0,
                                      NULL, detail, cap);
      (void)ct_raw_syscall6(SYS_close, dirfd, 0, 0, 0, 0, 0);
    } else if (!exe_readable && ct_exec_name_depends_on_cwd(file, use_path)) {
      size_t at = iomon_exec_append(detail, 0, cap,
          "spawned image unverifiable: the child exited before the directory "
          "its file actions chose could be read image=");
      iomon_exec_append(detail, at, cap, file);
      verdict = IOMON_EXEC_UNREADABLE;
    }
  }
  errno = saved_errno;
  return verdict != IOMON_EXEC_INJECTABLE;
}

/* The posix_spawn hooks' path when they cannot record (a thread inside a
 * hook, e.g. a signal handler that interrupted one, or a fork child skipping
 * bookkeeping), split around the real call as the recording path is:
 * ct_linux_spawn_entry_unrecorded_pre classifies before the spawn, and
 * ct_linux_spawn_entry_unrecorded_post reports through the unnamed frame
 * only after the spawn succeeded, classifying again in the child's directory
 * when file actions may have changed it (see
 * ct_linux_spawn_image_uninjectable). Allocation-free; errno is preserved. */
int ct_linux_spawn_entry_unrecorded_pre(const char *file, int use_path)
    __attribute__((visibility("hidden")));
int ct_linux_spawn_entry_unrecorded_pre(const char *file, int use_path) {
  char detail[CT_EXEC_DETAIL_CAP];
  if (file == NULL) return 0;
  return ct_linux_spawn_image_uninjectable(file, use_path, 0, detail,
                                           sizeof(detail));
}
void ct_linux_spawn_entry_unrecorded_post(const char *file, int use_path,
                                          int pre_flagged, int succeeded,
                                          int has_file_actions,
                                          long child_pid)
    __attribute__((visibility("hidden")));
void ct_linux_spawn_entry_unrecorded_post(const char *file, int use_path,
                                          int pre_flagged, int succeeded,
                                          int has_file_actions,
                                          long child_pid) {
  char detail[CT_EXEC_DETAIL_CAP];
  if (!succeeded || file == NULL) return;
  if (pre_flagged ||
      (has_file_actions && child_pid > 0 &&
       ct_linux_spawn_image_uninjectable(file, use_path, child_pid, detail,
                                         sizeof(detail))))
    ct_linux_report_uninjectable_exec_frame();
}

int ct_linux_preload_real_posix_spawn(pid_t *pid, char *path,
                                      void *file_actions, void *attrp,
                                      char **argv, char **envp) {
  CT_REAL("posix_spawn", real_posix_spawn_ptr, ct_posix_spawn_real_fn);
  return real_posix_spawn_ptr(pid, path, file_actions, attrp, argv, envp);
}

int ct_linux_preload_real_posix_spawnp(pid_t *pid, char *file,
                                       void *file_actions, void *attrp,
                                       char **argv, char **envp) {
  CT_REAL("posix_spawnp", real_posix_spawnp_ptr, ct_posix_spawn_real_fn);
  return real_posix_spawnp_ptr(pid, file, file_actions, attrp, argv, envp);
}

/* Resolve EVERY real_*_ptr slot now, from the shim's constructor, instead of
 * on the first hooked call.
 *
 * WHY. Each slot is otherwise filled lazily by dlsym(RTLD_NEXT) the first
 * time its hook runs — i.e. inside whatever the host was doing. dlsym is not
 * allocation-free: glibc's _dlerror_run frees this thread's previous dlerror
 * result through the process's free (the host's, if it replaces malloc), and a
 * lookup that fails (__xstat on a modern glibc, arc4random on an old one)
 * allocates its error string through the process's malloc. A host that makes
 * its first mprotect or clock_gettime while holding its allocator lock — as
 * PartitionAlloc does — then waits on that lock inside our dlsym. Resolving
 * here, before any host code runs, leaves the hooks with nothing to resolve.
 *
 * The lazy paths stay as they are, as a fallback for a slot this list
 * misses; tests/linux/test_io_mon_shim_host_allocator_isolation checks that
 * every slot declared above is primed here. The fallback chains mirror the
 * lazy ones exactly (pread64 -> pread, stat -> __xstat, ...). */
#define CT_PRIME(slot, type, name) \
  do { if ((slot) == NULL) (slot) = (type)ct_resolve(name); } while (0)
void ct_linux_preload_prime_real_functions(void) {
  CT_PRIME(real_open_ptr, ct_open_real_fn, "open");
  CT_PRIME(real_open64_ptr, ct_open_real_fn, "open64");
  CT_PRIME(real_open64_ptr, ct_open_real_fn, "open");
  CT_PRIME(real_openat_ptr, ct_openat_real_fn, "openat");
  CT_PRIME(real_openat64_ptr, ct_openat_real_fn, "openat64");
  CT_PRIME(real_openat64_ptr, ct_openat_real_fn, "openat");
  CT_PRIME(real_close_ptr, ct_close_real_fn, "close");
  CT_PRIME(real_read_ptr, ct_read_real_fn, "read");
  CT_PRIME(real_pread_ptr, ct_pread_real_fn, "pread");
  CT_PRIME(real_pread64_ptr, ct_pread_real_fn, "pread64");
  CT_PRIME(real_pread64_ptr, ct_pread_real_fn, "pread");
  CT_PRIME(real_readv_ptr, ct_readv_real_fn, "readv");
  CT_PRIME(real_preadv_ptr, ct_preadv_real_fn, "preadv");
  CT_PRIME(real_preadv64_ptr, ct_preadv_real_fn, "preadv64");
  CT_PRIME(real_preadv64_ptr, ct_preadv_real_fn, "preadv");
  CT_PRIME(real_write_ptr, ct_write_real_fn, "write");
  CT_PRIME(real_stat_ptr, ct_stat_real_fn, "stat");
  if (real_stat_ptr == NULL)
    CT_PRIME(real_xstat_ptr, ct_xstat_real_fn, "__xstat");
  CT_PRIME(real_lstat_ptr, ct_stat_real_fn, "lstat");
  if (real_lstat_ptr == NULL)
    CT_PRIME(real_lxstat_ptr, ct_xstat_real_fn, "__lxstat");
  CT_PRIME(real_opendir_ptr, ct_opendir_real_fn, "opendir");
  CT_PRIME(real_readdir_ptr, ct_readdir_real_fn, "readdir");
  CT_PRIME(real_closedir_ptr, ct_closedir_real_fn, "closedir");
  CT_PRIME(real_fopen_ptr, ct_fopen_real_fn, "fopen");
  CT_PRIME(real_fopen64_ptr, ct_fopen_real_fn, "fopen64");
  CT_PRIME(real_fread_ptr, ct_fread_real_fn, "fread");
  CT_PRIME(real_fclose_ptr, ct_fclose_real_fn, "fclose");
  CT_PRIME(real_connect_ptr, ct_connect_real_fn, "connect");
  CT_PRIME(real_pipe_ptr, ct_pipe_real_fn, "pipe");
  CT_PRIME(real_pipe2_ptr, ct_pipe2_real_fn, "pipe2");
  CT_PRIME(real_socketpair_ptr, ct_socketpair_real_fn, "socketpair");
  CT_PRIME(real_sendfile_ptr, ct_sendfile_real_fn, "sendfile");
  CT_PRIME(real_copy_file_range_ptr, ct_copy_file_range_real_fn,
           "copy_file_range");
  CT_PRIME(real_splice_ptr, ct_splice_real_fn, "splice");
  CT_PRIME(real_link_ptr, ct_link_real_fn, "link");
  CT_PRIME(real_linkat_ptr, ct_linkat_real_fn, "linkat");
  CT_PRIME(real_rename_ptr, ct_rename_real_fn, "rename");
  CT_PRIME(real_renameat_ptr, ct_renameat_real_fn, "renameat");
  CT_PRIME(real_renameat2_ptr, ct_renameat2_real_fn, "renameat2");
  CT_PRIME(real_dlopen_ptr, ct_dlopen_real_fn, "dlopen");
  CT_PRIME(real_dlmopen_ptr, ct_dlmopen_real_fn, "dlmopen");
  (void)ct_linux_preload_real_dlsym(RTLD_DEFAULT, "dlsym"); /* fills real_dlsym_ptr */
  CT_PRIME(real_mmap_ptr, ct_mmap_real_fn, "mmap");
  CT_PRIME(real_mprotect_ptr, ct_mprotect_real_fn, "mprotect");
  CT_PRIME(real_munmap_ptr, ct_munmap_real_fn, "munmap");
  CT_PRIME(real_mremap_ptr, ct_mremap_real_fn, "mremap");
  CT_PRIME(real_getenv_ptr, ct_getenv_real_fn, "getenv");
  CT_PRIME(real_uname_ptr, ct_uname_real_fn, "uname");
  CT_PRIME(real_sysconf_ptr, ct_sysconf_real_fn, "sysconf");
  CT_PRIME(real_clock_gettime_ptr, ct_clock_gettime_real_fn, "clock_gettime");
  CT_PRIME(real_gettimeofday_ptr, ct_gettimeofday_real_fn, "gettimeofday");
  CT_PRIME(real_time_ptr, ct_time_real_fn, "time");
  CT_PRIME(real_getrandom_ptr, ct_getrandom_real_fn, "getrandom");
  CT_PRIME(real_getentropy_ptr, ct_getentropy_real_fn, "getentropy");
  CT_PRIME(real_arc4random_ptr, ct_arc4random_real_fn, "arc4random");
  CT_PRIME(real_arc4random_buf_ptr, ct_arc4random_buf_real_fn, "arc4random_buf");
  CT_PRIME(real_arc4random_uniform_ptr, ct_arc4random_uniform_real_fn,
           "arc4random_uniform");
  CT_PRIME(real_fork_ptr, ct_fork_real_fn, "fork");
  CT_PRIME(real_execve_ptr, ct_execve_real_fn, "execve");
  CT_PRIME(real_execvp_ptr, ct_execvp_real_fn, "execvp");
  CT_PRIME(real_execvpe_ptr, ct_execvpe_real_fn, "execvpe");
  CT_PRIME(real_fexecve_ptr, ct_fexecve_real_fn, "fexecve");
  CT_PRIME(real_execveat_ptr, ct_execveat_real_fn, "execveat");
  CT_PRIME(real_posix_spawn_ptr, ct_posix_spawn_real_fn, "posix_spawn");
  CT_PRIME(real_posix_spawnp_ptr, ct_posix_spawn_real_fn, "posix_spawnp");
  CT_PRIME(real_access_ptr, ct_access_real_fn, "access");
  CT_PRIME(real_faccessat_ptr, ct_faccessat_real_fn, "faccessat");
  CT_PRIME(real_readlink_ptr, ct_readlink_real_fn, "readlink");
  CT_PRIME(real_readlinkat_ptr, ct_readlinkat_real_fn, "readlinkat");
  CT_PRIME(real_realpath_ptr, ct_realpath_real_fn, "realpath");
  CT_PRIME(real_canonicalize_file_name_ptr, ct_canonicalize_real_fn,
           "canonicalize_file_name");
  CT_PRIME(real_clone_ptr, ct_clone_fn, "clone");
  /* _Fork exists only in glibc 2.34 and later, so on an older glibc this
   * slot stays NULL and the hook returns ENOSYS. The hook's own lazy lookup
   * stays as the fallback for a call made before this constructor ran. */
  CT_PRIME(real_underscore_fork_ptr, ct_underscore_fork_fn, "_Fork");
  CT_PRIME(real_scandir_ptr, ct_scandir_real_fn, "scandir");
  CT_PRIME(real_scandir64_ptr, ct_scandir_real_fn, "scandir64");
  CT_PRIME(real_glob_ptr, ct_glob_real_fn, "glob");
  CT_PRIME(real_glob64_ptr, ct_glob_real_fn, "glob64");
  CT_PRIME(real_fdopendir_ptr, ct_fdopendir_real_fn, "fdopendir");
  CT_PRIME(real_statx_ptr, ct_statx_real_fn, "statx");
  CT_PRIME(real_fstatat_ptr, ct_fstatat_real_fn, "fstatat");
  CT_PRIME(real_fstatat64_ptr, ct_fstatat_real_fn, "fstatat64");
  CT_PRIME(real_pkey_mprotect_ptr, ct_pkey_mprotect_real_fn, "pkey_mprotect");
  CT_PRIME(real_realpath_chk_ptr, ct_realpath_chk_real_fn, "__realpath_chk");
  CT_PRIME(real_eventfd_ptr, ct_eventfd_real_fn, "eventfd");
  CT_PRIME(real_timerfd_create_ptr, ct_timerfd_create_real_fn, "timerfd_create");
  CT_PRIME(real_readlink_chk_ptr, ct_readlink_chk_real_fn, "__readlink_chk");
  CT_PRIME(real_readlinkat_chk_ptr, ct_readlinkat_chk_real_fn,
           "__readlinkat_chk");
  CT_PRIME(real_unlink_ptr, ct_unlink_real_fn, "unlink");
  CT_PRIME(real_unlinkat_ptr, ct_unlinkat_real_fn, "unlinkat");
  CT_PRIME(real_rmdir_ptr, ct_unlink_real_fn, "rmdir");
  CT_PRIME(real_remove_ptr, ct_unlink_real_fn, "remove");
  CT_PRIME(real_mkdir_ptr, ct_mkdir_real_fn, "mkdir");
  CT_PRIME(real_mkdirat_ptr, ct_mkdirat_real_fn, "mkdirat");
  CT_PRIME(real_symlink_ptr, ct_symlink_real_fn, "symlink");
  CT_PRIME(real_symlinkat_ptr, ct_symlinkat_real_fn, "symlinkat");
  CT_PRIME(real_truncate_ptr, ct_truncate_real_fn, "truncate");
  CT_PRIME(real_creat_ptr, ct_creat_real_fn, "creat");
  CT_PRIME(real_mkstemp_ptr, ct_mkstemp_real_fn, "mkstemp");
  CT_PRIME(real_mkostemp_ptr, ct_mkostemp_real_fn, "mkostemp");
  CT_PRIME(real_mkstemps_ptr, ct_mkstemps_real_fn, "mkstemps");
  CT_PRIME(real_mkostemps_ptr, ct_mkostemps_real_fn, "mkostemps");
  CT_PRIME(real_mkdtemp_ptr, ct_mkdtemp_real_fn, "mkdtemp");
  /* The lookups above that failed (symbols this glibc does not have) left
   * an error on this thread; consume it so the host's next dlerror() does
   * not report a lookup the shim made. */
  (void)dlerror();
}
#undef CT_PRIME

ssize_t read(int fd, void *buf, size_t count) __attribute__((visibility("default")));
ssize_t read(int fd, void *buf, size_t count) {
  if (CT_BYPASS() || ct_read_hook == NULL)
    return (ssize_t)ct_linux_preload_real_read(fd, buf, count);
  return (ssize_t)CT_CALL_HOOK(ct_read_hook(fd, buf, count));
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
    __attribute__((visibility("default")));
ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
  if (CT_BYPASS() || ct_pread_hook == NULL)
    return (ssize_t)ct_linux_preload_real_pread(fd, buf, count, (long)offset);
  return (ssize_t)CT_CALL_HOOK(ct_pread_hook(fd, buf, count, (long)offset));
}

ssize_t pread64(int fd, void *buf, size_t count, off64_t offset)
    __attribute__((visibility("default")));
ssize_t pread64(int fd, void *buf, size_t count, off64_t offset) {
  if (CT_BYPASS() || ct_pread_hook == NULL)
    return (ssize_t)ct_linux_preload_real_pread64(fd, buf, count, (long)offset);
  return (ssize_t)CT_CALL_HOOK(ct_pread_hook(fd, buf, count, (long)offset));
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
    __attribute__((visibility("default")));
ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
  if (CT_BYPASS() || ct_readv_hook == NULL)
    return (ssize_t)ct_linux_preload_real_readv(fd, (void *)iov, iovcnt);
  return (ssize_t)CT_CALL_HOOK(ct_readv_hook(fd, (void *)iov, iovcnt));
}

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
    __attribute__((visibility("default")));
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
  if (CT_BYPASS() || ct_preadv_hook == NULL)
    return (ssize_t)ct_linux_preload_real_preadv(fd, (void *)iov, iovcnt,
                                                 (long)offset);
  return (ssize_t)CT_CALL_HOOK(ct_preadv_hook(fd, (void *)iov, iovcnt,
                                              (long)offset));
}

ssize_t preadv64(int fd, const struct iovec *iov, int iovcnt, off64_t offset)
    __attribute__((visibility("default")));
ssize_t preadv64(int fd, const struct iovec *iov, int iovcnt, off64_t offset) {
  if (CT_BYPASS() || ct_preadv_hook == NULL)
    return (ssize_t)ct_linux_preload_real_preadv64(fd, (void *)iov, iovcnt,
                                                   (long)offset);
  return (ssize_t)CT_CALL_HOOK(ct_preadv_hook(fd, (void *)iov, iovcnt,
                                              (long)offset));
}

ssize_t write(int fd, const void *buf, size_t count) __attribute__((visibility("default")));
ssize_t write(int fd, const void *buf, size_t count) {
  if (CT_BYPASS() || ct_write_hook == NULL)
    return (ssize_t)ct_linux_preload_real_write(fd, (void *)buf, count);
  return (ssize_t)CT_CALL_HOOK(ct_write_hook(fd, (void *)buf, count));
}

static int ct_dispatch_open(const char *path, int flags, int mode) {
  if (CT_BYPASS() || ct_open_hook == NULL)
    return ct_linux_preload_real_open((char *)path, flags, mode);
  return CT_CALL_HOOK(ct_open_hook((char *)path, flags, mode));
}

int open(const char *path, int flags, ...) __attribute__((visibility("default")));
int open(const char *path, int flags, ...) {
  int mode = 0;
  if (ct_open_flags_need_mode(flags)) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  return ct_dispatch_open(path, flags, mode);
}

static int ct_dispatch_open64(const char *path, int flags, int mode) {
  if (CT_BYPASS() || ct_open64_hook == NULL)
    return ct_linux_preload_real_open64((char *)path, flags, mode);
  return CT_CALL_HOOK(ct_open64_hook((char *)path, flags, mode));
}

int open64(const char *path, int flags, ...) __attribute__((visibility("default")));
int open64(const char *path, int flags, ...) {
  int mode = 0;
  if (ct_open_flags_need_mode(flags)) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  return ct_dispatch_open64(path, flags, mode);
}

static int ct_dispatch_openat(int dirfd, const char *path, int flags, int mode) {
  if (CT_BYPASS() || ct_openat_hook == NULL)
    return ct_linux_preload_real_openat(dirfd, (char *)path, flags, mode);
  return CT_CALL_HOOK(ct_openat_hook(dirfd, (char *)path, flags, mode));
}

int openat(int dirfd, const char *path, int flags, ...) __attribute__((visibility("default")));
int openat(int dirfd, const char *path, int flags, ...) {
  int mode = 0;
  if (ct_open_flags_need_mode(flags)) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  return ct_dispatch_openat(dirfd, path, flags, mode);
}

static int ct_dispatch_openat64(int dirfd, const char *path, int flags, int mode) {
  if (CT_BYPASS() || ct_openat64_hook == NULL)
    return ct_linux_preload_real_openat64(dirfd, (char *)path, flags, mode);
  return CT_CALL_HOOK(ct_openat64_hook(dirfd, (char *)path, flags, mode));
}

int openat64(int dirfd, const char *path, int flags, ...) __attribute__((visibility("default")));
int openat64(int dirfd, const char *path, int flags, ...) {
  int mode = 0;
  if (ct_open_flags_need_mode(flags)) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  return ct_dispatch_openat64(dirfd, path, flags, mode);
}

int close(int fd) __attribute__((visibility("default")));
int close(int fd) {
  if (CT_BYPASS() || ct_close_hook == NULL)
    return ct_linux_preload_real_close(fd);
  return CT_CALL_HOOK(ct_close_hook(fd));
}

int stat(const char *path, struct stat *buf) __attribute__((visibility("default")));
int stat(const char *path, struct stat *buf) {
  if (CT_BYPASS() || ct_stat_hook == NULL)
    return ct_linux_preload_real_stat((char *)path, buf);
  return CT_CALL_HOOK(ct_stat_hook((char *)path, buf));
}

int lstat(const char *path, struct stat *buf) __attribute__((visibility("default")));
int lstat(const char *path, struct stat *buf) {
  if (CT_BYPASS() || ct_lstat_hook == NULL)
    return ct_linux_preload_real_lstat((char *)path, buf);
  return CT_CALL_HOOK(ct_lstat_hook((char *)path, buf));
}

int __xstat(int ver, const char *path, struct stat *buf) __attribute__((visibility("default")));
int __xstat(int ver, const char *path, struct stat *buf) {
  if (CT_BYPASS() || ct_stat_hook == NULL) {
    if (real_xstat_ptr == NULL) real_xstat_ptr = (ct_xstat_real_fn)ct_resolve("__xstat");
    if (real_xstat_ptr == NULL) return ct_linux_preload_real_stat((char *)path, buf);
    return real_xstat_ptr(ver, path, buf);
  }
  return CT_CALL_HOOK(ct_stat_hook((char *)path, buf));
}

int __lxstat(int ver, const char *path, struct stat *buf) __attribute__((visibility("default")));
int __lxstat(int ver, const char *path, struct stat *buf) {
  if (CT_BYPASS() || ct_lstat_hook == NULL) {
    if (real_lxstat_ptr == NULL) real_lxstat_ptr = (ct_xstat_real_fn)ct_resolve("__lxstat");
    if (real_lxstat_ptr == NULL) return ct_linux_preload_real_lstat((char *)path, buf);
    return real_lxstat_ptr(ver, path, buf);
  }
  return CT_CALL_HOOK(ct_lstat_hook((char *)path, buf));
}

DIR *opendir(const char *path) __attribute__((visibility("default")));
DIR *opendir(const char *path) {
  if (CT_BYPASS() || ct_opendir_hook == NULL)
    return (DIR *)ct_linux_preload_real_opendir((char *)path);
  return (DIR *)CT_CALL_HOOK(ct_opendir_hook((char *)path));
}

struct dirent *readdir(DIR *dirp) __attribute__((visibility("default")));
struct dirent *readdir(DIR *dirp) {
  if (CT_BYPASS() || ct_readdir_hook == NULL)
    return (struct dirent *)ct_linux_preload_real_readdir((void *)dirp);
  return (struct dirent *)CT_CALL_HOOK(ct_readdir_hook((void *)dirp));
}

int closedir(DIR *dirp) __attribute__((visibility("default")));
int closedir(DIR *dirp) {
  if (CT_BYPASS() || ct_closedir_hook == NULL)
    return ct_linux_preload_real_closedir((void *)dirp);
  return CT_CALL_HOOK(ct_closedir_hook((void *)dirp));
}

FILE *fopen(const char *path, const char *mode) __attribute__((visibility("default")));
FILE *fopen(const char *path, const char *mode) {
  if (CT_BYPASS() || ct_fopen_hook == NULL)
    return (FILE *)ct_linux_preload_real_fopen((char *)path, (char *)mode);
  return (FILE *)CT_CALL_HOOK(ct_fopen_hook((char *)path, (char *)mode));
}

FILE *fopen64(const char *path, const char *mode) __attribute__((visibility("default")));
FILE *fopen64(const char *path, const char *mode) {
  if (CT_BYPASS() || ct_fopen64_hook == NULL)
    return (FILE *)ct_linux_preload_real_fopen64((char *)path, (char *)mode);
  return (FILE *)CT_CALL_HOOK(ct_fopen64_hook((char *)path, (char *)mode));
}

size_t fread(void *buf, size_t size, size_t nmemb, FILE *stream)
    __attribute__((visibility("default")));
size_t fread(void *buf, size_t size, size_t nmemb, FILE *stream) {
  if (CT_BYPASS() || ct_fread_hook == NULL)
    return ct_linux_preload_real_fread(buf, size, nmemb, (void *)stream);
  return CT_CALL_HOOK(ct_fread_hook(buf, size, nmemb, (void *)stream));
}

int fclose(FILE *stream) __attribute__((visibility("default")));
int fclose(FILE *stream) {
  if (CT_BYPASS() || ct_fclose_hook == NULL)
    return ct_linux_preload_real_fclose((void *)stream);
  return CT_CALL_HOOK(ct_fclose_hook((void *)stream));
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
    __attribute__((visibility("default")));
int connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
  if (CT_BYPASS() || ct_connect_hook == NULL)
    return ct_linux_preload_real_connect(fd, (void *)addr, (unsigned int)addrlen);
  return CT_CALL_HOOK(ct_connect_hook(fd, (void *)addr, (unsigned int)addrlen));
}

int pipe(int fds[2]) __attribute__((visibility("default")));
int pipe(int fds[2]) {
  if (CT_BYPASS() || ct_pipe_hook == NULL)
    return ct_linux_preload_real_pipe((void *)fds);
  return CT_CALL_HOOK(ct_pipe_hook((void *)fds));
}

int pipe2(int fds[2], int flags) __attribute__((visibility("default")));
int pipe2(int fds[2], int flags) {
  if (CT_BYPASS() || ct_pipe2_hook == NULL)
    return ct_linux_preload_real_pipe2((void *)fds, flags);
  return CT_CALL_HOOK(ct_pipe2_hook((void *)fds, flags));
}

int socketpair(int domain, int type, int protocol, int sv[2])
    __attribute__((visibility("default")));
int socketpair(int domain, int type, int protocol, int sv[2]) {
  if (CT_BYPASS() || ct_socketpair_hook == NULL)
    return ct_linux_preload_real_socketpair(domain, type, protocol, (void *)sv);
  return CT_CALL_HOOK(ct_socketpair_hook(domain, type, protocol, (void *)sv));
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
    __attribute__((visibility("default")));
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
  if (CT_BYPASS() || ct_sendfile_hook == NULL)
    return (ssize_t)ct_linux_preload_real_sendfile(out_fd, in_fd, offset, count);
  return (ssize_t)CT_CALL_HOOK(ct_sendfile_hook(out_fd, in_fd, offset, count));
}

ssize_t copy_file_range(int in_fd, loff_t *off_in, int out_fd,
                        loff_t *off_out, size_t len, unsigned int flags)
    __attribute__((visibility("default")));
ssize_t copy_file_range(int in_fd, loff_t *off_in, int out_fd,
                        loff_t *off_out, size_t len, unsigned int flags) {
  if (CT_BYPASS() || ct_copy_file_range_hook == NULL)
    return (ssize_t)ct_linux_preload_real_copy_file_range(
      in_fd, off_in, out_fd, off_out, len, flags);
  return (ssize_t)CT_CALL_HOOK(ct_copy_file_range_hook(
    in_fd, off_in, out_fd, off_out, len, flags));
}

ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
               size_t len, unsigned int flags)
    __attribute__((visibility("default")));
ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
               size_t len, unsigned int flags) {
  if (CT_BYPASS() || ct_splice_hook == NULL)
    return (ssize_t)ct_linux_preload_real_splice(
      fd_in, off_in, fd_out, off_out, len, flags);
  return (ssize_t)CT_CALL_HOOK(ct_splice_hook(
    fd_in, off_in, fd_out, off_out, len, flags));
}

int link(const char *oldpath, const char *newpath)
    __attribute__((visibility("default")));
int link(const char *oldpath, const char *newpath) {
  if (CT_BYPASS() || ct_link_hook == NULL)
    return ct_linux_preload_real_link((char *)oldpath, (char *)newpath);
  return CT_CALL_HOOK(ct_link_hook((char *)oldpath, (char *)newpath));
}

int linkat(int olddirfd, const char *oldpath, int newdirfd,
           const char *newpath, int flags)
    __attribute__((visibility("default")));
int linkat(int olddirfd, const char *oldpath, int newdirfd,
           const char *newpath, int flags) {
  if (CT_BYPASS() || ct_linkat_hook == NULL)
    return ct_linux_preload_real_linkat(
      olddirfd, (char *)oldpath, newdirfd, (char *)newpath, flags);
  return CT_CALL_HOOK(ct_linkat_hook(
    olddirfd, (char *)oldpath, newdirfd, (char *)newpath, flags));
}

int rename(const char *oldpath, const char *newpath)
    __attribute__((visibility("default")));
int rename(const char *oldpath, const char *newpath) {
  if (CT_BYPASS() || ct_rename_hook == NULL)
    return ct_linux_preload_real_rename((char *)oldpath, (char *)newpath);
  return CT_CALL_HOOK(ct_rename_hook((char *)oldpath, (char *)newpath));
}

int renameat(int olddirfd, const char *oldpath, int newdirfd,
             const char *newpath)
    __attribute__((visibility("default")));
int renameat(int olddirfd, const char *oldpath, int newdirfd,
             const char *newpath) {
  if (CT_BYPASS() || ct_renameat_hook == NULL)
    return ct_linux_preload_real_renameat(
      olddirfd, (char *)oldpath, newdirfd, (char *)newpath);
  return CT_CALL_HOOK(ct_renameat_hook(
    olddirfd, (char *)oldpath, newdirfd, (char *)newpath));
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd,
              const char *newpath, unsigned int flags)
    __attribute__((visibility("default")));
int renameat2(int olddirfd, const char *oldpath, int newdirfd,
              const char *newpath, unsigned int flags) {
  if (CT_BYPASS() || ct_renameat2_hook == NULL)
    return ct_linux_preload_real_renameat2(
      olddirfd, (char *)oldpath, newdirfd, (char *)newpath, flags);
  return CT_CALL_HOOK(ct_renameat2_hook(
    olddirfd, (char *)oldpath, newdirfd, (char *)newpath, flags));
}

void *dlopen(const char *path, int flags) __attribute__((visibility("default")));
void *dlopen(const char *path, int flags) {
  /* Transparency: resolve a bare soname against the ORIGINAL caller's
     RPATH/RUNPATH (not the shim's) before the real dlopen. See
     ct_linux_preload_resolve_dlopen_caller_path. */
  ct_dlopen_scratch *scratch = ct_dlopen_scratch_new(path);
  const char *rp = ct_linux_preload_resolve_dlopen_caller_path(
      path, __builtin_return_address(0), scratch);
  void *handle;
  if (CT_BYPASS() || ct_dlopen_hook == NULL)
    handle = ct_linux_preload_real_dlopen((char *)rp, flags);
  else
    handle = CT_CALL_HOOK(ct_dlopen_hook((char *)rp, flags));
  ct_dlopen_scratch_free(scratch);
  return handle;
}

void *dlmopen(Lmid_t namespace_id, const char *path, int flags)
    __attribute__((visibility("default")));
void *dlmopen(Lmid_t namespace_id, const char *path, int flags) {
  ct_dlopen_scratch *scratch = ct_dlopen_scratch_new(path);
  const char *rp = ct_linux_preload_resolve_dlopen_caller_path(
      path, __builtin_return_address(0), scratch);
  void *handle;
  if (CT_BYPASS() || ct_dlmopen_hook == NULL)
    handle = ct_linux_preload_real_dlmopen((long)namespace_id, (char *)rp,
                                           flags);
  else
    handle = CT_CALL_HOOK(ct_dlmopen_hook((long)namespace_id, (char *)rp,
                                          flags));
  ct_dlopen_scratch_free(scratch);
  return handle;
}

void *ct_linux_preload_public_dlsym(void *handle, const char *name)
    __attribute__((visibility("default")));
void *ct_linux_preload_public_dlsym(void *handle, const char *name) {
  if (CT_BYPASS() || ct_dlsym_hook == NULL)
    return ct_linux_preload_real_dlsym(handle, (char *)name);
  return CT_CALL_HOOK(ct_dlsym_hook(handle, (char *)name));
}
#ifdef __GLIBC__
void *ct_linux_preload_public_dlsym_glibc_base(void *handle, const char *name)
    __attribute__((alias("ct_linux_preload_public_dlsym"),
                   visibility("default")));
void *ct_linux_preload_public_dlsym_glibc_2_34(void *handle, const char *name)
    __attribute__((alias("ct_linux_preload_public_dlsym"),
                   visibility("default")));
__asm__(".symver ct_linux_preload_public_dlsym_glibc_base,dlsym@" CT_DLSYM_GLIBC_BASE);
__asm__(".symver ct_linux_preload_public_dlsym_glibc_2_34,dlsym@@GLIBC_2.34");
#else
void *dlsym(void *handle, const char *name)
    __attribute__((alias("ct_linux_preload_public_dlsym"),
                   visibility("default")));
#endif

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    __attribute__((visibility("default")));
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  if (CT_BYPASS() || ct_mmap_hook == NULL)
    return ct_linux_preload_real_mmap(addr, length, prot, flags, fd, (long)offset);
  return CT_CALL_HOOK(ct_mmap_hook(addr, length, prot, flags, fd, (long)offset));
}

int mprotect(void *addr, size_t length, int prot)
    __attribute__((visibility("default")));
int mprotect(void *addr, size_t length, int prot) {
  if (CT_BYPASS() || ct_mprotect_hook == NULL)
    return ct_linux_preload_real_mprotect(addr, length, prot);
  return CT_CALL_HOOK(ct_mprotect_hook(addr, length, prot));
}

int munmap(void *addr, size_t length)
    __attribute__((visibility("default")));
int munmap(void *addr, size_t length) {
  if (CT_BYPASS() || ct_munmap_hook == NULL)
    return ct_linux_preload_real_munmap(addr, length);
  return CT_CALL_HOOK(ct_munmap_hook(addr, length));
}

void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...)
    __attribute__((visibility("default")));
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ...) {
  void *new_addr = NULL;
  if ((flags & MREMAP_FIXED) != 0) {
    va_list ap;
    va_start(ap, flags);
    new_addr = va_arg(ap, void *);
    va_end(ap);
  }
  if (CT_BYPASS() || ct_mremap_hook == NULL)
    return ct_linux_preload_real_mremap(old_addr, old_size, new_size, flags, new_addr);
  return CT_CALL_HOOK(ct_mremap_hook(old_addr, old_size, new_size, flags, new_addr));
}

/* ---------------------------------------------------------------------------
 * LARGE-FILE ALIASES AND OBSERVE-ONLY INTERPOSITIONS
 *
 * WHY. An LD_PRELOAD interposition only sees calls made through the symbol
 * NAME it exports. Hosts import more names than the hook set covered: Node 24
 * imports mmap64, stat64 and lstat64; its libuv imports scandir, access,
 * readlink and realpath; Chromium also imports readdir64, fstatat64, statx
 * and sendfile64. Measured with `nm -D --undefined-only` against the shim's
 * exports on x86_64 glibc 2.42. A call through a name the shim does not
 * export goes straight to libc and is invisible:
 *   - V8 reserves its code range with mmap64, so the range never entered the
 *     preload mmap lifecycle and V8's mprotect(PROT_EXEC) of it was reported
 *     as an untracked executable mapping (a spurious mcIncomplete on every
 *     Node run);
 *   - worse, the reads behind fs.readdirSync (scandir), fs.existsSync
 *     (access) or fs.realpathSync.native (realpath) were simply not recorded,
 *     which can grade a run mcComplete with dependencies missing.
 *
 * LARGE-FILE ALIASES. On LP64 glibc each *64 function is the same function
 * as its plain twin (off_t and struct stat are already 64-bit; glibc defines
 * one as an alias of the other), so the shim exports the *64 names as
 * aliases of its existing interpositions. The asm label gives the symbol its
 * name without redeclaring the header's prototype.
 *
 * OBSERVE-ONLY. The other names need no hook chain: the real call runs
 * unchanged, then one observer records what it means — a path probe, a
 * directory enumeration, a DIR*-to-path association, or the mprotect
 * lifecycle check. Observers are registered by the shim
 * (ct_linux_preload_register_observers) and run inside the usual hook
 * re-entrancy guard, with errno preserved.
 * ------------------------------------------------------------------------- */
#if defined(__LP64__) && defined(__GLIBC__)
extern void *ct_mmap64_alias(void *, size_t, int, int, int, off_t)
    __asm__("mmap64") __attribute__((alias("mmap"), visibility("default")));
extern int ct_stat64_alias(const char *, struct stat *)
    __asm__("stat64") __attribute__((alias("stat"), visibility("default")));
extern int ct_lstat64_alias(const char *, struct stat *)
    __asm__("lstat64") __attribute__((alias("lstat"), visibility("default")));
extern struct dirent *ct_readdir64_alias(DIR *)
    __asm__("readdir64") __attribute__((alias("readdir"), visibility("default")));
extern ssize_t ct_sendfile64_alias(int, int, off_t *, size_t)
    __asm__("sendfile64") __attribute__((alias("sendfile"), visibility("default")));
#endif

typedef void (*ct_probe_observer_fn)(int dirfd, const char *path, int rc);
typedef void (*ct_enumerate_observer_fn)(int dirfd, const char *path, int rc);
typedef void (*ct_fdopendir_observer_fn)(int fd, void *dirp);
typedef void (*ct_mprotect_observer_fn)(void *addr, size_t len, int prot, int rc);
typedef void (*ct_localfd_create_observer_fn)(int fd);
static ct_probe_observer_fn ct_probe_observer = NULL;
static ct_localfd_create_observer_fn ct_localfd_create_observer = NULL;
static ct_enumerate_observer_fn ct_enumerate_observer = NULL;
static ct_fdopendir_observer_fn ct_fdopendir_observer = NULL;
static ct_mprotect_observer_fn ct_mprotect_observer = NULL;

/* Records the resolution of `path` (relative to `dirfd`) the way the kernel
 * and realpath(3) perform it: every symbolic link met on the way, with its
 * target, and the path it leads to. `follow_final` says whether the last
 * component is itself followed (realpath) or only read (readlink). */
typedef void (*ct_resolution_observer_fn)(int dirfd, const char *path,
                                          int follow_final);
static ct_resolution_observer_fn ct_resolution_observer = NULL;
void ct_linux_preload_register_resolution_observer(
    ct_resolution_observer_fn observer) {
  ct_resolution_observer = observer;
}

/* The resolution walk's primitives, unrecorded: what lstat(2) says the path
 * is (1 a symbolic link, 0 anything else, -1 absent or unreadable), and
 * readlink(2) through the real function. */
int ct_linux_preload_lstat_kind(const char *path) {
  struct stat st;
  if (ct_linux_preload_real_lstat((char *)path, &st) != 0) return -1;
  return S_ISLNK(st.st_mode) ? 1 : 0;
}

long ct_linux_preload_real_readlink(const char *path, char *buf, size_t size) {
  if (real_readlink_ptr == NULL)
    real_readlink_ptr = (ct_readlink_real_fn)ct_resolve("readlink");
  if (real_readlink_ptr == NULL) { errno = ENOSYS; return -1; }
  return (long)real_readlink_ptr(path, buf, size);
}

void ct_linux_preload_register_observers(ct_probe_observer_fn probe,
                                         ct_enumerate_observer_fn enumerate,
                                         ct_fdopendir_observer_fn fdopendir_fn,
                                         ct_mprotect_observer_fn mprotect_fn,
                                         ct_localfd_create_observer_fn create_fn) {
  ct_localfd_create_observer = create_fn;
  ct_probe_observer = probe;
  ct_enumerate_observer = enumerate;
  ct_fdopendir_observer = fdopendir_fn;
  ct_mprotect_observer = mprotect_fn;
}

#define CT_OBSERVE(observer, ...) do { \
  if (!CT_BYPASS() && (observer) != NULL) { \
    int ct_saved_errno = errno; \
    stackable_linux_preload_enter_hook(); \
    (observer)(__VA_ARGS__); \
    stackable_linux_preload_exit_hook(); \
    errno = ct_saved_errno; \
  } \
} while (0)

#define CT_OBSERVED_REAL(slot, type, name, fail) do { \
  if ((slot) == NULL) (slot) = (type)ct_resolve(name); \
  if ((slot) == NULL) { errno = ENOSYS; return fail; } \
} while (0)

int access(const char *path, int mode) __attribute__((visibility("default")));
int access(const char *path, int mode) {
  CT_OBSERVED_REAL(real_access_ptr, ct_access_real_fn, "access", -1);
  int rc = real_access_ptr(path, mode);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc);
  return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags)
    __attribute__((visibility("default")));
int faccessat(int dirfd, const char *path, int mode, int flags) {
  CT_OBSERVED_REAL(real_faccessat_ptr, ct_faccessat_real_fn, "faccessat", -1);
  int rc = real_faccessat_ptr(dirfd, path, mode, flags);
  CT_OBSERVE(ct_probe_observer, dirfd, path, rc);
  return rc;
}

ssize_t readlink(const char *path, char *buf, size_t size)
    __attribute__((visibility("default")));
ssize_t readlink(const char *path, char *buf, size_t size) {
  CT_OBSERVED_REAL(real_readlink_ptr, ct_readlink_real_fn, "readlink", -1);
  ssize_t rc = real_readlink_ptr(path, buf, size);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc < 0 ? -1 : 0);
  CT_OBSERVE(ct_resolution_observer, AT_FDCWD, path, 0);
  return rc;
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t size)
    __attribute__((visibility("default")));
ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t size) {
  CT_OBSERVED_REAL(real_readlinkat_ptr, ct_readlinkat_real_fn, "readlinkat", -1);
  ssize_t rc = real_readlinkat_ptr(dirfd, path, buf, size);
  CT_OBSERVE(ct_probe_observer, dirfd, path, rc < 0 ? -1 : 0);
  CT_OBSERVE(ct_resolution_observer, dirfd, path, 0);
  return rc;
}

/* realpath resolves every component inside libc, through calls no
 * interposition sees. Its result depends on more than the path the caller
 * named: on every symbolic link it follows and on where each one points
 * (a -> b -> c resolves to c, and retargeting b changes the answer while a
 * stays as it was). So besides the probe of the path asked about, the
 * resolution observer replays the walk and records each link it meets, with
 * its target, and the path it leads to, absent or not. */
char *realpath(const char *path, char *resolved)
    __attribute__((visibility("default")));
char *realpath(const char *path, char *resolved) {
  CT_OBSERVED_REAL(real_realpath_ptr, ct_realpath_real_fn, "realpath", NULL);
  char *rc = real_realpath_ptr(path, resolved);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc != NULL ? 0 : -1);
  CT_OBSERVE(ct_resolution_observer, AT_FDCWD, path, 1);
  return rc;
}

char *canonicalize_file_name(const char *path)
    __attribute__((visibility("default")));
char *canonicalize_file_name(const char *path) {
  CT_OBSERVED_REAL(real_canonicalize_file_name_ptr, ct_canonicalize_real_fn,
                   "canonicalize_file_name", NULL);
  char *rc = real_canonicalize_file_name_ptr(path);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc != NULL ? 0 : -1);
  CT_OBSERVE(ct_resolution_observer, AT_FDCWD, path, 1);
  return rc;
}

/* The _FORTIFY_SOURCE spellings: a caller compiled with fortification (the
 * default in nixpkgs' and most distributions' toolchains) calls these instead
 * of realpath/readlink, so they need the same observation. */
char *__realpath_chk(const char *path, char *resolved, size_t resolvedlen)
    __attribute__((visibility("default")));
char *__realpath_chk(const char *path, char *resolved, size_t resolvedlen) {
  CT_OBSERVED_REAL(real_realpath_chk_ptr, ct_realpath_chk_real_fn,
                   "__realpath_chk", NULL);
  char *rc = real_realpath_chk_ptr(path, resolved, resolvedlen);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc != NULL ? 0 : -1);
  CT_OBSERVE(ct_resolution_observer, AT_FDCWD, path, 1);
  return rc;
}

ssize_t __readlink_chk(const char *path, char *buf, size_t len, size_t buflen)
    __attribute__((visibility("default")));
ssize_t __readlink_chk(const char *path, char *buf, size_t len, size_t buflen) {
  CT_OBSERVED_REAL(real_readlink_chk_ptr, ct_readlink_chk_real_fn,
                   "__readlink_chk", -1);
  ssize_t rc = real_readlink_chk_ptr(path, buf, len, buflen);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc < 0 ? -1 : 0);
  CT_OBSERVE(ct_resolution_observer, AT_FDCWD, path, 0);
  return rc;
}

ssize_t __readlinkat_chk(int dirfd, const char *path, char *buf, size_t len,
                         size_t buflen) __attribute__((visibility("default")));
ssize_t __readlinkat_chk(int dirfd, const char *path, char *buf, size_t len,
                         size_t buflen) {
  CT_OBSERVED_REAL(real_readlinkat_chk_ptr, ct_readlinkat_chk_real_fn,
                   "__readlinkat_chk", -1);
  ssize_t rc = real_readlinkat_chk_ptr(dirfd, path, buf, len, buflen);
  CT_OBSERVE(ct_probe_observer, dirfd, path, rc < 0 ? -1 : 0);
  CT_OBSERVE(ct_resolution_observer, dirfd, path, 0);
  return rc;
}

/* scandir opens and reads the directory INSIDE libc (no PLT call reaches
 * the opendir/readdir interpositions), so it is recorded here as one
 * enumeration of the directory. */
int scandir(const char *dir, struct dirent ***namelist,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **))
    __attribute__((visibility("default")));
int scandir(const char *dir, struct dirent ***namelist,
            int (*filter)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **)) {
  CT_OBSERVED_REAL(real_scandir_ptr, ct_scandir_real_fn, "scandir", -1);
  int rc = real_scandir_ptr(dir, (void *)namelist, (void *)filter, (void *)compar);
  CT_OBSERVE(ct_enumerate_observer, AT_FDCWD, dir, rc);
  return rc;
}

#if defined(__LP64__) && defined(__GLIBC__)
int ct_scandir64_impl(const char *, void *, void *, void *)
    __asm__("scandir64") __attribute__((visibility("default")));
int ct_scandir64_impl(const char *dir, void *namelist, void *filter,
                      void *compar) {
  CT_OBSERVED_REAL(real_scandir64_ptr, ct_scandir_real_fn, "scandir64", -1);
  int rc = real_scandir64_ptr(dir, namelist, filter, compar);
  CT_OBSERVE(ct_enumerate_observer, AT_FDCWD, dir, rc);
  return rc;
}
#endif

/* glob(3) opens, reads and stats directories INSIDE libc (glibc calls
 * __opendir, __readdir64 and __fstatat64), so a scan made through it reaches
 * none of the interpositions: a pattern such as "<dir>/*.nimble" left no
 * evidence that <dir> was listed, although whether anything matches decides
 * the caller's outcome (Nim's walkFiles is glob on POSIX, and the compiler
 * finds a project's .nimble file with it). Darwin's glob calls the public
 * opendir, so the macOS backend already records these scans.
 *
 * glibc's GLOB_ALTDIRFUNC extension makes glob do all of its directory and
 * stat access through function pointers in the caller's glob_t
 * (https://sourceware.org/glibc/manual/latest/html_node/More-Flags-for-Globbing.html).
 * The interposition passes its own: each calls the real function and records
 * what the call means. Every directory glob scans is a directory enumeration
 * (one it cannot open is a probe of whether the name exists), and every name
 * it looks up with stat/lstat is a probe. The caller's glob_t fields and the
 * GLOB_ALTDIRFUNC bit of gl_flags are restored afterwards, so the caller sees
 * what an unmonitored glob returns.
 *
 * A caller that passes GLOB_ALTDIRFUNC itself does its own directory access,
 * observed through whatever its callbacks call; its glob runs unchanged.
 * On LP64 glibc struct dirent/stat are their *64 twins, so one set of
 * callbacks serves both glob and glob64.
 *
 * A scan is PATTERN-SCOPED: glob keeps only the entries that match one
 * component of the pattern, so the caller's outcome depends on which names
 * match it and on nothing else in the directory. The observer receives that
 * component whenever it can be named with certainty (see
 * ct_glob_scan_component), and NULL otherwise, in which case the scan is
 * reported as an ordinary full enumeration. Reporting a pattern that
 * matches fewer names than glob's would lose a dependency, so every
 * uncertain case falls back to the full listing. */
typedef void (*ct_glob_scan_observer_fn)(const char *path,
                                         const char *pattern);
static ct_glob_scan_observer_fn ct_glob_scan_observer = NULL;
void ct_linux_preload_register_glob_scan_observer(
    ct_glob_scan_observer_fn observer) {
  ct_glob_scan_observer = observer;
}

#if defined(__LP64__) && defined(__GLIBC__) && defined(GLOB_ALTDIRFUNC)
/* The pattern of the glob call running on this thread, or NULL when its
 * components cannot be mapped onto the directories glob opens. Saved and
 * restored around each call, so a glob made from inside an errfunc does not
 * clobber the outer call's. */
static __thread const char *ct_glob_active_pattern = NULL;

/* Advance past one '/'-separated component of `s`, skipping repeated
 * slashes first. Returns the component's start and stores its length. */
static const char *ct_glob_next_component(const char *s, size_t *len) {
  while (*s == '/') s++;
  const char *start = s;
  while (*s != '\0' && *s != '/') s++;
  *len = (size_t)(s - start);
  return start;
}

/* The pattern component glob matches against the entries of `dir`, copied
 * into `out` (NUL-terminated), or 0 when it cannot be named with certainty.
 *
 * glob builds every directory it opens by appending matched names to the
 * pattern's leading components, one name per component
 * (https://sourceware.org/git/?p=glibc.git;a=blob;f=posix/glob.c, glob and
 * glob_in_dir; its recursive scan of a wildcard dirname copies the
 * GLOB_ALTDIRFUNC callbacks into the inner glob_t, so intermediate levels
 * arrive here too). So the directory's component count is the index of the
 * component being matched: "<a>/x" under the pattern "<a>/ * /c*" (spaces
 * only to keep this comment closed) is matched against "c*". A pattern with
 * no '/' is matched against the working directory, which glob opens as ""
 * or ".".
 *
 * The one name this counting cannot place is a bare ".". glob opens the
 * working directory under it for a pattern's literal "./" prefix, but also
 * as the implicit start of a relative pattern whose FIRST component is a
 * wildcard (the "*" of "* /x*" is matched in "."), and when a wildcard such
 * as ".*" matched the entry "." itself. Only the literal prefix places the
 * component, so under a pattern with a '/' a bare "." is scoped only when
 * the pattern's first component is a literal ".".
 *
 * Certainty requires, and this returns 0 unless:
 * - the opened path is rooted exactly when the pattern is;
 * - each literal component of the pattern equals the opened path's
 *   component at that position (a wildcard component is the name glob
 *   matched, which this does not re-match);
 * - the component exists and uses only literals, '*' and '?'. Bracket
 *   expressions and backslash escapes are left to the full listing, so a
 *   consumer can match the reported pattern without reproducing fnmatch's
 *   locale-dependent classes;
 * - the component holds no whitespace, so it stays a single token in the
 *   record's whitespace-separated detail (GlobPatternDetailPrefix in
 *   io_mon/types.nim). */
static int ct_glob_scan_component(const char *pattern, const char *dir,
                                  char *out, size_t out_len) {
  if (pattern == NULL || dir == NULL) return 0;
  const char *component;
  size_t component_len;
  if (strchr(pattern, '/') == NULL) {
    if (!(dir[0] == '\0' || strcmp(dir, ".") == 0)) return 0;
    component = pattern;
    component_len = strlen(pattern);
  } else {
    if ((pattern[0] == '/') != (dir[0] == '/')) return 0;
    if (dir[0] == '\0') return 0;
    if (strcmp(dir, ".") == 0) {
      size_t first_len;
      const char *first = ct_glob_next_component(pattern, &first_len);
      if (first_len != 1 || first[0] != '.') return 0;
    }
    const char *p = pattern;
    const char *d = dir;
    for (;;) {
      size_t dir_len;
      const char *dir_part = ct_glob_next_component(d, &dir_len);
      component = ct_glob_next_component(p, &component_len);
      if (dir_len == 0) break;
      if (component_len == 0) return 0;
      if (strcspn(component, "*?[\\") >= component_len &&
          (component_len != dir_len ||
           memcmp(component, dir_part, dir_len) != 0))
        return 0;
      d = dir_part + dir_len;
      p = component + component_len;
    }
  }
  if (component_len == 0 || component_len >= out_len) return 0;
  for (size_t i = 0; i < component_len; i++)
    if (strchr("[\\ \t\n\r\v\f", component[i]) != NULL) return 0;
  memcpy(out, component, component_len);
  out[component_len] = '\0';
  return 1;
}

static void *ct_glob_opendir(const char *path) {
  void *dir = ct_linux_preload_real_opendir((char *)path);
  if (dir != NULL) {
    char component[256];
    const char *pattern =
        ct_glob_scan_component(ct_glob_active_pattern, path, component,
                               sizeof component)
            ? component
            : NULL;
    CT_OBSERVE(ct_glob_scan_observer, path, pattern);
  } else {
    /* glob skips a directory it cannot open (an absent name, a file, no
     * permission), so the outcome depends on whether the name exists. Keep
     * opendir's errno: glob hands it to the caller's errfunc. */
    int saved_errno = errno;
    struct stat st;
    int rc = ct_linux_preload_real_stat((char *)path, &st) == 0 ? 0 : -1;
    errno = saved_errno;
    CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc);
  }
  return dir;
}

static struct dirent *ct_glob_readdir(void *dir) {
  return (struct dirent *)ct_linux_preload_real_readdir(dir);
}

static void ct_glob_closedir(void *dir) {
  ct_linux_preload_real_closedir(dir);
}

static int ct_glob_stat(const char *path, struct stat *buf) {
  int rc = ct_linux_preload_real_stat((char *)path, buf);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc);
  return rc;
}

static int ct_glob_lstat(const char *path, struct stat *buf) {
  int rc = ct_linux_preload_real_lstat((char *)path, buf);
  CT_OBSERVE(ct_probe_observer, AT_FDCWD, path, rc);
  return rc;
}

static int ct_glob_observed(ct_glob_real_fn real, const char *pattern,
                            int flags, int (*errfunc)(const char *, int),
                            glob_t *pglob) {
  if (CT_BYPASS() || ct_glob_scan_observer == NULL || pglob == NULL ||
      (flags & GLOB_ALTDIRFUNC) != 0)
    return real(pattern, flags, errfunc, pglob);
  void (*saved_closedir)(void *) = pglob->gl_closedir;
  struct dirent *(*saved_readdir)(void *) = pglob->gl_readdir;
  void *(*saved_opendir)(const char *) = pglob->gl_opendir;
  int (*saved_lstat)(const char *, struct stat *) = pglob->gl_lstat;
  int (*saved_stat)(const char *, struct stat *) = pglob->gl_stat;
  pglob->gl_closedir = ct_glob_closedir;
  pglob->gl_readdir = ct_glob_readdir;
  pglob->gl_opendir = ct_glob_opendir;
  pglob->gl_lstat = ct_glob_lstat;
  pglob->gl_stat = ct_glob_stat;
  /* Brace and tilde expansion rewrite the pattern before any directory is
   * opened, so its components no longer line up with what glob opens: such
   * a call reports full enumerations. A backslash may escape a '/', which
   * would shift every component after it, so it is treated the same way. */
  const char *outer_pattern = ct_glob_active_pattern;
  int expands = ((flags & GLOB_BRACE) != 0 && strchr(pattern, '{') != NULL) ||
                ((flags & (GLOB_TILDE | GLOB_TILDE_CHECK)) != 0 &&
                 pattern[0] == '~') ||
                strchr(pattern, '\\') != NULL;
  ct_glob_active_pattern = expands ? NULL : pattern;
  int rc = real(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob);
  int saved_errno = errno;
  ct_glob_active_pattern = outer_pattern;
  pglob->gl_closedir = saved_closedir;
  pglob->gl_readdir = saved_readdir;
  pglob->gl_opendir = saved_opendir;
  pglob->gl_lstat = saved_lstat;
  pglob->gl_stat = saved_stat;
  pglob->gl_flags &= ~GLOB_ALTDIRFUNC;
  errno = saved_errno;
  return rc;
}

int glob(const char *pattern, int flags, int (*errfunc)(const char *, int),
         glob_t *pglob) __attribute__((visibility("default")));
int glob(const char *pattern, int flags, int (*errfunc)(const char *, int),
         glob_t *pglob) {
  CT_OBSERVED_REAL(real_glob_ptr, ct_glob_real_fn, "glob", GLOB_ABORTED);
  return ct_glob_observed(real_glob_ptr, pattern, flags, errfunc, pglob);
}

int ct_glob64_impl(const char *, int, int (*)(const char *, int), glob_t *)
    __asm__("glob64") __attribute__((visibility("default")));
int ct_glob64_impl(const char *pattern, int flags,
                   int (*errfunc)(const char *, int), glob_t *pglob) {
  CT_OBSERVED_REAL(real_glob64_ptr, ct_glob_real_fn, "glob64", GLOB_ABORTED);
  return ct_glob_observed(real_glob64_ptr, pattern, flags, errfunc, pglob);
}
#endif

/* fdopendir: the DIR* reads a directory the shim knows by its fd, so the
 * readdir interposition can attribute later entries to that path. */
DIR *fdopendir(int fd) __attribute__((visibility("default")));
DIR *fdopendir(int fd) {
  CT_OBSERVED_REAL(real_fdopendir_ptr, ct_fdopendir_real_fn, "fdopendir", NULL);
  DIR *rc = real_fdopendir_ptr(fd);
  if (rc != NULL) CT_OBSERVE(ct_fdopendir_observer, fd, (void *)rc);
  return rc;
}

int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *buf) __attribute__((visibility("default")));
int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *buf) {
  CT_OBSERVED_REAL(real_statx_ptr, ct_statx_real_fn, "statx", -1);
  int rc = real_statx_ptr(dirfd, path, flags, mask, (void *)buf);
  CT_OBSERVE(ct_probe_observer, dirfd, path, rc);
  return rc;
}

int fstatat(int dirfd, const char *path, struct stat *buf, int flags)
    __attribute__((visibility("default")));
int fstatat(int dirfd, const char *path, struct stat *buf, int flags) {
  CT_OBSERVED_REAL(real_fstatat_ptr, ct_fstatat_real_fn, "fstatat", -1);
  int rc = real_fstatat_ptr(dirfd, path, (void *)buf, flags);
  CT_OBSERVE(ct_probe_observer, dirfd, path, rc);
  return rc;
}

#if defined(__LP64__) && defined(__GLIBC__)
int ct_fstatat64_impl(int, const char *, void *, int)
    __asm__("fstatat64") __attribute__((visibility("default")));
int ct_fstatat64_impl(int dirfd, const char *path, void *buf, int flags) {
  CT_OBSERVED_REAL(real_fstatat64_ptr, ct_fstatat_real_fn, "fstatat64", -1);
  int rc = real_fstatat64_ptr(dirfd, path, buf, flags);
  CT_OBSERVE(ct_probe_observer, dirfd, path, rc);
  return rc;
}
#endif

/* PATH MUTATIONS. unlink, mkdir, rmdir, symlink, remove and truncate change
 * the namespace or a file's size without an open, so no other interposition
 * sees them; Node's libuv and Chromium import all of them. Each runs the real
 * call unchanged and then reports it to the mutation observer
 * (repro_linux_observe_mutation in linux_preload.nim), which records only a
 * successful call. The op codes match the Mutation* constants there.
 *
 * ftruncate is not interposed: it needs a descriptor open for writing, and
 * that open is already recorded as a write of the same path. */
#define CT_MUTATION_UNLINK 1
#define CT_MUTATION_UNLINKAT 2
#define CT_MUTATION_RMDIR 3
#define CT_MUTATION_MKDIR 4
#define CT_MUTATION_MKDIRAT 5
#define CT_MUTATION_SYMLINK 6
#define CT_MUTATION_SYMLINKAT 7
#define CT_MUTATION_REMOVE 8
#define CT_MUTATION_TRUNCATE 9
#define CT_MUTATION_MKDTEMP 10
#define CT_MUTATION_MKSTEMP 11

typedef void (*ct_mutation_observer_fn)(int op, int dirfd, const char *path,
                                        const char *target, long arg, int rc);
static ct_mutation_observer_fn ct_mutation_observer = NULL;
void ct_linux_preload_register_mutation_observer(
    ct_mutation_observer_fn observer) {
  ct_mutation_observer = observer;
}

int unlink(const char *path) __attribute__((visibility("default")));
int unlink(const char *path) {
  CT_OBSERVED_REAL(real_unlink_ptr, ct_unlink_real_fn, "unlink", -1);
  int rc = real_unlink_ptr(path);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_UNLINK, AT_FDCWD, path, NULL,
             0L, rc);
  return rc;
}

int unlinkat(int dirfd, const char *path, int flags)
    __attribute__((visibility("default")));
int unlinkat(int dirfd, const char *path, int flags) {
  CT_OBSERVED_REAL(real_unlinkat_ptr, ct_unlinkat_real_fn, "unlinkat", -1);
  int rc = real_unlinkat_ptr(dirfd, path, flags);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_UNLINKAT, dirfd, path, NULL,
             (long)flags, rc);
  return rc;
}

int rmdir(const char *path) __attribute__((visibility("default")));
int rmdir(const char *path) {
  CT_OBSERVED_REAL(real_rmdir_ptr, ct_unlink_real_fn, "rmdir", -1);
  int rc = real_rmdir_ptr(path);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_RMDIR, AT_FDCWD, path, NULL,
             0L, rc);
  return rc;
}

/* remove(3) calls unlink, then rmdir for a directory, inside libc where no
 * interposition sees either. */
int remove(const char *path) __attribute__((visibility("default")));
int remove(const char *path) {
  CT_OBSERVED_REAL(real_remove_ptr, ct_unlink_real_fn, "remove", -1);
  int rc = real_remove_ptr(path);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_REMOVE, AT_FDCWD, path, NULL,
             0L, rc);
  return rc;
}

int mkdir(const char *path, mode_t mode) __attribute__((visibility("default")));
int mkdir(const char *path, mode_t mode) {
  CT_OBSERVED_REAL(real_mkdir_ptr, ct_mkdir_real_fn, "mkdir", -1);
  int rc = real_mkdir_ptr(path, mode);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_MKDIR, AT_FDCWD, path, NULL,
             0L, rc);
  return rc;
}

int mkdirat(int dirfd, const char *path, mode_t mode)
    __attribute__((visibility("default")));
int mkdirat(int dirfd, const char *path, mode_t mode) {
  CT_OBSERVED_REAL(real_mkdirat_ptr, ct_mkdirat_real_fn, "mkdirat", -1);
  int rc = real_mkdirat_ptr(dirfd, path, mode);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_MKDIRAT, dirfd, path, NULL,
             0L, rc);
  return rc;
}

/* The mutation is the new LINK; `target` is its contents, recorded for
 * provenance. */
int symlink(const char *target, const char *linkpath)
    __attribute__((visibility("default")));
int symlink(const char *target, const char *linkpath) {
  CT_OBSERVED_REAL(real_symlink_ptr, ct_symlink_real_fn, "symlink", -1);
  int rc = real_symlink_ptr(target, linkpath);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_SYMLINK, AT_FDCWD, linkpath,
             target, 0L, rc);
  return rc;
}

int symlinkat(const char *target, int newdirfd, const char *linkpath)
    __attribute__((visibility("default")));
int symlinkat(const char *target, int newdirfd, const char *linkpath) {
  CT_OBSERVED_REAL(real_symlinkat_ptr, ct_symlinkat_real_fn, "symlinkat", -1);
  int rc = real_symlinkat_ptr(target, newdirfd, linkpath);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_SYMLINKAT, newdirfd, linkpath,
             target, 0L, rc);
  return rc;
}

int truncate(const char *path, off_t length)
    __attribute__((visibility("default")));
int truncate(const char *path, off_t length) {
  CT_OBSERVED_REAL(real_truncate_ptr, ct_truncate_real_fn, "truncate", -1);
  int rc = real_truncate_ptr(path, length);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_TRUNCATE, AT_FDCWD, path, NULL,
             (long)length, rc);
  return rc;
}

/* creat(path, mode) is open(path, O_CREAT|O_WRONLY|O_TRUNC, mode) (POSIX), so
 * it goes through the open hook chain and is recorded, and its descriptor
 * tracked, exactly as that open would be. */
int creat(const char *path, mode_t mode) __attribute__((visibility("default")));
int creat(const char *path, mode_t mode) {
  if (CT_BYPASS() || ct_open_hook == NULL) {
    CT_OBSERVED_REAL(real_creat_ptr, ct_creat_real_fn, "creat", -1);
    return real_creat_ptr(path, mode);
  }
  return CT_CALL_HOOK(ct_open_hook((char *)path, O_CREAT | O_WRONLY | O_TRUNC,
                                   (int)mode));
}

/* TEMPORARY FILES AND DIRECTORIES. mkstemp and its variants create and open
 * a file, and mkdtemp creates a directory, through libc's internal open and
 * mkdir, where none of the hooks above see them: a build's temporary file,
 * written and left behind or renamed into place, had no record at all. Each
 * runs the real call and reports the name it chose (the template, filled
 * in): a file as the O_CREAT|O_EXCL|O_RDWR open it is, with the descriptor
 * entered in the table so later writes are attributed, a directory as a
 * created directory. `arg` carries the descriptor and `dirfd` the extra open
 * flags (mkostemp's), since the observer's `rc` is only success or failure.
 * tmpfile(3) is not interposed: its file never has a name. */
static int ct_report_mkstemp(char *template_name, int fd, int flags) {
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_MKSTEMP, flags, template_name,
             NULL, (long)fd, fd >= 0 ? 0 : -1);
  return fd;
}

int mkstemp(char *template_name) __attribute__((visibility("default")));
int mkstemp(char *template_name) {
  CT_OBSERVED_REAL(real_mkstemp_ptr, ct_mkstemp_real_fn, "mkstemp", -1);
  return ct_report_mkstemp(template_name, real_mkstemp_ptr(template_name), 0);
}

int mkostemp(char *template_name, int flags)
    __attribute__((visibility("default")));
int mkostemp(char *template_name, int flags) {
  CT_OBSERVED_REAL(real_mkostemp_ptr, ct_mkostemp_real_fn, "mkostemp", -1);
  return ct_report_mkstemp(template_name,
                           real_mkostemp_ptr(template_name, flags), flags);
}

int mkstemps(char *template_name, int suffixlen)
    __attribute__((visibility("default")));
int mkstemps(char *template_name, int suffixlen) {
  CT_OBSERVED_REAL(real_mkstemps_ptr, ct_mkstemps_real_fn, "mkstemps", -1);
  return ct_report_mkstemp(template_name,
                           real_mkstemps_ptr(template_name, suffixlen), 0);
}

int mkostemps(char *template_name, int suffixlen, int flags)
    __attribute__((visibility("default")));
int mkostemps(char *template_name, int suffixlen, int flags) {
  CT_OBSERVED_REAL(real_mkostemps_ptr, ct_mkostemps_real_fn, "mkostemps", -1);
  return ct_report_mkstemp(
      template_name, real_mkostemps_ptr(template_name, suffixlen, flags),
      flags);
}

char *mkdtemp(char *template_name) __attribute__((visibility("default")));
char *mkdtemp(char *template_name) {
  CT_OBSERVED_REAL(real_mkdtemp_ptr, ct_mkdtemp_real_fn, "mkdtemp", NULL);
  char *result = real_mkdtemp_ptr(template_name);
  CT_OBSERVE(ct_mutation_observer, CT_MUTATION_MKDTEMP, AT_FDCWD, result,
             NULL, 0L, result != NULL ? 0 : -1);
  return result;
}

/* On LP64 glibc each *64 name is the same function as its plain twin (see
 * LARGE-FILE ALIASES above). */
#if defined(__LP64__) && defined(__GLIBC__)
extern int ct_truncate64_alias(const char *, off_t)
    __asm__("truncate64") __attribute__((alias("truncate"), visibility("default")));
extern int ct_creat64_alias(const char *, mode_t)
    __asm__("creat64") __attribute__((alias("creat"), visibility("default")));
extern int ct_mkstemp64_alias(char *)
    __asm__("mkstemp64") __attribute__((alias("mkstemp"), visibility("default")));
extern int ct_mkostemp64_alias(char *, int)
    __asm__("mkostemp64") __attribute__((alias("mkostemp"), visibility("default")));
extern int ct_mkstemps64_alias(char *, int)
    __asm__("mkstemps64") __attribute__((alias("mkstemps"), visibility("default")));
extern int ct_mkostemps64_alias(char *, int, int)
    __asm__("mkostemps64") __attribute__((alias("mkostemps"), visibility("default")));
#endif

/* In-tree creation of the anonymous local channels Chromium's message pump
 * uses (eventfd, timerfd). A child that later reads such an fd it inherited
 * is pairing with an object its own tree created, which is exactly what the
 * IM-3 `localfd role=create` record is for (see recordLocalFdCreate in
 * linux_preload.nim); without it every such read was an "out-of-tree content
 * channel" downgrade.
 *
 * Known coarseness: Linux backs most anon_inode objects with ONE shared
 * inode, so the localfd key (localFdChannelKey in linux_preload.nim) adds the
 * kernel's type name (anon_inode:[eventfd], anon_inode:[timerfd]) to tell the
 * classes apart — without it an in-tree eventfd would pair with an inherited
 * inotify or fanotify fd, whose reads carry external input. Within one type
 * the key still names the class, not the object: an in-tree eventfd pairs
 * with an out-of-tree eventfd. Those carry counters and expirations, not file
 * content, so this can hide an out-of-tree signalling peer but not a file
 * dependency. Telling objects apart would need /proc/<pid>/fdinfo's
 * per-object ids. */
int eventfd(unsigned int initval, int flags) __attribute__((visibility("default")));
int eventfd(unsigned int initval, int flags) {
  CT_OBSERVED_REAL(real_eventfd_ptr, ct_eventfd_real_fn, "eventfd", -1);
  int rc = real_eventfd_ptr(initval, flags);
  if (rc >= 0) CT_OBSERVE(ct_localfd_create_observer, rc);
  return rc;
}

int timerfd_create(int clockid, int flags) __attribute__((visibility("default")));
int timerfd_create(int clockid, int flags) {
  CT_OBSERVED_REAL(real_timerfd_create_ptr, ct_timerfd_create_real_fn,
                   "timerfd_create", -1);
  int rc = real_timerfd_create_ptr(clockid, flags);
  if (rc >= 0) CT_OBSERVE(ct_localfd_create_observer, rc);
  return rc;
}

/* pkey_mprotect is mprotect plus a protection key; V8 and PartitionAlloc
 * use it for W^X. An executable transition through it gets the same
 * lifecycle check as one through mprotect. */
int pkey_mprotect(void *addr, size_t len, int prot, int pkey)
    __attribute__((visibility("default")));
int pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
  CT_OBSERVED_REAL(real_pkey_mprotect_ptr, ct_pkey_mprotect_real_fn,
                   "pkey_mprotect", -1);
  int rc = real_pkey_mprotect_ptr(addr, len, prot, pkey);
  CT_OBSERVE(ct_mprotect_observer, addr, len, prot, rc);
  return rc;
}

char *getenv(const char *name) __attribute__((visibility("default")));
char *getenv(const char *name) {
  if (CT_BYPASS() || ct_getenv_hook == NULL)
    return ct_linux_preload_real_getenv((char *)name);
  return CT_CALL_HOOK(ct_getenv_hook((char *)name));
}

int uname(struct utsname *buf) __attribute__((visibility("default")));
int uname(struct utsname *buf) {
  if (CT_BYPASS() || ct_uname_hook == NULL)
    return ct_linux_preload_real_uname((void *)buf);
  return CT_CALL_HOOK(ct_uname_hook((void *)buf));
}

long sysconf(int name) __attribute__((visibility("default")));
long sysconf(int name) {
  if (CT_BYPASS() || ct_sysconf_hook == NULL)
    return ct_linux_preload_real_sysconf(name);
  return CT_CALL_HOOK(ct_sysconf_hook(name));
}

int clock_gettime(clockid_t clock_id, struct timespec *tp)
    __attribute__((visibility("default")));
int clock_gettime(clockid_t clock_id, struct timespec *tp) {
  if (CT_BYPASS() || ct_clock_gettime_hook == NULL)
    return ct_linux_preload_real_clock_gettime((int)clock_id, (void *)tp);
  return CT_CALL_HOOK(ct_clock_gettime_hook((int)clock_id, (void *)tp));
}

int gettimeofday(struct timeval *tv, void *tz)
    __attribute__((visibility("default")));
int gettimeofday(struct timeval *tv, void *tz) {
  if (CT_BYPASS() || ct_gettimeofday_hook == NULL)
    return ct_linux_preload_real_gettimeofday((void *)tv, (void *)tz);
  return CT_CALL_HOOK(ct_gettimeofday_hook((void *)tv, (void *)tz));
}

time_t time(time_t *tloc) __attribute__((visibility("default")));
time_t time(time_t *tloc) {
  if (CT_BYPASS() || ct_time_hook == NULL)
    return (time_t)ct_linux_preload_real_time((void *)tloc);
  return (time_t)CT_CALL_HOOK(ct_time_hook((void *)tloc));
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
    __attribute__((visibility("default")));
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
  if (CT_BYPASS() || ct_getrandom_hook == NULL)
    return (ssize_t)ct_linux_preload_real_getrandom(buf, buflen, flags);
  return (ssize_t)CT_CALL_HOOK(ct_getrandom_hook(buf, buflen, flags));
}

int getentropy(void *buf, size_t len) __attribute__((visibility("default")));
int getentropy(void *buf, size_t len) {
  if (CT_BYPASS() || ct_getentropy_hook == NULL)
    return ct_linux_preload_real_getentropy(buf, len);
  return CT_CALL_HOOK(ct_getentropy_hook(buf, len));
}

unsigned int arc4random(void) __attribute__((visibility("default")));
unsigned int arc4random(void) {
  if (CT_BYPASS() || ct_arc4random_hook == NULL)
    return ct_linux_preload_real_arc4random();
  return CT_CALL_HOOK(ct_arc4random_hook());
}

void arc4random_buf(void *buf, size_t n) __attribute__((visibility("default")));
void arc4random_buf(void *buf, size_t n) {
  if (CT_BYPASS() || ct_arc4random_buf_hook == NULL) {
    ct_linux_preload_real_arc4random_buf(buf, n);
    return;
  }
  /* CT_CALL_HOOK is an expression macro (__typeof__ of the call), so a void
     hook is sequenced with the comma operator — the same idiom the exit(3)
     interposer uses. */
  CT_CALL_HOOK((ct_arc4random_buf_hook(buf, n), 0));
}

unsigned int arc4random_uniform(unsigned int upper)
    __attribute__((visibility("default")));
unsigned int arc4random_uniform(unsigned int upper) {
  if (CT_BYPASS() || ct_arc4random_uniform_hook == NULL)
    return ct_linux_preload_real_arc4random_uniform(upper);
  return CT_CALL_HOOK(ct_arc4random_uniform_hook(upper));
}

pid_t fork(void) __attribute__((visibility("default")));
pid_t fork(void) {
  if (CT_BYPASS() || ct_fork_hook == NULL)
    return ct_linux_preload_real_fork();
  return CT_CALL_HOOK(ct_fork_hook());
}

static int ct_linux_preload_dispatch_execve(const char *path,
                                            char *const argv[],
                                            char *const envp[]) {
  if (CT_BYPASS() || ct_execve_hook == NULL) {
    /* No hook runs, so no drain either: a successful exec would take any
     * unclassified trapped event with it. */
    ct_linux_report_inline_events_if_pending();
    return ct_linux_preload_real_execve((char *)path, (char **)argv, (char **)envp);
  }
  return CT_CALL_EXEC_HOOK(ct_execve_hook((char *)path, (char **)argv, (char **)envp));
}

int execve(const char *path, char *const argv[], char *const envp[])
    __attribute__((visibility("default")));
int execve(const char *path, char *const argv[], char *const envp[]) {
  return ct_linux_preload_dispatch_execve(path, argv, envp);
}

int execv(const char *path, char *const argv[])
    __attribute__((visibility("default")));
int execv(const char *path, char *const argv[]) {
  return ct_linux_preload_dispatch_execve(path, argv, environ);
}

int execl(const char *path, const char *arg, ...)
    __attribute__((visibility("default")));
int execl(const char *path, const char *arg, ...) {
  size_t argc = 0;
  if (arg != NULL) {
    argc = 1;
    va_list count_ap;
    va_start(count_ap, arg);
    while (va_arg(count_ap, char *) != NULL) {
      argc++;
    }
    va_end(count_ap);
  }

  char **argv = (char **)alloca((argc + 1) * sizeof(char *));
  if (arg != NULL) {
    argv[0] = (char *)arg;
    va_list fill_ap;
    va_start(fill_ap, arg);
    for (size_t i = 1; i < argc; i++) {
      argv[i] = va_arg(fill_ap, char *);
    }
    va_end(fill_ap);
  }
  argv[argc] = NULL;
  return ct_linux_preload_dispatch_execve(path, argv, environ);
}

int execle(const char *path, const char *arg, ...)
    __attribute__((visibility("default")));
int execle(const char *path, const char *arg, ...) {
  size_t argc = 0;
  va_list count_ap;
  va_start(count_ap, arg);
  if (arg != NULL) {
    argc = 1;
    while (va_arg(count_ap, char *) != NULL) {
      argc++;
    }
  }
  char **envp = va_arg(count_ap, char **);
  va_end(count_ap);

  char **argv = (char **)alloca((argc + 1) * sizeof(char *));
  if (arg != NULL) {
    argv[0] = (char *)arg;
    va_list fill_ap;
    va_start(fill_ap, arg);
    for (size_t i = 1; i < argc; i++) {
      argv[i] = va_arg(fill_ap, char *);
    }
    va_end(fill_ap);
  }
  argv[argc] = NULL;
  return ct_linux_preload_dispatch_execve(path, argv, envp);
}

/* M9.R.65.2 — the path-searching exec family (execvp / execvpe / execlp);
 * fexecve and execveat are below (ct_linux_preload_dispatch_execveat).  glibc's execvp/execvpe/execlp perform PATH lookup then
 * internally call execve via a hidden reference that BYPASSES the
 * LD_PRELOAD PLT.  Callers on this route therefore missed the shim's
 * execve hook entirely — the M9.R.65 kill-before-flush residual on
 * NixOS-WSL's wrapped-sh Rust binary was 100 % this gap.  Fire the
 * shim's execve hook logic (emit mrProcessExec + flush the pending
 * read-tail marker) BEFORE handing off to glibc's real execvp so the
 * fragment slot's committed marker lands durably before the kernel
 * jumps into the exec.  The child inherits LD_PRELOAD via `environ`
 * (which glibc's execvp propagates), so the shim reloads correctly in
 * the new image. */
/* The shim's exec-environment preparation (registered by linux_preload.nim;
 * NULL when this runtime is used without it): `envp` plus LD_PRELOAD and the
 * next exec generation, from the shim's private heap; and its release when
 * the exec fails. */
typedef char **(*ct_exec_env_for_fn)(char *const envp[]);
typedef void (*ct_exec_env_release_fn)(char **prepared, char *const envp[]);
static ct_exec_env_for_fn ct_exec_env_for = NULL;
static ct_exec_env_release_fn ct_exec_env_release = NULL;
void ct_linux_preload_register_exec_env(ct_exec_env_for_fn prepare,
                                        ct_exec_env_release_fn release) {
  ct_exec_env_for = prepare;
  ct_exec_env_release = release;
}

/* glibc's PATH-searching execvpe with the prepared environment. Bracketed so
 * the internal execve() calls glibc makes per PATH candidate see CT_BYPASS()
 * (M9.R.66.2) and so the preparation's own libc calls (getenv) are not
 * recorded. The prepared array is the shim's and is freed by the shim if the
 * exec fails; the host's `environ` is never replaced. */
static int ct_linux_preload_exec_with_prepared_env(const char *file,
                                                   char *const argv[],
                                                   char *const envp[]) {
  char **prepared = NULL;
  if (ct_exec_env_for != NULL) {
    stackable_linux_preload_enter_hook();
    prepared = ct_exec_env_for(envp);
    stackable_linux_preload_exit_hook();
  }
  char **use = prepared != NULL ? prepared : (char **)envp;
  int rc = CT_CALL_EXEC_HOOK(ct_linux_preload_real_execvpe((char *)file,
                                                          (char **)argv, use));
  int saved_errno = errno;
  if (prepared != NULL && ct_exec_env_release != NULL)
    ct_exec_env_release(prepared, envp);
  errno = saved_errno;
  return rc;
}

/* Run the execve hook for a PATH-searching exec (it records the exec and
 * flushes). Its own real execve runs only for a name containing a slash,
 * which execvp also executes directly; see ct_exec_announce_only. */
static void ct_announce_exec(char *file, char **argv, char **envp) {
  int bare = file != NULL && strchr(file, '/') == NULL;
  if (bare) ct_exec_announce_only = 1;
  CT_CALL_EXEC_HOOK(ct_execve_hook(file, argv, envp));
  ct_exec_announce_only = 0;
}

static int ct_linux_preload_dispatch_execvp(const char *file,
                                            char *const argv[]) {
  if (CT_BYPASS() || ct_execve_hook == NULL) {
    ct_linux_report_inline_events_if_pending();
    return ct_linux_preload_real_execvp((char *)file, (char **)argv);
  }
  /* Invoke the execve hook to emit mrProcessExec + flush the fragment
   * slot's committed marker.  For a name without a slash (the common
   * `execvp("sh", argv)`) its chained real-execve call fails with ENOENT
   * without reaching the kernel (ct_announce_exec), and we then fall
   * through to glibc's execvpe, whose PATH search jumps into the image.
   * The bracket bookkeeping (enter_hook / exit_hook) is done by
   * CT_CALL_HOOK.
   *
   * M9.R.66.2: glibc's real_execvp does PATH lookup by calling
   * execve() internally, once per candidate directory, until a
   * matching image is found.  Each of those internal execve() calls
   * lands on OUR execve interposer above, which — outside a bracket
   * — would re-fire the execve hook and emit ANOTHER mrProcessExec
   * per candidate.  On a NixOS-WSL host with per-tool $PATH entries
   * that yields 4× exec records for the same pid (see
   * m9r66_phaseB_subtree.txt) which trips the T0 `execCount(pid) >=
   * startCount(pid)` unmonitored-subtree loss.  Bracket the
   * real_execvp call so those internal execve interposers see
   * CT_BYPASS() and delegate straight to real_execve without
   * re-emitting the hook. */
  ct_announce_exec((char *)file, (char **)argv, environ);
  /* Hand glibc's PATH search the prepared environment (LD_PRELOAD plus the
   * next REPRO_MONITOR_EXEC_GEN) explicitly through execvpe, rather than
   * rewriting the process's `environ` for execvp to pick up. */
  return ct_linux_preload_exec_with_prepared_env(file, argv, environ);
}

static int ct_linux_preload_dispatch_execvpe(const char *file,
                                             char *const argv[],
                                             char *const envp[]) {
  if (CT_BYPASS() || ct_execve_hook == NULL) {
    ct_linux_report_inline_events_if_pending();
    return ct_linux_preload_real_execvpe((char *)file, (char **)argv,
                                          (char **)envp);
  }
  ct_announce_exec((char *)file, (char **)argv, (char **)envp);
  /* M9.R.66.2: same PATH-lookup double-count guard as dispatch_execvp. */
  return ct_linux_preload_exec_with_prepared_env(file, argv, envp);
}

/* The image an execveat or fexecve runs, for its exec record: the path
 * itself when it is absolute or relative to the working directory, else the
 * descriptor's path (/proc/self/fd, read with a raw syscall so the shim does
 * not record its own lookup) joined with it. Falls back to the path as
 * given. */
static void ct_exec_image_label(char *out, size_t cap, int dirfd,
                                const char *path) {
  out[0] = '\0';
  if (path == NULL) path = "";
  size_t at = 0;
  if (path[0] != '/' && dirfd != AT_FDCWD) {
    char link[48];
    long l = ct_inline_loss_append_text(link, 0, sizeof(link) - 1,
                                        "/proc/self/fd/");
    l = ct_inline_loss_append_decimal(link, l, sizeof(link) - 1,
                                      (unsigned long)(unsigned int)dirfd);
    link[l] = '\0';
    long n = ct_raw_syscall6(SYS_readlinkat, AT_FDCWD, (long)link, (long)out,
                             (long)cap - 1, 0, 0);
    if (n > 0 && out[0] == '/') {
      at = (size_t)n;
      if (path[0] != '\0' && at + 1 < cap) out[at++] = '/';
    }
  }
  size_t len = strlen(path);
  if (at + len >= cap) len = cap - 1 - at;
  memcpy(out + at, path, len);
  out[at + len] = '\0';
}

/* execveat and fexecve: through the execve hook, like every other exec, so
 * the exec is recorded, the child gets LD_PRELOAD and the next exec
 * generation, and buffered and trapped events are drained and flushed before
 * the image is replaced. The hook's real execve performs the actual call
 * (ct_exec_redirect_state). glibc's own wrappers would make the system call
 * directly and run none of that. */
static int ct_linux_preload_dispatch_execveat(int dirfd, const char *path,
                                              char *const argv[],
                                              char *const envp[], int flags,
                                              int is_fexecve) {
  if (CT_BYPASS() || ct_execve_hook == NULL) {
    ct_linux_report_inline_events_if_pending();
    if (is_fexecve)
      return ct_linux_preload_real_fexecve(dirfd, (char **)argv,
                                            (char **)envp);
    return ct_linux_preload_real_execveat(dirfd, path, (char **)argv,
                                          (char **)envp, flags);
  }
  char image[PATH_MAX];
  ct_exec_image_label(image, sizeof(image), dirfd, path);
  struct ct_exec_redirect redirect;
  redirect.active = 1;
  redirect.pid = getpid();
  redirect.announced = image;
  redirect.fd = dirfd;
  redirect.path = path;
  redirect.flags = flags;
  redirect.fexecve = is_fexecve;
  ct_exec_redirect_state = redirect;
  /* The bracket also keeps glibc's fallback for an old kernel, an execve of
   * /proc/self/fd/<fd>, from running the hook a second time (M9.R.66.2). */
  int rc = CT_CALL_EXEC_HOOK(ct_execve_hook(image, (char **)argv,
                                            (char **)envp));
  ct_exec_redirect_state.active = 0;
  return rc;
}

static int ct_linux_preload_dispatch_fexecve(int fd,
                                             char *const argv[],
                                             char *const envp[]) {
  return ct_linux_preload_dispatch_execveat(fd, "", argv, envp, AT_EMPTY_PATH,
                                            1);
}

int execvp(const char *file, char *const argv[])
    __attribute__((visibility("default")));
int execvp(const char *file, char *const argv[]) {
  return ct_linux_preload_dispatch_execvp(file, argv);
}

int execvpe(const char *file, char *const argv[], char *const envp[])
    __attribute__((visibility("default")));
int execvpe(const char *file, char *const argv[], char *const envp[]) {
  return ct_linux_preload_dispatch_execvpe(file, argv, envp);
}

int execlp(const char *file, const char *arg, ...)
    __attribute__((visibility("default")));
int execlp(const char *file, const char *arg, ...) {
  size_t argc = 0;
  if (arg != NULL) {
    argc = 1;
    va_list count_ap;
    va_start(count_ap, arg);
    while (va_arg(count_ap, char *) != NULL) {
      argc++;
    }
    va_end(count_ap);
  }

  char **argv = (char **)alloca((argc + 1) * sizeof(char *));
  if (arg != NULL) {
    argv[0] = (char *)arg;
    va_list fill_ap;
    va_start(fill_ap, arg);
    for (size_t i = 1; i < argc; i++) {
      argv[i] = va_arg(fill_ap, char *);
    }
    va_end(fill_ap);
  }
  argv[argc] = NULL;
  return ct_linux_preload_dispatch_execvp(file, argv);
}

int fexecve(int fd, char *const argv[], char *const envp[])
    __attribute__((visibility("default")));
int fexecve(int fd, char *const argv[], char *const envp[]) {
  return ct_linux_preload_dispatch_fexecve(fd, argv, envp);
}

int execveat(int dirfd, const char *path, char *const argv[],
             char *const envp[], int flags)
    __attribute__((visibility("default")));
int execveat(int dirfd, const char *path, char *const argv[],
             char *const envp[], int flags) {
  return ct_linux_preload_dispatch_execveat(dirfd, path, argv, envp, flags, 0);
}

int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
    __attribute__((visibility("default")));
int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
  if (CT_BYPASS() || ct_posix_spawn_hook == NULL)
    return ct_linux_preload_real_posix_spawn(pid, (char *)path, (void *)file_actions,
                                             (void *)attrp, (char **)argv, (char **)envp);
  return CT_CALL_HOOK(ct_posix_spawn_hook(pid, (char *)path, (void *)file_actions,
                                          (void *)attrp, (char **)argv, (char **)envp));
}

int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
    __attribute__((visibility("default")));
int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
  if (CT_BYPASS() || ct_posix_spawnp_hook == NULL)
    return ct_linux_preload_real_posix_spawnp(pid, (char *)file, (void *)file_actions,
                                              (void *)attrp, (char **)argv, (char **)envp);
  return CT_CALL_HOOK(ct_posix_spawnp_hook(pid, (char *)file, (void *)file_actions,
                                           (void *)attrp, (char **)argv, (char **)envp));
}

void _exit(int status) __attribute__((visibility("default"), noreturn));
void _exit(int status) {
  if (!CT_BYPASS() && ct_exit_hook != NULL) {
    CT_CALL_HOOK((ct_exit_hook(status), 0));
  }
  ct_linux_preload_real_exit(status);
}

void _Exit(int status) __attribute__((visibility("default"), noreturn));
void _Exit(int status) {
  _exit(status);
}

/* glibc's <fcntl.h> and <unistd.h> expand to the __*_2 / __*_chk
 * fortify entry points whenever the compiler can prove the safety
 * invariants at compile time (e.g. _FORTIFY_SOURCE >= 1, a constant
 * `flags` argument without O_CREAT). Nix's cc-wrapper enables
 * _FORTIFY_SOURCE=2 by default, so a fixture like
 *   int fd = open(argv[1], O_RDONLY);
 *   read(fd, buf, sizeof(buf));
 * resolves to __open_2 / __read_chk rather than open / read, and an
 * LD_PRELOAD shim that only exports open / read silently sees zero
 * calls. Share internal dispatch with the public entries: calling open()
 * here is itself fortified by glibc's inline headers back into __open_2(),
 * which GCC folds into an unconditional self-jump. The fixed-signature
 * helpers also avoid reading a nonexistent mode vararg. */
static void ct_check_fortified_open_flags(int flags) {
  /* Like glibc's _2 entries, reject O_CREAT / O_TMPFILE without a mode.
   * Never manufacture a mode for a call whose contract requires one. */
  if (ct_open_flags_need_mode(flags)) abort();
}
int __open_2(const char *path, int flags) __attribute__((visibility("default")));
int __open_2(const char *path, int flags) {
  ct_check_fortified_open_flags(flags);
  return ct_dispatch_open(path, flags, 0);
}

int __open64_2(const char *path, int flags) __attribute__((visibility("default")));
int __open64_2(const char *path, int flags) {
  ct_check_fortified_open_flags(flags);
  return ct_dispatch_open64(path, flags, 0);
}

int __openat_2(int dirfd, const char *path, int flags) __attribute__((visibility("default")));
int __openat_2(int dirfd, const char *path, int flags) {
  ct_check_fortified_open_flags(flags);
  return ct_dispatch_openat(dirfd, path, flags, 0);
}

int __openat64_2(int dirfd, const char *path, int flags) __attribute__((visibility("default")));
int __openat64_2(int dirfd, const char *path, int flags) {
  ct_check_fortified_open_flags(flags);
  return ct_dispatch_openat64(dirfd, path, flags, 0);
}

ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen)
    __attribute__((visibility("default")));
ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen) {
  /* The buflen >= nbytes contract is the caller's; the fortify check
   * collapses at compile time when the bound is provable. Delegating
   * to read() preserves the hook chain and matches what every other
   * LD_PRELOAD shim ships. */
  (void)buflen;
  return read(fd, buf, nbytes);
}
""".}

proc setPreloadShimEnvVar*(name: cstring) {.importc: "ct_linux_preload_set_shim_env_name",
    raises: [].}
proc childCaptureRouteStatus*(envp: cstringArray): cint
  {.importc: "ct_linux_preload_child_capture_route_status", raises: [].}

proc freeOwnedEnv*(envp: cstringArray; original: cstringArray)
  {.importc: "ct_linux_preload_free_owned_env", raises: [].}

proc envWithPreload*(envp: cstringArray): cstringArray
  {.importc: "ct_linux_preload_env_with_preload", raises: [].}
proc envWithExecGen*(envp: cstringArray; nextGen: clong): cstringArray
  {.importc: "ct_linux_preload_exec_env_prepare", raises: [].}
  ## The exec hooks' environment: freed with `freeOwnedEnv` when the exec
  ## fails, and released by the resuming parent when a vfork child's exec
  ## succeeds.

proc realOpen*(path: cstring; flags, mode: cint): cint
  {.importc: "ct_linux_preload_real_open", raises: [].}
proc realOpen64*(path: cstring; flags, mode: cint): cint
  {.importc: "ct_linux_preload_real_open64", raises: [].}
proc realOpenat*(dirfd: cint; path: cstring; flags, mode: cint): cint
  {.importc: "ct_linux_preload_real_openat", raises: [].}
proc realOpenat64*(dirfd: cint; path: cstring; flags, mode: cint): cint
  {.importc: "ct_linux_preload_real_openat64", raises: [].}
proc realClose*(fd: cint): cint {.importc: "ct_linux_preload_real_close",
    raises: [].}
proc realRead*(fd: cint; buf: pointer; count: csize_t): clong
  {.importc: "ct_linux_preload_real_read", raises: [].}
proc realPread*(fd: cint; buf: pointer; count: csize_t; offset: clong): clong
  {.importc: "ct_linux_preload_real_pread", raises: [].}
proc realReadv*(fd: cint; iov: pointer; iovcnt: cint): clong
  {.importc: "ct_linux_preload_real_readv", raises: [].}
proc realPreadv*(fd: cint; iov: pointer; iovcnt: cint; offset: clong): clong
  {.importc: "ct_linux_preload_real_preadv", raises: [].}
proc realWrite*(fd: cint; buf: pointer; count: csize_t): clong
  {.importc: "ct_linux_preload_real_write", raises: [].}
proc realStat*(path: cstring; buf: pointer): cint
  {.importc: "ct_linux_preload_real_stat", raises: [].}
proc realLstat*(path: cstring; buf: pointer): cint
  {.importc: "ct_linux_preload_real_lstat", raises: [].}
proc realOpendir*(path: cstring): pointer
  {.importc: "ct_linux_preload_real_opendir", raises: [].}
proc realReaddir*(dirp: pointer): pointer
  {.importc: "ct_linux_preload_real_readdir", raises: [].}
proc realClosedir*(dirp: pointer): cint
  {.importc: "ct_linux_preload_real_closedir", raises: [].}
proc realFopen*(path, mode: cstring): pointer
  {.importc: "ct_linux_preload_real_fopen", raises: [].}
proc realFopen64*(path, mode: cstring): pointer
  {.importc: "ct_linux_preload_real_fopen64", raises: [].}
proc realFread*(buf: pointer; size, nmemb: csize_t; stream: pointer): csize_t
  {.importc: "ct_linux_preload_real_fread", raises: [].}
proc realFclose*(stream: pointer): cint
  {.importc: "ct_linux_preload_real_fclose", raises: [].}
proc realConnect*(fd: cint; address: pointer; addrLen: uint32): cint
  {.importc: "ct_linux_preload_real_connect", raises: [].}
proc realPipe*(fds: pointer): cint
  {.importc: "ct_linux_preload_real_pipe", raises: [].}
proc realPipe2*(fds: pointer; flags: cint): cint
  {.importc: "ct_linux_preload_real_pipe2", raises: [].}
proc realSocketpair*(domain, typ, protocol: cint; sv: pointer): cint
  {.importc: "ct_linux_preload_real_socketpair", raises: [].}
proc realSendfile*(outFd, inFd: cint; offset: pointer; count: csize_t): clong
  {.importc: "ct_linux_preload_real_sendfile", raises: [].}
proc realCopyFileRange*(inFd: cint; offIn: pointer; outFd: cint;
                        offOut: pointer; length: csize_t;
                        flags: cuint): clong
  {.importc: "ct_linux_preload_real_copy_file_range", raises: [].}
proc realSplice*(fdIn: cint; offIn: pointer; fdOut: cint; offOut: pointer;
                 length: csize_t; flags: cuint): clong
  {.importc: "ct_linux_preload_real_splice", raises: [].}
proc realLink*(oldPath, newPath: cstring): cint
  {.importc: "ct_linux_preload_real_link", raises: [].}
proc realLinkat*(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                 newPath: cstring; flags: cint): cint
  {.importc: "ct_linux_preload_real_linkat", raises: [].}
proc realRename*(oldPath, newPath: cstring): cint
  {.importc: "ct_linux_preload_real_rename", raises: [].}
proc realRenameat*(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                   newPath: cstring): cint
  {.importc: "ct_linux_preload_real_renameat", raises: [].}
proc realRenameat2*(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                    newPath: cstring; flags: cuint): cint
  {.importc: "ct_linux_preload_real_renameat2", raises: [].}
proc linuxLibraryScan*(sink: pointer; reason: cstring;
                       performed, removed: ptr uint64;
                       newlyActive, newlySeen, countersValid,
                       overflow: ptr cint): cint
  {.importc: "ct_linux_library_scan", raises: [].}
  ## Enumerate the loader's link map (see the design note above
  ## `ct_linux_library_scan`), invoking `sink` once for each entry NOT SEEN
  ## BEFORE — a `proc(name: cstring; address: culong; reason: cstring) {.cdecl.}`
  ## cast to `pointer`, called after `dl_iterate_phdr` has returned so the
  ## loader lock is no longer held and the sink may allocate and record.
  ##
  ## `performed` and `removed` report the deltas of the loader's cumulative
  ## `dlpi_adds` and `dlpi_subs`; `newlyActive` reports entries absent from the
  ## immediately preceding link-map snapshot, while `newlySeen` reports entries
  ## first observed during the process. A short newly-active count is a gap only
  ## if an unload also occurred: scans immediately before and after interposed
  ## loads make ordinary unload/reload cycles visible as separate transitions.
  ##
  ## The seen-set and previous loader counters live on the C side ON PURPOSE:
  ## scans run on whichever thread called `dlopen`, and long-lived Nim heap
  ## state shared between threads is the FUP-C allocator-corruption class.

proc realDlopen*(path: cstring; flags: cint): pointer
  {.importc: "ct_linux_preload_real_dlopen", raises: [].}
proc realDlmopen*(namespaceId: clong; path: cstring; flags: cint): pointer
  {.importc: "ct_linux_preload_real_dlmopen", raises: [].}
proc realDlsym*(handle: pointer; name: cstring): pointer
  {.importc: "ct_linux_preload_real_dlsym", raises: [].}
proc realMmap*(address: pointer; length: csize_t; prot, flags, fd: cint;
               offset: clong): pointer
  {.importc: "ct_linux_preload_real_mmap", raises: [].}
proc realMprotect*(address: pointer; length: csize_t; prot: cint): cint
  {.importc: "ct_linux_preload_real_mprotect", raises: [].}
proc realMunmap*(address: pointer; length: csize_t): cint
  {.importc: "ct_linux_preload_real_munmap", raises: [].}
proc realMremap*(oldAddress: pointer; oldSize, newSize: csize_t; flags: cint;
                 newAddress: pointer): pointer
  {.importc: "ct_linux_preload_real_mremap", raises: [].}
proc realGetenv*(name: cstring): cstring
  {.importc: "ct_linux_preload_real_getenv", raises: [].}
proc realUname*(buf: pointer): cint
  {.importc: "ct_linux_preload_real_uname", raises: [].}
proc realSysconf*(name: cint): clong
  {.importc: "ct_linux_preload_real_sysconf", raises: [].}
proc realClockGettime*(clockId: cint; timespecPtr: pointer): cint
  {.importc: "ct_linux_preload_real_clock_gettime", raises: [].}
proc realGettimeofday*(timevalPtr, timezonePtr: pointer): cint
  {.importc: "ct_linux_preload_real_gettimeofday", raises: [].}
proc realTime*(timePtr: pointer): clong
  {.importc: "ct_linux_preload_real_time", raises: [].}
proc realGetrandom*(buf: pointer; buflen: csize_t; flags: cuint): clong
  {.importc: "ct_linux_preload_real_getrandom", raises: [].}
proc realGetentropy*(buf: pointer; length: csize_t): cint
  {.importc: "ct_linux_preload_real_getentropy", raises: [].}
proc realArc4random*(): cuint
  {.importc: "ct_linux_preload_real_arc4random", raises: [].}
proc realArc4randomBuf*(buf: pointer; length: csize_t)
  {.importc: "ct_linux_preload_real_arc4random_buf", raises: [].}
proc realArc4randomUniform*(upper: cuint): cuint
  {.importc: "ct_linux_preload_real_arc4random_uniform", raises: [].}
proc realFork*(): PidT {.importc: "ct_linux_preload_real_fork", raises: [].}
proc realExecve*(path: cstring; argv, envp: cstringArray): cint
  {.importc: "ct_linux_preload_real_execve", raises: [].}
proc realPosixSpawn*(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                     argv, envp: cstringArray): cint
  {.importc: "ct_linux_preload_real_posix_spawn", raises: [].}
proc realPosixSpawnp*(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                      argv, envp: cstringArray): cint
  {.importc: "ct_linux_preload_real_posix_spawnp", raises: [].}
proc realExit*(status: cint) {.importc: "ct_linux_preload_real_exit",
  raises: [], noreturn.}

type
  OpenDispatch = proc(path: cstring; flags, mode: cint): cint
    {.cdecl, raises: [].}
  OpenatDispatch = proc(dirfd: cint; path: cstring; flags, mode: cint): cint
    {.cdecl, raises: [].}
  CloseDispatch = proc(fd: cint): cint {.cdecl, raises: [].}
  ReadDispatch = proc(fd: cint; buf: pointer; count: csize_t): clong
    {.cdecl, raises: [].}
  PreadDispatch = proc(fd: cint; buf: pointer; count: csize_t;
                       offset: clong): clong {.cdecl, raises: [].}
  ReadvDispatch = proc(fd: cint; iov: pointer; iovcnt: cint): clong
    {.cdecl, raises: [].}
  PreadvDispatch = proc(fd: cint; iov: pointer; iovcnt: cint;
                        offset: clong): clong {.cdecl, raises: [].}
  WriteDispatch = proc(fd: cint; buf: pointer; count: csize_t): clong
    {.cdecl, raises: [].}
  StatDispatch = proc(path: cstring; buf: pointer): cint {.cdecl, raises: [].}
  OpendirDispatch = proc(path: cstring): pointer {.cdecl, raises: [].}
  ReaddirDispatch = proc(dirp: pointer): pointer {.cdecl, raises: [].}
  ClosedirDispatch = proc(dirp: pointer): cint {.cdecl, raises: [].}
  FopenDispatch = proc(path, mode: cstring): pointer {.cdecl, raises: [].}
  FreadDispatch = proc(buf: pointer; size, nmemb: csize_t; stream: pointer):
    csize_t {.cdecl, raises: [].}
  FcloseDispatch = proc(stream: pointer): cint {.cdecl, raises: [].}
  ConnectDispatch = proc(fd: cint; address: pointer; addrLen: uint32): cint
    {.cdecl, raises: [].}
  PipeDispatch = proc(fds: pointer): cint {.cdecl, raises: [].}
  Pipe2Dispatch = proc(fds: pointer; flags: cint): cint {.cdecl, raises: [].}
  SocketpairDispatch = proc(domain, typ, protocol: cint; sv: pointer): cint
    {.cdecl, raises: [].}
  SendfileDispatch = proc(outFd, inFd: cint; offset: pointer;
                          count: csize_t): clong {.cdecl, raises: [].}
  CopyFileRangeDispatch = proc(inFd: cint; offIn: pointer; outFd: cint;
                               offOut: pointer; length: csize_t;
                               flags: cuint): clong {.cdecl, raises: [].}
  SpliceDispatch = proc(fdIn: cint; offIn: pointer; fdOut: cint;
                        offOut: pointer; length: csize_t;
                        flags: cuint): clong {.cdecl, raises: [].}
  LinkDispatch = proc(oldPath, newPath: cstring): cint {.cdecl, raises: [].}
  LinkatDispatch = proc(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                        newPath: cstring; flags: cint): cint
    {.cdecl, raises: [].}
  RenameDispatch = proc(oldPath, newPath: cstring): cint {.cdecl, raises: [].}
  RenameatDispatch = proc(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                          newPath: cstring): cint {.cdecl, raises: [].}
  Renameat2Dispatch = proc(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                           newPath: cstring; flags: cuint): cint
    {.cdecl, raises: [].}
  DlopenDispatch = proc(path: cstring; flags: cint): pointer
    {.cdecl, raises: [].}
  DlmopenDispatch = proc(namespaceId: clong; path: cstring; flags: cint): pointer
    {.cdecl, raises: [].}
  DlsymDispatch = proc(handle: pointer; name: cstring): pointer
    {.cdecl, raises: [].}
  MmapDispatch = proc(address: pointer; length: csize_t; prot, flags, fd: cint;
                      offset: clong): pointer {.cdecl, raises: [].}
  MprotectDispatch = proc(address: pointer; length: csize_t; prot: cint): cint
    {.cdecl, raises: [].}
  MunmapDispatch = proc(address: pointer; length: csize_t): cint
    {.cdecl, raises: [].}
  MremapDispatch = proc(oldAddress: pointer; oldSize, newSize: csize_t;
                        flags: cint; newAddress: pointer): pointer
    {.cdecl, raises: [].}
  GetenvDispatch = proc(name: cstring): cstring {.cdecl, raises: [].}
  UnameDispatch = proc(buf: pointer): cint {.cdecl, raises: [].}
  SysconfDispatch = proc(name: cint): clong {.cdecl, raises: [].}
  ClockGettimeDispatch = proc(clockId: cint; timespecPtr: pointer): cint
    {.cdecl, raises: [].}
  GettimeofdayDispatch = proc(timevalPtr, timezonePtr: pointer): cint
    {.cdecl, raises: [].}
  TimeDispatch = proc(timePtr: pointer): clong {.cdecl, raises: [].}
  GetrandomDispatch = proc(buf: pointer; buflen: csize_t; flags: cuint): clong
    {.cdecl, raises: [].}
  GetentropyDispatch = proc(buf: pointer; length: csize_t): cint
    {.cdecl, raises: [].}
  Arc4randomDispatch = proc(): cuint {.cdecl, raises: [].}
  Arc4randomBufDispatch = proc(buf: pointer; length: csize_t)
    {.cdecl, raises: [].}
  Arc4randomUniformDispatch = proc(upper: cuint): cuint {.cdecl, raises: [].}
  ForkDispatch = proc(): PidT {.cdecl, raises: [].}
  ExecveDispatch = proc(path: cstring; argv, envp: cstringArray): cint
    {.cdecl, raises: [].}
  PosixSpawnDispatch = proc(pid: ptr PidT; path: cstring; fileActions,
                           attrp: pointer; argv, envp: cstringArray): cint
    {.cdecl, raises: [].}
  ExitDispatch = proc(status: cint) {.cdecl, raises: [].}
  RawSyscallDispatch = proc(number, a1, a2, a3, a4, a5, a6, result: clong;
                            inlineTrap: cint) {.cdecl, raises: [].}

proc rawSyscallReplacement(number, a1, a2, a3, a4, a5, a6: clong): clong
  {.importc: "ct_linux_preload_syscall_replacement", cdecl, raises: [].}
proc cRawSyscallOwnerReason(): cstring
  {.importc: "ct_linux_preload_raw_owner_join_reason", raises: [].}
proc cRawSyscallOwnerImage(): cstring
  {.importc: "ct_linux_preload_raw_owner_join_image", raises: [].}
proc rawSyscallOwnerJoinReason*(): string {.raises: [].} =
  $cRawSyscallOwnerReason()
proc rawSyscallOwnerJoinImage*(): string {.raises: [].} =
  $cRawSyscallOwnerImage()
proc cRawSyscallOwnerPrepare(): cint
  {.importc: "ct_linux_preload_raw_owner_prepare", raises: [].}
proc cRawSyscallOwnerCommit(target: pointer)
  {.importc: "ct_linux_preload_raw_owner_commit", raises: [].}
proc cRawSyscallOwnerJoin(target: pointer): cint
  {.importc: "ct_linux_preload_raw_owner_join", raises: [].}
proc cInlineSyscallReset()
  {.importc: "ct_linux_inline_syscall_reset", raises: [].}
proc cInlineSyscallRecordSite(address: culong): cint
  {.importc: "ct_linux_inline_syscall_record_site", raises: [].}
proc cInlineSyscallHandlerAddress(): pointer
  {.importc: "ct_linux_inline_syscall_handler_address", raises: [].}
proc cInlineSyscallSiteCount(): clong
  {.importc: "ct_linux_inline_syscall_site_count", raises: [].}
proc cInlineSyscallTrapCount(): clong
  {.importc: "ct_linux_inline_syscall_trap_count", raises: [].}
proc cInlineSyscallFailureCount(): clong
  {.importc: "ct_linux_inline_syscall_failure_count", raises: [].}
proc cInlineSyscallLastNr(): clong
  {.importc: "ct_linux_inline_syscall_last_nr", raises: [].}
proc cInlineSyscallLastAddress(): culong
  {.importc: "ct_linux_inline_syscall_last_address", raises: [].}
proc cInlineSyscallOverflowed(): cint
  {.importc: "ct_linux_inline_syscall_overflowed", raises: [].}
proc cRawSyscallEventCount(): clong
  {.importc: "ct_linux_raw_syscall_event_count", raises: [].}
proc cRawSyscallEventOverflowed(): cint
  {.importc: "ct_linux_raw_syscall_event_overflowed", raises: [].}
proc cRawSyscallEventAt(index: clong; number, a1, a2, a3, a4, a5, a6,
                        result: ptr clong; source: ptr cint;
                        address: ptr culong): cint
  {.importc: "ct_linux_raw_syscall_event_at", raises: [].}
proc cRawCurrentPid(): cint
  {.importc: "ct_linux_raw_current_pid", raises: [].}
proc cRawSyscallEventClaim(index: clong; pid: cint): cint
  {.importc: "ct_linux_raw_syscall_event_claim", raises: [].}
proc cRawSyscallEventCaptureState(index: clong): cint
  {.importc: "ct_linux_raw_syscall_event_capture_state", raises: [].}
proc cRawSyscallEventCapture(index: clong; slot: cint; text: ptr cstring;
                             len: ptr clong): cint
  {.importc: "ct_linux_raw_syscall_event_capture", raises: [].}
proc cRawSyscallEventOpenHow(index: clong; flags, mode: ptr culonglong): cint
  {.importc: "ct_linux_raw_syscall_event_open_how", raises: [].}
proc cRegisterInlineDrain(observer: proc() {.cdecl, raises: [].})
  {.importc: "ct_linux_preload_register_inline_drain", raises: [].}
proc cArmInlineLossReport(dir: cstring; frame: pointer; frameLen: clong;
                          pidOffset, tidOffset: clong): cint
  {.importc: "ct_linux_preload_arm_inline_loss_report", nodecl, raises: [].}
proc cReportInlineEventsIfPending()
  {.importc: "ct_linux_report_inline_events_if_pending", raises: [].}
proc cArmForkSkipLossReport(frame: pointer; frameLen: clong;
                            pidOffset, tidOffset: clong): cint
  {.importc: "ct_linux_preload_arm_fork_skip_loss_report", nodecl,
    raises: [].}
proc cArmSubscriberForkSkipLossReport(frame: pointer; frameLen: clong;
                            pidOffset, tidOffset: clong): cint
  {.importc: "ct_linux_preload_arm_subscriber_fork_skip_loss_report", nodecl,
    raises: [].}
proc cArmUninjectableExecLossReport(frame: pointer; frameLen: clong;
                                    pidOffset, tidOffset: clong): cint
  {.importc: "ct_linux_preload_arm_uninjectable_exec_loss_report", nodecl,
    raises: [].}
proc cRegisterUninjectableExec(observer: pointer)
  {.importc: "ct_linux_preload_register_uninjectable_exec", nodecl,
    raises: [].}
proc cExecHookImageUninjectable(path: cstring; detail: cstring;
                                cap: csize_t): cint
  {.importc: "ct_linux_exec_hook_image_uninjectable", nodecl, raises: [].}
proc cReportExecHookEntryUnrecorded(path: cstring)
  {.importc: "ct_linux_report_exec_hook_entry_unrecorded", nodecl,
    raises: [].}
proc cSpawnImageUninjectable(file: cstring; usePath: cint; childPid: clong;
                             detail: cstring; cap: csize_t): cint
  {.importc: "ct_linux_spawn_image_uninjectable", nodecl, raises: [].}
proc cSpawnEntryUnrecordedPre(file: cstring; usePath: cint): cint
  {.importc: "ct_linux_spawn_entry_unrecorded_pre", nodecl, raises: [].}
proc cSpawnEntryUnrecordedPost(file: cstring; usePath, preFlagged, succeeded,
                               hasFileActions: cint; childPid: clong)
  {.importc: "ct_linux_spawn_entry_unrecorded_post", nodecl, raises: [].}
proc cReportForkChildSkippedEvidence()
  {.importc: "ct_linux_report_fork_child_skipped_evidence", nodecl,
    raises: [].}

proc installOpenDispatcher(dispatch: OpenDispatch)
  {.importc: "ct_linux_preload_register_open_hook", raises: [].}
proc installOpen64Dispatcher(dispatch: OpenDispatch)
  {.importc: "ct_linux_preload_register_open64_hook", raises: [].}
proc installOpenatDispatcher(dispatch: OpenatDispatch)
  {.importc: "ct_linux_preload_register_openat_hook", raises: [].}
proc installOpenat64Dispatcher(dispatch: OpenatDispatch)
  {.importc: "ct_linux_preload_register_openat64_hook", raises: [].}
proc installCloseDispatcher(dispatch: CloseDispatch)
  {.importc: "ct_linux_preload_register_close_hook", raises: [].}
proc installReadDispatcher(dispatch: ReadDispatch)
  {.importc: "ct_linux_preload_register_read_hook", raises: [].}
proc installPreadDispatcher(dispatch: PreadDispatch)
  {.importc: "ct_linux_preload_register_pread_hook", raises: [].}
proc installReadvDispatcher(dispatch: ReadvDispatch)
  {.importc: "ct_linux_preload_register_readv_hook", raises: [].}
proc installPreadvDispatcher(dispatch: PreadvDispatch)
  {.importc: "ct_linux_preload_register_preadv_hook", raises: [].}
proc installWriteDispatcher(dispatch: WriteDispatch)
  {.importc: "ct_linux_preload_register_write_hook", raises: [].}
proc installStatDispatcher(dispatch: StatDispatch)
  {.importc: "ct_linux_preload_register_stat_hook", raises: [].}
proc installLstatDispatcher(dispatch: StatDispatch)
  {.importc: "ct_linux_preload_register_lstat_hook", raises: [].}
proc installOpendirDispatcher(dispatch: OpendirDispatch)
  {.importc: "ct_linux_preload_register_opendir_hook", raises: [].}
proc installReaddirDispatcher(dispatch: ReaddirDispatch)
  {.importc: "ct_linux_preload_register_readdir_hook", raises: [].}
proc installClosedirDispatcher(dispatch: ClosedirDispatch)
  {.importc: "ct_linux_preload_register_closedir_hook", raises: [].}
proc installFopenDispatcher(dispatch: FopenDispatch)
  {.importc: "ct_linux_preload_register_fopen_hook", raises: [].}
proc installFopen64Dispatcher(dispatch: FopenDispatch)
  {.importc: "ct_linux_preload_register_fopen64_hook", raises: [].}
proc installFreadDispatcher(dispatch: FreadDispatch)
  {.importc: "ct_linux_preload_register_fread_hook", raises: [].}
proc installFcloseDispatcher(dispatch: FcloseDispatch)
  {.importc: "ct_linux_preload_register_fclose_hook", raises: [].}
proc installConnectDispatcher(dispatch: ConnectDispatch)
  {.importc: "ct_linux_preload_register_connect_hook", raises: [].}
proc installPipeDispatcher(dispatch: PipeDispatch)
  {.importc: "ct_linux_preload_register_pipe_hook", raises: [].}
proc installPipe2Dispatcher(dispatch: Pipe2Dispatch)
  {.importc: "ct_linux_preload_register_pipe2_hook", raises: [].}
proc installSocketpairDispatcher(dispatch: SocketpairDispatch)
  {.importc: "ct_linux_preload_register_socketpair_hook", raises: [].}
proc installSendfileDispatcher(dispatch: SendfileDispatch)
  {.importc: "ct_linux_preload_register_sendfile_hook", raises: [].}
proc installCopyFileRangeDispatcher(dispatch: CopyFileRangeDispatch)
  {.importc: "ct_linux_preload_register_copy_file_range_hook", raises: [].}
proc installSpliceDispatcher(dispatch: SpliceDispatch)
  {.importc: "ct_linux_preload_register_splice_hook", raises: [].}
proc installLinkDispatcher(dispatch: LinkDispatch)
  {.importc: "ct_linux_preload_register_link_hook", raises: [].}
proc installLinkatDispatcher(dispatch: LinkatDispatch)
  {.importc: "ct_linux_preload_register_linkat_hook", raises: [].}
proc installRenameDispatcher(dispatch: RenameDispatch)
  {.importc: "ct_linux_preload_register_rename_hook", raises: [].}
proc installRenameatDispatcher(dispatch: RenameatDispatch)
  {.importc: "ct_linux_preload_register_renameat_hook", raises: [].}
proc installRenameat2Dispatcher(dispatch: Renameat2Dispatch)
  {.importc: "ct_linux_preload_register_renameat2_hook", raises: [].}
proc installDlopenDispatcher(dispatch: DlopenDispatch)
  {.importc: "ct_linux_preload_register_dlopen_hook", raises: [].}
proc installDlmopenDispatcher(dispatch: DlmopenDispatch)
  {.importc: "ct_linux_preload_register_dlmopen_hook", raises: [].}
proc installDlsymDispatcher(dispatch: DlsymDispatch)
  {.importc: "ct_linux_preload_register_dlsym_hook", raises: [].}
proc installMmapDispatcher(dispatch: MmapDispatch)
  {.importc: "ct_linux_preload_register_mmap_hook", raises: [].}
proc installMprotectDispatcher(dispatch: MprotectDispatch)
  {.importc: "ct_linux_preload_register_mprotect_hook", raises: [].}
proc installMunmapDispatcher(dispatch: MunmapDispatch)
  {.importc: "ct_linux_preload_register_munmap_hook", raises: [].}
proc installMremapDispatcher(dispatch: MremapDispatch)
  {.importc: "ct_linux_preload_register_mremap_hook", raises: [].}
proc installGetenvDispatcher(dispatch: GetenvDispatch)
  {.importc: "ct_linux_preload_register_getenv_hook", raises: [].}
proc installUnameDispatcher(dispatch: UnameDispatch)
  {.importc: "ct_linux_preload_register_uname_hook", raises: [].}
proc installSysconfDispatcher(dispatch: SysconfDispatch)
  {.importc: "ct_linux_preload_register_sysconf_hook", raises: [].}
proc installClockGettimeDispatcher(dispatch: ClockGettimeDispatch)
  {.importc: "ct_linux_preload_register_clock_gettime_hook", raises: [].}
proc installGettimeofdayDispatcher(dispatch: GettimeofdayDispatch)
  {.importc: "ct_linux_preload_register_gettimeofday_hook", raises: [].}
proc installTimeDispatcher(dispatch: TimeDispatch)
  {.importc: "ct_linux_preload_register_time_hook", raises: [].}
proc installGetrandomDispatcher(dispatch: GetrandomDispatch)
  {.importc: "ct_linux_preload_register_getrandom_hook", raises: [].}
proc installGetentropyDispatcher(dispatch: GetentropyDispatch)
  {.importc: "ct_linux_preload_register_getentropy_hook", raises: [].}
proc installArc4randomDispatcher(dispatch: Arc4randomDispatch)
  {.importc: "ct_linux_preload_register_arc4random_hook", raises: [].}
proc installArc4randomBufDispatcher(dispatch: Arc4randomBufDispatch)
  {.importc: "ct_linux_preload_register_arc4random_buf_hook", raises: [].}
proc installArc4randomUniformDispatcher(dispatch: Arc4randomUniformDispatch)
  {.importc: "ct_linux_preload_register_arc4random_uniform_hook", raises: [].}
proc installForkDispatcher(dispatch: ForkDispatch)
  {.importc: "ct_linux_preload_register_fork_hook", raises: [].}
proc installExecveDispatcher(dispatch: ExecveDispatch)
  {.importc: "ct_linux_preload_register_execve_hook", raises: [].}
proc installPosixSpawnDispatcher(dispatch: PosixSpawnDispatch)
  {.importc: "ct_linux_preload_register_posix_spawn_hook", raises: [].}
proc installPosixSpawnpDispatcher(dispatch: PosixSpawnDispatch)
  {.importc: "ct_linux_preload_register_posix_spawnp_hook", raises: [].}
proc installExitDispatcher(dispatch: ExitDispatch)
  {.importc: "ct_linux_preload_register_exit_hook", raises: [].}
proc installRawSyscallDispatcher(dispatch: RawSyscallDispatch)
  {.importc: "ct_linux_preload_register_raw_syscall_hook", raises: [].}

const
  anonymousRangeCap = 4096
    ## FUP-C — fixed capacity of the anonymous-mmap ownership table. See the
    ## table declaration below for why it is a POD array rather than a ``seq``.

var
  openHooks: seq[OpenHookEntry] = @[]
  open64Hooks: seq[OpenHookEntry] = @[]
  openatHooks: seq[OpenatHookEntry] = @[]
  openat64Hooks: seq[OpenatHookEntry] = @[]
  closeHooks: seq[CloseHookEntry] = @[]
  readHooks: seq[ReadHookEntry] = @[]
  preadHooks: seq[PreadHookEntry] = @[]
  readvHooks: seq[ReadvHookEntry] = @[]
  preadvHooks: seq[PreadvHookEntry] = @[]
  writeHooks: seq[WriteHookEntry] = @[]
  statHooks: seq[StatHookEntry] = @[]
  lstatHooks: seq[StatHookEntry] = @[]
  opendirHooks: seq[OpendirHookEntry] = @[]
  readdirHooks: seq[ReaddirHookEntry] = @[]
  closedirHooks: seq[ClosedirHookEntry] = @[]
  fopenHooks: seq[FopenHookEntry] = @[]
  fopen64Hooks: seq[FopenHookEntry] = @[]
  freadHooks: seq[FreadHookEntry] = @[]
  fcloseHooks: seq[FcloseHookEntry] = @[]
  connectHooks: seq[ConnectHookEntry] = @[]
  pipeHooks: seq[PipeHookEntry] = @[]
  pipe2Hooks: seq[Pipe2HookEntry] = @[]
  socketpairHooks: seq[SocketpairHookEntry] = @[]
  sendfileHooks: seq[SendfileHookEntry] = @[]
  copyFileRangeHooks: seq[CopyFileRangeHookEntry] = @[]
  spliceHooks: seq[SpliceHookEntry] = @[]
  linkHooks: seq[LinkHookEntry] = @[]
  linkatHooks: seq[LinkatHookEntry] = @[]
  renameHooks: seq[RenameHookEntry] = @[]
  renameatHooks: seq[RenameatHookEntry] = @[]
  renameat2Hooks: seq[RenameatHookEntry] = @[]
  dlopenHooks: seq[DlopenHookEntry] = @[]
  dlmopenHooks: seq[DlmopenHookEntry] = @[]
  dlsymHooks: seq[DlsymHookEntry] = @[]
  mmapHooks: seq[MmapHookEntry] = @[]
  mprotectHooks: seq[MprotectHookEntry] = @[]
  munmapHooks: seq[MunmapHookEntry] = @[]
  mremapHooks: seq[MremapHookEntry] = @[]
  getenvHooks: seq[GetenvHookEntry] = @[]
  unameHooks: seq[UnameHookEntry] = @[]
  sysconfHooks: seq[SysconfHookEntry] = @[]
  clockGettimeHooks: seq[ClockGettimeHookEntry] = @[]
  gettimeofdayHooks: seq[GettimeofdayHookEntry] = @[]
  timeHooks: seq[TimeHookEntry] = @[]
  getrandomHooks: seq[GetrandomHookEntry] = @[]
  entropyHooks: seq[EntropyHookEntry] = @[]
  forkHooks: seq[ForkHookEntry] = @[]
  execveHooks: seq[ExecveHookEntry] = @[]
  posixSpawnHooks: seq[PosixSpawnHookEntry] = @[]
  posixSpawnpHooks: seq[PosixSpawnHookEntry] = @[]
  exitHooks: seq[ExitHookEntry] = @[]
  rawSyscallHook: RawSyscallHook = nil
  rawSyscallPatchAttempted = false
  rawSyscallPatchStatus = RawSyscallPatchStatus(
    installed: false,
    diagnostic: lrsInvalidArgument,
    stage: lpsNone)
  inlineSyscallPatchAttempted = false
  inlineSyscallPatchStatus = InlineSyscallPatchStatus(
    attempted: false,
    handlerInstalled: false,
    scanDiagnostic: lrsInvalidArgument,
    installDiagnostic: lrsInvalidArgument,
    firstPatchDiagnostic: lrsOk,
    firstPatchStage: lpsNone)
  anonymousRangeLock: Lock
  # FUP-C — the anonymous-mmap ownership table is a FIXED-CAPACITY POD array,
  # NOT a growable ``seq``. Under ``--mm:orc`` a process-global ``seq`` is
  # backed by the thread-local ``MemRegion`` of whichever thread first grew
  # it, but ``recordAnonymousPrivateMmap`` / ``removeAnonymousPrivateRange``
  # run from EVERY host thread's ``mmap``/``munmap`` hook. ORC's
  # ``reallocSharedImpl`` routes to the CALLING thread's region (the shared
  # heap lock is compiled out when ``gcDestructors`` is defined), so a
  # ``seq`` realloc from a different thread than the one that allocated the
  # buffer frees a chunk owned by another thread's region and corrupts its
  # free-list — an intermittent SIGSEGV in ``rawDealloc``/``listRemove``.
  # A fixed POD array touches NO allocator on the hot path, so the
  # ``anonymousRangeLock`` (which already serialises the table) is the only
  # synchronisation the table needs. Capacity is generous: allocator-growth
  # anonymous maps coalesce as the runtime munmaps them; a full table simply
  # drops the OLDEST tracked range (see ``recordAnonymousPrivateMmap``),
  # which at worst under-reports a JIT range to the inline-syscall scanner —
  # never a crash and never a false dependency.
  anonymousExecutableRanges: array[anonymousRangeCap, AnonymousExecutableRange]
  anonymousExecutableRangeCount: int = 0
  anonymousRangeScratch: array[anonymousRangeCap, AnonymousExecutableRange]
    ## Working space for `removeAnonymousPrivateRange` (the compacted table)
    ## and `rangeFullyTrackedLocked` (the sorted intersections). Both used to
    ## declare this 64 KiB array ON THE STACK — inside the munmap / mprotect /
    ## mremap hooks of whatever host thread made the call — so any monitored
    ## thread with a stack of 64 KiB or less died with SIGSEGV on its first
    ## munmap (`tests/linux/test_io_mon_shim_static_tls_small_stack_threads`).
    ##
    ## A process global (BSS, not TLS: TLS would put it back on every
    ## thread's stack) is safe because it is touched ONLY while
    ## `anonymousRangeLock` is held, and each user finishes with it before
    ## releasing the lock. The lock is not recursive and neither user calls
    ## the other or anything that re-acquires it, so the two can never be live
    ## at once on any thread: a nested hook on the same thread would already
    ## deadlock on the lock before it could reach the buffer.

initLock(anonymousRangeLock)

proc anonymousRangeLockFree*(): bool {.raises: [].} =
  ## In a fork child, the only thread of its process: whether no parent
  ## thread held `anonymousRangeLock` at the fork, so the range table is in
  ## a state some complete update left it in.
  if not tryAcquire(anonymousRangeLock):
    return false
  release(anonymousRangeLock)
  true

when defined(ioMonShimForkLockTest):
  proc anonymousRangeTestHoldLock*(hold: bool) {.raises: [].} =
    ## Test-only (`-d:ioMonShimForkLockTest`): take or give back
    ## `anonymousRangeLock` on the calling thread.
    if hold: acquire(anonymousRangeLock) else: release(anonymousRangeLock)

proc registerOpenHook*(hook: OpenHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  openHooks.add(OpenHookEntry(priority: priority, callback: hook))
  openHooks.sort(proc(a, b: OpenHookEntry): int = cmp(a.priority, b.priority))

proc registerOpen64Hook*(hook: OpenHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  open64Hooks.add(OpenHookEntry(priority: priority, callback: hook))
  open64Hooks.sort(proc(a, b: OpenHookEntry): int = cmp(a.priority, b.priority))

proc registerOpenatHook*(hook: OpenatHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  openatHooks.add(OpenatHookEntry(priority: priority, callback: hook))
  openatHooks.sort(proc(a, b: OpenatHookEntry): int = cmp(a.priority, b.priority))

proc registerOpenat64Hook*(hook: OpenatHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  openat64Hooks.add(OpenatHookEntry(priority: priority, callback: hook))
  openat64Hooks.sort(proc(a, b: OpenatHookEntry): int = cmp(a.priority, b.priority))

proc registerCloseHook*(hook: CloseHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  closeHooks.add(CloseHookEntry(priority: priority, callback: hook))
  closeHooks.sort(proc(a, b: CloseHookEntry): int = cmp(a.priority, b.priority))

proc registerReadHook*(hook: ReadHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  readHooks.add(ReadHookEntry(priority: priority, callback: hook))
  readHooks.sort(proc(a, b: ReadHookEntry): int = cmp(a.priority, b.priority))

proc registerPreadHook*(hook: PreadHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  preadHooks.add(PreadHookEntry(priority: priority, callback: hook))
  preadHooks.sort(proc(a, b: PreadHookEntry): int = cmp(a.priority, b.priority))

proc registerReadvHook*(hook: ReadvHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  readvHooks.add(ReadvHookEntry(priority: priority, callback: hook))
  readvHooks.sort(proc(a, b: ReadvHookEntry): int = cmp(a.priority, b.priority))

proc registerPreadvHook*(hook: PreadvHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  preadvHooks.add(PreadvHookEntry(priority: priority, callback: hook))
  preadvHooks.sort(proc(a, b: PreadvHookEntry): int = cmp(a.priority, b.priority))

proc registerWriteHook*(hook: WriteHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  writeHooks.add(WriteHookEntry(priority: priority, callback: hook))
  writeHooks.sort(proc(a, b: WriteHookEntry): int = cmp(a.priority, b.priority))

proc registerStatHook*(hook: StatHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  statHooks.add(StatHookEntry(priority: priority, callback: hook))
  statHooks.sort(proc(a, b: StatHookEntry): int = cmp(a.priority, b.priority))

proc registerLstatHook*(hook: StatHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  lstatHooks.add(StatHookEntry(priority: priority, callback: hook))
  lstatHooks.sort(proc(a, b: StatHookEntry): int = cmp(a.priority, b.priority))

proc registerOpendirHook*(hook: OpendirHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  opendirHooks.add(OpendirHookEntry(priority: priority, callback: hook))
  opendirHooks.sort(proc(a, b: OpendirHookEntry): int = cmp(a.priority, b.priority))

proc registerReaddirHook*(hook: ReaddirHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  readdirHooks.add(ReaddirHookEntry(priority: priority, callback: hook))
  readdirHooks.sort(proc(a, b: ReaddirHookEntry): int = cmp(a.priority, b.priority))

proc registerClosedirHook*(hook: ClosedirHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  closedirHooks.add(ClosedirHookEntry(priority: priority, callback: hook))
  closedirHooks.sort(proc(a, b: ClosedirHookEntry): int = cmp(a.priority, b.priority))

proc registerFopenHook*(hook: FopenHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  fopenHooks.add(FopenHookEntry(priority: priority, callback: hook))
  fopenHooks.sort(proc(a, b: FopenHookEntry): int = cmp(a.priority, b.priority))

proc registerFopen64Hook*(hook: FopenHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  fopen64Hooks.add(FopenHookEntry(priority: priority, callback: hook))
  fopen64Hooks.sort(proc(a, b: FopenHookEntry): int = cmp(a.priority, b.priority))

proc registerFreadHook*(hook: FreadHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  freadHooks.add(FreadHookEntry(priority: priority, callback: hook))
  freadHooks.sort(proc(a, b: FreadHookEntry): int = cmp(a.priority, b.priority))

proc registerFcloseHook*(hook: FcloseHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  fcloseHooks.add(FcloseHookEntry(priority: priority, callback: hook))
  fcloseHooks.sort(proc(a, b: FcloseHookEntry): int = cmp(a.priority, b.priority))

proc registerConnectHook*(hook: ConnectHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  connectHooks.add(ConnectHookEntry(priority: priority, callback: hook))
  connectHooks.sort(proc(a, b: ConnectHookEntry): int = cmp(a.priority, b.priority))

proc registerPipeHook*(hook: PipeHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  pipeHooks.add(PipeHookEntry(priority: priority, callback: hook))
  pipeHooks.sort(proc(a, b: PipeHookEntry): int = cmp(a.priority, b.priority))

proc registerPipe2Hook*(hook: Pipe2Hook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  pipe2Hooks.add(Pipe2HookEntry(priority: priority, callback: hook))
  pipe2Hooks.sort(proc(a, b: Pipe2HookEntry): int = cmp(a.priority, b.priority))

proc registerSocketpairHook*(hook: SocketpairHook; priority = 100)
    {.raises: [].} =
  if hook == nil:
    return
  socketpairHooks.add(SocketpairHookEntry(priority: priority, callback: hook))
  socketpairHooks.sort(proc(a, b: SocketpairHookEntry): int =
    cmp(a.priority, b.priority))

proc registerSendfileHook*(hook: SendfileHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  sendfileHooks.add(SendfileHookEntry(priority: priority, callback: hook))
  sendfileHooks.sort(proc(a, b: SendfileHookEntry): int = cmp(a.priority, b.priority))

proc registerCopyFileRangeHook*(hook: CopyFileRangeHook; priority = 100)
    {.raises: [].} =
  if hook == nil:
    return
  copyFileRangeHooks.add(CopyFileRangeHookEntry(priority: priority,
    callback: hook))
  copyFileRangeHooks.sort(proc(a, b: CopyFileRangeHookEntry): int =
    cmp(a.priority, b.priority))

proc registerSpliceHook*(hook: SpliceHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  spliceHooks.add(SpliceHookEntry(priority: priority, callback: hook))
  spliceHooks.sort(proc(a, b: SpliceHookEntry): int = cmp(a.priority, b.priority))

proc registerLinkHook*(hook: LinkHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  linkHooks.add(LinkHookEntry(priority: priority, callback: hook))
  linkHooks.sort(proc(a, b: LinkHookEntry): int = cmp(a.priority, b.priority))

proc registerLinkatHook*(hook: LinkatHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  linkatHooks.add(LinkatHookEntry(priority: priority, callback: hook))
  linkatHooks.sort(proc(a, b: LinkatHookEntry): int = cmp(a.priority, b.priority))

proc registerRenameHook*(hook: RenameHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  renameHooks.add(RenameHookEntry(priority: priority, callback: hook))
  renameHooks.sort(proc(a, b: RenameHookEntry): int = cmp(a.priority, b.priority))

proc registerRenameatHook*(hook: RenameatHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  renameatHooks.add(RenameatHookEntry(priority: priority, callback: hook))
  renameatHooks.sort(proc(a, b: RenameatHookEntry): int = cmp(a.priority, b.priority))

proc registerRenameat2Hook*(hook: RenameatHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  renameat2Hooks.add(RenameatHookEntry(priority: priority, callback: hook))
  renameat2Hooks.sort(proc(a, b: RenameatHookEntry): int = cmp(a.priority, b.priority))

proc registerDlopenHook*(hook: DlopenHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  dlopenHooks.add(DlopenHookEntry(priority: priority, callback: hook))
  dlopenHooks.sort(proc(a, b: DlopenHookEntry): int = cmp(a.priority, b.priority))

proc registerDlmopenHook*(hook: DlmopenHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  dlmopenHooks.add(DlmopenHookEntry(priority: priority, callback: hook))
  dlmopenHooks.sort(proc(a, b: DlmopenHookEntry): int = cmp(a.priority, b.priority))

proc registerDlsymHook*(hook: DlsymHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  dlsymHooks.add(DlsymHookEntry(priority: priority, callback: hook))
  dlsymHooks.sort(proc(a, b: DlsymHookEntry): int = cmp(a.priority, b.priority))

proc registerMmapHook*(hook: MmapHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  mmapHooks.add(MmapHookEntry(priority: priority, callback: hook))
  mmapHooks.sort(proc(a, b: MmapHookEntry): int = cmp(a.priority, b.priority))

proc registerMprotectHook*(hook: MprotectHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  mprotectHooks.add(MprotectHookEntry(priority: priority, callback: hook))
  mprotectHooks.sort(proc(a, b: MprotectHookEntry): int = cmp(a.priority, b.priority))

proc registerMunmapHook*(hook: MunmapHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  munmapHooks.add(MunmapHookEntry(priority: priority, callback: hook))
  munmapHooks.sort(proc(a, b: MunmapHookEntry): int = cmp(a.priority, b.priority))

proc registerMremapHook*(hook: MremapHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  mremapHooks.add(MremapHookEntry(priority: priority, callback: hook))
  mremapHooks.sort(proc(a, b: MremapHookEntry): int = cmp(a.priority, b.priority))

proc registerGetenvHook*(hook: GetenvHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  getenvHooks.add(GetenvHookEntry(priority: priority, callback: hook))
  getenvHooks.sort(proc(a, b: GetenvHookEntry): int = cmp(a.priority, b.priority))

proc registerUnameHook*(hook: UnameHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  unameHooks.add(UnameHookEntry(priority: priority, callback: hook))
  unameHooks.sort(proc(a, b: UnameHookEntry): int = cmp(a.priority, b.priority))

proc registerSysconfHook*(hook: SysconfHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  sysconfHooks.add(SysconfHookEntry(priority: priority, callback: hook))
  sysconfHooks.sort(proc(a, b: SysconfHookEntry): int = cmp(a.priority, b.priority))

proc registerClockGettimeHook*(hook: ClockGettimeHook; priority = 100)
    {.raises: [].} =
  if hook == nil:
    return
  clockGettimeHooks.add(ClockGettimeHookEntry(priority: priority,
    callback: hook))
  clockGettimeHooks.sort(proc(a, b: ClockGettimeHookEntry): int =
    cmp(a.priority, b.priority))

proc registerGettimeofdayHook*(hook: GettimeofdayHook; priority = 100)
    {.raises: [].} =
  if hook == nil:
    return
  gettimeofdayHooks.add(GettimeofdayHookEntry(priority: priority,
    callback: hook))
  gettimeofdayHooks.sort(proc(a, b: GettimeofdayHookEntry): int =
    cmp(a.priority, b.priority))

proc registerTimeHook*(hook: TimeHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  timeHooks.add(TimeHookEntry(priority: priority, callback: hook))
  timeHooks.sort(proc(a, b: TimeHookEntry): int = cmp(a.priority, b.priority))

proc registerGetrandomHook*(hook: GetrandomHook; priority = 100)
    {.raises: [].} =
  if hook == nil:
    return
  getrandomHooks.add(GetrandomHookEntry(priority: priority, callback: hook))
  getrandomHooks.sort(proc(a, b: GetrandomHookEntry): int =
    cmp(a.priority, b.priority))

proc registerEntropyHook*(hook: EntropyHook; priority = 100) {.raises: [].} =
  ## One chain for getentropy / arc4random / arc4random_buf /
  ## arc4random_uniform; the hook reads `ctx.source` to tell them apart.
  if hook == nil:
    return
  entropyHooks.add(EntropyHookEntry(priority: priority, callback: hook))
  entropyHooks.sort(proc(a, b: EntropyHookEntry): int =
    cmp(a.priority, b.priority))

proc registerForkHook*(hook: ForkHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  forkHooks.add(ForkHookEntry(priority: priority, callback: hook))
  forkHooks.sort(proc(a, b: ForkHookEntry): int = cmp(a.priority, b.priority))

proc registerExecveHook*(hook: ExecveHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  execveHooks.add(ExecveHookEntry(priority: priority, callback: hook))
  execveHooks.sort(proc(a, b: ExecveHookEntry): int = cmp(a.priority, b.priority))

proc registerPosixSpawnHook*(hook: PosixSpawnHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  posixSpawnHooks.add(PosixSpawnHookEntry(priority: priority, callback: hook))
  posixSpawnHooks.sort(proc(a, b: PosixSpawnHookEntry): int =
    cmp(a.priority, b.priority))

proc registerPosixSpawnpHook*(hook: PosixSpawnHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  posixSpawnpHooks.add(PosixSpawnHookEntry(priority: priority, callback: hook))
  posixSpawnpHooks.sort(proc(a, b: PosixSpawnHookEntry): int =
    cmp(a.priority, b.priority))

proc registerExitHook*(hook: ExitHook; priority = 100) {.raises: [].} =
  if hook == nil:
    return
  exitHooks.add(ExitHookEntry(priority: priority, callback: hook))
  exitHooks.sort(proc(a, b: ExitHookEntry): int = cmp(a.priority, b.priority))

proc registerRawSyscallHook*(hook: RawSyscallHook) {.raises: [].} =
  rawSyscallHook = hook

proc rawSyscallDispatcher(number, a1, a2, a3, a4, a5, a6, result: clong;
                          inlineTrap: cint) {.cdecl, raises: [].} =
  if rawSyscallHook != nil:
    rawSyscallHook(number, a1, a2, a3, a4, a5, a6, result, inlineTrap)

proc rawSyscallEventCount*(): int {.raises: [].} =
  int(cRawSyscallEventCount())

proc rawSyscallEventOverflowed*(): bool {.raises: [].} =
  cRawSyscallEventOverflowed() != 0

type
  RawSyscallCaptureSlot* = enum
    ## The strings captured with a trapped event (CT_RAW_CAP_* in the C half).
    rcsBase,   ## directory a relative pathname was resolved against
    rcsPath,   ## the pathname argument as passed
    rcsTarget, ## symlink(at)'s target
    rcsFd0,    ## what the first descriptor named ("" = no path)
    rcsFd1     ## what the second descriptor named ("" = no path)
  RawSyscallCaptureState* = enum
    rcsNone,   ## the classification reads nothing indirectly
    rcsCaptured,
    rcsFailed  ## needed, but could not be captured: classify as loss

proc rawCurrentPid*(): cint {.raises: [].} =
  cRawCurrentPid()

proc rawSyscallEventClaim*(index: int; pid: cint): int {.raises: [].} =
  ## 1: taken for classification; 0: another process's or already taken;
  ## -1: still being written.
  int(cRawSyscallEventClaim(clong(index), pid))

proc rawSyscallEventCaptureState*(index: int): RawSyscallCaptureState
    {.raises: [].} =
  case cRawSyscallEventCaptureState(clong(index))
  of 1: rcsCaptured
  of 2: rcsFailed
  else: rcsNone

proc rawSyscallEventCapture*(index: int; slot: RawSyscallCaptureSlot):
    tuple[ok: bool, text: string] {.raises: [].} =
  var text: cstring
  var len: clong
  if cRawSyscallEventCapture(clong(index), cint(ord(slot)), addr text,
                             addr len) == 0:
    return (false, "")
  var copy = newString(int(len))
  if len > 0:
    copyMem(addr copy[0], text, int(len))
  (true, copy)

proc rawSyscallEventOpenHow*(index: int):
    tuple[ok: bool, flags, mode: uint64] {.raises: [].} =
  var flags, mode: culonglong
  if cRawSyscallEventOpenHow(clong(index), addr flags, addr mode) == 0:
    return (false, 0'u64, 0'u64)
  (true, uint64(flags), uint64(mode))

proc registerInlineRawSyscallDrain*(observer: proc() {.cdecl, raises: [].})
    {.raises: [].} =
  ## The classification `ct_linux_drain_inline_events_before_image_end` runs
  ## before an exit or exec that bypasses the destructor and the exec hooks.
  cRegisterInlineDrain(observer)

proc armInlineLossReport*(fragmentDir: string; frame: openArray[byte];
                          pidOffset, tidOffset: int): bool {.raises: [].} =
  ## Hand the runtime the pre-encoded event-loss frame it writes, with raw
  ## syscalls, when trapped events cannot be classified before the image
  ## ends (`ct_report_unclassified_inline_events`). `fragmentDir` must be
  ## absolute; the offsets locate the frame's pid and thread id (-1: none).
  if frame.len == 0:
    return false
  cArmInlineLossReport(cstring(fragmentDir), unsafeAddr frame[0],
    clong(frame.len), clong(pidOffset), clong(tidOffset)) == 1

proc armForkSkipLossReport*(frame: openArray[byte];
                            pidOffset, tidOffset: int;
                            subscriber = false): bool {.raises: [].} =
  ## Hand the runtime the pre-encoded event-loss frame a fork child writes,
  ## with raw syscalls, when it skips a hook that would have produced
  ## evidence (`ct_linux_report_fork_child_skipped_evidence`). Call after
  ## `armInlineLossReport`, whose fragment directory it shares.
  if frame.len == 0:
    return false
  if subscriber:
    cArmSubscriberForkSkipLossReport(unsafeAddr frame[0], clong(frame.len),
      clong(pidOffset), clong(tidOffset)) == 1
  else:
    cArmForkSkipLossReport(unsafeAddr frame[0], clong(frame.len),
      clong(pidOffset), clong(tidOffset)) == 1

proc armUninjectableExecLossReport*(frame: openArray[byte];
                                    pidOffset, tidOffset: int): bool
    {.raises: [].} =
  ## Hand the runtime the pre-encoded event-loss frame it writes, with raw
  ## syscalls, for an entry into an image the shim cannot enter that it
  ## cannot record by name (`ct_linux_report_uninjectable_exec_frame`). Call
  ## after `armInlineLossReport`, whose fragment directory it shares.
  if frame.len == 0:
    return false
  cArmUninjectableExecLossReport(unsafeAddr frame[0], clong(frame.len),
    clong(pidOffset), clong(tidOffset)) == 1

proc registerUninjectableExecRecorder*(
    observer: proc(entry, detail: cstring): cint {.cdecl, raises: [].})
    {.raises: [].} =
  ## What a raw execve/execveat into an image the shim cannot enter calls
  ## to record the loss by name (see `ct_report_uninjectable_exec`). It runs
  ## inside a hook bracket and returns 0 when it could not record.
  # A pointer: the C side takes `const char *` parameters, Nim passes
  # `char *`, and the function is the same.
  cRegisterUninjectableExec(cast[pointer](observer))

const uninjectableDetailCap = 4096 + 512
  ## A full path, a `#!` script's path and the reason.

proc execHookImageUninjectable*(path: cstring): string {.raises: [].} =
  ## For the execve hook: "" when the shim can enter the image the exec on
  ## `path` will run, else "<reason> image=<image>[ script=<file>]". Resolves
  ## the target the kernel will run (fexecve/execveat descriptor, execvp PATH
  ## search); see `ct_linux_exec_hook_image_uninjectable`.
  if path == nil:
    return ""
  var buf = newString(uninjectableDetailCap)
  if cExecHookImageUninjectable(path, cstring(buf), csize_t(buf.len)) == 0:
    return ""
  $cstring(buf)

proc reportExecHookEntryUnrecorded*(path: cstring) {.raises: [].} =
  ## For the execve hook where it cannot record (a fork child skipping
  ## bookkeeping): an uninjectable target is reported through the unnamed
  ## pre-encoded frame. Allocation-free.
  cReportExecHookEntryUnrecorded(path)

proc spawnImageUninjectable*(file: cstring; usePath: bool;
                             childPid: int = 0): string {.raises: [].} =
  ## For the posix_spawn/posix_spawnp hooks: "" or the detail, as
  ## `execHookImageUninjectable`; `usePath` searches the caller's PATH. With
  ## `childPid` (after a successful spawn) a relative name is resolved in
  ## that child's working directory instead of the caller's; see
  ## `ct_linux_spawn_image_uninjectable`.
  if file == nil:
    return ""
  var buf = newString(uninjectableDetailCap)
  if cSpawnImageUninjectable(file, cint(usePath), clong(childPid),
                             cstring(buf), csize_t(buf.len)) == 0:
    return ""
  $cstring(buf)

proc spawnEntryUnrecordedPre*(file: cstring; usePath: bool): bool
    {.raises: [].} =
  ## For the posix_spawn hooks where they cannot record: whether the spawn
  ## is about to start an image the shim cannot enter. Allocation-free; pass
  ## the answer to `reportSpawnEntryUnrecorded` after the real call.
  cSpawnEntryUnrecordedPre(file, cint(usePath)) != 0

proc reportSpawnEntryUnrecorded*(file: cstring; usePath, preFlagged,
                                 succeeded, hasFileActions: bool;
                                 childPid: int) {.raises: [].} =
  ## `reportExecHookEntryUnrecorded` for the posix_spawn hooks, after the
  ## real call: reports through the unnamed frame when the spawn succeeded
  ## and started an image the shim cannot enter. Allocation-free.
  cSpawnEntryUnrecordedPost(file, cint(usePath), cint(preFlagged),
    cint(succeeded), cint(hasFileActions), clong(childPid))

proc reportForkChildSkippedEvidence*() {.raises: [].} =
  ## Report, once per process, that this fork child skipped a hook that
  ## would have produced evidence (see `armForkSkipLossReport`).
  cReportForkChildSkippedEvidence()

proc reportInlineEventsIfPending*() {.raises: [].} =
  ## Report unclassified trapped events of this process as event-loss, for
  ## an image end that runs no drain (see `armInlineLossReport`).
  cReportInlineEventsIfPending()

proc rawSyscallEventAt*(index: int):
    tuple[ok: bool, number, a1, a2, a3, a4, a5, a6, result: clong,
          source: cint, address: uint] {.raises: [].} =
  var
    number, a1, a2, a3, a4, a5, a6, callResult: clong
    source: cint
    address: culong
  let rc = cRawSyscallEventAt(clong(index), addr number, addr a1, addr a2,
    addr a3, addr a4, addr a5, addr a6, addr callResult, addr source,
    addr address)
  if rc != 0:
    return (false, 0.clong, 0.clong, 0.clong, 0.clong, 0.clong, 0.clong,
      0.clong, 0.clong, 0.cint, 0'u)
  (true, number, a1, a2, a3, a4, a5, a6, callResult, source, uint(address))

proc c_calloc(count, size: csize_t): pointer
  {.importc: "calloc", header: "<stdlib.h>", raises: [].}
proc c_free(p: pointer) {.importc: "free", header: "<stdlib.h>", raises: [].}
  # The C heap directly (in the shim, its own mmap-backed heap, never the
  # host's allocator — see `shim/linux_private_heap.c`), for scratch that is
  # allocated and freed within one hook call.

proc rangesIntersect(aStart, aStop, bStart, bStop: uint): bool {.inline, raises: [].} =
  aStart < bStop and bStart < aStop

proc isSuccessfulMmapResult*(value: pointer): bool {.inline, raises: [].} =
  value != nil and cast[int](value) != -1

proc isAnonymousPrivateMmap*(flags, fd: cint): bool {.inline, raises: [].} =
  (flags and linuxMapAnonymous) != 0 and (flags and linuxMapPrivate) != 0 and
    fd == -1

proc protIncludesExec*(prot: cint): bool {.inline, raises: [].} =
  (prot and linuxProtExec) != 0

proc protIncludesWrite*(prot: cint): bool {.inline, raises: [].} =
  (prot and linuxProtWrite) != 0

proc recordAnonymousPrivateMmap*(result: pointer; length: csize_t) {.raises: [].} =
  if not isSuccessfulMmapResult(result) or length == 0:
    return
  let start = cast[uint](result)
  let stop = start + uint(length)
  if stop <= start:
    return
  acquire(anonymousRangeLock)
  try:
    if anonymousExecutableRangeCount < anonymousRangeCap:
      anonymousExecutableRanges[anonymousExecutableRangeCount] =
        AnonymousExecutableRange(start: start, stop: stop)
      inc anonymousExecutableRangeCount
    else:
      # FUP-C — table full: drop the OLDEST tracked range (shift down by one)
      # and append the new one at the tail. Never allocates; at worst the
      # inline-syscall scanner loses visibility of a long-lived JIT range that
      # has since been superseded by ``anonymousRangeCap`` newer mappings.
      for i in 1 ..< anonymousRangeCap:
        anonymousExecutableRanges[i - 1] = anonymousExecutableRanges[i]
      anonymousExecutableRanges[anonymousRangeCap - 1] =
        AnonymousExecutableRange(start: start, stop: stop)
  finally:
    release(anonymousRangeLock)

proc removeAnonymousPrivateRange*(address: pointer; length: csize_t) {.raises: [].} =
  if address == nil or length == 0:
    return
  let removeStart = cast[uint](address)
  let removeStop = removeStart + uint(length)
  if removeStop <= removeStart:
    return
  acquire(anonymousRangeLock)
  try:
    # FUP-C — compact into a fixed array (no heap allocation) and copy back. A
    # range that straddles the removed interval can split into two halves, so
    # an over-cap output is truncated (safe: only under-reports). The array is
    # the lock-guarded `anonymousRangeScratch`, not a 64 KiB stack local.
    template updated: untyped = anonymousRangeScratch
    var updatedCount = 0
    template pushRange(r: AnonymousExecutableRange) =
      if updatedCount < anonymousRangeCap:
        updated[updatedCount] = r
        inc updatedCount
    for idx in 0 ..< anonymousExecutableRangeCount:
      let tracked = anonymousExecutableRanges[idx]
      if not rangesIntersect(removeStart, removeStop, tracked.start, tracked.stop):
        pushRange tracked
        continue
      if tracked.start < removeStart:
        pushRange AnonymousExecutableRange(
          start: tracked.start,
          stop: min(removeStart, tracked.stop))
      if removeStop < tracked.stop:
        pushRange AnonymousExecutableRange(
          start: max(removeStop, tracked.start),
          stop: tracked.stop)
    for i in 0 ..< updatedCount:
      anonymousExecutableRanges[i] = updated[i]
    anonymousExecutableRangeCount = updatedCount
  finally:
    release(anonymousRangeLock)

proc rangeFullyTrackedLocked(start, stop: uint): bool {.raises: [].} =
  if stop <= start:
    return false
  # FUP-C — collect intersections into a fixed array (no heap allocation) and
  # insertion-sort by start. Over-cap intersections are ignored; the coverage
  # check then conservatively returns "not fully tracked" for that range,
  # which is the safe direction. The caller holds `anonymousRangeLock`, which
  # is what makes the shared `anonymousRangeScratch` usable here (see it).
  template intersections: untyped = anonymousRangeScratch
  var intersectionCount = 0
  for idx in 0 ..< anonymousExecutableRangeCount:
    let tracked = anonymousExecutableRanges[idx]
    if rangesIntersect(start, stop, tracked.start, tracked.stop):
      if intersectionCount >= anonymousRangeCap:
        break
      let clipped = AnonymousExecutableRange(
        start: max(start, tracked.start),
        stop: min(stop, tracked.stop))
      # Insertion sort by ``start`` so the coverage sweep below is monotone.
      var j = intersectionCount
      while j > 0 and intersections[j - 1].start > clipped.start:
        intersections[j] = intersections[j - 1]
        dec j
      intersections[j] = clipped
      inc intersectionCount
  if intersectionCount == 0:
    return false
  var cursor = start
  for i in 0 ..< intersectionCount:
    let item = intersections[i]
    if item.start > cursor:
      return false
    if item.stop > cursor:
      cursor = item.stop
    if cursor >= stop:
      return true
  false

proc anonymousPrivateRangeFullyTracked*(address: pointer; length: csize_t): bool
    {.raises: [].} =
  if address == nil or length == 0:
    return false
  let start = cast[uint](address)
  let stop = start + uint(length)
  if stop <= start:
    return false
  acquire(anonymousRangeLock)
  try:
    result = rangeFullyTrackedLocked(start, stop)
  finally:
    release(anonymousRangeLock)

proc anonymousPrivateRangeIntersects*(address: pointer; length: csize_t): bool
    {.raises: [].} =
  if address == nil or length == 0:
    return false
  let start = cast[uint](address)
  let stop = start + uint(length)
  if stop <= start:
    return false
  acquire(anonymousRangeLock)
  try:
    for idx in 0 ..< anonymousExecutableRangeCount:
      let tracked = anonymousExecutableRanges[idx]
      if rangesIntersect(start, stop, tracked.start, tracked.stop):
        return true
  finally:
    release(anonymousRangeLock)

proc remapAnonymousPrivateRange*(oldAddress: pointer; oldSize: csize_t;
                                 newAddress: pointer; newSize: csize_t): bool
    {.raises: [].} =
  ## Returns true only when ownership was moved precisely for a fully tracked
  ## old interval. Partial ownership is dropped instead of widened.
  if oldAddress == nil or oldSize == 0:
    return false
  let oldStart = cast[uint](oldAddress)
  let oldStop = oldStart + uint(oldSize)
  if oldStop <= oldStart:
    return false
  acquire(anonymousRangeLock)
  try:
    result = rangeFullyTrackedLocked(oldStart, oldStop)
  finally:
    release(anonymousRangeLock)
  removeAnonymousPrivateRange(oldAddress, oldSize)
  if result:
    recordAnonymousPrivateMmap(newAddress, newSize)

proc mappingLooksOwnedAnonymousExecutable(mapping: LinuxExecutableMapping): bool
    {.raises: [].} =
  mapping.readable and mapping.executable and mapping.privateMapping and
    mapping.path.len == 0 and mapping.stop > mapping.start

proc trackedAnonymousRangeIntersects(start, stop: uint): bool
    {.raises: [].} =
  ## FUP-C — allocation-free replacement for the old
  ## ``trackedAnonymousIntersections(...).len > 0`` probe: the only caller
  ## needs to know whether ANY tracked range overlaps ``[start, stop)``.
  if stop <= start:
    return false
  acquire(anonymousRangeLock)
  try:
    for idx in 0 ..< anonymousExecutableRangeCount:
      let tracked = anonymousExecutableRanges[idx]
      if rangesIntersect(start, stop, tracked.start, tracked.stop):
        return true
  finally:
    release(anonymousRangeLock)

proc trackedAnonymousExecutableRangeExists*(start: pointer; length: csize_t): bool
    {.raises: [].} =
  if start == nil or length == 0:
    return false
  let rangeStart = cast[uint](start)
  let rangeStop = rangeStart + uint(length)
  trackedAnonymousRangeIntersects(rangeStart, rangeStop)

proc liveAnonymousExecutableMappingIntersects*(start: pointer; length: csize_t):
    bool {.raises: [].} =
  if start == nil or length == 0:
    return false
  let rangeStart = cast[uint](start)
  let rangeStop = rangeStart + uint(length)
  if rangeStop <= rangeStart:
    return false
  let mappings =
    try:
      enumerateLinuxExecutableMappings()
    except CatchableError:
      return false
  if mappings.diagnostic != lrsOk:
    return false
  for mapping in mappings.mappings:
    if mappingLooksOwnedAnonymousExecutable(mapping) and
        rangesIntersect(rangeStart, rangeStop, mapping.start, mapping.stop):
      return true

proc liveAnonymousExecutableCoverage*(start: pointer; length: csize_t):
    tuple[mapsAvailable: bool; liveIntersects: bool; fullyTracked: bool]
    {.raises: [].} =
  ## Describes the live anonymous executable bytes inside a requested range.
  ## fullyTracked is true only when every live executable anonymous byte in the
  ## requested range is covered by the current mmap lifecycle ownership table.
  result = (mapsAvailable: false, liveIntersects: false, fullyTracked: false)
  if start == nil or length == 0:
    return
  let rangeStart = cast[uint](start)
  let rangeStop = rangeStart + uint(length)
  if rangeStop <= rangeStart:
    return
  let mappings =
    try:
      enumerateLinuxExecutableMappings()
    except CatchableError:
      return
  if mappings.diagnostic != lrsOk:
    return
  result.mapsAvailable = true
  result.fullyTracked = true
  acquire(anonymousRangeLock)
  try:
    for mapping in mappings.mappings:
      if not mappingLooksOwnedAnonymousExecutable(mapping):
        continue
      if not rangesIntersect(rangeStart, rangeStop, mapping.start, mapping.stop):
        continue
      result.liveIntersects = true
      let intersectStart = max(rangeStart, mapping.start)
      let intersectStop = min(rangeStop, mapping.stop)
      if not rangeFullyTrackedLocked(intersectStart, intersectStop):
        result.fullyTracked = false
  finally:
    release(anonymousRangeLock)

proc installRawSyscallWrapperPatch*(): RawSyscallPatchStatus {.raises: [].} =
  # Interposed calls can initialise the shim before this module's ordinary
  # registration tail runs. Publish the real dispatcher before joining an
  # existing process-wide owner; a null callback cannot supply child evidence.
  installRawSyscallDispatcher(rawSyscallDispatcher)
  if rawSyscallPatchAttempted:
    return rawSyscallPatchStatus
  rawSyscallPatchAttempted = true
  result.diagnostic = linuxRawSyscallSupported()
  result.stage = lpsNone
  if result.diagnostic != lrsOk:
    rawSyscallPatchStatus = result
    return
  let target = resolveDefaultSymbol("syscall")
  result.target = target
  if target == nil:
    result.diagnostic = lrsSymbolNotFound
    rawSyscallPatchStatus = result
    return
  if cRawSyscallOwnerPrepare() == 0:
    result.diagnostic = lrsPatchWriteFailed
    rawSyscallPatchStatus = result
    return
  try:
    let tx = installAbsoluteJumpPatchTransaction(
      target, cast[pointer](rawSyscallReplacement), captureRestoreBytes = false)
    result.diagnostic = tx.diagnostic
    result.stage = tx.stage
    result.osErrno = tx.osErrno
    result.installed = tx.diagnostic == lrsOk or
      (tx.diagnostic == lrsPostPatchMprotectBackFailed and tx.patchLive)
    if result.installed:
      cRawSyscallOwnerCommit(target)
    elif tx.diagnostic == lrsAlreadyPatched and cRawSyscallOwnerJoin(target) != 0:
      result.installed = true
      result.diagnostic = lrsOk
  except CatchableError:
    result.diagnostic = lrsPatchWriteFailed
    result.stage = lpsWritePatch
  rawSyscallPatchStatus = result

proc rawSyscallWrapperPatchStatus*(): RawSyscallPatchStatus {.raises: [].} =
  rawSyscallPatchStatus

proc currentExecutablePath(): string {.raises: [].} =
  try:
    result = expandSymlink("/proc/self/exe")
  except CatchableError:
    result = ""

proc patchInlineSyscallMapping(mapping: LinuxExecutableMapping;
                               status: var InlineSyscallPatchStatus)
    {.raises: [].} =
  let statusPtr = addr status
  visitLinuxExecutableMappingSyscalls(mapping, proc(site: LinuxSyscallSite): bool =
    let tx = installInt3SyscallPatchTransaction(cast[pointer](site.address))
    if tx.diagnostic == lrsOk and tx.patchLive:
      if cInlineSyscallRecordSite(culong(site.address)) == 0:
        inc statusPtr[].patchedSites
    elif statusPtr[].firstPatchDiagnostic == lrsOk:
      statusPtr[].firstPatchDiagnostic = tx.diagnostic
      statusPtr[].firstPatchStage = tx.stage
      statusPtr[].firstPatchErrno = tx.osErrno
      statusPtr[].firstPatchAddress = site.address
    true
  )

proc installInlineSyscallPatches*(): InlineSyscallPatchStatus {.raises: [].}

proc patchOwnedAnonymousInlineSyscallRange(start, stop: uint;
                                           status: var InlineSyscallPatchStatus)
    {.raises: [].} =
  if stop <= start:
    return
  let span = stop - start
  if span > uint(linuxInlineAnonScanMaxBytes):
    if status.firstPatchDiagnostic == lrsOk:
      status.firstPatchDiagnostic = lrsInvalidArgument
      status.firstPatchStage = lpsNone
      status.firstPatchAddress = start
    return
  let mapping = LinuxExecutableMapping(
    start: start,
    stop: stop,
    readable: true,
    writable: false,
    executable: true,
    privateMapping: true,
    path: "")
  patchInlineSyscallMapping(mapping, status)

proc scanInlineSyscallPatchesForOwnedAnonymousRange*(start: pointer;
                                                     length: csize_t):
    InlineSyscallPatchStatus {.raises: [].} =
  ## Incremental JIT/anonymous scan for ranges whose ownership was established
  ## through io-mon's mmap wrapper. The startup installer owns handler setup.
  if length < 3:
    return inlineSyscallPatchStatus
  if not inlineSyscallPatchAttempted:
    discard installInlineSyscallPatches()
  var status = inlineSyscallPatchStatus
  if not status.handlerInstalled or status.scanDiagnostic != lrsOk:
    return status
  let rangeStart = cast[uint](start)
  let rangeStop = rangeStart + uint(length)
  patchOwnedAnonymousInlineSyscallRange(rangeStart, rangeStop, status)
  status.patchedSites = int(cInlineSyscallSiteCount())
  if cInlineSyscallOverflowed() != 0 and status.firstPatchDiagnostic == lrsOk:
    status.firstPatchDiagnostic = lrsInvalidArgument
  inlineSyscallPatchStatus = status
  status

proc scanInlineSyscallPatchesForTrackedMprotectRange*(start: pointer;
                                                      length: csize_t):
    InlineSyscallPatchStatus {.raises: [].} =
  ## Scan only live anonymous/private executable map entries that overlap a
  ## range previously created through the mmap wrapper.
  if length < 3:
    return inlineSyscallPatchStatus
  if not inlineSyscallPatchAttempted:
    discard installInlineSyscallPatches()
  var status = inlineSyscallPatchStatus
  if not status.handlerInstalled or status.scanDiagnostic != lrsOk:
    return status
  let requestedStart = cast[uint](start)
  let requestedStop = requestedStart + uint(length)
  # FUP-C — snapshot the intersecting tracked ranges under the lock, then
  # release the lock before the (potentially slow, procfs-reading) mapping
  # enumeration + patch loop.
  #
  # The snapshot used to be a 64 KiB stack array, which overflowed any host
  # thread with a stack of 64 KiB or less inside its mprotect hook. It cannot
  # use the lock-guarded `anonymousRangeScratch` either, because it must
  # outlive the lock. So it is sized exactly and taken from the C heap:
  # count under the lock, allocate OUTSIDE it (an allocation can mmap, and the
  # mmap hook takes `anonymousRangeLock`), then fill under the lock again.
  #
  # The table may change in between, and the snapshot must still be ONE
  # consistent view of it: a concurrent munmap of the middle of a tracked
  # range splits it in two, so the count can GROW with no new mmap behind it,
  # and a fill capped at the old count would silently skip the second half of
  # a range this mprotect made executable. So the fill re-counts under the
  # lock and, when the allocation is too small, retries with the new count. A
  # table that keeps outgrowing the allocation (or an allocation failure) is
  # reported as a scan failure for this call (the caller records the loss)
  # without poisoning the cached status for later calls. This path already
  # allocates (`enumerateLinuxExecutableMappings` returns a seq), so the heap
  # adds no new hazard.
  const maxSnapshotAttempts = 4
  var wanted = 0
  acquire(anonymousRangeLock)
  try:
    for idx in 0 ..< anonymousExecutableRangeCount:
      let r = anonymousExecutableRanges[idx]
      if rangesIntersect(requestedStart, requestedStop, r.start, r.stop):
        inc wanted
  finally:
    release(anonymousRangeLock)
  if wanted == 0:
    return status
  var tracked: ptr UncheckedArray[AnonymousExecutableRange] = nil
  var trackedCount = 0
  for _ in 0 ..< maxSnapshotAttempts:
    tracked = cast[ptr UncheckedArray[AnonymousExecutableRange]](
      c_calloc(csize_t(wanted), csize_t(sizeof(AnonymousExecutableRange))))
    if tracked == nil:
      break
    var present = 0
    trackedCount = 0
    acquire(anonymousRangeLock)
    try:
      for idx in 0 ..< anonymousExecutableRangeCount:
        let r = anonymousExecutableRanges[idx]
        if rangesIntersect(requestedStart, requestedStop, r.start, r.stop):
          if present < wanted:
            tracked[present] = AnonymousExecutableRange(
              start: max(requestedStart, r.start),
              stop: min(requestedStop, r.stop))
          inc present
    finally:
      release(anonymousRangeLock)
    if present <= wanted:
      trackedCount = present
      break
    # Outgrown since the count: free, resize, and take the snapshot again.
    c_free(tracked)
    tracked = nil
    wanted = present
  if tracked == nil:
    status.scanDiagnostic = lrsInvalidArgument
    return status
  defer: c_free(tracked)
  if trackedCount == 0:
    return status
  let mappings =
    try:
      enumerateLinuxExecutableMappings()
    except CatchableError:
      (diagnostic: lrsInvalidArgument, mappings: newSeq[LinuxExecutableMapping]())
  status.scanDiagnostic = mappings.diagnostic
  if mappings.diagnostic != lrsOk:
    inlineSyscallPatchStatus = status
    return status
  for mapping in mappings.mappings:
    if not mappingLooksOwnedAnonymousExecutable(mapping):
      continue
    for ti in 0 ..< trackedCount:
      let owned = tracked[ti]
      if not rangesIntersect(mapping.start, mapping.stop, owned.start, owned.stop):
        continue
      patchOwnedAnonymousInlineSyscallRange(
        max(mapping.start, owned.start),
        min(mapping.stop, owned.stop),
        status)
  status.patchedSites = int(cInlineSyscallSiteCount())
  if cInlineSyscallOverflowed() != 0 and status.firstPatchDiagnostic == lrsOk:
    status.firstPatchDiagnostic = lrsInvalidArgument
  inlineSyscallPatchStatus = status
  status

# M9.R.64.2 — `patchLibcExitFamilySyscalls` was removed as a real
# regression. See the M9.R.64.2 note at the (former) call site in
# `installInlineSyscallPatches` below.

proc installInlineSyscallPatches*(): InlineSyscallPatchStatus {.raises: [].} =
  if inlineSyscallPatchAttempted:
    return inlineSyscallPatchStatus
  inlineSyscallPatchAttempted = true
  var status = InlineSyscallPatchStatus(
    attempted: true,
    scanDiagnostic: linuxRawSyscallSupported(),
    installDiagnostic: lrsInvalidArgument,
    firstPatchDiagnostic: lrsOk,
    firstPatchStage: lpsNone)
  if status.scanDiagnostic != lrsOk:
    inlineSyscallPatchStatus = status
    return status

  cInlineSyscallReset()
  let handler = cInlineSyscallHandlerAddress()
  if handler == nil:
    status.installDiagnostic = lrsInvalidArgument
    inlineSyscallPatchStatus = status
    return status
  status.installDiagnostic = installLinuxSigtrapHandler(handler)
  status.handlerInstalled = status.installDiagnostic == lrsOk
  if not status.handlerInstalled:
    inlineSyscallPatchStatus = status
    return status

  let executablePath = currentExecutablePath()
  let mappings =
    try:
      enumerateLinuxExecutableMappings()
    except CatchableError:
      (diagnostic: lrsInvalidArgument, mappings: newSeq[LinuxExecutableMapping]())
  status.scanDiagnostic = mappings.diagnostic
  if mappings.diagnostic != lrsOk:
    inlineSyscallPatchStatus = status
    return status

  for mapping in mappings.mappings:
    if not shouldPatchInlineSyscallMapping(mapping, executablePath):
      continue
    patchInlineSyscallMapping(mapping, status)
  # M9.R.64.2 revert of M9.R.63.5 — the targeted INT3 patch on libc's
  # `_exit` / `_Exit` inline syscalls caused clang to die with SIGTRAP
  # (WIFSIGNALED, exit code 128+5) on its LLVM crash-handler path, which
  # calls `_exit(N)` from within an already-active SIGSEGV handler
  # (nested signal delivery). The nested SIGTRAP was NOT dispatched by
  # our handler on all pixman `cc` invocations — clang exited with the
  # raw signal, breaking every Nim provider compile. Reproduced 24
  # crashes per pixman build with the M9.R.63.5 pin against the pixman
  # workload on WSL; falsified as regression by testing the M9.R.63.3
  # baseline in the same environment (zero clang crashes).
  #
  # The M9.R.63.5 patch was defensive — it targeted an escape class that
  # M9.R.63.7's close-out already documented as NOT closing the 182
  # kill-before-flush residual. The M9.R.64 attribution phase (with
  # `IO_MON_KILL_DIAG_DEEP=1`) attributes the residual to a DIFFERENT
  # class (parent-driven SIGKILL of bash+cc children from nim's
  # parallel-compile driver — see recipes/reproos-image/run-evidence/
  # m9r64/m9r64_complete.txt). So the M9.R.63.5 patch is retired: it
  # never closed any real escape and it broke every clang invocation.
  #
  # The M9.R.63.3 SIGTRAP-flush wiring in
  # `ct_linux_inline_syscall_sigtrap_handler` stays — it correctly
  # handles inline-asm `syscall #exit_group` from USER-CODE mappings
  # (tests/linux/test_io_mon_linux_inline_asm_exit_group.nim regression
  # test still passes). The gap being retired is only the libc-
  # symbol-targeted variant.
  status.patchedSites = int(cInlineSyscallSiteCount())
  if cInlineSyscallOverflowed() != 0 and status.firstPatchDiagnostic == lrsOk:
    status.firstPatchDiagnostic = lrsInvalidArgument
  inlineSyscallPatchStatus = status
  status

proc scanInlineSyscallPatchesForNewMappings*(): InlineSyscallPatchStatus
    {.raises: [].} =
  ## Incremental post-loader scan. The startup installer owns handler setup and
  ## event-buffer initialization; this pass must not reset either, because a
  ## dlopen hook can run after earlier inline raw syscalls have already trapped.
  if not inlineSyscallPatchAttempted:
    return installInlineSyscallPatches()
  var status = inlineSyscallPatchStatus
  if not status.handlerInstalled or status.scanDiagnostic != lrsOk:
    return status
  let executablePath = currentExecutablePath()
  let mappings =
    try:
      enumerateLinuxExecutableMappings()
    except CatchableError:
      (diagnostic: lrsInvalidArgument, mappings: newSeq[LinuxExecutableMapping]())
  status.scanDiagnostic = mappings.diagnostic
  if mappings.diagnostic != lrsOk:
    inlineSyscallPatchStatus = status
    return status
  for mapping in mappings.mappings:
    if not shouldPatchInlineSyscallMapping(mapping, executablePath):
      continue
    patchInlineSyscallMapping(mapping, status)
  status.patchedSites = int(cInlineSyscallSiteCount())
  if cInlineSyscallOverflowed() != 0 and status.firstPatchDiagnostic == lrsOk:
    status.firstPatchDiagnostic = lrsInvalidArgument
  inlineSyscallPatchStatus = status
  status

proc inlineSyscallPatchInstallStatus*(): InlineSyscallPatchStatus {.raises: [].} =
  inlineSyscallPatchStatus

proc inlineSyscallTrapCount*(): int {.raises: [].} =
  int(cInlineSyscallTrapCount())

proc inlineSyscallFailureCount*(): int {.raises: [].} =
  int(cInlineSyscallFailureCount())

proc inlineSyscallLastNumber*(): int {.raises: [].} =
  int(cInlineSyscallLastNr())

proc inlineSyscallLastAddress*(): uint {.raises: [].} =
  uint(cInlineSyscallLastAddress())

proc callReal*(ctx: var OpenContext) {.raises: [].} =
  case ctx.symbol
  of lhsOpen64:
    ctx.result = realOpen64(ctx.path, ctx.flags, ctx.mode)
  else:
    ctx.result = realOpen(ctx.path, ctx.flags, ctx.mode)

proc callReal*(ctx: var OpenatContext) {.raises: [].} =
  case ctx.symbol
  of lhsOpenat64:
    ctx.result = realOpenat64(ctx.dirfd, ctx.path, ctx.flags, ctx.mode)
  else:
    ctx.result = realOpenat(ctx.dirfd, ctx.path, ctx.flags, ctx.mode)

proc callReal*(ctx: var CloseContext) {.raises: [].} =
  ctx.result = realClose(ctx.fd)

proc callReal*(ctx: var ReadContext) {.raises: [].} =
  ctx.result = realRead(ctx.fd, ctx.buf, ctx.count)

proc callReal*(ctx: var PreadContext) {.raises: [].} =
  ctx.result = realPread(ctx.fd, ctx.buf, ctx.count, ctx.offset)

proc callReal*(ctx: var ReadvContext) {.raises: [].} =
  ctx.result = realReadv(ctx.fd, ctx.iov, ctx.iovcnt)

proc callReal*(ctx: var PreadvContext) {.raises: [].} =
  ctx.result = realPreadv(ctx.fd, ctx.iov, ctx.iovcnt, ctx.offset)

proc callReal*(ctx: var WriteContext) {.raises: [].} =
  ctx.result = realWrite(ctx.fd, ctx.buf, ctx.count)

proc callReal*(ctx: var StatContext) {.raises: [].} =
  case ctx.symbol
  of lhsLstat:
    ctx.result = realLstat(ctx.path, ctx.buf)
  else:
    ctx.result = realStat(ctx.path, ctx.buf)

proc callReal*(ctx: var OpendirContext) {.raises: [].} =
  ctx.result = realOpendir(ctx.path)

proc callReal*(ctx: var ReaddirContext) {.raises: [].} =
  ctx.result = realReaddir(ctx.dirp)

proc callReal*(ctx: var ClosedirContext) {.raises: [].} =
  ctx.result = realClosedir(ctx.dirp)

proc callReal*(ctx: var FopenContext) {.raises: [].} =
  case ctx.symbol
  of lhsFopen64:
    ctx.result = realFopen64(ctx.path, ctx.mode)
  else:
    ctx.result = realFopen(ctx.path, ctx.mode)

proc callReal*(ctx: var FreadContext) {.raises: [].} =
  ctx.result = realFread(ctx.data, ctx.size, ctx.nmemb, ctx.stream)

proc callReal*(ctx: var FcloseContext) {.raises: [].} =
  ctx.result = realFclose(ctx.stream)

proc callReal*(ctx: var ConnectContext) {.raises: [].} =
  ctx.result = realConnect(ctx.fd, ctx.address, ctx.addrLen)

proc callReal*(ctx: var PipeContext) {.raises: [].} =
  ctx.result = realPipe(ctx.fds)

proc callReal*(ctx: var Pipe2Context) {.raises: [].} =
  ctx.result = realPipe2(ctx.fds, ctx.flags)

proc callReal*(ctx: var SocketpairContext) {.raises: [].} =
  ctx.result = realSocketpair(ctx.domain, ctx.typ, ctx.protocol, ctx.sv)

proc callReal*(ctx: var SendfileContext) {.raises: [].} =
  ctx.result = realSendfile(ctx.outFd, ctx.inFd, ctx.offset, ctx.count)

proc callReal*(ctx: var CopyFileRangeContext) {.raises: [].} =
  ctx.result = realCopyFileRange(ctx.inFd, ctx.offIn, ctx.outFd, ctx.offOut,
    ctx.length, ctx.flags)

proc callReal*(ctx: var SpliceContext) {.raises: [].} =
  ctx.result = realSplice(ctx.fdIn, ctx.offIn, ctx.fdOut, ctx.offOut,
    ctx.length, ctx.flags)

proc callReal*(ctx: var LinkContext) {.raises: [].} =
  ctx.result = realLink(ctx.oldPath, ctx.newPath)

proc callReal*(ctx: var LinkatContext) {.raises: [].} =
  ctx.result = realLinkat(ctx.oldDirfd, ctx.oldPath, ctx.newDirfd,
    ctx.newPath, ctx.flags)

proc callReal*(ctx: var RenameContext) {.raises: [].} =
  ctx.result = realRename(ctx.oldPath, ctx.newPath)

proc callReal*(ctx: var RenameatContext) {.raises: [].} =
  case ctx.symbol
  of lhsRenameat2:
    ctx.result = realRenameat2(ctx.oldDirfd, ctx.oldPath, ctx.newDirfd,
      ctx.newPath, ctx.flags)
  else:
    ctx.result = realRenameat(ctx.oldDirfd, ctx.oldPath, ctx.newDirfd,
      ctx.newPath)

proc callReal*(ctx: var DlopenContext) {.raises: [].} =
  ctx.result = realDlopen(ctx.path, ctx.flags)

proc callReal*(ctx: var DlmopenContext) {.raises: [].} =
  ctx.result = realDlmopen(ctx.namespaceId, ctx.path, ctx.flags)

proc callReal*(ctx: var DlsymContext) {.raises: [].} =
  ctx.result = realDlsym(ctx.handle, ctx.name)

proc callReal*(ctx: var MmapContext) {.raises: [].} =
  ctx.result = realMmap(ctx.address, ctx.length, ctx.prot, ctx.flags, ctx.fd,
    ctx.offset)

proc callReal*(ctx: var MprotectContext) {.raises: [].} =
  ctx.result = realMprotect(ctx.address, ctx.length, ctx.prot)

proc callReal*(ctx: var MunmapContext) {.raises: [].} =
  ctx.result = realMunmap(ctx.address, ctx.length)

proc callReal*(ctx: var MremapContext) {.raises: [].} =
  ctx.result = realMremap(ctx.oldAddress, ctx.oldSize, ctx.newSize, ctx.flags,
    ctx.newAddress)

proc callReal*(ctx: var GetenvContext) {.raises: [].} =
  ctx.result = realGetenv(ctx.name)

proc callReal*(ctx: var UnameContext) {.raises: [].} =
  ctx.result = realUname(ctx.buf)

proc callReal*(ctx: var SysconfContext) {.raises: [].} =
  ctx.result = realSysconf(ctx.name)

proc callReal*(ctx: var ClockGettimeContext) {.raises: [].} =
  ctx.result = realClockGettime(ctx.clockId, ctx.timespecPtr)

proc callReal*(ctx: var GettimeofdayContext) {.raises: [].} =
  ctx.result = realGettimeofday(ctx.timevalPtr, ctx.timezonePtr)

proc callReal*(ctx: var TimeContext) {.raises: [].} =
  ctx.result = realTime(ctx.timePtr)

proc callReal*(ctx: var GetrandomContext) {.raises: [].} =
  ctx.result = realGetrandom(ctx.buf, ctx.buflen, ctx.flags)

proc callReal*(ctx: var EntropyContext) {.raises: [].} =
  case ctx.source
  of lesGetentropy:
    ctx.result = realGetentropy(ctx.buf, ctx.length)
  of lesArc4random:
    ctx.value = realArc4random()
  of lesArc4randomBuf:
    realArc4randomBuf(ctx.buf, ctx.length)
  of lesArc4randomUniform:
    ctx.value = realArc4randomUniform(ctx.upper)

proc callReal*(ctx: var ForkContext) {.raises: [].} =
  ctx.result = realFork()

proc callReal*(ctx: var ExecveContext) {.raises: [].} =
  ctx.result = realExecve(ctx.path, ctx.argv, ctx.envp)

proc callReal*(ctx: var PosixSpawnContext) {.raises: [].} =
  case ctx.symbol
  of lhsPosixSpawnp:
    ctx.result = realPosixSpawnp(ctx.pid, ctx.path, ctx.fileActions,
                                 ctx.attrp, ctx.argv, ctx.envp)
  else:
    ctx.result = realPosixSpawn(ctx.pid, ctx.path, ctx.fileActions,
                                ctx.attrp, ctx.argv, ctx.envp)

proc callReal*(ctx: var ExitContext) {.raises: [], noreturn.} =
  realExit(ctx.status)

proc callNext*(ctx: var OpenContext) {.raises: [].} =
  case ctx.symbol
  of lhsOpen64:
    if ctx.nextIndex < open64Hooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      open64Hooks[index].callback(ctx)
    else:
      callReal(ctx)
  else:
    if ctx.nextIndex < openHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      openHooks[index].callback(ctx)
    else:
      callReal(ctx)

proc callNext*(ctx: var OpenatContext) {.raises: [].} =
  case ctx.symbol
  of lhsOpenat64:
    if ctx.nextIndex < openat64Hooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      openat64Hooks[index].callback(ctx)
    else:
      callReal(ctx)
  else:
    if ctx.nextIndex < openatHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      openatHooks[index].callback(ctx)
    else:
      callReal(ctx)

proc callNext*(ctx: var CloseContext) {.raises: [].} =
  if ctx.nextIndex < closeHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    closeHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ReadContext) {.raises: [].} =
  if ctx.nextIndex < readHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    readHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var PreadContext) {.raises: [].} =
  if ctx.nextIndex < preadHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    preadHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ReadvContext) {.raises: [].} =
  if ctx.nextIndex < readvHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    readvHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var PreadvContext) {.raises: [].} =
  if ctx.nextIndex < preadvHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    preadvHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var WriteContext) {.raises: [].} =
  if ctx.nextIndex < writeHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    writeHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var StatContext) {.raises: [].} =
  case ctx.symbol
  of lhsLstat:
    if ctx.nextIndex < lstatHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      lstatHooks[index].callback(ctx)
    else:
      callReal(ctx)
  else:
    if ctx.nextIndex < statHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      statHooks[index].callback(ctx)
    else:
      callReal(ctx)

proc callNext*(ctx: var OpendirContext) {.raises: [].} =
  if ctx.nextIndex < opendirHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    opendirHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ReaddirContext) {.raises: [].} =
  if ctx.nextIndex < readdirHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    readdirHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ClosedirContext) {.raises: [].} =
  if ctx.nextIndex < closedirHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    closedirHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var FopenContext) {.raises: [].} =
  case ctx.symbol
  of lhsFopen64:
    if ctx.nextIndex < fopen64Hooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      fopen64Hooks[index].callback(ctx)
    else:
      callReal(ctx)
  else:
    if ctx.nextIndex < fopenHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      fopenHooks[index].callback(ctx)
    else:
      callReal(ctx)

proc callNext*(ctx: var FreadContext) {.raises: [].} =
  if ctx.nextIndex < freadHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    freadHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var FcloseContext) {.raises: [].} =
  if ctx.nextIndex < fcloseHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    fcloseHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ConnectContext) {.raises: [].} =
  if ctx.nextIndex < connectHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    connectHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var PipeContext) {.raises: [].} =
  if ctx.nextIndex < pipeHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    pipeHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var Pipe2Context) {.raises: [].} =
  if ctx.nextIndex < pipe2Hooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    pipe2Hooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var SocketpairContext) {.raises: [].} =
  if ctx.nextIndex < socketpairHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    socketpairHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var SendfileContext) {.raises: [].} =
  if ctx.nextIndex < sendfileHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    sendfileHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var CopyFileRangeContext) {.raises: [].} =
  if ctx.nextIndex < copyFileRangeHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    copyFileRangeHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var SpliceContext) {.raises: [].} =
  if ctx.nextIndex < spliceHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    spliceHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var LinkContext) {.raises: [].} =
  if ctx.nextIndex < linkHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    linkHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var LinkatContext) {.raises: [].} =
  if ctx.nextIndex < linkatHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    linkatHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var RenameContext) {.raises: [].} =
  if ctx.nextIndex < renameHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    renameHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var RenameatContext) {.raises: [].} =
  case ctx.symbol
  of lhsRenameat2:
    if ctx.nextIndex < renameat2Hooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      renameat2Hooks[index].callback(ctx)
    else:
      callReal(ctx)
  else:
    if ctx.nextIndex < renameatHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      renameatHooks[index].callback(ctx)
    else:
      callReal(ctx)

proc callNext*(ctx: var DlopenContext) {.raises: [].} =
  if ctx.nextIndex < dlopenHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    dlopenHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var DlsymContext) {.raises: [].} =
  if ctx.nextIndex < dlsymHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    dlsymHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var DlmopenContext) {.raises: [].} =
  if ctx.nextIndex < dlmopenHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    dlmopenHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var MmapContext) {.raises: [].} =
  if ctx.nextIndex < mmapHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    mmapHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var MprotectContext) {.raises: [].} =
  if ctx.nextIndex < mprotectHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    mprotectHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var MunmapContext) {.raises: [].} =
  if ctx.nextIndex < munmapHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    munmapHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var MremapContext) {.raises: [].} =
  if ctx.nextIndex < mremapHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    mremapHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var GetenvContext) {.raises: [].} =
  if ctx.nextIndex < getenvHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    getenvHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var UnameContext) {.raises: [].} =
  if ctx.nextIndex < unameHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    unameHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var SysconfContext) {.raises: [].} =
  if ctx.nextIndex < sysconfHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    sysconfHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ClockGettimeContext) {.raises: [].} =
  if ctx.nextIndex < clockGettimeHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    clockGettimeHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var GettimeofdayContext) {.raises: [].} =
  if ctx.nextIndex < gettimeofdayHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    gettimeofdayHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var TimeContext) {.raises: [].} =
  if ctx.nextIndex < timeHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    timeHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var GetrandomContext) {.raises: [].} =
  if ctx.nextIndex < getrandomHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    getrandomHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var EntropyContext) {.raises: [].} =
  if ctx.nextIndex < entropyHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    entropyHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ForkContext) {.raises: [].} =
  if ctx.nextIndex < forkHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    forkHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var ExecveContext) {.raises: [].} =
  if ctx.nextIndex < execveHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    execveHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc callNext*(ctx: var PosixSpawnContext) {.raises: [].} =
  case ctx.symbol
  of lhsPosixSpawnp:
    if ctx.nextIndex < posixSpawnpHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      posixSpawnpHooks[index].callback(ctx)
    else:
      callReal(ctx)
  else:
    if ctx.nextIndex < posixSpawnHooks.len:
      let index = ctx.nextIndex
      inc ctx.nextIndex
      posixSpawnHooks[index].callback(ctx)
    else:
      callReal(ctx)

proc callNext*(ctx: var ExitContext) {.raises: [].} =
  if ctx.nextIndex < exitHooks.len:
    let index = ctx.nextIndex
    inc ctx.nextIndex
    exitHooks[index].callback(ctx)
  else:
    callReal(ctx)

proc dispatchOpen(path: cstring; flags, mode: cint): cint {.cdecl, raises: [].} =
  var ctx = OpenContext(path: path, flags: flags, mode: mode, result: -1,
                        symbol: lhsOpen)
  callNext(ctx)
  result = ctx.result

proc dispatchOpen64(path: cstring; flags, mode: cint): cint {.cdecl, raises: [].} =
  var ctx = OpenContext(path: path, flags: flags, mode: mode, result: -1,
                        symbol: lhsOpen64)
  callNext(ctx)
  result = ctx.result

proc dispatchOpenat(dirfd: cint; path: cstring; flags, mode: cint): cint
    {.cdecl, raises: [].} =
  var ctx = OpenatContext(dirfd: dirfd, path: path, flags: flags, mode: mode,
                          result: -1, symbol: lhsOpenat)
  callNext(ctx)
  result = ctx.result

proc dispatchOpenat64(dirfd: cint; path: cstring; flags, mode: cint): cint
    {.cdecl, raises: [].} =
  var ctx = OpenatContext(dirfd: dirfd, path: path, flags: flags, mode: mode,
                          result: -1, symbol: lhsOpenat64)
  callNext(ctx)
  result = ctx.result

proc dispatchClose(fd: cint): cint {.cdecl, raises: [].} =
  var ctx = CloseContext(fd: fd, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchRead(fd: cint; buf: pointer; count: csize_t): clong
    {.cdecl, raises: [].} =
  var ctx = ReadContext(fd: fd, buf: buf, count: count, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchPread(fd: cint; buf: pointer; count: csize_t;
                   offset: clong): clong {.cdecl, raises: [].} =
  var ctx = PreadContext(fd: fd, buf: buf, count: count, offset: offset,
                         result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchReadv(fd: cint; iov: pointer; iovcnt: cint): clong
    {.cdecl, raises: [].} =
  var ctx = ReadvContext(fd: fd, iov: iov, iovcnt: iovcnt, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchPreadv(fd: cint; iov: pointer; iovcnt: cint;
                    offset: clong): clong {.cdecl, raises: [].} =
  var ctx = PreadvContext(fd: fd, iov: iov, iovcnt: iovcnt, offset: offset,
                          result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchWrite(fd: cint; buf: pointer; count: csize_t): clong
    {.cdecl, raises: [].} =
  var ctx = WriteContext(fd: fd, buf: buf, count: count, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchStat(path: cstring; buf: pointer): cint {.cdecl, raises: [].} =
  var ctx = StatContext(path: path, buf: buf, result: -1, symbol: lhsStat)
  callNext(ctx)
  result = ctx.result

proc dispatchLstat(path: cstring; buf: pointer): cint {.cdecl, raises: [].} =
  var ctx = StatContext(path: path, buf: buf, result: -1, symbol: lhsLstat)
  callNext(ctx)
  result = ctx.result

proc dispatchOpendir(path: cstring): pointer {.cdecl, raises: [].} =
  var ctx = OpendirContext(path: path, result: nil)
  callNext(ctx)
  result = ctx.result

proc dispatchReaddir(dirp: pointer): pointer {.cdecl, raises: [].} =
  var ctx = ReaddirContext(dirp: dirp, result: nil)
  callNext(ctx)
  result = ctx.result

proc dispatchClosedir(dirp: pointer): cint {.cdecl, raises: [].} =
  var ctx = ClosedirContext(dirp: dirp, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchFopen(path, mode: cstring): pointer {.cdecl, raises: [].} =
  var ctx = FopenContext(path: path, mode: mode, result: nil, symbol: lhsFopen)
  callNext(ctx)
  result = ctx.result

proc dispatchFopen64(path, mode: cstring): pointer {.cdecl, raises: [].} =
  var ctx = FopenContext(path: path, mode: mode, result: nil, symbol: lhsFopen64)
  callNext(ctx)
  result = ctx.result

proc dispatchFread(buf: pointer; size, nmemb: csize_t; stream: pointer): csize_t
    {.cdecl, raises: [].} =
  var ctx = FreadContext(data: buf, size: size, nmemb: nmemb, stream: stream,
                         result: 0)
  callNext(ctx)
  result = ctx.result

proc dispatchFclose(stream: pointer): cint {.cdecl, raises: [].} =
  var ctx = FcloseContext(stream: stream, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchConnect(fd: cint; address: pointer; addrLen: uint32): cint
    {.cdecl, raises: [].} =
  var ctx = ConnectContext(fd: fd, address: address, addrLen: addrLen,
                           result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchPipe(fds: pointer): cint {.cdecl, raises: [].} =
  var ctx = PipeContext(fds: cast[ptr cint](fds), result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchPipe2(fds: pointer; flags: cint): cint {.cdecl, raises: [].} =
  var ctx = Pipe2Context(fds: cast[ptr cint](fds), flags: flags, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchSocketpair(domain, typ, protocol: cint; sv: pointer): cint
    {.cdecl, raises: [].} =
  var ctx = SocketpairContext(domain: domain, typ: typ, protocol: protocol,
                              sv: cast[ptr cint](sv), result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchSendfile(outFd, inFd: cint; offset: pointer;
                      count: csize_t): clong {.cdecl, raises: [].} =
  var ctx = SendfileContext(outFd: outFd, inFd: inFd, offset: offset,
                            count: count, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchCopyFileRange(inFd: cint; offIn: pointer; outFd: cint;
                           offOut: pointer; length: csize_t;
                           flags: cuint): clong {.cdecl, raises: [].} =
  var ctx = CopyFileRangeContext(inFd: inFd, offIn: offIn, outFd: outFd,
                                 offOut: offOut, length: length,
                                 flags: flags, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchSplice(fdIn: cint; offIn: pointer; fdOut: cint; offOut: pointer;
                    length: csize_t; flags: cuint): clong
    {.cdecl, raises: [].} =
  var ctx = SpliceContext(fdIn: fdIn, offIn: offIn, fdOut: fdOut,
                          offOut: offOut, length: length, flags: flags,
                          result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchLink(oldPath, newPath: cstring): cint {.cdecl, raises: [].} =
  var ctx = LinkContext(oldPath: oldPath, newPath: newPath, result: -1,
                        symbol: lhsLink)
  callNext(ctx)
  result = ctx.result

proc dispatchLinkat(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                    newPath: cstring; flags: cint): cint
    {.cdecl, raises: [].} =
  var ctx = LinkatContext(oldDirfd: oldDirfd, oldPath: oldPath,
                          newDirfd: newDirfd, newPath: newPath, flags: flags,
                          result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchRename(oldPath, newPath: cstring): cint {.cdecl, raises: [].} =
  var ctx = RenameContext(oldPath: oldPath, newPath: newPath, result: -1,
                          symbol: lhsRename)
  callNext(ctx)
  result = ctx.result

proc dispatchRenameat(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                      newPath: cstring): cint {.cdecl, raises: [].} =
  var ctx = RenameatContext(oldDirfd: oldDirfd, oldPath: oldPath,
                            newDirfd: newDirfd, newPath: newPath, flags: 0,
                            result: -1, symbol: lhsRenameat)
  callNext(ctx)
  result = ctx.result

proc dispatchRenameat2(oldDirfd: cint; oldPath: cstring; newDirfd: cint;
                       newPath: cstring; flags: cuint): cint
    {.cdecl, raises: [].} =
  var ctx = RenameatContext(oldDirfd: oldDirfd, oldPath: oldPath,
                            newDirfd: newDirfd, newPath: newPath,
                            flags: flags, result: -1, symbol: lhsRenameat2)
  callNext(ctx)
  result = ctx.result

proc dispatchDlopen(path: cstring; flags: cint): pointer {.cdecl, raises: [].} =
  var ctx = DlopenContext(path: path, flags: flags, result: nil)
  callNext(ctx)
  result = ctx.result

proc dispatchDlmopen(namespaceId: clong; path: cstring; flags: cint): pointer
    {.cdecl, raises: [].} =
  var ctx = DlmopenContext(namespaceId: namespaceId, path: path, flags: flags,
                           result: nil)
  callNext(ctx)
  result = ctx.result

proc dispatchDlsym(handle: pointer; name: cstring): pointer
    {.cdecl, raises: [].} =
  var ctx = DlsymContext(handle: handle, name: name, result: nil)
  callNext(ctx)
  result = ctx.result

proc dispatchMmap(address: pointer; length: csize_t; prot, flags, fd: cint;
                  offset: clong): pointer {.cdecl, raises: [].} =
  var ctx = MmapContext(address: address, length: length, prot: prot, flags: flags,
                        fd: fd, offset: offset, result: cast[pointer](-1))
  callNext(ctx)
  result = ctx.result

proc dispatchMprotect(address: pointer; length: csize_t; prot: cint): cint
    {.cdecl, raises: [].} =
  var ctx = MprotectContext(address: address, length: length, prot: prot, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchMunmap(address: pointer; length: csize_t): cint
    {.cdecl, raises: [].} =
  var ctx = MunmapContext(address: address, length: length, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchMremap(oldAddress: pointer; oldSize, newSize: csize_t;
                    flags: cint; newAddress: pointer): pointer
    {.cdecl, raises: [].} =
  var ctx = MremapContext(oldAddress: oldAddress, oldSize: oldSize,
                          newSize: newSize, flags: flags,
                          newAddress: newAddress, result: cast[pointer](-1))
  callNext(ctx)
  result = ctx.result

proc dispatchGetenv(name: cstring): cstring {.cdecl, raises: [].} =
  var ctx = GetenvContext(name: name, result: nil)
  callNext(ctx)
  result = ctx.result

proc dispatchUname(buf: pointer): cint {.cdecl, raises: [].} =
  var ctx = UnameContext(buf: buf, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchSysconf(name: cint): clong {.cdecl, raises: [].} =
  var ctx = SysconfContext(name: name, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchClockGettime(clockId: cint; timespecPtr: pointer): cint
    {.cdecl, raises: [].} =
  var ctx = ClockGettimeContext(clockId: clockId, timespecPtr: timespecPtr,
                                result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchGettimeofday(timevalPtr, timezonePtr: pointer): cint
    {.cdecl, raises: [].} =
  var ctx = GettimeofdayContext(timevalPtr: timevalPtr,
                                timezonePtr: timezonePtr, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchTime(timePtr: pointer): clong {.cdecl, raises: [].} =
  var ctx = TimeContext(timePtr: timePtr, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchGetrandom(buf: pointer; buflen: csize_t; flags: cuint): clong
    {.cdecl, raises: [].} =
  var ctx = GetrandomContext(buf: buf, buflen: buflen, flags: flags, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchGetentropy(buf: pointer; length: csize_t): cint
    {.cdecl, raises: [].} =
  var ctx = EntropyContext(source: lesGetentropy, buf: buf, length: length,
                           result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchArc4random(): cuint {.cdecl, raises: [].} =
  var ctx = EntropyContext(source: lesArc4random)
  callNext(ctx)
  result = ctx.value

proc dispatchArc4randomBuf(buf: pointer; length: csize_t) {.cdecl, raises: [].} =
  var ctx = EntropyContext(source: lesArc4randomBuf, buf: buf, length: length)
  callNext(ctx)

proc dispatchArc4randomUniform(upper: cuint): cuint {.cdecl, raises: [].} =
  var ctx = EntropyContext(source: lesArc4randomUniform, upper: upper)
  callNext(ctx)
  result = ctx.value

proc dispatchFork(): PidT {.cdecl, raises: [].} =
  var ctx = ForkContext(result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchExecve(path: cstring; argv, envp: cstringArray): cint
    {.cdecl, raises: [].} =
  var ctx = ExecveContext(path: path, argv: argv, envp: envp, result: -1)
  callNext(ctx)
  result = ctx.result

proc dispatchPosixSpawn(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                        argv, envp: cstringArray): cint {.cdecl, raises: [].} =
  var ctx = PosixSpawnContext(pid: pid, path: path, fileActions: fileActions,
                              attrp: attrp, argv: argv, envp: envp, result: -1,
                              symbol: lhsPosixSpawn)
  callNext(ctx)
  result = ctx.result

proc dispatchPosixSpawnp(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                         argv, envp: cstringArray): cint {.cdecl, raises: [].} =
  var ctx = PosixSpawnContext(pid: pid, path: path, fileActions: fileActions,
                              attrp: attrp, argv: argv, envp: envp, result: -1,
                              symbol: lhsPosixSpawnp)
  callNext(ctx)
  result = ctx.result

proc dispatchExit(status: cint) {.cdecl, raises: [].} =
  var ctx = ExitContext(status: status)
  callNext(ctx)

installOpenDispatcher(dispatchOpen)
installOpen64Dispatcher(dispatchOpen64)
installOpenatDispatcher(dispatchOpenat)
installOpenat64Dispatcher(dispatchOpenat64)
installCloseDispatcher(dispatchClose)
installReadDispatcher(dispatchRead)
installPreadDispatcher(dispatchPread)
installReadvDispatcher(dispatchReadv)
installPreadvDispatcher(dispatchPreadv)
installWriteDispatcher(dispatchWrite)
installStatDispatcher(dispatchStat)
installLstatDispatcher(dispatchLstat)
installOpendirDispatcher(dispatchOpendir)
installReaddirDispatcher(dispatchReaddir)
installClosedirDispatcher(dispatchClosedir)
installFopenDispatcher(dispatchFopen)
installFopen64Dispatcher(dispatchFopen64)
installFreadDispatcher(dispatchFread)
installFcloseDispatcher(dispatchFclose)
installConnectDispatcher(dispatchConnect)
installPipeDispatcher(dispatchPipe)
installPipe2Dispatcher(dispatchPipe2)
installSocketpairDispatcher(dispatchSocketpair)
installSendfileDispatcher(dispatchSendfile)
installCopyFileRangeDispatcher(dispatchCopyFileRange)
installSpliceDispatcher(dispatchSplice)
installLinkDispatcher(dispatchLink)
installLinkatDispatcher(dispatchLinkat)
installRenameDispatcher(dispatchRename)
installRenameatDispatcher(dispatchRenameat)
installRenameat2Dispatcher(dispatchRenameat2)
installDlopenDispatcher(dispatchDlopen)
installDlmopenDispatcher(dispatchDlmopen)
installDlsymDispatcher(dispatchDlsym)
installMmapDispatcher(dispatchMmap)
installMprotectDispatcher(dispatchMprotect)
installMunmapDispatcher(dispatchMunmap)
installMremapDispatcher(dispatchMremap)
installGetenvDispatcher(dispatchGetenv)
installUnameDispatcher(dispatchUname)
installSysconfDispatcher(dispatchSysconf)
installClockGettimeDispatcher(dispatchClockGettime)
installGettimeofdayDispatcher(dispatchGettimeofday)
installTimeDispatcher(dispatchTime)
installGetrandomDispatcher(dispatchGetrandom)
installGetentropyDispatcher(dispatchGetentropy)
installArc4randomDispatcher(dispatchArc4random)
installArc4randomBufDispatcher(dispatchArc4randomBuf)
installArc4randomUniformDispatcher(dispatchArc4randomUniform)
installForkDispatcher(dispatchFork)
installExecveDispatcher(dispatchExecve)
installPosixSpawnDispatcher(dispatchPosixSpawn)
installPosixSpawnpDispatcher(dispatchPosixSpawnp)
installExitDispatcher(dispatchExit)
installRawSyscallDispatcher(rawSyscallDispatcher)

type LibraryScanDispatch* = proc(reason: cstring) {.cdecl, raises: [].}
proc registerCooperativeLibraryScan*(scan: LibraryScanDispatch)
  {.importc: "ct_linux_preload_library_scan_register", raises: [].}
proc cooperativeLibraryScan*(reason: cstring)
  {.importc: "ct_linux_preload_library_scan_all", raises: [].}
