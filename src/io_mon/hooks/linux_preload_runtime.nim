when not defined(linux):
  {.error: "repro_monitor_hooks/linux_preload_runtime is Linux-only".}

import std/[algorithm, locks, os, strutils]

import stackable_hooks/platform/linux_preload
import stackable_hooks/platform/linux_raw_syscalls

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
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
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
typedef pid_t (*ct_fork_real_fn)(void);
typedef int (*ct_execve_real_fn)(const char *, char *const [], char *const []);
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
static ct_fork_hook_fn ct_fork_hook = NULL;
static ct_execve_hook_fn ct_execve_hook = NULL;
static ct_posix_spawn_hook_fn ct_posix_spawn_hook = NULL;
static ct_posix_spawn_hook_fn ct_posix_spawnp_hook = NULL;
static ct_exit_hook_fn ct_exit_hook = NULL;
typedef void (*ct_raw_syscall_hook_fn)(long, long, long, long, long, long, long,
                                       long, int);
static ct_raw_syscall_hook_fn ct_raw_syscall_hook = NULL;

#define CT_RAW_SYSCALL_EVENT_CAP 4096
#define CT_RAW_SYSCALL_SOURCE_LIBC 0
#define CT_RAW_SYSCALL_SOURCE_INLINE 1
struct ct_raw_syscall_event {
  long nr;
  long args[6];
  long result;
  int source;
  unsigned long address;
};
static struct ct_raw_syscall_event ct_raw_syscall_events[CT_RAW_SYSCALL_EVENT_CAP];
static volatile sig_atomic_t ct_raw_syscall_event_count_value = 0;
static volatile sig_atomic_t ct_raw_syscall_event_overflow_value = 0;

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
static ct_fork_real_fn real_fork_ptr = NULL;
static ct_execve_real_fn real_execve_ptr = NULL;
static ct_posix_spawn_real_fn real_posix_spawn_ptr = NULL;
static ct_posix_spawn_real_fn real_posix_spawnp_ptr = NULL;

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
extern void stackable_linux_preload_enter_hook(void);
extern void stackable_linux_preload_exit_hook(void);
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

static void *ct_resolve(const char *name) {
  return stackable_linux_preload_resolve_next(name);
}

static void ct_record_raw_syscall_event(long nr, const long args[6],
                                        long result, int source,
                                        unsigned long address) {
  sig_atomic_t count = ct_raw_syscall_event_count_value;
  if (count >= CT_RAW_SYSCALL_EVENT_CAP) {
    ct_raw_syscall_event_overflow_value = 1;
    return;
  }
  struct ct_raw_syscall_event *event = &ct_raw_syscall_events[count];
  event->nr = nr;
  for (int i = 0; i < 6; i++) event->args[i] = args[i];
  event->result = result;
  event->source = source;
  event->address = address;
  ct_raw_syscall_event_count_value = count + 1;
}

long ct_linux_raw_syscall_event_count(void) {
  return (long)ct_raw_syscall_event_count_value;
}

int ct_linux_raw_syscall_event_overflowed(void) {
  return ct_raw_syscall_event_overflow_value != 0;
}

int ct_linux_raw_syscall_event_at(long index, long *nr, long *a1, long *a2,
                                  long *a3, long *a4, long *a5, long *a6,
                                  long *result, int *source,
                                  unsigned long *address) {
  if (index < 0 || index >= ct_raw_syscall_event_count_value) return -1;
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
  ct_raw_syscall_event_count_value = 0;
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
  long result = stackable_linux_replay_syscall_regs(&regs);
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

#define CT_BYPASS() (!stackable_linux_preload_hooks_allowed())
#define CT_CALL_HOOK(expr) ({ \
  stackable_linux_preload_enter_hook(); \
  __typeof__(expr) _ct_result = (expr); \
  stackable_linux_preload_exit_hook(); \
  _ct_result; \
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

char **ct_linux_preload_env_with_preload(char *const envp[]) {
  if (ct_linux_preload_shim_env_name == NULL ||
      ct_linux_preload_shim_env_name[0] == '\0') {
    return (char **)envp;
  }
  const char *shim = getenv(ct_linux_preload_shim_env_name);
  if (shim == NULL || shim[0] == '\0') {
    return (char **)envp;
  }
  char *const *source = envp != NULL ? envp : environ;
  if (source == NULL) {
    return (char **)envp;
  }

  int count = 0;
  const char *existing = NULL;
  for (char *const *it = source; *it != NULL; it++) {
    if (ct_starts_with(*it, "LD_PRELOAD=")) {
      existing = *it;
      if (ct_env_contains_shim(*it, shim)) {
        return (char **)envp;
      }
    } else {
      count++;
    }
  }

  const char *existingValue =
    existing != NULL ? existing + strlen("LD_PRELOAD=") : "";
  size_t entryLen = strlen("LD_PRELOAD=") + strlen(shim) + 1;
  if (existingValue[0] != '\0') {
    entryLen += 1 + strlen(existingValue);
  }
  char *entry = (char *)malloc(entryLen);
  if (entry == NULL) {
    return (char **)envp;
  }
  if (existingValue[0] != '\0') {
    snprintf(entry, entryLen, "LD_PRELOAD=%s:%s", shim, existingValue);
  } else {
    snprintf(entry, entryLen, "LD_PRELOAD=%s", shim);
  }

  char **result = (char **)calloc((size_t)count + 2, sizeof(char *));
  if (result == NULL) {
    free(entry);
    return (char **)envp;
  }
  int index = 0;
  for (char *const *it = source; *it != NULL; it++) {
    if (!ct_starts_with(*it, "LD_PRELOAD=")) {
      result[index++] = *it;
    }
  }
  result[index++] = entry;
  result[index] = NULL;
  return result;
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
void ct_linux_preload_register_fork_hook(ct_fork_hook_fn hook) { ct_fork_hook = hook; }
void ct_linux_preload_register_execve_hook(ct_execve_hook_fn hook) { ct_execve_hook = hook; }
void ct_linux_preload_register_posix_spawn_hook(ct_posix_spawn_hook_fn hook) { ct_posix_spawn_hook = hook; }
void ct_linux_preload_register_posix_spawnp_hook(ct_posix_spawn_hook_fn hook) { ct_posix_spawnp_hook = hook; }
void ct_linux_preload_register_exit_hook(ct_exit_hook_fn hook) { ct_exit_hook = hook; }
void ct_linux_preload_register_raw_syscall_hook(ct_raw_syscall_hook_fn hook) { ct_raw_syscall_hook = hook; }

void ct_linux_preload_real_exit(int status) __attribute__((noreturn));
void ct_linux_preload_real_exit(int status) {
#ifdef SYS_exit_group
  syscall(SYS_exit_group, status);
#endif
  syscall(SYS_exit, status);
  __builtin_unreachable();
}

static long ct_linux_preload_raw_syscall6(long nr, long a1, long a2, long a3,
                                          long a4, long a5, long a6) {
  long result = stackable_linux_raw_syscall6(nr, a1, a2, a3, a4, a5, a6);
  if (result < 0 && result >= -4095) {
    errno = (int)-result;
    return -1;
  }
  return result;
}

long ct_linux_preload_syscall_replacement(long nr, long a1, long a2, long a3,
                                          long a4, long a5, long a6)
    __attribute__((visibility("default")));
long ct_linux_preload_syscall_replacement(long nr, long a1, long a2, long a3,
                                          long a4, long a5, long a6) {
  long result = stackable_linux_raw_syscall6(nr, a1, a2, a3, a4, a5, a6);
  if (!CT_BYPASS() && ct_raw_syscall_hook != NULL) {
    CT_CALL_HOOK((ct_raw_syscall_hook(nr, a1, a2, a3, a4, a5, a6, result,
                                      CT_RAW_SYSCALL_SOURCE_LIBC), 0));
  }
  if (result < 0 && result >= -4095) {
    errno = (int)-result;
    return -1;
  }
  return result;
}

static int ct_real_open_common(ct_open_real_fn *slot, const char *symbol,
                               char *path, int flags, int mode) {
  if (*slot == NULL) *slot = (ct_open_real_fn)ct_resolve(symbol);
  if (*slot == NULL && strcmp(symbol, "open64") == 0)
    *slot = (ct_open_real_fn)ct_resolve("open");
  if (*slot == NULL) { errno = ENOSYS; return -1; }
  return (flags & O_CREAT) ? (*slot)(path, flags, mode) : (*slot)(path, flags);
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
  return (flags & O_CREAT) ? (*slot)(dirfd, path, flags, mode) :
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

int ct_linux_preload_real_stat(char *path, void *buf) {
  CT_REAL("stat", real_stat_ptr, ct_stat_real_fn);
  return real_stat_ptr(path, (struct stat *)buf);
}

int ct_linux_preload_real_lstat(char *path, void *buf) {
  CT_REAL("lstat", real_lstat_ptr, ct_stat_real_fn);
  return real_lstat_ptr(path, (struct stat *)buf);
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

int ct_linux_preload_real_connect(int fd, void *addr, unsigned int addrlen) {
  CT_REAL("connect", real_connect_ptr, ct_connect_real_fn);
  return real_connect_ptr(fd, (const struct sockaddr *)addr, (socklen_t)addrlen);
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

void *ct_linux_preload_real_dlsym(void *handle, char *name) {
#ifdef __GLIBC__
  if (real_dlsym_ptr == NULL)
    real_dlsym_ptr = (ct_dlsym_real_fn)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
#endif
  if (real_dlsym_ptr == NULL)
    real_dlsym_ptr = (ct_dlsym_real_fn)ct_resolve("dlsym");
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

pid_t ct_linux_preload_real_fork(void) {
  CT_REAL("fork", real_fork_ptr, ct_fork_real_fn);
  return real_fork_ptr();
}

int ct_linux_preload_real_execve(char *path, char **argv, char **envp) {
  CT_REAL("execve", real_execve_ptr, ct_execve_real_fn);
  return real_execve_ptr(path, argv, envp);
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

int open(const char *path, int flags, ...) __attribute__((visibility("default")));
int open(const char *path, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  if (CT_BYPASS() || ct_open_hook == NULL)
    return ct_linux_preload_real_open((char *)path, flags, mode);
  return CT_CALL_HOOK(ct_open_hook((char *)path, flags, mode));
}

int open64(const char *path, int flags, ...) __attribute__((visibility("default")));
int open64(const char *path, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  if (CT_BYPASS() || ct_open64_hook == NULL)
    return ct_linux_preload_real_open64((char *)path, flags, mode);
  return CT_CALL_HOOK(ct_open64_hook((char *)path, flags, mode));
}

int openat(int dirfd, const char *path, int flags, ...) __attribute__((visibility("default")));
int openat(int dirfd, const char *path, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  if (CT_BYPASS() || ct_openat_hook == NULL)
    return ct_linux_preload_real_openat(dirfd, (char *)path, flags, mode);
  return CT_CALL_HOOK(ct_openat_hook(dirfd, (char *)path, flags, mode));
}

int openat64(int dirfd, const char *path, int flags, ...) __attribute__((visibility("default")));
int openat64(int dirfd, const char *path, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) {
    va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
  }
  if (CT_BYPASS() || ct_openat64_hook == NULL)
    return ct_linux_preload_real_openat64(dirfd, (char *)path, flags, mode);
  return CT_CALL_HOOK(ct_openat64_hook(dirfd, (char *)path, flags, mode));
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
  if (CT_BYPASS() || ct_dlopen_hook == NULL)
    return ct_linux_preload_real_dlopen((char *)path, flags);
  return CT_CALL_HOOK(ct_dlopen_hook((char *)path, flags));
}

void *dlmopen(Lmid_t namespace_id, const char *path, int flags)
    __attribute__((visibility("default")));
void *dlmopen(Lmid_t namespace_id, const char *path, int flags) {
  if (CT_BYPASS() || ct_dlmopen_hook == NULL)
    return ct_linux_preload_real_dlmopen((long)namespace_id, (char *)path, flags);
  return CT_CALL_HOOK(ct_dlmopen_hook((long)namespace_id, (char *)path, flags));
}

void *ct_linux_preload_public_dlsym(void *handle, const char *name)
    __attribute__((visibility("default")));
void *ct_linux_preload_public_dlsym(void *handle, const char *name) {
  if (CT_BYPASS() || ct_dlsym_hook == NULL)
    return ct_linux_preload_real_dlsym(handle, (char *)name);
  return CT_CALL_HOOK(ct_dlsym_hook(handle, (char *)name));
}
#ifdef __GLIBC__
void *ct_linux_preload_public_dlsym_glibc_2_2_5(void *handle, const char *name)
    __attribute__((alias("ct_linux_preload_public_dlsym"),
                   visibility("default")));
void *ct_linux_preload_public_dlsym_glibc_2_34(void *handle, const char *name)
    __attribute__((alias("ct_linux_preload_public_dlsym"),
                   visibility("default")));
__asm__(".symver ct_linux_preload_public_dlsym_glibc_2_2_5,dlsym@GLIBC_2.2.5");
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

pid_t fork(void) __attribute__((visibility("default")));
pid_t fork(void) {
  if (CT_BYPASS() || ct_fork_hook == NULL)
    return ct_linux_preload_real_fork();
  return CT_CALL_HOOK(ct_fork_hook());
}

int execve(const char *path, char *const argv[], char *const envp[])
    __attribute__((visibility("default")));
int execve(const char *path, char *const argv[], char *const envp[]) {
  if (CT_BYPASS() || ct_execve_hook == NULL)
    return ct_linux_preload_real_execve((char *)path, (char **)argv, (char **)envp);
  return CT_CALL_HOOK(ct_execve_hook((char *)path, (char **)argv, (char **)envp));
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
 * calls. Forward each fortify entry point to its public sibling so
 * the registered hook chain fires regardless of how aggressively
 * the host glibc fortifies. */
int __open_2(const char *path, int flags) __attribute__((visibility("default")));
int __open_2(const char *path, int flags) { return open(path, flags); }

int __open64_2(const char *path, int flags) __attribute__((visibility("default")));
int __open64_2(const char *path, int flags) { return open64(path, flags); }

int __openat_2(int dirfd, const char *path, int flags) __attribute__((visibility("default")));
int __openat_2(int dirfd, const char *path, int flags) { return openat(dirfd, path, flags); }

int __openat64_2(int dirfd, const char *path, int flags) __attribute__((visibility("default")));
int __openat64_2(int dirfd, const char *path, int flags) { return openat64(dirfd, path, flags); }

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
proc envWithPreload*(envp: cstringArray): cstringArray
  {.importc: "ct_linux_preload_env_with_preload", raises: [].}

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
  anonymousExecutableRanges: seq[AnonymousExecutableRange] = @[]

initLock(anonymousRangeLock)

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
    anonymousExecutableRanges.add AnonymousExecutableRange(start: start, stop: stop)
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
    var updated: seq[AnonymousExecutableRange] = @[]
    for tracked in anonymousExecutableRanges:
      if not rangesIntersect(removeStart, removeStop, tracked.start, tracked.stop):
        updated.add tracked
        continue
      if tracked.start < removeStart:
        updated.add AnonymousExecutableRange(
          start: tracked.start,
          stop: min(removeStart, tracked.stop))
      if removeStop < tracked.stop:
        updated.add AnonymousExecutableRange(
          start: max(removeStop, tracked.start),
          stop: tracked.stop)
    anonymousExecutableRanges = updated
  finally:
    release(anonymousRangeLock)

proc rangeFullyTrackedLocked(start, stop: uint): bool {.raises: [].} =
  if stop <= start:
    return false
  var intersections: seq[AnonymousExecutableRange] = @[]
  for tracked in anonymousExecutableRanges:
    if rangesIntersect(start, stop, tracked.start, tracked.stop):
      intersections.add AnonymousExecutableRange(
        start: max(start, tracked.start),
        stop: min(stop, tracked.stop))
  if intersections.len == 0:
    return false
  intersections.sort(proc(a, b: AnonymousExecutableRange): int =
    cmp(a.start, b.start))
  var cursor = start
  for item in intersections:
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
    for tracked in anonymousExecutableRanges:
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

proc trackedAnonymousIntersections(start, stop: uint): seq[AnonymousExecutableRange]
    {.raises: [].} =
  if stop <= start:
    return @[]
  acquire(anonymousRangeLock)
  try:
    for tracked in anonymousExecutableRanges:
      if rangesIntersect(start, stop, tracked.start, tracked.stop):
        result.add AnonymousExecutableRange(
          start: max(start, tracked.start),
          stop: min(stop, tracked.stop))
  finally:
    release(anonymousRangeLock)

proc trackedAnonymousExecutableRangeExists*(start: pointer; length: csize_t): bool
    {.raises: [].} =
  if start == nil or length == 0:
    return false
  let rangeStart = cast[uint](start)
  let rangeStop = rangeStart + uint(length)
  trackedAnonymousIntersections(rangeStart, rangeStop).len > 0

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
  try:
    let tx = installAbsoluteJumpPatchTransaction(
      target, cast[pointer](rawSyscallReplacement), captureRestoreBytes = false)
    result.diagnostic = tx.diagnostic
    result.stage = tx.stage
    result.osErrno = tx.osErrno
    result.installed = tx.diagnostic == lrsOk or
      (tx.diagnostic == lrsPostPatchMprotectBackFailed and tx.patchLive)
  except CatchableError:
    result.diagnostic = lrsPatchWriteFailed
    result.stage = lpsWritePatch
  rawSyscallPatchStatus = result

proc rawSyscallWrapperPatchStatus*(): RawSyscallPatchStatus {.raises: [].} =
  rawSyscallPatchStatus

proc normalizeMappingPath(path: string): string {.raises: [].} =
  if path.len == 0:
    return ""
  try:
    result = expandSymlink(path)
  except CatchableError:
    result = path

proc currentExecutablePath(): string {.raises: [].} =
  try:
    result = expandSymlink("/proc/self/exe")
  except CatchableError:
    result = ""

proc isSystemRuntimeMappingPath(path: string): bool {.raises: [].} =
  ## Keep startup DSO scanning out of loader/libc/toolchain runtime mappings.
  ## io-mon can safely classify file syscalls once a selected site traps, but
  ## broad runtime-library patching would turn ordinary libc/loader internals
  ## into false raw-syscall event-loss for every monitored process.
  path.startsWith("/lib/") or path.startsWith("/lib64/") or
    path.startsWith("/usr/lib/") or path.startsWith("/usr/lib64/") or
    path.startsWith("/nix/store/")

proc isMonitorShimMappingPath(path: string): bool {.raises: [].} =
  path.contains("/librepro_monitor_shim.") or
    path.endsWith("/librepro_monitor_shim.so") or
    path.endsWith("/librepro_monitor_shim.so (deleted)")

proc shouldPatchInlineSyscallMapping(mapping: LinuxExecutableMapping;
                                     executablePath: string): bool {.raises: [].} =
  if not (mapping.readable and mapping.executable):
    return false
  if mapping.writable or mapping.path.len == 0 or not mapping.privateMapping:
    return false
  if mapping.path[0] == '[' or mapping.path[0] != '/':
    return false
  if executablePath.len == 0:
    return false
  let normalized = normalizeMappingPath(mapping.path)
  if normalized == executablePath:
    return true
  if isMonitorShimMappingPath(normalized) or isSystemRuntimeMappingPath(normalized):
    return false
  normalized.endsWith(".so") or normalized.contains(".so.")

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
  let tracked = trackedAnonymousIntersections(requestedStart, requestedStop)
  if tracked.len == 0:
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
    for owned in tracked:
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
installForkDispatcher(dispatchFork)
installExecveDispatcher(dispatchExecve)
installPosixSpawnDispatcher(dispatchPosixSpawn)
installPosixSpawnpDispatcher(dispatchPosixSpawnp)
installExitDispatcher(dispatchExit)
installRawSyscallDispatcher(rawSyscallDispatcher)
