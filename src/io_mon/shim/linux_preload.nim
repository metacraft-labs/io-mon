when not defined(linux):
  {.error: "repro_monitor_shim/linux_preload is Linux-only".}

# The shim is loaded into processes whose threads it does not own, and Nim's
# default allocator owns one heap per thread: a cell freed on a thread other
# than its allocator's is handed back through a pointer into the OWNING
# thread's TLS, which the loader discards when that thread exits. Measured as
# a 0xC0000005 in `addToSharedFreeList` on .NET's finalizer thread -- see
# scripts/build_shim.sh. Only the library build is held to this: a test that
# imports the module into a console binary runs on threads Nim created.
when appType == "lib" and not defined(useMalloc):
  {.error: "the io-mon shim must be built with -d:useMalloc; " &
    "scripts/build_shim.sh sets it, and says why".}

when defined(ioMonGlibcPrivateHeap):
  {.compile: "linux_private_heap.c".}
  {.passL: "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free".}

import std/[locks, os, strutils]
from io_mon/paths import extendedPath

import io_mon/types
import io_mon/writer
import io_mon/hooks/linux_preload_runtime
import io_mon/shim/linux_pod_tables
import stackable_hooks/platform/linux_raw_syscalls

# Raw syscall numbers used by the classifier, the vDSO replacements and the
# raw-syscall helpers. They are PER ARCHITECTURE: x86_64 has its own table
# and arm64 uses the asm-generic one, which also drops the legacy
# open/stat/lstat/access/readlink/time calls entirely. (Before, the x86_64
# numbers were used everywhere, so on arm64 e.g. nr 2 — io_submit — was
# classified as open(2) and `getcwd` was issued as nr 79, which is fstatat
# there.) A Nim `case` needs compile-time constants, so the numbers are
# spelled out here, and the `_Static_assert`s emitted below compare every
# one with `SYS_*` from <sys/syscall.h> when the shim's C is compiled: the
# table cannot drift from the kernel headers of the architecture being
# built. A syscall the architecture lacks gets a distinct negative sentinel
# no kernel number can equal.
when defined(amd64):
  const
    LinuxSysRead                  = 0.clong
    LinuxSysOpen                  = 2.clong
    LinuxSysClose                 = 3.clong
    LinuxSysStat                  = 4.clong
    LinuxSysLstat                 = 6.clong
    LinuxSysMmap                  = 9.clong
    LinuxSysMprotect              = 10.clong
    LinuxSysMunmap                = 11.clong
    LinuxSysAccess                = 21.clong
    LinuxSysGetpid                = 39.clong
    LinuxSysSendfile              = 40.clong
    LinuxSysGetcwd                = 79.clong
    LinuxSysReadlink              = 89.clong
    LinuxSysGettimeofday          = 96.clong
    LinuxSysCapget                = 125.clong
    LinuxSysCapset                = 126.clong
    LinuxSysGettid                = 186.clong
    LinuxSysTime                  = 201.clong
    LinuxSysFutex                 = 202.clong
    LinuxSysGetdents64            = 217.clong
    LinuxSysClockGettime          = 228.clong
    LinuxSysClockGetres           = 229.clong
    LinuxSysOpenat                = 257.clong
    LinuxSysNewfstatat            = 262.clong
    LinuxSysReadlinkat            = 267.clong
    LinuxSysFaccessat             = 269.clong
    LinuxSysSplice                = 275.clong
    LinuxSysEventfd2              = 290.clong
    LinuxSysGetcpu                = 309.clong
    LinuxSysGetrandom             = 318.clong
    LinuxSysMemfdCreate           = 319.clong
    LinuxSysCopyFileRange         = 326.clong
    LinuxSysPkeyMprotect          = 329.clong
    LinuxSysPkeyAlloc             = 330.clong
    LinuxSysPkeyFree              = 331.clong
    LinuxSysStatx                 = 332.clong
    LinuxSysIoUringSetup          = 425.clong
    LinuxSysIoUringEnter          = 426.clong
    LinuxSysOpenat2               = 437.clong
    LinuxSysLandlockCreateRuleset = 444.clong
    LinuxSysLandlockAddRule       = 445.clong
    LinuxSysLandlockRestrictSelf  = 446.clong
    LinuxSysTruncate              = 76.clong
    LinuxSysMkdir                 = 83.clong
    LinuxSysRmdir                 = 84.clong
    LinuxSysCreat                 = 85.clong
    LinuxSysUnlink                = 87.clong
    LinuxSysSymlink               = 88.clong
    LinuxSysMkdirat               = 258.clong
    LinuxSysUnlinkat              = 263.clong
    LinuxSysSymlinkat             = 266.clong
elif defined(arm64):
  const
    LinuxSysRead                  = 63.clong
    LinuxSysOpen                  = -1001.clong  # no SYS_open on this architecture
    LinuxSysClose                 = 57.clong
    LinuxSysStat                  = -1002.clong  # no SYS_stat on this architecture
    LinuxSysLstat                 = -1003.clong  # no SYS_lstat on this architecture
    LinuxSysMmap                  = 222.clong
    LinuxSysMprotect              = 226.clong
    LinuxSysMunmap                = 215.clong
    LinuxSysAccess                = -1004.clong  # no SYS_access on this architecture
    LinuxSysGetpid                = 172.clong
    LinuxSysSendfile              = 71.clong
    LinuxSysGetcwd                = 17.clong
    LinuxSysReadlink              = -1005.clong  # no SYS_readlink on this architecture
    LinuxSysGettimeofday          = 169.clong
    LinuxSysCapget                = 90.clong
    LinuxSysCapset                = 91.clong
    LinuxSysGettid                = 178.clong
    LinuxSysTime                  = -1006.clong  # no SYS_time on this architecture
    LinuxSysFutex                 = 98.clong
    LinuxSysGetdents64            = 61.clong
    LinuxSysClockGettime          = 113.clong
    LinuxSysClockGetres           = 114.clong
    LinuxSysOpenat                = 56.clong
    LinuxSysNewfstatat            = 79.clong
    LinuxSysReadlinkat            = 78.clong
    LinuxSysFaccessat             = 48.clong
    LinuxSysSplice                = 76.clong
    LinuxSysEventfd2              = 19.clong
    LinuxSysGetcpu                = 168.clong
    LinuxSysGetrandom             = 278.clong
    LinuxSysMemfdCreate           = 279.clong
    LinuxSysCopyFileRange         = 285.clong
    LinuxSysPkeyMprotect          = 288.clong
    LinuxSysPkeyAlloc             = 289.clong
    LinuxSysPkeyFree              = 290.clong
    LinuxSysStatx                 = 291.clong
    LinuxSysIoUringSetup          = 425.clong
    LinuxSysIoUringEnter          = 426.clong
    LinuxSysOpenat2               = 437.clong
    LinuxSysLandlockCreateRuleset = 444.clong
    LinuxSysLandlockAddRule       = 445.clong
    LinuxSysLandlockRestrictSelf  = 446.clong
    LinuxSysTruncate              = 45.clong
    LinuxSysMkdir                 = -1007.clong  # no SYS_mkdir on this architecture
    LinuxSysRmdir                 = -1008.clong  # no SYS_rmdir on this architecture
    LinuxSysCreat                 = -1009.clong  # no SYS_creat on this architecture
    LinuxSysUnlink                = -1010.clong  # no SYS_unlink on this architecture
    LinuxSysSymlink               = -1011.clong  # no SYS_symlink on this architecture
    LinuxSysMkdirat               = 34.clong
    LinuxSysUnlinkat              = 35.clong
    LinuxSysSymlinkat             = 36.clong
else:
  {.error: "io-mon's Linux shim needs this architecture's syscall numbers".}

{.emit: ["""
#include <sys/syscall.h>
#ifdef SYS_truncate
_Static_assert(""", LinuxSysTruncate, """ == SYS_truncate, "LinuxSysTruncate != SYS_truncate");
#else
_Static_assert(""", LinuxSysTruncate, """ < 0, "LinuxSysTruncate: SYS_truncate is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_mkdir
_Static_assert(""", LinuxSysMkdir, """ == SYS_mkdir, "LinuxSysMkdir != SYS_mkdir");
#else
_Static_assert(""", LinuxSysMkdir, """ < 0, "LinuxSysMkdir: SYS_mkdir is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_rmdir
_Static_assert(""", LinuxSysRmdir, """ == SYS_rmdir, "LinuxSysRmdir != SYS_rmdir");
#else
_Static_assert(""", LinuxSysRmdir, """ < 0, "LinuxSysRmdir: SYS_rmdir is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_creat
_Static_assert(""", LinuxSysCreat, """ == SYS_creat, "LinuxSysCreat != SYS_creat");
#else
_Static_assert(""", LinuxSysCreat, """ < 0, "LinuxSysCreat: SYS_creat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_unlink
_Static_assert(""", LinuxSysUnlink, """ == SYS_unlink, "LinuxSysUnlink != SYS_unlink");
#else
_Static_assert(""", LinuxSysUnlink, """ < 0, "LinuxSysUnlink: SYS_unlink is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_symlink
_Static_assert(""", LinuxSysSymlink, """ == SYS_symlink, "LinuxSysSymlink != SYS_symlink");
#else
_Static_assert(""", LinuxSysSymlink, """ < 0, "LinuxSysSymlink: SYS_symlink is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_mkdirat
_Static_assert(""", LinuxSysMkdirat, """ == SYS_mkdirat, "LinuxSysMkdirat != SYS_mkdirat");
#else
_Static_assert(""", LinuxSysMkdirat, """ < 0, "LinuxSysMkdirat: SYS_mkdirat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_unlinkat
_Static_assert(""", LinuxSysUnlinkat, """ == SYS_unlinkat, "LinuxSysUnlinkat != SYS_unlinkat");
#else
_Static_assert(""", LinuxSysUnlinkat, """ < 0, "LinuxSysUnlinkat: SYS_unlinkat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_symlinkat
_Static_assert(""", LinuxSysSymlinkat, """ == SYS_symlinkat, "LinuxSysSymlinkat != SYS_symlinkat");
#else
_Static_assert(""", LinuxSysSymlinkat, """ < 0, "LinuxSysSymlinkat: SYS_symlinkat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_read
_Static_assert(""", LinuxSysRead, """ == SYS_read, "LinuxSysRead != SYS_read");
#else
_Static_assert(""", LinuxSysRead, """ < 0, "LinuxSysRead: SYS_read is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_open
_Static_assert(""", LinuxSysOpen, """ == SYS_open, "LinuxSysOpen != SYS_open");
#else
_Static_assert(""", LinuxSysOpen, """ < 0, "LinuxSysOpen: SYS_open is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_close
_Static_assert(""", LinuxSysClose, """ == SYS_close, "LinuxSysClose != SYS_close");
#else
_Static_assert(""", LinuxSysClose, """ < 0, "LinuxSysClose: SYS_close is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_stat
_Static_assert(""", LinuxSysStat, """ == SYS_stat, "LinuxSysStat != SYS_stat");
#else
_Static_assert(""", LinuxSysStat, """ < 0, "LinuxSysStat: SYS_stat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_lstat
_Static_assert(""", LinuxSysLstat, """ == SYS_lstat, "LinuxSysLstat != SYS_lstat");
#else
_Static_assert(""", LinuxSysLstat, """ < 0, "LinuxSysLstat: SYS_lstat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_mmap
_Static_assert(""", LinuxSysMmap, """ == SYS_mmap, "LinuxSysMmap != SYS_mmap");
#else
_Static_assert(""", LinuxSysMmap, """ < 0, "LinuxSysMmap: SYS_mmap is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_mprotect
_Static_assert(""", LinuxSysMprotect, """ == SYS_mprotect, "LinuxSysMprotect != SYS_mprotect");
#else
_Static_assert(""", LinuxSysMprotect, """ < 0, "LinuxSysMprotect: SYS_mprotect is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_munmap
_Static_assert(""", LinuxSysMunmap, """ == SYS_munmap, "LinuxSysMunmap != SYS_munmap");
#else
_Static_assert(""", LinuxSysMunmap, """ < 0, "LinuxSysMunmap: SYS_munmap is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_access
_Static_assert(""", LinuxSysAccess, """ == SYS_access, "LinuxSysAccess != SYS_access");
#else
_Static_assert(""", LinuxSysAccess, """ < 0, "LinuxSysAccess: SYS_access is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_getpid
_Static_assert(""", LinuxSysGetpid, """ == SYS_getpid, "LinuxSysGetpid != SYS_getpid");
#else
_Static_assert(""", LinuxSysGetpid, """ < 0, "LinuxSysGetpid: SYS_getpid is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_sendfile
_Static_assert(""", LinuxSysSendfile, """ == SYS_sendfile, "LinuxSysSendfile != SYS_sendfile");
#else
_Static_assert(""", LinuxSysSendfile, """ < 0, "LinuxSysSendfile: SYS_sendfile is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_getcwd
_Static_assert(""", LinuxSysGetcwd, """ == SYS_getcwd, "LinuxSysGetcwd != SYS_getcwd");
#else
_Static_assert(""", LinuxSysGetcwd, """ < 0, "LinuxSysGetcwd: SYS_getcwd is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_readlink
_Static_assert(""", LinuxSysReadlink, """ == SYS_readlink, "LinuxSysReadlink != SYS_readlink");
#else
_Static_assert(""", LinuxSysReadlink, """ < 0, "LinuxSysReadlink: SYS_readlink is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_gettimeofday
_Static_assert(""", LinuxSysGettimeofday, """ == SYS_gettimeofday, "LinuxSysGettimeofday != SYS_gettimeofday");
#else
_Static_assert(""", LinuxSysGettimeofday, """ < 0, "LinuxSysGettimeofday: SYS_gettimeofday is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_capget
_Static_assert(""", LinuxSysCapget, """ == SYS_capget, "LinuxSysCapget != SYS_capget");
#else
_Static_assert(""", LinuxSysCapget, """ < 0, "LinuxSysCapget: SYS_capget is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_capset
_Static_assert(""", LinuxSysCapset, """ == SYS_capset, "LinuxSysCapset != SYS_capset");
#else
_Static_assert(""", LinuxSysCapset, """ < 0, "LinuxSysCapset: SYS_capset is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_gettid
_Static_assert(""", LinuxSysGettid, """ == SYS_gettid, "LinuxSysGettid != SYS_gettid");
#else
_Static_assert(""", LinuxSysGettid, """ < 0, "LinuxSysGettid: SYS_gettid is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_time
_Static_assert(""", LinuxSysTime, """ == SYS_time, "LinuxSysTime != SYS_time");
#else
_Static_assert(""", LinuxSysTime, """ < 0, "LinuxSysTime: SYS_time is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_futex
_Static_assert(""", LinuxSysFutex, """ == SYS_futex, "LinuxSysFutex != SYS_futex");
#else
_Static_assert(""", LinuxSysFutex, """ < 0, "LinuxSysFutex: SYS_futex is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_getdents64
_Static_assert(""", LinuxSysGetdents64, """ == SYS_getdents64, "LinuxSysGetdents64 != SYS_getdents64");
#else
_Static_assert(""", LinuxSysGetdents64, """ < 0, "LinuxSysGetdents64: SYS_getdents64 is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_clock_gettime
_Static_assert(""", LinuxSysClockGettime, """ == SYS_clock_gettime, "LinuxSysClockGettime != SYS_clock_gettime");
#else
_Static_assert(""", LinuxSysClockGettime, """ < 0, "LinuxSysClockGettime: SYS_clock_gettime is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_clock_getres
_Static_assert(""", LinuxSysClockGetres, """ == SYS_clock_getres, "LinuxSysClockGetres != SYS_clock_getres");
#else
_Static_assert(""", LinuxSysClockGetres, """ < 0, "LinuxSysClockGetres: SYS_clock_getres is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_openat
_Static_assert(""", LinuxSysOpenat, """ == SYS_openat, "LinuxSysOpenat != SYS_openat");
#else
_Static_assert(""", LinuxSysOpenat, """ < 0, "LinuxSysOpenat: SYS_openat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_newfstatat
_Static_assert(""", LinuxSysNewfstatat, """ == SYS_newfstatat, "LinuxSysNewfstatat != SYS_newfstatat");
#else
_Static_assert(""", LinuxSysNewfstatat, """ < 0, "LinuxSysNewfstatat: SYS_newfstatat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_readlinkat
_Static_assert(""", LinuxSysReadlinkat, """ == SYS_readlinkat, "LinuxSysReadlinkat != SYS_readlinkat");
#else
_Static_assert(""", LinuxSysReadlinkat, """ < 0, "LinuxSysReadlinkat: SYS_readlinkat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_faccessat
_Static_assert(""", LinuxSysFaccessat, """ == SYS_faccessat, "LinuxSysFaccessat != SYS_faccessat");
#else
_Static_assert(""", LinuxSysFaccessat, """ < 0, "LinuxSysFaccessat: SYS_faccessat is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_splice
_Static_assert(""", LinuxSysSplice, """ == SYS_splice, "LinuxSysSplice != SYS_splice");
#else
_Static_assert(""", LinuxSysSplice, """ < 0, "LinuxSysSplice: SYS_splice is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_eventfd2
_Static_assert(""", LinuxSysEventfd2, """ == SYS_eventfd2, "LinuxSysEventfd2 != SYS_eventfd2");
#else
_Static_assert(""", LinuxSysEventfd2, """ < 0, "LinuxSysEventfd2: SYS_eventfd2 is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_getcpu
_Static_assert(""", LinuxSysGetcpu, """ == SYS_getcpu, "LinuxSysGetcpu != SYS_getcpu");
#else
_Static_assert(""", LinuxSysGetcpu, """ < 0, "LinuxSysGetcpu: SYS_getcpu is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_getrandom
_Static_assert(""", LinuxSysGetrandom, """ == SYS_getrandom, "LinuxSysGetrandom != SYS_getrandom");
#else
_Static_assert(""", LinuxSysGetrandom, """ < 0, "LinuxSysGetrandom: SYS_getrandom is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_memfd_create
_Static_assert(""", LinuxSysMemfdCreate, """ == SYS_memfd_create, "LinuxSysMemfdCreate != SYS_memfd_create");
#else
_Static_assert(""", LinuxSysMemfdCreate, """ < 0, "LinuxSysMemfdCreate: SYS_memfd_create is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_copy_file_range
_Static_assert(""", LinuxSysCopyFileRange, """ == SYS_copy_file_range, "LinuxSysCopyFileRange != SYS_copy_file_range");
#else
_Static_assert(""", LinuxSysCopyFileRange, """ < 0, "LinuxSysCopyFileRange: SYS_copy_file_range is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_pkey_mprotect
_Static_assert(""", LinuxSysPkeyMprotect, """ == SYS_pkey_mprotect, "LinuxSysPkeyMprotect != SYS_pkey_mprotect");
#else
_Static_assert(""", LinuxSysPkeyMprotect, """ < 0, "LinuxSysPkeyMprotect: SYS_pkey_mprotect is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_pkey_alloc
_Static_assert(""", LinuxSysPkeyAlloc, """ == SYS_pkey_alloc, "LinuxSysPkeyAlloc != SYS_pkey_alloc");
#else
_Static_assert(""", LinuxSysPkeyAlloc, """ < 0, "LinuxSysPkeyAlloc: SYS_pkey_alloc is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_pkey_free
_Static_assert(""", LinuxSysPkeyFree, """ == SYS_pkey_free, "LinuxSysPkeyFree != SYS_pkey_free");
#else
_Static_assert(""", LinuxSysPkeyFree, """ < 0, "LinuxSysPkeyFree: SYS_pkey_free is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_statx
_Static_assert(""", LinuxSysStatx, """ == SYS_statx, "LinuxSysStatx != SYS_statx");
#else
_Static_assert(""", LinuxSysStatx, """ < 0, "LinuxSysStatx: SYS_statx is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_io_uring_setup
_Static_assert(""", LinuxSysIoUringSetup, """ == SYS_io_uring_setup, "LinuxSysIoUringSetup != SYS_io_uring_setup");
#else
_Static_assert(""", LinuxSysIoUringSetup, """ < 0, "LinuxSysIoUringSetup: SYS_io_uring_setup is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_io_uring_enter
_Static_assert(""", LinuxSysIoUringEnter, """ == SYS_io_uring_enter, "LinuxSysIoUringEnter != SYS_io_uring_enter");
#else
_Static_assert(""", LinuxSysIoUringEnter, """ < 0, "LinuxSysIoUringEnter: SYS_io_uring_enter is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_openat2
_Static_assert(""", LinuxSysOpenat2, """ == SYS_openat2, "LinuxSysOpenat2 != SYS_openat2");
#else
_Static_assert(""", LinuxSysOpenat2, """ < 0, "LinuxSysOpenat2: SYS_openat2 is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_landlock_create_ruleset
_Static_assert(""", LinuxSysLandlockCreateRuleset, """ == SYS_landlock_create_ruleset, "LinuxSysLandlockCreateRuleset != SYS_landlock_create_ruleset");
#else
_Static_assert(""", LinuxSysLandlockCreateRuleset, """ < 0, "LinuxSysLandlockCreateRuleset: SYS_landlock_create_ruleset is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_landlock_add_rule
_Static_assert(""", LinuxSysLandlockAddRule, """ == SYS_landlock_add_rule, "LinuxSysLandlockAddRule != SYS_landlock_add_rule");
#else
_Static_assert(""", LinuxSysLandlockAddRule, """ < 0, "LinuxSysLandlockAddRule: SYS_landlock_add_rule is absent, so the Nim value must be a negative sentinel");
#endif
#ifdef SYS_landlock_restrict_self
_Static_assert(""", LinuxSysLandlockRestrictSelf, """ == SYS_landlock_restrict_self, "LinuxSysLandlockRestrictSelf != SYS_landlock_restrict_self");
#else
_Static_assert(""", LinuxSysLandlockRestrictSelf, """ < 0, "LinuxSysLandlockRestrictSelf: SYS_landlock_restrict_self is absent, so the Nim value must be a negative sentinel");
#endif
"""].}

const
  OAccMode = 0x0003.cint
  OWrOnly = 0x0001.cint
  ORdWr = 0x0002.cint
  OCreat = 0x0040.cint
  OTrunc = 0x0200.cint
  OAppend = 0x0400.cint
  LinuxAtFdcwd = -100.cint
  LinuxAtRemovedir = 0x200.cint
  LinuxEfault = 14.clong
  LinuxRenameExchange = 2'u32

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
  # FUP-H — the fd/dir/stream path maps, the observed-input dedup set, and
  # the empty-fd / inherited-fd sets moved to `linux_pod_tables`: they are
  # mutated from EVERY host thread's open/close/opendir/fopen/getenv hook,
  # and Nim `Table`/`HashSet`/`string` (ORC heap) corrupts the process
  # allocator when a chunk allocated on one thread is freed on another (the
  # FUP-C mechanism — it crashed live-Vulkan replay in `rawDealloc` off
  # `updateFdPath`). Those tables now use libc-malloc'd payloads in
  # fixed-capacity POD storage, each guarded by its own lock inside the
  # module; the accessor procs below just forward to it.
  fragmentDir: string
  runId: string
  # The consumer's event-interest set (REPRO_MONITOR_INTEREST). Set ONCE at init
  # and only read thereafter, so the concurrent reads in `emitRecord` need no
  # lock. `FullInterest` until init runs and if the var is absent, so a shim that
  # is never told an interest captures everything (back-compat). See
  # docs/contributors/event-interest-filter.md.
  gInterest: set[EventCategory] = FullInterest
  # DA-1i — the consumer's evidence scope (REPRO_MONITOR_EVIDENCE). Same
  # discipline as `gInterest`: set ONCE at init and only read thereafter, so the
  # concurrent reads in `emitRecord` need no lock. `esFull` until init runs and
  # if the var is absent, so a shim that is never told a scope writes everything
  # down (back-compat).
  gEvidenceScope: EvidenceScope = esFull
  # DEP-SHM-2 — the shared-memory dependency-queue segment path (the value of
  # REPRO_MONITOR_DEP_SHM). Empty when the engine did not create a ring, in
  # which case every record takes the file path unchanged. Remembered so the
  # fork-child atfork handler can RE-ATTACH the child fresh.
  depShmPath: string
  # io-mon-Lossless-Event-Capture M3 — this incarnation's EXEC GENERATION, read
  # from REPRO_MONITOR_EXEC_GEN at init (0 when unset — the root launch) and
  # incremented across each exec through the child env. Folded into the SET
  # element identity so two same-pid process-starts whose /proc/self/exe is
  # byte-identical (a Nix gcc/rustc bash-wrapper that re-execs the real compiler
  # in-place) remain DISTINCT elements instead of deduping down to mcIncomplete.
  currentExecGen: clong = 0
  nextProcessSeq: uint64 = 0
  rawSyscallCoverageRecorded = false
  inlineSyscallCoverageRecorded = false
  inlineSyscallTrapCoverageRecorded = false
  linuxVdsoPatchFailureDetails: seq[string] = @[]
  linuxVdsoPatchFailureEmitted = false
  # Thread id of the thread that ran the preload constructor (the process
  # main thread). Its fragment batch is flushed by the process-exit
  # destructor; worker threads flush eagerly per record (see emitRecord),
  # mirroring the macOS shim, because a pthread-key thread-exit destructor
  # cannot safely touch Nim TLS during teardown.
  mainThreadId: uint64 = 0

var
  disabled {.threadvar.}: int
  inForkChild {.threadvar.}: bool
  # DEP-FLUSH-3 — set once per thread after it first arms the pthread-key
  # thread-exit flush, so the arming call stays off the steady-state hot
  # path (one branch on a threadvar bool per emit).
  threadExitArmed {.threadvar.}: bool
  # FUP-K — per-thread caches for the process/thread identity that
  # `baseRecord` stamps on EVERY record. `getpid(2)` / `getppid(2)` /
  # `gettid(2)` are un-cached raw syscalls in glibc (since 2.25) / musl, so
  # a recorder-heavy workload (the BEAM VM emitting a record per port write)
  # pays THREE extra syscalls per record. pid/ppid are process-constant and
  # tid is thread-constant for a thread's whole lifetime. After `fork`, the
  # pthread_atfork CHILD handler (`repro_linux_atfork_child`) resets them.
  # Exec records sample live identities instead: a vfork child shares these
  # caches with its parent and does not run the atfork handlers. A sentinel of 0
  # means "unset"; a real pid/tid is always > 0, so 0 unambiguously forces a
  # first fetch. The recorded VALUES are byte-identical to the un-cached path
  # — this is a pure syscall-count reduction, not a semantic change.
  cachedTid {.threadvar.}: uint64
  cachedPid {.threadvar.}: uint64
  cachedPpid {.threadvar.}: uint64

{.emit: """
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>

/* nim-stackable-hooks emits ``stackable_linux_raw_syscall6`` (and the rest of
 * its raw-syscall substrate) only under
 * ``when defined(linux) and defined(amd64)``. This file is LD_PRELOADed, so an
 * undefined symbol here is not a dormant reference — the loader binds it
 * eagerly and the process dies before ``main``. See the matching guard in
 * ``hooks/linux_preload_runtime.nim``.
 *
 * ``repro_raw_syscall6`` is the arch-portable spelling every call site below
 * uses. On x86_64 it is a direct passthrough, so nothing about the amd64 build
 * changes. Elsewhere it issues the syscall instruction directly.
 *
 * It must NOT fall back to libc ``syscall(2)``. THIS FILE defines
 * ``long syscall(long number, ...)`` with default visibility a few hundred
 * lines below — that is the LD_PRELOAD interposer for libc's ``syscall``.
 * Because the shim is preloaded it sits first in the lookup scope, so a call to
 * ``syscall`` from inside it binds back to that interposer and recurses until
 * the stack is gone. Several call sites here are also on the async-signal-safe
 * flush path, where that would be especially unpleasant.
 *
 * aarch64 Linux ABI: number in x8, args in x0-x5, ``svc #0``, result in x0
 * under the kernel ``-errno`` convention — already the convention every call
 * site here tests against (``!= 0``, ``< 0``), so nothing is re-encoded.
 * Issuing the instruction directly is also strictly more async-signal-safe than
 * any libc route. */
#if defined(__x86_64__)
extern long stackable_linux_raw_syscall6(long nr, long a1, long a2, long a3,
                                         long a4, long a5, long a6);
#endif

static long repro_raw_syscall6(long nr, long a1, long a2, long a3, long a4,
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
rather than routing through libc syscall(2) — this shim interposes that \
symbol, so calling it would recurse forever."
#endif
}

/* Exported so the Nim side can bind one always-present name rather than a
 * symbol that exists on only one architecture. */
long repro_linux_raw_syscall6(long nr, long a1, long a2, long a3, long a4,
                              long a5, long a6) {
  return repro_raw_syscall6(nr, a1, a2, a3, a4, a5, a6);
}

long repro_linux_gettid(void) {
  return repro_raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
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

long repro_linux_socket_peer_uid(int fd) {
  struct ucred cred;
  socklen_t len = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
    return (long)cred.uid;
  return -1;
}

/* The AF_UNIX address a client dialled, as text: the filesystem path, or
   "@<name>" for an abstract-namespace address (leading NUL). Returns the
   length written (excluding the terminator), 0 for an unnamed or non-AF_UNIX
   address. Never reads past `addrlen`. */
int repro_linux_sockaddr_un_path(void *addr, unsigned int addrlen,
                                 char *out, int cap) {
  if (addr == NULL || out == NULL || cap < 2) return 0;
  if (addrlen <= sizeof(sa_family_t)) return 0;
  struct sockaddr_un *un = (struct sockaddr_un *)addr;
  if (un->sun_family != AF_UNIX) return 0;
  size_t avail = addrlen - offsetof(struct sockaddr_un, sun_path);
  if (avail > sizeof(un->sun_path)) avail = sizeof(un->sun_path);
  int n = 0;
  size_t i = 0;
  if (avail > 0 && un->sun_path[0] == '\0') {
    out[n++] = '@';
    i = 1;
    for (; i < avail && n < cap - 1; i++) {
      char c = un->sun_path[i];
      out[n++] = (c == '\0') ? '@' : c;
    }
  } else {
    for (; i < avail && n < cap - 1; i++) {
      char c = un->sun_path[i];
      if (c == '\0') break;
      out[n++] = c;
    }
  }
  out[n] = '\0';
  return n;
}

int repro_linux_fd_identity_kind(int fd, unsigned long *dev,
                                 unsigned long *ino, int *kind) {
  struct stat st;
  if (repro_raw_syscall6(SYS_fstat, fd, (long)&st, 0, 0, 0, 0) != 0)
    return 0;
  *dev = (unsigned long)st.st_dev;
  *ino = (unsigned long)st.st_ino;
  if (S_ISREG(st.st_mode))
    *kind = 1;
  else if (S_ISFIFO(st.st_mode))
    *kind = 2;
  else if (S_ISSOCK(st.st_mode))
    *kind = 3;
  else if (S_ISDIR(st.st_mode))
    *kind = 4;
  else
    *kind = 5;
  return 1;
}

static int repro_linux_append_uint(char *buf, int pos, int limit, int value) {
  char tmp[32];
  int n = 0;
  if (value == 0) {
    tmp[n++] = '0';
  } else {
    while (value > 0 && n < (int)sizeof(tmp)) {
      tmp[n++] = (char)('0' + (value % 10));
      value /= 10;
    }
  }
  while (n > 0 && pos < limit)
    buf[pos++] = tmp[--n];
  return pos;
}

int repro_linux_fd_proc_path(int fd, void *raw_buf, unsigned long len) {
  const char prefix[] = "/proc/self/fd/";
  char *buf = (char *)raw_buf;
  char linkpath[64];
  int pos = 0;
  if (len == 0 || fd < 0)
    return 0;
  for (unsigned long i = 0; i + 1 < sizeof(prefix); ++i)
    linkpath[pos++] = prefix[i];
  pos = repro_linux_append_uint(linkpath, pos, (int)sizeof(linkpath) - 1, fd);
  linkpath[pos] = '\0';
  /* aarch64 (and other newer Linux ABIs) drop the legacy readlink syscall and
     only provide readlinkat; readlink(p,b,n) == readlinkat(AT_FDCWD,p,b,n).
     Keep the x86-64 path byte-identical to avoid any behavioral change there. */
#ifdef SYS_readlink
  long n = repro_raw_syscall6(SYS_readlink, (long)linkpath,
                                        (long)buf, (long)(len - 1),
                                        0, 0, 0);
#else
  long n = repro_raw_syscall6(SYS_readlinkat, (long)AT_FDCWD,
                                        (long)linkpath, (long)buf,
                                        (long)(len - 1), 0, 0);
#endif
  if (n <= 0)
    return 0;
  buf[n] = '\0';
  return 1;
}

/* io-mon-Lossless-Event-Capture M3 part 2a — read THIS incarnation's real
 * on-disk image via a raw readlink("/proc/self/exe"). Used as the per-exec
 * identity appended to every SET dep element so the pre/post-exec process-start
 * of one pid stays distinct without a synthetic tag. Raw syscall (no libc, no
 * hooked call) keeps it re-entrancy-safe at constructor time. Returns the byte
 * length written (0 on failure). */
int repro_linux_self_exe_path(void *raw_buf, unsigned long len) {
  char *buf = (char *)raw_buf;
  if (len == 0)
    return 0;
  /* aarch64 (and other newer Linux ABIs) lack the legacy readlink syscall;
     readlink(p,b,n) == readlinkat(AT_FDCWD,p,b,n). x86-64 stays byte-identical. */
#ifdef SYS_readlink
  long n = repro_raw_syscall6(SYS_readlink, (long)"/proc/self/exe",
                                        (long)buf, (long)(len - 1),
                                        0, 0, 0);
#else
  long n = repro_raw_syscall6(SYS_readlinkat, (long)AT_FDCWD,
                                        (long)"/proc/self/exe", (long)buf,
                                        (long)(len - 1), 0, 0);
#endif
  if (n <= 0)
    return 0;
  return (int)n;
}

extern int repro_monitor_shim_init(char *configPath);
extern int repro_monitor_shim_shutdown(void);

/* M9.R.62.2 — async-signal-safe kill-before-flush recovery.
 *
 * Phase A characterisation (see recipes/reproos-image/run-evidence/m9r62/
 * m9r62_phaseA_attribution.txt) proved every remaining pixman escape
 * carries diag-ctx=[phase=init bypassed=0 inForkChild=0 disabled=0]. The
 * escape class is a process that (a) loaded the shim, (b) buffered reads,
 * (c) died WITHOUT entering fork / execve / exit hooks AND without the
 * libc destructor firing — i.e. terminating signals with default
 * disposition, or raw syscall(SYS_exit_group) that bypasses the shim.
 *
 * The handler below writes the calling thread's pre-encoded
 * `read-tail-committed` marker (populated at slot open by
 * precomputeSigSafeCommittedFrame in writer.nim) directly to the
 * fragment fd via raw `write(2)`, plus any in-flight batch buffer, and
 * closes the fd — all async-signal-safe. Then it restores the previous
 * handler and re-raises so WIFSIGNALED / WEXITSTATUS observers still see
 * the correct termination cause.
 *
 * Every raw-syscall used here (write, close, sigaction, kill,
 * sigemptyset, sigfillset) is on POSIX.1-2017 Table 2-4 (Signal Concepts
 * → Signal Actions) as async-signal-safe. Nim proc calls into
 * writer.nim's `sigSafeSlotFd` / `sigSafeBatchPtr` / etc. are pure POD
 * reads (no allocation, no lock acquisition) — see the writer-side
 * signature.
 *
 * SIGKILL and SIGSTOP are uncatchable by design; losses through those
 * paths remain inherent event-loss (correctly counted by mergeFragments).
 */

extern int repro_linux_sig_safe_slot_is_open(void);
extern int repro_linux_sig_safe_slot_fd(void);
extern int repro_linux_sig_safe_slot_identity_matches(void);
extern void* repro_linux_sig_safe_batch_ptr(void);
extern long repro_linux_sig_safe_batch_len(void);
extern void* repro_linux_sig_safe_committed_ptr(void);
extern long repro_linux_sig_safe_committed_len(void);
extern void repro_linux_sig_safe_mark_slot_closed(void);

#include <signal.h>
#include <string.h>

/* Previous-handler cache indexed by signal number. Signals we hook are
 * < 32 (standard POSIX signals); realtime signals are not in scope.
 * `struct sigaction` is a POD; a fixed-size array is safe at file scope
 * and initialisation is done once by installTerminatingSignalHandlers. */
static struct sigaction repro_prev_sigaction[32];
static int repro_prev_sigaction_valid[32];

/* Exported so the inline-syscall SIGTRAP handler in
 * `linux_preload_runtime.nim` can invoke the same async-signal-safe flush
 * before replaying an inline-asm SYS_exit_group / SYS_exit that would
 * otherwise terminate the process with an un-flushed read batch (the
 * M9.R.62.4 pixman residual, closed by M9.R.63.3). All other callers
 * remain inside this translation unit; the external symbol is only
 * consumed by the runtime's SIGTRAP handler through a matching extern
 * declaration. */
void repro_linux_sig_safe_flush(void) {
  int fd;
  long saved_errno = errno;
  if (!repro_linux_sig_safe_slot_is_open())
    return;
  fd = repro_linux_sig_safe_slot_fd();
  if (fd < 0)
    return;
  /* The tracee may have closed or replaced the cached descriptor through a
   * raw syscall or dup2. Never write monitor frames into its replacement. */
  if (!repro_linux_sig_safe_slot_identity_matches()) {
    repro_linux_sig_safe_mark_slot_closed();
    errno = (int)saved_errno;
    return;
  }
  /* Flush any in-flight batch buffer FIRST so buffered read records land
   * before the committed marker. Partial writes are best-effort at the
   * async-signal-safe level; the tolerant reader (decodeFramesTolerant)
   * drops a truncated tail cleanly, and mergeFragments treats the
   * committed marker's presence as retiring the pending sentinel. */
  {
    long len = repro_linux_sig_safe_batch_len();
    if (len > 0) {
      void *p = repro_linux_sig_safe_batch_ptr();
      long written = 0;
      while (written < len) {
        long n = repro_raw_syscall6(SYS_write, fd,
                                              (long)((char*)p + written),
                                              len - written, 0, 0, 0);
        if (n <= 0) break;
        written += n;
      }
    }
  }
  /* Write the pre-encoded committed marker. Retires the ROUND-5 F pending
   * sentinel; mergeFragments' netting then sees a clean pending/committed
   * pair and doesn't inject a false kill-before-flush event-loss. */
  {
    long len = repro_linux_sig_safe_committed_len();
    if (len > 0) {
      void *p = repro_linux_sig_safe_committed_ptr();
      long written = 0;
      while (written < len) {
        long n = repro_raw_syscall6(SYS_write, fd,
                                              (long)((char*)p + written),
                                              len - written, 0, 0, 0);
        if (n <= 0) break;
        written += n;
      }
    }
  }
  /* fsync so the writes are on-disk before the signal terminates the
   * process (the OS page cache would otherwise survive process death,
   * but a subsequent host crash would drop the tail). Best-effort. */
  repro_raw_syscall6(SYS_fsync, fd, 0, 0, 0, 0, 0);
  repro_raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
  repro_linux_sig_safe_mark_slot_closed();
  errno = (int)saved_errno;
}

extern void repro_linux_sig_safe_note_signal(long signum);

static void repro_linux_terminating_signal_handler(int signum) {
  /* Only bother flushing if the slot is open AND this is one of the
   * signals we installed for. The signum-bounds check is defensive —
   * we register for signums < 32 only. */
  repro_linux_sig_safe_note_signal((long)signum);
  repro_linux_sig_safe_flush();
  if (signum > 0 && signum < 32 && repro_prev_sigaction_valid[signum]) {
    /* Restore the previously-installed handler + re-raise. If the
     * previous handler was SIG_DFL for a default-terminating signal
     * (SIGPIPE / SIGTERM / SIGSEGV / …), sigaction restore + kill
     * delivers the default termination with the correct WIFSIGNALED
     * status. If it was a user handler, we forward. */
    struct sigaction prev = repro_prev_sigaction[signum];
    sigaction(signum, &prev, NULL);
  } else {
    /* No cached prev — set to SIG_DFL and let re-raise terminate. */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigaction(signum, &dfl, NULL);
  }
  /* Re-raise the signal via glibc's `raise(3)` — pthread_kill(self, sig)
   * under the hood; async-signal-safe per POSIX.1-2017 Table 2-4 and
   * simpler than piecing together kill(getpid(),sig) via raw syscalls
   * (which had a SYS_kill / SYS_getpid nesting artefact that mis-fired
   * on the first M9.R.62.2 attempt). With SA_RESETHAND, disposition
   * has already reverted to whatever we sigaction()'d above (SIG_DFL
   * for a default-terminating signal), so the raise delivers the
   * default termination. */
  raise(signum);
}

static int repro_linux_install_one_signal_handler(int signum) {
  struct sigaction sa;
  struct sigaction prev;
  if (signum <= 0 || signum >= 32) return 0;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = repro_linux_terminating_signal_handler;
  sigemptyset(&sa.sa_mask);
  /* SA_RESETHAND — after handler fires once, disposition returns to
   * default. Belt-and-braces: even if our re-raise+restore path fails,
   * a second delivery kills the process. SA_NODEFER lets us fire even
   * if the caller is inside a masked signal region (rare in the target
   * workload — clang/meson/bash don't block SIGPIPE). */
  sa.sa_flags = SA_RESETHAND | SA_NODEFER;
  if (sigaction(signum, &sa, &prev) != 0) return 0;
  repro_prev_sigaction[signum] = prev;
  repro_prev_sigaction_valid[signum] = 1;
  return 1;
}

/* The set of terminating signals we hook. Deliberately CONSERVATIVE:
 *   - SIGKILL / SIGSTOP: uncatchable by kernel; inherent loss.
 *   - SIGCHLD / SIGURG / SIGCONT: default ignore/continue; not terminating.
 *   - SIGTRAP: io-mon's own inline-syscall trap coverage sets an internal
 *     disposition (recordInlineSyscallTrapCoverage). Hooking it here would
 *     race the shim's own probe and break the JIT-code adversarial tests.
 *   - SIGSYS: same reasoning as SIGTRAP — reserved for the shim's raw-
 *     syscall trap infrastructure. Also, seccomp-driven SIGSYS in a
 *     tracee is a legitimate observation, not a shim-recovery event.
 *   - SIGUSR1 / SIGUSR2 / SIGXFSZ / SIGXCPU / SIGVTALRM / SIGPROF /
 *     SIGALRM: default terminates, but real-world tracee code often
 *     installs its own handlers (POSIX timers, profiler probes,
 *     user-defined IPC). Hooking these would shadow legitimate user
 *     handlers via SA_RESETHAND. Deferred to a future milestone if
 *     evidence surfaces (M9.R.62 evidence carries none of these).
 *
 * The retained set is the DEFAULT=TERMINATE class that the M9.R.62 Phase
 * A characterisation shows is empirically triggered by the pixman /
 * meson / clang workload (shell pipelines → SIGPIPE, parent-driven
 * cancellations → SIGTERM/SIGINT/SIGHUP/SIGQUIT, crashes → SIGSEGV /
 * SIGABRT / SIGBUS / SIGFPE / SIGILL). */
static const int repro_linux_terminating_signals[] = {
  SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGFPE, SIGBUS, SIGSEGV,
  SIGPIPE, SIGTERM
};

int repro_linux_install_terminating_signal_handlers(void) {
  size_t i;
  int installed = 0;
  for (i = 0; i < sizeof(repro_linux_terminating_signals) / sizeof(int); i++) {
    installed += repro_linux_install_one_signal_handler(
        repro_linux_terminating_signals[i]);
  }
  return installed;
}

/* M9.R.62.2 addendum — interpose libc's `syscall(3)` wrapper so raw
 * `syscall(SYS_exit_group, N)` and `syscall(SYS_exit, N)` calls flush
 * the fragment slot before the kernel tears the process down. Phase A
 * characterisation on pixman proved 182/182 escapees carry
 * `phase=emit kind=N` (a real captured mrFileOpen etc) with no
 * subsequent transition, i.e. the process died via a path outside every
 * hooked libc entry point AND outside every default-terminating signal
 * — the ONLY remaining route is a raw exit_group / exit syscall issued
 * via libc's `syscall(3)` wrapper (bash / gcc / clang / meson all use
 * it for niche error-exit fast paths). LD_PRELOAD lets us interpose
 * `syscall` by name because it's a real symbol in libc.
 *
 * Inline `syscall` assembly (a program that emits `syscall` opcode
 * directly from user code) STILL bypasses this — but no such
 * caller is present in the empirical pixman workload. If future evidence
 * surfaces one, seccomp-BPF is the next tier (kernel-side interception).
 */

#include <stdarg.h>
#include <stdint.h>

extern int ct_linux_drain_inline_events_before_image_end(void);

typedef long (*repro_libc_syscall_fn)(long, ...);
static repro_libc_syscall_fn repro_real_libc_syscall = NULL;

static void repro_linux_resolve_libc_syscall(void) {
  if (repro_real_libc_syscall != NULL) return;
  /* dlsym(RTLD_NEXT, ...) is standard LD_PRELOAD chain resolution. */
  repro_real_libc_syscall = (repro_libc_syscall_fn)
    dlsym(RTLD_NEXT, "syscall");
}

long syscall(long number, ...) __attribute__((visibility("default")));
long syscall(long number, ...) {
  va_list ap;
  long a0, a1, a2, a3, a4, a5;
  repro_linux_resolve_libc_syscall();
  /* Pull up to 6 args from varargs — matches glibc's syscall(3) contract
   * of forwarding at most 6 args to the raw repro_raw_syscall6
   * wrapper. Callers passing fewer args have zero-init trailing regs on
   * every ABI we run on (x86_64 SysV / aarch64 AAPCS). */
  va_start(ap, number);
  a0 = va_arg(ap, long); a1 = va_arg(ap, long); a2 = va_arg(ap, long);
  a3 = va_arg(ap, long); a4 = va_arg(ap, long); a5 = va_arg(ap, long);
  va_end(ap);
#ifdef SYS_exit_group
  if (number == SYS_exit_group) {
    /* Classify trapped inline syscalls first; when some cannot be (this
     * thread is inside a hook), withhold the commit so the loss shows. */
    if (ct_linux_drain_inline_events_before_image_end())
      repro_linux_sig_safe_flush();
  }
#endif
#ifdef SYS_exit
  if (number == SYS_exit) {
    repro_linux_sig_safe_flush();
  }
#endif
  if (number == SYS_execve
#ifdef SYS_execveat
      || number == SYS_execveat
#endif
      ) {
    ct_linux_drain_inline_events_before_image_end();
  }
  if (repro_real_libc_syscall != NULL)
    return repro_real_libc_syscall(number, a0, a1, a2, a3, a4, a5);
  /* Fall back to the raw wrapper if libc's syscall wasn't dlsym-able
   * (extremely unusual — implies a statically-linked host or a stripped
   * libc). */
  return repro_raw_syscall6(number, a0, a1, a2, a3, a4, a5);
}

extern void ct_linux_preload_prepare_real_connect(void);
extern void ct_linux_preload_prime_real_functions(void);
extern void repro_linux_prepare_thread_exit_key(void);

__attribute__((constructor))
static void repro_linux_monitor_constructor(void) {
  /* Resolve every "next" libc entry point the hooks forward to BEFORE any
   * host code runs. Resolving lazily means calling dlsym inside a hook, and
   * dlsym frees/allocates through the HOST's allocator, which the host may be
   * holding the lock of at that moment (PartitionAlloc's syscall(SYS_mprotect)
   * under its lock). See ct_linux_preload_prime_real_functions. The private
   * heap (linux_private_heap.c) needs no resolution: it is the shim's own
   * mmap-backed allocator, set up by its priority-101 constructor. */
  ct_linux_preload_prime_real_functions();
  repro_linux_resolve_libc_syscall();
  repro_linux_prepare_thread_exit_key();
  repro_monitor_shim_init(NULL);
  ct_linux_preload_prepare_real_connect();
}

__attribute__((destructor))
static void repro_linux_monitor_destructor(void) {
  /* DEP-FLUSH-2 — flush EVERY registered thread's buffered fragment batch
     on process exit (via the registry sweep in repro_monitor_shim_shutdown)
     so a short-lived process (or the trailing batch of any process) does
     not drop its records — which would otherwise make a fast child look
     un-injected and downgrade completeness to mcIncomplete. */
  repro_monitor_shim_shutdown();
}

/* DEP-FLUSH-3 — per-thread exit flush via a pthread_key destructor.
 *
 * The FragmentSlot is POD per-thread state (heap-resident on Linux, reached
 * through a threadvar pointer; see `fragmentSlotOnHeap` in writer.nim); Nim
 * installs NO thread-exit finalizer for it (that is deliberate, for --mm:orc fork safety), so a
 * worker thread that emits a sub-64-KiB batch and returns before the
 * 100 ms staleness flush would lose its whole batch — and the process-exit
 * destructor (main thread) cannot reach an already-dead worker's TLS.
 *
 * We create ONE process-global pthread key whose value-destructor libc
 * invokes on EACH thread's exit (for threads that set a non-NULL value).
 * When a thread first opens its fragment slot it sets the key to a
 * non-NULL sentinel (repro_linux_arm_thread_exit_flush); on thread exit
 * libc calls repro_linux_thread_exit_destructor with that sentinel, which
 * flushes + closes + unregisters the calling thread's slot via the Nim
 * bridge. The key is created once, guarded by pthread_once. If key
 * creation fails (extremely unusual), arming is a no-op and worker
 * threads fall back to the eager per-record flush already in emitRecord —
 * correctness preserved, batching win lost only for that degenerate host.
 */
#include <pthread.h>

extern void repro_linux_thread_exit_flush(void);

static pthread_key_t repro_thread_exit_key;
static pthread_once_t repro_thread_exit_key_once = PTHREAD_ONCE_INIT;
static int repro_thread_exit_key_ready = 0;

/* The non-NULL sentinel stored in the key. Its ADDRESS is a stable,
 * process-unique value; libc only cares that it is non-NULL so the
 * destructor fires. */
static char repro_thread_exit_sentinel = 1;

static void repro_linux_thread_exit_destructor(void *value) {
  (void)value;
  repro_linux_thread_exit_flush();
}

/* glibc keeps the values of the first PTHREAD_KEY_2NDLEVEL_SIZE (32) keys in
 * the thread descriptor itself; for a higher key, a thread's FIRST
 * pthread_setspecific callocs a second-level block — with the process's
 * calloc, i.e. the HOST's if it replaces malloc
 * (https://sourceware.org/git/?p=glibc.git;a=blob;f=nptl/pthread_setspecific.c).
 * Arming happens inside emitRecord, inside a hook the host may have entered
 * while holding its allocator lock (see linux_private_heap.c), so arming must
 * not allocate. The key is therefore created from the shim's constructor —
 * before the host's own code has created its keys, so it normally gets a low
 * number — and arming is skipped when the key is nevertheless above the
 * in-descriptor range. Skipping costs the batching win on that host's worker
 * threads (emitRecord flushes a worker's batch after every record) and, on
 * the file transport only, leaves an exited worker's heap fragment slot
 * unfreed (writer.nim, fragmentSlotOnHeap). Neither loses a record. */
#define REPRO_THREAD_EXIT_KEY_INLINE_LIMIT 32

static void repro_linux_create_thread_exit_key(void) {
  if (pthread_key_create(&repro_thread_exit_key,
                         repro_linux_thread_exit_destructor) == 0)
    repro_thread_exit_key_ready = 1;
}

void repro_linux_prepare_thread_exit_key(void) {
  pthread_once(&repro_thread_exit_key_once,
               repro_linux_create_thread_exit_key);
}

/* Called (via the Nim bridge repro_linux_arm_thread_exit_flush) when a
 * thread first opens its fragment slot. Idempotent per thread: re-setting
 * the same non-NULL value is harmless. */
void repro_linux_arm_thread_exit_flush_c(void) {
  repro_linux_prepare_thread_exit_key();
  if (repro_thread_exit_key_ready &&
      (unsigned long)repro_thread_exit_key < REPRO_THREAD_EXIT_KEY_INLINE_LIMIT)
    pthread_setspecific(repro_thread_exit_key,
                        (void *)&repro_thread_exit_sentinel);
}

/* Called (via the Nim bridge) when a thread's slot is torn down normally
 * (close / shutdown), so libc does NOT double-invoke the destructor. */
void repro_linux_disarm_thread_exit_flush_c(void) {
  if (repro_thread_exit_key_ready)
    pthread_setspecific(repro_thread_exit_key, NULL);
}

/* DEP-FLUSH-4 — pthread_atfork child handler.
 *
 * The libc `fork` interpose hook (repro_hook_fork) already resets the
 * child's inherited fragment slot + registry. This atfork child handler is
 * a defensive SECOND line that also fires when a child is created through a
 * path the libc hook does not see (e.g. a direct clone(2) via pthread
 * internals). It runs in the CHILD right after fork, before the child
 * returns to user code, and resets the calling thread's slot + the whole
 * inherited registry so the child never replays the parent's buffered
 * frames nor writes through the COW-shared fd. Idempotent with the fork
 * hook's own reset (a second reset of an already-empty slot is a no-op). */
extern void repro_linux_atfork_child(void);

void repro_linux_atfork_child_c(void) {
  repro_linux_atfork_child();
}
""".}

proc c_getpid(): cint {.importc: "getpid", header: "<unistd.h>".}
proc c_getppid(): cint {.importc: "getppid", header: "<unistd.h>".}
proc c_gettid(): clong {.importc: "repro_linux_gettid", raises: [].}
proc c_fileno(stream: pointer): cint
  {.importc: "fileno", header: "<stdio.h>", raises: [].}
proc c_get_errno(): cint {.importc: "repro_linux_get_errno", raises: [].}
proc c_set_errno(value: cint) {.importc: "repro_linux_set_errno", raises: [].}
proc c_errno_is_connect_in_progress(value: cint): cint
  {.importc: "repro_linux_errno_is_connect_in_progress", raises: [].}
proc c_sockaddr_family(address: pointer; addrLen: uint32): cint
  {.importc: "repro_linux_sockaddr_family", raises: [].}
proc c_socket_peer_pid(fd: cint): clong
  {.importc: "repro_linux_socket_peer_pid", raises: [].}
proc c_socket_peer_uid(fd: cint): clong
  {.importc: "repro_linux_socket_peer_uid", raises: [].}
proc c_sockaddr_un_path(address: pointer; addrLen: uint32; buf: ptr char;
                        cap: cint): cint
  {.importc: "repro_linux_sockaddr_un_path", raises: [].}
proc c_fd_identity_kind(fd: cint; dev, ino: ptr uint64; kind: ptr cint): cint
  {.importc: "repro_linux_fd_identity_kind", raises: [].}
proc c_fd_proc_path(fd: cint; buf: pointer; len: csize_t): cint
  {.importc: "repro_linux_fd_proc_path", raises: [].}
proc c_self_exe_path(buf: pointer; len: csize_t): cint
  {.importc: "repro_linux_self_exe_path", raises: [].}
proc c_raw_syscall6(nr, a1, a2, a3, a4, a5, a6: clong): clong
  {.importc: "repro_linux_raw_syscall6", cdecl, raises: [].}
  ## Bound to the exported portable wrapper, NOT to
  ## ``stackable_linux_raw_syscall6`` directly and NOT to the ``static``
  ## ``repro_raw_syscall6``. nim-stackable-hooks emits the former only on amd64,
  ## and this binding has live call sites that are not behind an arch guard
  ## (``getcwd`` at minimum) — so binding it directly left an undefined symbol
  ## in an LD_PRELOADed object on aarch64.

# M9.R.62.2 — bridge procs the C-side signal handler calls to reach into
# writer.nim's threadvar-resident fragment slot. Every proc is a pure POD
# read (no allocation, no lock acquisition), so calling from a signal
# context is async-signal-safe. Return-type mapping: `bool` → `int`
# (0/1), `pointer` → `pointer`, `int` → `long`.

proc repro_linux_sig_safe_slot_is_open(): cint {.exportc, cdecl, raises: [].} =
  if sigSafeSlotIsOpen(): 1 else: 0

proc repro_linux_sig_safe_slot_fd(): cint {.exportc, cdecl, raises: [].} =
  sigSafeSlotFd()

proc repro_linux_sig_safe_slot_identity_matches(): cint
    {.exportc, cdecl, raises: [].} =
  let fd = sigSafeSlotFd()
  if fd < 0:
    return 0
  var device, fileId: uint64
  var kind: cint
  if c_fd_identity_kind(fd, addr device, addr fileId, addr kind) != 1:
    return 0
  if kind == 1 and device == sigSafeSlotDevice() and
      fileId == sigSafeSlotFileId():
    return 1
  0

proc repro_linux_sig_safe_batch_ptr(): pointer {.exportc, cdecl, raises: [].} =
  sigSafeBatchPtr()

proc repro_linux_sig_safe_batch_len(): clong {.exportc, cdecl, raises: [].} =
  clong(sigSafeBatchLen())

proc repro_linux_sig_safe_committed_ptr(): pointer {.exportc, cdecl, raises: [].} =
  sigSafeCommittedPtr()

proc repro_linux_sig_safe_committed_len(): clong {.exportc, cdecl, raises: [].} =
  clong(sigSafeCommittedLen())

proc repro_linux_sig_safe_mark_slot_closed() {.exportc, cdecl, raises: [].} =
  sigSafeMarkSlotClosed()

proc repro_linux_sig_safe_note_signal(signum: clong)
    {.exportc, cdecl, raises: [].} =
  ## M9.R.64.1 — bridge to record the last terminating signum in the
  ## per-thread deep-diag slot. Async-signal-safe: `setKillDiagDeepSignalCode`
  ## does a single POD integer store into a threadvar. Ignored when
  ## deep mode is off.
  setKillDiagDeepSignalCode(int(signum))

proc repro_linux_install_terminating_signal_handlers(): cint
  {.importc, cdecl, raises: [].}

# DEP-FLUSH-3/4 — C-side bridges (imported). The exported Nim halves that
# libc calls back into (`repro_linux_thread_exit_flush`,
# `repro_linux_atfork_child`) are defined AFTER `withShimMuted` below.
proc repro_linux_arm_thread_exit_flush_c()
  {.importc, cdecl, raises: [].}
proc repro_linux_disarm_thread_exit_flush_c()
  {.importc, cdecl, raises: [].}
proc c_pthread_atfork(prepare, parent, child: pointer): cint
  {.importc: "pthread_atfork", header: "<pthread.h>", raises: [].}
proc repro_linux_atfork_child_c() {.importc, cdecl, raises: [].}

type
  FdKind = enum
    fkUnknown = 0
    fkRegular = 1
    fkFifo = 2
    fkSocket = 3
    fkDirectory = 4
    fkOther = 5

proc currentThreadId(): uint64 =
  ## FUP-K — thread-cached `gettid`. Stable for the thread's lifetime; the
  ## fork-child handler clears the cache so a child re-fetches its own tid.
  if cachedTid == 0:
    cachedTid = uint64(c_gettid())
  cachedTid

proc currentPid(): uint64 {.raises: [].} =
  ## FUP-K — thread-cached `getpid`. Process-constant; reset in the fork child.
  if cachedPid == 0:
    cachedPid = uint64(c_getpid())
  cachedPid

proc currentPpid(): uint64 {.raises: [].} =
  ## FUP-K — thread-cached `getppid`. Reset in the fork child so the child
  ## re-fetches (its parent is the process that forked it).
  if cachedPpid == 0:
    cachedPpid = uint64(c_getppid())
  cachedPpid

proc resetIdentityCaches() {.raises: [].} =
  ## FUP-K — invalidate the pid/ppid/tid caches. Called from the
  ## pthread_atfork CHILD handler: the child has a new tid, a new pid, and a
  ## new parent, so all three must be re-fetched on next use.
  cachedTid = 0
  cachedPid = 0
  cachedPpid = 0

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

proc repro_linux_thread_exit_flush() {.exportc, cdecl, raises: [].} =
  ## DEP-FLUSH-3 — invoked by libc from the pthread-key value-destructor on
  ## thread exit. Flushes + closes + unregisters the calling thread's slot
  ## so a short-lived worker thread's buffered batch is durable before its
  ## TLS is torn down. Muted so the teardown emits no new records.
  ##
  ## `threadExitFlushSlot` also frees the thread's heap-resident slot (see
  ## `fragmentSlotOnHeap` in writer.nim). libc cleared this key's value
  ## before calling us, so drop `threadExitArmed` too: if a later TLS
  ## destructor on this thread emits a record (allocating a fresh slot),
  ## `emitRecord` re-arms the key and libc's destructor loop (up to
  ## PTHREAD_DESTRUCTOR_ITERATIONS passes) calls us again to flush and free
  ## it, instead of leaking it.
  withShimMuted:
    try: threadExitFlushSlot()
    except CatchableError: discard
  threadExitArmed = false

proc armThreadExitFlush() {.raises: [].} =
  ## DEP-FLUSH-3 — set the pthread key to a non-NULL sentinel so libc fires
  ## the thread-exit destructor for THIS thread. Called once per thread,
  ## right after it first opens its fragment slot (see emitRecord).
  repro_linux_arm_thread_exit_flush_c()

proc repro_linux_atfork_prepare() {.cdecl, raises: [].} =
  # The shared table is atomic; its process-local mapped-shard sequence is
  # mutable. Fork must copy that view only between complete publications.
  acquire(recordLock)

proc repro_linux_atfork_parent() {.cdecl, raises: [].} =
  release(recordLock)

proc repro_linux_atfork_child() {.exportc, cdecl, raises: [].} =
  ## DEP-FLUSH-4 — reset the child's inherited slot + registry so it never
  ## replays the parent's buffered frames or writes through the COW-shared
  ## fd. Muted so no record is emitted during the reset.
  # FUP-K — the child has a fresh pid/ppid/tid; drop the inherited (COW) caches
  # so `baseRecord` re-fetches them for the child's records. Runs inside fork()
  # in the child before fork() returns, so every child record sees fresh values.
  # prepare acquired this lock on the forking thread. Release the child's
  # copy before detaching/re-attaching its private producer view.
  release(recordLock)
  resetIdentityCaches()
  withShimMuted:
    try: discardFragmentSlotAfterFork()
    except CatchableError: discard
    # DEP-SHM-2 — the child inherited the parent's dep-queue mapping COW; detach
    # + re-attach FRESH so the child publishes through its OWN fd, never the
    # parent's inherited handle. Empty path ⇒ no ring, a harmless no-op.
    try: discardDepQueueAfterFork(depShmPath)
    except CatchableError: discard

proc sampleKillDiag(phase: string) {.raises: [].} =
  ## M9.R.62.1 — precise-attribution instrumentation for the parent-side
  ## kill-before-flush residual. Publishes the calling thread's current
  ## shim state ("phase=<name> bypassed=<0|1> inForkChild=<0|1>
  ## disabled=<N>") to the writer's per-thread diag context slot so any
  ## subsequent read-tail-pending marker carries this attribution. The
  ## writer's mergeFragments extracts the last-seen ctx from an unmatched
  ## pending marker and copies it into the synthetic event-loss detail;
  ## empty no-op when IO_MON_KILL_DIAG is off. Kept branch-cheap so the
  ## non-diagnostic build path pays only the env-var probe on first call.
  when false: # keep string ops out of hot builds
    discard
  var buf = "phase=" & phase &
    " bypassed=" & (if shouldBypass(): "1" else: "0") &
    " inForkChild=" & (if inForkChild: "1" else: "0") &
    " disabled=" & $disabled &
    " pid=" & $c_getpid() &
    " ppid=" & $c_getppid()
  setKillDiagContext(buf)
  setKillDiagDeepLastHook(phase)

proc readProcFile(path: cstring): string {.raises: [].} =
  ## The contents of a small procfs file, or "" on any error. Replaces
  ## `readFile` on the hook path: `readFile` goes through stdio, and glibc's
  ## `fopen` allocates its `FILE` with the process's `malloc` — the HOST's, if
  ## it replaces malloc — from inside a hook the host may have entered while
  ## holding its allocator lock (see `shim/linux_private_heap.c`). This reads
  ## with the real `open`/`read`/`close` into a Nim string, which the shim's
  ## private heap backs.
  const O_RDONLY_CLOEXEC = 0o2000000.cint   # O_RDONLY | O_CLOEXEC
  let fd = realOpen(path, O_RDONLY_CLOEXEC, 0)
  if fd < 0:
    return ""
  var used = 0
  result = newString(4096)
  while true:
    if used == result.len:
      result.setLen(result.len * 2)
    let n = realRead(fd, addr result[used], csize_t(result.len - used))
    if n < 0:
      if c_get_errno() == 4: continue   # EINTR
      used = 0
      break
    if n == 0:
      break
    used += int(n)
  discard realClose(fd)
  result.setLen(used)

proc sampleKillDiagArgvOnce() {.raises: [].} =
  ## M9.R.64.1 — one-shot per-thread /proc/self/cmdline snapshot. The
  ## cmdline stays constant after the last execve, so subsequent calls
  ## are no-ops (guarded inside `setKillDiagDeepArgv`). Silently returns
  ## on read failure so the shim never depends on procfs for
  ## correctness. `withShimMuted` prevents the read itself from being
  ## re-sampled by our own file-open hooks.
  if not killDiagDeepIsOn():
    return
  var content: string
  withShimMuted:
    content = readProcFile("/proc/self/cmdline")
  if content.len == 0:
    return
  let bufPtr =
    cast[ptr UncheckedArray[byte]](unsafeAddr content[0])
  setKillDiagDeepArgv(bufPtr, content.len)

proc baseRecord(kind: MonitorRecordKind;
                observationKind: MonitorObservationKind): MonitorRecord =
  result = MonitorRecord(
    kind: kind,
    observationKind: observationKind,
    seq: processSeq(),
    probeResult: prUnknown)
  if kind == mrProcessExec:
    # vfork shares the suspended parent's TLS and skips pthread_atfork.
    # Attribute both exec attempts and failures to the actual caller without
    # overwriting caches the parent will reuse when the child execs or exits.
    result.osPid = uint64(c_getpid())
    result.parentOsPid = uint64(c_getppid())
    result.threadId = uint64(c_gettid())
  else:
    result.osPid = currentPid()
    result.parentOsPid = currentPpid()
    result.threadId = currentThreadId()

proc stampRunId(record: var MonitorRecord) {.raises: [].} =
  ## Scope Linux records to the launcher's run id so reused fragment directories
  ## can be filtered without relying only on pid ownership.
  if runId.len == 0 or detailToken(record.detail, "run").len > 0:
    return
  if record.detail.len > 0:
    record.detail.add " "
  record.detail.add "run=" & runId

proc emitRecord(record: MonitorRecord) {.raises: [].} =
  if not initialized or fragmentDir.len == 0 or shouldBypass():
    return
  # Event-interest gate (docs/contributors/event-interest-filter.md §4.1). Skip
  # the whole record — construction already happened at the call site, but the
  # expensive publish (gset insert + dedup, or fragment write) is avoided — for a
  # category the consumer did not ask for. `recordWanted` returns true for
  # META/loss kinds, so a suppressed interest can never drop an `mrEventLoss`
  # (LF-1: that would risk a false `mcComplete`).
  if not recordWanted(gInterest, record.kind):
    return
  # DA-1i — evidence-scope gate, RIGHT HERE and not at the host, because the
  # whole point of `--evidence=reads-only` is to MEASURE what the records cost:
  # a mode that publishes the record and filters it later saves nothing and
  # measures nothing. So the expensive part — the gset insert + dedup, or the
  # fragment write — is what this skips.
  #
  # A DIFFERENT PREDICATE FROM THE ONE ABOVE, deliberately. `recordWanted` gates
  # on the record's KIND; this gates on its RESULT, and no refinement of
  # `EventCategory` can do it because success is not a kind (measured: gating a
  # probes category yields 41,736 records where `reads-only` means 23,049,
  # discarding 2,066 successful probes and keeping 20,753 failed opens).
  #
  # `recordIsFailedExistenceLookup` answers false for every META kind BY
  # CONSTRUCTION — it asks `categoryOf`, the one definition of what META is — so
  # exactly as with `recordWanted` above, a narrowed capture can never drop an
  # `mrEventLoss` and manufacture a false `mcComplete` (LF-1). That is asserted
  # exhaustively over `MonitorRecordKind` in
  # `tests/portable/test_io_mon_evidence_scope.nim`, not left to this comment.
  if not recordInEvidenceScope(gEvidenceScope, record):
    return
  # M9.R.62.2 — refresh the diagnostic context on every emit so an
  # unmatched pending marker carries the LAST-observed record kind
  # instead of the stale "phase=init" from the constructor. A process
  # that reads then dies via raw exit_group (bypassing every hook AND
  # the destructor AND the signal handler) will have the final pending
  # marker's ctx reflect the most recent record's `kind` — a class
  # signal for the M9.R.62.5 evidence + a target for future
  # instrumentation. Cheap no-op when IO_MON_KILL_DIAG is off.
  when defined(io_mon_kill_diag_hot):
    sampleKillDiag("emit kind=" & $ord(record.kind))
  else:
    if killDiagIsOn():
      sampleKillDiag("emit kind=" & $ord(record.kind))
  # M9.R.64.1 — always refresh the deep-diag last-emit slots when
  # deep mode is on. This runs OUTSIDE `withShimMuted` so the ctx and
  # last-path/kind slot both reflect the same emit even when the
  # process dies before the batch flushes. Non-deep mode: single
  # branch mispredict (killDiagDeepIsOn returns false).
  if killDiagDeepIsOn():
    setKillDiagDeepLastPath(record.path, ord(record.kind))
  withShimMuted:
    var stamped = record
    stampRunId(stamped)
    # All host threads share one producer. Its local shard mapping sequence
    # can grow even though the shared-memory inserts themselves are atomic.
    # Muting precedes the lock so allocation/file hooks cannot reenter it.
    acquire(recordLock)
    try:
      appendFragmentRecord(fragmentDir, stamped)
    finally:
      release(recordLock)
    # DEP-FLUSH-3 — arm the pthread-key thread-exit flush once per thread,
    # right after this thread's slot is open (appendFragmentRecord opened /
    # registered it above). libc then fires the value-destructor on this
    # thread's exit, flushing + closing + unregistering its slot. This lets
    # a worker thread keep the 64 KiB batching win — its durability no
    # longer depends on the process-exit destructor (which cannot reach an
    # already-dead worker's TLS) nor on an eager per-record flush.
    if not threadExitArmed:
      armThreadExitFlush()
      threadExitArmed = true
    # Belt-and-braces: worker threads (non-main) ALSO flush eagerly per
    # record. On glibc/musl the pthread-key destructor above runs while
    # native TLS is still valid and makes this redundant, but the eager
    # flush is a zero-risk fallback for any exotic libc whose key-destructor
    # ordering we have not characterised. The main thread keeps a pure
    # batch (flushed by the process-exit destructor / registry sweep).
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

# ---------------------------------------------------------------------------
# LIBRARY-LOAD OBSERVATION (`mcapLibraryLoad`) — see the long design note above
# `ct_linux_library_scan` in `linux_preload_runtime.nim` for WHY this asks the
# loader instead of hooking it, and for the coverage arithmetic it implements.
#
# NOTE ON WHERE THE STATE LIVES. The seen-set and the previous `dlpi_adds` are
# deliberately NOT Nim globals here; they are C-side POD (see that same note).
# A scan runs on whichever thread called `dlopen`, so long-lived Nim heap state
# shared between scans would be allocated on one thread and grown or freed on
# another — the FUP-C allocator-corruption class this file already warns about
# for the fd/dir/stream tables. Serialising with a lock orders the accesses; it
# does not make the ORC allocator cross-thread safe. What remains on the Nim
# side is per-record temporaries, created and released inside a single sink call
# on one thread, exactly like every other hook.
#
# Fork/exec: the C state is inherited across `fork` (correctly — the child has
# the same mappings and the same history) and reset by the constructor re-running
# after `exec` (correctly — a new image has a new link map).
# ---------------------------------------------------------------------------
var
  libScanLock: Lock
  libScanSinkFailed = false   ## plain bool, no heap: safe to touch from any thread

proc libraryLoadRecordablePath(path: string): bool {.raises: [].} =
  ## Which enumerated objects become `mrLibraryLoad` records.
  ##
  ## Excluded, and why each exclusion is not a coverage hole:
  ##   * the MAIN EXECUTABLE (`dlpi_name == ""`) — already captured as the
  ##     process image by `mrProcessExec` / `mrProcessStart`; recording it again
  ##     under a different kind would double-count, not add coverage.
  ##   * the VDSO (`linux-vdso.so.1`) — kernel-provided, has no on-disk file, so
  ##     there is nothing for a consumer to fingerprint.
  ##   * THIS SHIM — the monitor's own footprint. Recording it would make every
  ##     captured dependency set depend on the monitor binary, so upgrading
  ##     io-mon would invalidate every cached action for a reason that has
  ##     nothing to do with the action.
  ## Everything else — libc, the loader itself, every toolchain library — IS
  ## recorded. Unlike macOS's shared cache there is no Linux system-library blob
  ## that could justify a baseline exemption: on a Nix or container image the
  ## libc under `/nix/store` or `/usr/lib` is a genuine, upgradeable input.
  if path.len == 0: return false
  if not path.startsWith("/"): return false
  if path.endsWith("librepro_monitor_shim.so"): return false
  true

proc libraryScanSink(name: cstring; address: culong; reason: cstring)
    {.cdecl, raises: [].} =
  ## Invoked once per NEWLY-SEEN link-map entry, after `dl_iterate_phdr` has
  ## returned and the loader lock is released — so allocating and recording here
  ## is safe, and every allocation is freed on this same thread before returning.
  try:
    let path = if name == nil: "" else: $name
    if libraryLoadRecordablePath(path):
      var record = baseRecord(mrLibraryLoad, moFileRead)
      record.path = path
      record.detail = "library-load dl_iterate_phdr " &
        (if reason == nil: "" else: $reason)
      emitRecord(record)
    elif path.len > 0 and not path.startsWith("/") and
        not path.startsWith("linux-vdso") and not path.startsWith("linux-gate"):
      # An object the loader names relatively: it IS a real file dependency but
      # we cannot state WHICH one, because a relative name is only meaningful
      # against a working directory that has since moved on. Flagged, not
      # guessed — a wrong path in a dependency set is worse than a stated gap.
      libScanSinkFailed = true
  except CatchableError:
    libScanSinkFailed = true

proc scanLoadedLibraries(reason: cstring) {.raises: [].} =
  ## Enumerate the loader's link map, record every newly-seen object as a
  ## content dependency, and then PROVE that the enumeration covered every load
  ## the loader performed since the previous scan.
  ##
  ## The proof is what makes this honest rather than merely useful. Sampling the
  ## link map at chosen points leaves one question open — "what about an object
  ## loaded and unloaded between two samples?" — and an open question about
  ## input coverage may not be answered with `mcComplete`. Scanning immediately
  ## before and after interposed loader calls separates ordinary unload/reload
  ## transitions. The loader counters can then prove a gap only when more loads
  ## occurred than objects appeared since the preceding link-map snapshot and
  ## an unload confirms that an object could have vanished between scans.
  if not initialized or inForkChild:
    return
  acquire(libScanLock)
  defer: release(libScanLock)
  libScanSinkFailed = false
  var performed: uint64 = 0
  var removed: uint64 = 0
  var newlyActive: cint = 0
  var newlySeen: cint = 0
  var countersValid: cint = 0
  var overflow: cint = 0
  # NOT muted. The sink records on behalf of the monitored process, and
  # `emitRecord` is a no-op while the shim is muted. The loader walk itself
  # cannot re-enter the hooks: `dl_iterate_phdr` performs no file I/O and
  # resolves no symbols.
  let count = linuxLibraryScan(cast[pointer](libraryScanSink), reason,
                               addr performed, addr removed, addr newlyActive,
                               addr newlySeen, addr countersValid, addr overflow)
  let why = if reason == nil: "" else: $reason
  if count < 0:
    emitEventLoss("library-load scan failed (" & why & ")")
    return

  # --- coverage proof -----------------------------------------------------
  if libScanSinkFailed:
    emitEventLoss("library-load coverage gap: a loaded object could not be " &
      "recorded or is named only relatively by the loader, so the file behind " &
      "it cannot be identified (" & why & ")")
  elif overflow != 0:
    emitEventLoss("library-load enumeration overflowed its snapshot buffer: " &
      "the process has more loaded objects than the scan can hold (" &
      why & ")")
  elif countersValid == 0:
    emitEventLoss("library-load coverage is unprovable: this loader does not " &
      "report dlpi_adds/dlpi_subs, so a library loaded and unloaded between " &
      "scans would be undetectable (" & why & ")")
  elif uint64(newlyActive) < performed and removed > 0:
    emitEventLoss("library-load coverage gap: the loader performed " &
      $performed & " load(s) since the previous scan but only " &
      $newlyActive & " object(s) appeared in the link map (" &
      why & "); " & $removed & " object(s) were unloaded — at least one " &
      "shared object may have been loaded and unloaded without " &
      "being observed, so its bytes are an input this capture cannot name")

proc drainInlineRawSyscallEvents() {.raises: [].}
proc installLinuxVdsoPatches() {.raises: [].}
proc emitLinuxVdsoPatchFailures(source: string) {.raises: [].}
# Defined next to the other `record*` helpers, below the vDSO block; forward
# declared because `classifyRawFileSyscall` (the raw-`syscall()` classifier)
# sits above it and must emit the same entropy observation the libc-symbol and
# vDSO entry points do.
proc recordNonDeterministic(source: string) {.raises: [].}
proc repro_vdso_clock_gettime*(clockId: cint; tp: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].}
proc repro_vdso_gettimeofday*(tv, tz: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].}
proc repro_vdso_time*(tloc: ptr clong): clong
    {.exportc, cdecl, dynlib, raises: [].}
proc repro_vdso_clock_getres*(clockId: cint; res: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].}
proc repro_vdso_getcpu*(cpu, node: ptr cuint; unused: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].}
proc repro_vdso_getrandom*(buf: pointer; buflen: csize_t; flags: cuint): clong
    {.exportc, cdecl, dynlib, raises: [].}

proc recordRawSyscallCoverage(status: RawSyscallPatchStatus) {.raises: [].} =
  if rawSyscallCoverageRecorded:
    return
  rawSyscallCoverageRecorded = true
  if status.installed:
    return
  emitEventLoss("linux raw-syscall wrapper patch unavailable diagnostic=" &
    $status.diagnostic & " stage=" & $status.stage &
    " errno=" & $status.osErrno & " ownerJoin=" & rawSyscallOwnerJoinReason() &
    " ownerImage=" & rawSyscallOwnerJoinImage())

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
  # Drained whatever the trap count says: an event can also arrive from
  # another loaded io-mon shim that owns the trap and forwards it here
  # (`ct_linux_preload_raw_enqueue_v1`), and this shim's own count does not
  # include those.
  drainInlineRawSyscallEvents()
  if inlineSyscallTrapCoverageRecorded:
    return
  let traps = inlineSyscallTrapCount()
  let failures = inlineSyscallFailureCount()
  if traps == 0 and failures == 0:
    return
  inlineSyscallTrapCoverageRecorded = true
  if failures != 0:
    emitEventLoss("linux inline raw syscall replay failed nr=" &
      $inlineSyscallLastNumber() & " address=0x" &
      toHex(inlineSyscallLastAddress()) & " traps=" & $traps &
      " failures=" & $failures, int64(inlineSyscallLastNumber()))

proc observerLibraryScan(reason: cstring) {.cdecl, raises: [].} =
  scanLoadedLibraries(reason)

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
  podFileReadExcl(fd)
  podFdPathSet(fd, path)

proc removeFdPath(fd: cint) =
  podFdPathDel(fd)
  podEmptyFdExcl(fd)
  podInheritedFdExcl(fd)
  podFileReadExcl(fd)

proc pathForFd(fd: cint): string =
  podFdPathGet(fd)

proc markEmptyFdClassified(fd: cint) {.raises: [].} =
  podEmptyFdSet(fd)

proc emptyFdAlreadyClassified(fd: cint): bool {.raises: [].} =
  podEmptyFdContains(fd)

proc inheritedFd(fd: cint): bool {.raises: [].} =
  podInheritedFdContains(fd)

proc rememberInheritedOpenFds() {.raises: [].} =
  podInheritedFdClear()
  for fd in 0.cint .. 1024.cint:
    var dev, ino: uint64
    var kind: cint
    if c_fd_identity_kind(fd, addr dev, addr ino, addr kind) != 0:
      podInheritedFdSet(fd)

proc localFdKey(dev, ino: uint64): string {.raises: [].} =
  "localfd:" & $dev & ":" & $ino

proc recordExternalContent(chan, role, path: string; fd: cint;
                           peerPid: uint64 = 0) {.raises: [].} =
  ## `peerPid` (0 = unknown) names the process on the OTHER end of the channel,
  ## carried in `childOsPid` exactly as `mrIpcConnect` does. IoMon-Pipeline-Capture
  ## IM-4: the merge uses it to answer "is the producer inside the monitored tree?"
  ## directly, instead of inferring it from an in-tree create record.
  var record = baseRecord(mrExternalContent, moExternalContent)
  record.path = path
  record.flags = uint32(fd)
  record.childOsPid = peerPid
  record.detail = "chan=" & chan & " role=" & role &
    (if peerPid == 0: "" else: " peer=" & $peerPid)
  emitRecord(record)

proc channelPeerPid(fd: cint; kind: FdKind): uint64 {.raises: [].} =
  ## IoMon-Pipeline-Capture IM-4 — the pid of the process on the other end of a
  ## content channel, or 0 when the channel cannot name it.
  ##
  ## Only an AF_UNIX socket can: `SO_PEERCRED` returns the KERNEL's record of the
  ## credentials the peer had when the connection was established (for an accepted
  ## fd, the connector; for a connector's fd, the listener; for a `socketpair`, its
  ## creator). It is stamped by the kernel, not by either userspace end, so it
  ## cannot be forged from inside the monitored tree, and it survives the peer's
  ## exit. A pipe, a FIFO, an AF_INET socket or any other fd fails the `getsockopt`
  ## and yields 0.
  ##
  ## Fails SAFE in one direction only: an unobtainable peer leaves the consume
  ## unattributed, which at worst costs a conservative re-run. It can never invent
  ## an in-tree producer.
  if kind != fkSocket:
    return 0
  let pid = c_socket_peer_pid(fd)
  if pid > 0: uint64(pid) else: 0

proc localFdChannelKey(fd: cint; dev, ino: uint64; kind: FdKind): string
    {.raises: [].}

proc recordLocalFdCreate(fd: cint) {.raises: [].} =
  ## IoMon-Pipeline-Capture IM-3 — record that a monitored (in-tree) process
  ## CREATED a local IPC fd (`pipe`/`pipe2`/`socketpair`), stamping the kernel
  ## (dev,ino) identity of the underlying object so the merge can PAIR a later
  ## inherited `chan=opaque role=read` against it (writer.externalContentLossCount).
  ##
  ## This is the cardinal-sin guard for the Linux arm of ROUND-4 IP1, mirroring
  ## `macos_interpose.recordLocalFdCreate`: an entirely in-tree pipeline —
  ## `sh -c 'echo hi | cat'`, a compiler driver's driver↔cc1 pipes — is paired and
  ## stays `mcComplete`, while an fd inherited from an OUT-OF-TREE creator has no
  ## in-tree create, stays unpaired, and still downgrades.
  ##
  ## Direction of failure is deliberately one-way: the `fstat` is a raw syscall and
  ## a failure is swallowed. A MISSING create can only leave a consume unpaired,
  ## i.e. a conservative re-run; it can never manufacture a pairing. Conversely an
  ## EXTRA create only suppresses a downgrade for an object the monitored tree
  ## demonstrably made itself, which is the whole point.
  if fd < 0:
    return
  var dev, ino: uint64
  var kind: cint
  if c_fd_identity_kind(fd, addr dev, addr ino, addr kind) == 0:
    return
  recordExternalContent("localfd", "create",
    localFdChannelKey(fd, dev, ino, FdKind(kind)), fd)

proc recordLocalFdPair(fds: ptr cint) {.raises: [].} =
  ## Record BOTH ends of a freshly created fd pair. On Linux the two ends of a
  ## `pipe` share ONE pipefs inode (so the second record dedups in the set), but a
  ## `socketpair`'s ends have DISTINCT inodes and the consumer may fstat either —
  ## so both are recorded unconditionally rather than relying on which end is
  ## which.
  if fds == nil:
    return
  let arr = cast[ptr UncheckedArray[cint]](fds)
  recordLocalFdCreate(arr[0])
  recordLocalFdCreate(arr[1])

proc hookScratchString(): string {.inline, raises: [].} =
  ## A PATH_MAX-sized byte buffer for a C helper to write a path into, as a
  ## heap-backed Nim string rather than a stack array.
  ##
  ## WHY. A hook runs on the stack of whatever HOST thread made the call, and a
  ## host may legally create that thread with PTHREAD_STACK_MIN (16 KiB on
  ## x86_64) — minus glibc's guard page, TCB and static TLS. Each 4 KiB path
  ## array on the hook path was a quarter of that; together with the 16 KiB
  ## dep-set key buffer in the writer they overflowed such a thread inside a
  ## hooked `open` (SIGSEGV), which
  ## `tests/linux/test_io_mon_shim_static_tls_small_stack_threads` now grades.
  ##
  ## SAFE HERE. Every caller already builds Nim strings from the result, so the
  ## path allocates on the same thread either way (the shim's allocator is the
  ## C heap: `-d:useMalloc`, routed to the shim's own mmap-backed heap by
  ## `linux_private_heap.c`). The string is a local, so it is neither shared
  ## with a nested hook nor live after the call returns.
  newString(4096)

proc isLinuxDeletedProcFdTarget(path: string): bool {.raises: [].} =
  path.endsWith(" (deleted)")

proc localFdChannelKey(fd: cint; dev, ino: uint64; kind: FdKind): string
    {.raises: [].} =
  ## The pairing key of a local channel object: its kernel `(dev, ino)`, and
  ## for an anonymous-inode object also its type as the kernel names it.
  ##
  ## WHY THE TYPE. Linux backs most anonymous-inode objects — eventfd, timerfd,
  ## signalfd, inotify, epoll, fanotify, bpf maps, ... — with ONE shared inode,
  ## so `(dev, ino)` alone names "some anonymous object", not this one. Keyed
  ## that way, an in-tree `eventfd` create (Chromium makes many) would pair
  ## with a read of ANY inherited anonymous-inode fd, including an inotify or
  ## fanotify descriptor handed in from outside the tree, whose reads carry
  ## external input. The `/proc/self/fd` link names the type
  ## (`anon_inode:[eventfd]`, `anon_inode:inotify`, ...), so a create only
  ## pairs with reads of the same kind of object. What remains coarse is
  ## within one type: an in-tree eventfd still pairs with an out-of-tree
  ## eventfd, which carries a counter, not content.
  ##
  ## Only `fkOther` fds are anonymous inodes; pipes, sockets and files keep
  ## the plain key (their inodes are per object). If the link cannot be read
  ## the plain key is used on both sides alike, which is the old behaviour.
  result = localFdKey(dev, ino)
  if kind != fkOther:
    return
  var buf = hookScratchString()
  if c_fd_proc_path(fd, addr buf[0], csize_t(buf.len)) == 0:
    return
  let target = $cast[cstring](addr buf[0])
  if target.startsWith("anon_inode:"):
    result.add ":" & target

proc recoverNamedFdRead(fd: cint; kind: FdKind): bool {.raises: [].} =
  ## Recover regular files and named devices after an inherited fd or an
  ## untracked dup replaced the descriptor that carried the original path.
  if kind notin {fkRegular, fkOther}:
    return false
  # Heap, not a stack array: this runs inside a hooked `read` on the HOST's
  # thread, whose stack may be as small as PTHREAD_STACK_MIN. See
  # `hookScratchString`.
  var buf = hookScratchString()
  if c_fd_proc_path(fd, addr buf[0], csize_t(buf.len)) == 0:
    return false
  let resolved = $cast[cstring](addr buf[0])
  if not resolved.isAbsolute or resolved.startsWith("anon_inode:") or
      isLinuxDeletedProcFdTarget(resolved):
    return false
  updateFdPath(fd, cstring(resolved))
  var record = baseRecord(mrFileRead, moFileRead)
  record.path = resolved
  record.result = 0
  record.flags = uint32(fd)
  record.detail = "inherited-fd"
  discard podFileReadMarkIsNew(fd)
  emitRecord(record)
  true

proc classifyEmptyFdRead(fd: cint): bool {.raises: [].} =
  if fd < 0 or emptyFdAlreadyClassified(fd):
    return false
  var dev, ino: uint64
  var rawKind: cint
  if c_fd_identity_kind(fd, addr dev, addr ino, addr rawKind) == 0:
    emitEventLoss("linux inherited fd read unresolved fd=" & $fd)
    markEmptyFdClassified(fd)
    return false
  let kind = FdKind(rawKind)
  if recoverNamedFdRead(fd, kind):
    return true
  if kind == fkRegular:
    emitEventLoss("linux inherited regular fd read unnamed key=" &
      localFdKey(dev, ino) & " fd=" & $fd)
    markEmptyFdClassified(fd)
  elif kind == fkFifo or kind == fkSocket or kind == fkOther:
    if not inheritedFd(fd):
      # FUP-K — a NON-inherited pipe/socket/other fd (BEAM opens its ports
      # AFTER shim init) never names a file, so it produces no dependency on
      # any read. Mark it classified so the enormous volume of subsequent
      # reads on the SAME hot fd skip the `fstat` in c_fd_identity_kind. The
      # bit is cleared by removeFdPath on close, so a later reuse of the fd
      # number re-classifies. No record is emitted here in either case, so
      # the recorded dependency set is byte-identical.
      markEmptyFdClassified(fd)
      return false
    recordExternalContent("opaque", "read",
      localFdChannelKey(fd, dev, ino, kind), fd, channelPeerPid(fd, kind))
    markEmptyFdClassified(fd)
  else:
    if not inheritedFd(fd):
      markEmptyFdClassified(fd)  # FUP-K — see the fifo/socket branch above.
      return false
    recordExternalContent("opaque", "read",
      localFdChannelKey(fd, dev, ino, kind), fd, channelPeerPid(fd, kind))
    markEmptyFdClassified(fd)
  false

proc pathForAt(dirfd: cint; path: cstring): string {.raises: [].} =
  if path == nil:
    return ""
  let raw = $path
  if raw.len == 0 or raw.isAbsolute:
    return raw
  if dirfd == LinuxAtFdcwd:
    # Heap, not a stack array — see `hookScratchString`.
    var cwdBuf = hookScratchString()
    let n = c_raw_syscall6(LinuxSysGetcwd,
      cast[clong](addr cwdBuf[0]), clong(cwdBuf.len), 0, 0, 0, 0)
    if n > 0:
      let cwd = $cast[cstring](addr cwdBuf[0])
      if cwd.len > 0:
        return cwd / raw
    return raw
  var base = pathForFd(dirfd)
  if base.len == 0:
    # A directory fd the shim did not see opened (inherited, opened inside
    # libc, or before the shim initialised): ask the kernel what it names, as
    # `recordRawGetdents` does. Joining the relative path onto nothing would
    # leave it relative, and a consumer resolves a relative path against the
    # action's working directory -- a different file.
    var buf = hookScratchString()
    if c_fd_proc_path(dirfd, addr buf[0], csize_t(buf.len)) != 0:
      let resolved = $cast[cstring](addr buf[0])
      if resolved.isAbsolute and not isLinuxDeletedProcFdTarget(resolved):
        base = resolved
  if base.len == 0:
    return raw
  result = base / raw

proc dirKey(dirp: pointer): uint =
  cast[uint](dirp)

proc updateDirPath(dirp: pointer; path: cstring) =
  if dirp == nil or path == nil:
    return
  podDirPathSet(dirKey(dirp), path)

proc removeDirPath(dirp: pointer) =
  podDirPathDel(dirKey(dirp))

proc pathForDir(dirp: pointer): string =
  podDirPathGet(dirKey(dirp))

proc streamKey(stream: pointer): uint =
  cast[uint](stream)

proc updateStreamPath(stream: pointer; path: cstring) =
  if stream == nil or path == nil:
    return
  podStreamPathSet(streamKey(stream), path)

proc removeStreamPath(stream: pointer) =
  podStreamPathDel(streamKey(stream))

proc pathForStream(stream: pointer): string =
  podStreamPathGet(streamKey(stream))

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
    initLock(libScanLock)
    initPodTables()
    locksReady = true
  acquire(initLockVar)
  defer: release(initLockVar)
  if initialized:
    return 0
  withShimMuted:
    fragmentDir = getEnv("REPRO_MONITOR_FRAGMENT_DIR")
    runId = getEnv("REPRO_MONITOR_SESSION")
    # `shimInterestFromEnv`, not `parseInterestTokens`: a value naming nothing
    # this build knows is read as "capture everything" rather than "capture
    # nothing". The shim has no way to refuse, and only one of the two readings
    # can be wrong in a direction the host filter cannot undo.
    gInterest = shimInterestFromEnv(getEnv("REPRO_MONITOR_INTEREST"))
    gEvidenceScope = parseEvidenceScopeToken(getEnv("REPRO_MONITOR_EVIDENCE"))
    let collection = getEnv("REPRO_MONITOR_COLLECTION_EVIDENCE")
    if collection.len > 0:
      # This can only broaden collection. It never grants capture completeness.
      # Tie the host collection request to this exact child capture route.
      gEvidenceScope = esFull
    if fragmentDir.len > 0:
      createDir(extendedPath(fragmentDir))
    # DEP-SHM-2 — attach the process to the edge's shared-memory dependency
    # queue (the FAST PATH in front of the file fragments). The engine created
    # the segment before launching us and named it via REPRO_MONITOR_DEP_SHM;
    # a failed attach silently leaves us on the file path (correctness never
    # depends on the ring being present).
    depShmPath = getEnv("REPRO_MONITOR_DEP_SHM")
    if depShmPath.len > 0:
      attachDepQueueForShim(depShmPath)
    # io-mon-Lossless-Event-Capture M3 — read THIS incarnation's exec generation
    # (REPRO_MONITOR_EXEC_GEN, set/incremented by the parent's exec hook through
    # the child env; absent ⇒ 0, the root launch). Folded into the incarnation
    # identity below so a same-pid, same-image re-exec (the Nix wrapper case)
    # yields DISTINCT process-start elements. Read inside `withShimMuted`, so the
    # getenv hook never records it as an observed dependency (golden depfiles are
    # unaffected).
    block:
      let g = getEnv("REPRO_MONITOR_EXEC_GEN")
      if g.len > 0:
        try: currentExecGen = clong(parseInt(g))
        except ValueError: currentExecGen = 0
    # io-mon-Lossless-Event-Capture M3 part 2a — capture THIS incarnation's real
    # image (`/proc/self/exe`) and hand it to the writer as the per-exec identity
    # appended to every SET dep element. The constructor re-runs on every exec, so
    # a post-exec incarnation gets its NEW image here BEFORE its process-start is
    # emitted — keeping the pre/post-exec process-starts distinct set elements with
    # no synthetic tag (LF-2/LF-7 real dedup element-key). The exec generation is
    # appended so that even a SAME-image re-exec (identical `/proc/self/exe`) stays
    # a distinct element.
    block:
      # Heap, not a stack array: the constructor normally runs on the main
      # thread, but a hook that fires first initialises lazily on whatever
      # thread made the call. See `hookScratchString`.
      var exeBuf = hookScratchString()
      let n = c_self_exe_path(addr exeBuf[0], csize_t(exeBuf.len))
      var img = ""
      if n > 0:
        img = newString(n)
        for i in 0 ..< n: img[i] = exeBuf[i]
      # Separator (0x1f, unit-separator) cannot occur in a path; the generation
      # suffix keeps same-image re-execs on one pid distinct. Opaque identity
      # bytes only — `decodeDepRecord` ignores everything past the framed record.
      setDepSetIncarnationImage(img & '\x1f' & $int(currentExecGen))
    rememberInheritedOpenFds()
  initialized = true
  mainThreadId = currentThreadId()
  # M9.R.64.1 — publish the deep shim-state bitmap early so a
  # pending marker written by the FIRST captured-dep emit already
  # carries "initialized=1", "sigHandlersInstalled=0",
  # "inlinePatchesInstalled=0", and any subsequent sample refines it.
  setKillDiagDeepShimState(KillDiagShimStateInitialized)
  # M9.R.64.1 — snapshot argv[] before any of the sub-installers
  # can spawn a child. `sampleKillDiagArgvOnce` is a cheap no-op when
  # deep mode is off.
  sampleKillDiagArgvOnce()
  sampleKillDiag("init")
  recordProcessStart()
  let collection = getEnv("REPRO_MONITOR_COLLECTION_EVIDENCE")
  if collection.len > 0 and collection != "full:" & runId:
    emitEventLoss("invalid internal collection scope for active capture route")
  # LIBRARY-LOAD OBSERVATION — the first scan, and the one that does the most
  # work. `ld.so` maps the ENTIRE initial closure before running any ELF
  # constructor, so by the time this shim's constructor runs, every DT_NEEDED of
  # the executable, every other `LD_PRELOAD`, and the loader itself are already
  # on the link map and are enumerated here. That is why "loaded before the shim
  # was initialised" is a covered case and not a hole: this design reads loader
  # STATE, and state includes everything that happened before it looked.
  scanLoadedLibraries("startup-closure")
  registerCooperativeLibraryScan(observerLibraryScan)
  let rawStatus = installRawSyscallWrapperPatch()
  recordRawSyscallCoverage(rawStatus)
  let inlineStatus = installInlineSyscallPatches()
  recordInlineSyscallCoverage(inlineStatus)
  installLinuxVdsoPatches()
  if killDiagDeepIsOn() and inlineStatus.handlerInstalled:
    setKillDiagDeepShimState(
      KillDiagShimStateInitialized or
      KillDiagShimStateInlinePatchesInstalled)
  # M9.R.62.2 — install async-signal-safe terminating-signal handlers so
  # a process that dies via SIGPIPE / SIGTERM / SIGSEGV / SIGABRT / …
  # (default-terminating dispositions) still gets its ROUND-5 F pending
  # sentinel retired via a raw-syscall write of the pre-encoded committed
  # marker + close of the fragment fd. Falsifies M9.R.60/61's residual
  # "182 kill-before-flush event-loss" class (see Phase A attribution).
  # SIGKILL / SIGSTOP are uncatchable by design; losses through those
  # paths remain inherent-loss and are correctly counted.
  # DEP-FLUSH-4 — register the pthread_atfork child handler once. Defensive
  # second line behind the libc `fork` interpose hook: fires in any child,
  # including those spawned through a clone(2) path the hook does not see,
  # resetting the inherited slot + registry so the child never replays the
  # parent's buffered frames. Best-effort; a non-zero return is ignored.
  discard c_pthread_atfork(cast[pointer](repro_linux_atfork_prepare),
    cast[pointer](repro_linux_atfork_parent),
    cast[pointer](repro_linux_atfork_child_c))
  let sigInstalled = repro_linux_install_terminating_signal_handlers()
  if killDiagDeepIsOn() and sigInstalled > 0:
    # M9.R.64.1 (correction): install returns the COUNT of successfully
    # installed handlers (>0 on any success), not a boolean. Refresh the
    # bitmap only when at least one handler landed.
    var state = KillDiagShimStateInitialized or
      KillDiagShimStateSigHandlersInstalled
    if inlineStatus.handlerInstalled:
      state = state or KillDiagShimStateInlinePatchesInstalled
    setKillDiagDeepShimState(state)
  result = 0

proc repro_monitor_shim_flush*(): cint {.exportc, dynlib, raises: [].} =
  ## Flush + close the calling thread's fragment slot so no buffered records
  ## are dropped (previously a no-op, which lost the batched tail).
  withShimMuted:
    try: closeFragmentSlot()
    except CatchableError: discard
  result = 0
proc repro_monitor_shim_shutdown*(): cint {.exportc, dynlib, raises: [].} =
  ## DEP-FLUSH-1/2 — process shutdown: flush the in-flight batch of EVERY
  ## thread's registered fragment slot, then close the calling thread's own
  ## slot. Invoked by the process-exit `__attribute__((destructor))` and the
  ## `exit`/`_exit` hook on the main thread. Sweeping the process-global
  ## registry (not just the caller's threadvar) means a short-lived multi-
  ## threaded process — the common cmake/configure/cargo probe shape — does
  ## not strand any live worker thread's buffered tail on exit. Muted so the
  ## teardown emits no new records (`withShimMuted`).
  sampleKillDiag("shutdown-enter")
  recordInlineSyscallTrapCoverage()
  # LIBRARY-LOAD OBSERVATION — the closing scan. Its job is less to find new
  # libraries (the load-time scans do that) than to CLOSE THE ACCOUNT: it is the
  # last chance to compare the loader's cumulative load counter against what was
  # enumerated, and so the point at which a load that never reached the
  # interposed `dlopen` — glibc's internal `__libc_dlopen_mode` for NSS or gconv
  # modules — is detected and downgrades the capture. Runs BEFORE the mute
  # below, because `emitRecord` is a no-op while the shim is muted.
  scanLoadedLibraries("shutdown")
  withShimMuted:
    try: flushAllRegisteredSlots()
    except CatchableError: discard
  result = 0
proc repro_monitor_shim_disable_current_thread*() {.exportc, dynlib, raises: [].} =
  inc disabled
proc repro_monitor_shim_enable_current_thread*() {.exportc, dynlib, raises: [].} =
  if disabled > 0:
    dec disabled
proc repro_monitor_shim_version*(): cstring {.exportc, dynlib, raises: [].} =
  "repro_monitor_shim_m11"

proc recordOpen(path: cstring; flags, mode, fd: cint;
                dirfd = LinuxAtFdcwd; trackFd = true) {.raises: [].} =
  ## `trackFd` false: the open is classified after the fact (a trapped inline
  ## syscall), when `fd` may already name another file; record it without
  ## entering it into the live descriptor table.
  let resolved = pathForAt(dirfd, path)
  if resolved.len > 0 and trackFd:
    updateFdPath(fd, cstring(resolved))
  var record = baseRecord(mrFileOpen, observationForOpen(flags))
  record.result = fd.int64
  record.flags = uint32(flags)
  record.path = resolved
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
  recordOpen(ctx.path, ctx.flags, ctx.mode, ctx.result, ctx.dirfd)
  c_set_errno(savedErrno)

proc repro_hook_openat64*(ctx: var OpenatContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  recordOpen(ctx.path, ctx.flags, ctx.mode, ctx.result, ctx.dirfd)
  c_set_errno(savedErrno)

proc recordFdRead(fd: cint; bytes: clong) {.raises: [].} =
  if bytes > 0:
    let path = pathForFd(fd)
    if path.len == 0:
      discard classifyEmptyFdRead(fd)
    elif podFileReadMarkIsNew(fd):
      var record = baseRecord(mrFileRead, moFileRead)
      record.path = path
      record.result = bytes.int64
      record.flags = uint32(fd)
      emitRecord(record)

proc recordFdWrite(fd: cint; bytes: clong) {.raises: [].} =
  if bytes >= 0 and fd > 2:
    let path = pathForFd(fd)
    # FUP-K — a write to an fd with no tracked path is a write to a
    # socket / pipe / port (the BEAM VM's dominant write target), never a
    # file, so it carries NO output dependency: every consumer already
    # filters `moFileWrite` records with an empty path (see writer.nim's
    # `breakawayAuthContext` / merge output-path folding), so these records
    # are pure noise that also floods the DEP-SHM ring and forces the
    # file-fragment fallback. Skipping them here makes the libc-hook write
    # path consistent with the raw-syscall write path (`recordRawWrite`,
    # which already returns without emitting on an empty path) and leaves the
    # recorded dependency set byte-identical.
    if path.len == 0:
      return
    var record = baseRecord(mrFileWrite, moFileWrite)
    record.path = path
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
  # Generated configure scripts routinely close every descriptor above
  # stderr before creating command-substitution pipes. If one of those
  # descriptors is our cached fragment FILE, letting the raw close proceed
  # leaves FragmentSlot pointing at a descriptor number the shell can reuse.
  # Subsequent monitor frames then enter the shell pipe instead of the fragment
  # file. Close through the writer so it flushes and retires the slot first.
  # Only when the descriptor is still the fragment, though: if the tracee
  # replaced it (dup2 over the number), the close is the tracee's own and must
  # reach the kernel; `fragmentSlotOwnsDescriptor` detaches the stale handle.
  var ownsFragment = false
  if ctx.fd == sigSafeSlotFd():
    withShimMuted:
      ownsFragment = fragmentSlotOwnsDescriptor(ctx.fd)
  if ownsFragment:
    var closed = false
    withShimMuted:
      closeFragmentSlot()
      closed = true
    ctx.result = (if closed: 0.cint else: (-1).cint)
    removeFdPath(ctx.fd)
    return
  callNext(ctx)
  let savedErrno = c_get_errno()
  removeFdPath(ctx.fd)
  c_set_errno(savedErrno)

proc emitProbe(path: cstring; callResult: cint;
               dirfd = LinuxAtFdcwd) {.raises: [].} =
  var record = baseRecord(mrPathProbe, moPathProbe)
  record.result = callResult.int64
  record.probeResult = probeFromResult(callResult)
  record.path = pathForAt(dirfd, path)
  emitRecord(record)

# --- Path mutations: unlink, mkdir, rmdir, symlink, remove, truncate ---------
#
# These change the namespace or a file's size without opening anything, so no
# open/write record reaches the path. Each SUCCESSFUL call is recorded the way
# the macOS shim records it (`macos_interpose.nim`, the ROUND-4 RW2 block): a
# namespace change — a directory created or removed, an entry unlinked, a
# symbolic link created — is an `mrPathMutation` output fact on the path that
# changed; a `truncate` changes the bytes of an existing file, so it is a
# content write (`mrFileWrite`), as an `O_TRUNC` open is.
#
# A FAILED call is not recorded: it changed nothing, so an output record would
# be false, and the `rm -f` idiom would turn every absent temporary into one.
# What a build learns from a failure is read through stat/access/open probes,
# which are recorded. Neither kind downgrades completeness: a normal build
# creates directories and removes temporaries.

proc recordPathMutation(dirfd: cint; path: cstring; detail: string)
    {.raises: [].} =
  if path == nil or path[0] == '\0':
    return
  let resolved = pathForAt(dirfd, path)
  if not resolved.isAbsolute:
    # The directory it is relative to could not be named; a relative record
    # would be read as relative to the action's directory. Fail closed.
    emitEventLoss("path mutation relative to an unresolvable directory: " &
      detail)
    return
  var record = baseRecord(mrPathMutation, moPathMutation)
  record.path = resolved
  record.result = 0
  record.detail = detail
  emitRecord(record)

proc recordPathTruncate(path: cstring; length: int64; detail: string)
    {.raises: [].} =
  if path == nil or path[0] == '\0':
    return
  let resolved = pathForAt(LinuxAtFdcwd, path)
  if not resolved.isAbsolute:
    emitEventLoss("truncate relative to an unresolvable directory")
    return
  var record = baseRecord(mrFileWrite, moFileWrite)
  record.path = resolved
  record.result = length
  record.detail = detail
  emitRecord(record)

proc unlinkatDetail(dirfd, flags: cint): string {.raises: [].} =
  ## `unlinkat(..., AT_REMOVEDIR)` is rmdir; say which, for provenance.
  (if (flags and LinuxAtRemovedir) != 0: "rmdir " else: "") &
    "unlinkat dirfd=" & $dirfd & " flags=" & $flags

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

type
  RawFdPaths = object
    ## What up to two descriptors of a TRAPPED inline syscall named when it
    ## ran (`ct_raw_capture_fd`), in place of the shim's descriptor table,
    ## which by classification time may map those numbers to other files.
    ## `path` "" means the descriptor named no path (a pipe, a socket, a
    ## deleted file). An overridden descriptor is never looked up in, or
    ## written to, the live table.
    known0, known1: bool
    fd0, fd1: cint
    path0, path1: string

proc overridden(paths: RawFdPaths; fd: cint): bool {.inline, raises: [].} =
  (paths.known0 and fd == paths.fd0) or (paths.known1 and fd == paths.fd1)

proc rawFdPath(fd: cint; paths: RawFdPaths): string {.raises: [].} =
  if paths.known0 and fd == paths.fd0:
    paths.path0
  elif paths.known1 and fd == paths.fd1:
    paths.path1
  else:
    pathForFd(fd)

proc recordRawRead(fd: cint; callResult: clong;
                   paths = RawFdPaths()): bool {.raises: [].} =
  if callResult < 0:
    return true
  if fd <= 2:
    return true
  let path = rawFdPath(fd, paths)
  if path.len == 0:
    return false
  if not paths.overridden(fd) and not podFileReadMarkIsNew(fd):
    return true
  var record = baseRecord(mrFileRead, moFileRead)
  record.path = path
  record.result = callResult.int64
  record.flags = uint32(fd)
  emitRecord(record)
  true

proc recordRawWrite(fd: cint; callResult: clong;
                    paths = RawFdPaths()): bool {.raises: [].} =
  if callResult < 0:
    return true
  if fd <= 2:
    return true
  let path = rawFdPath(fd, paths)
  if path.len == 0:
    return false
  var record = baseRecord(mrFileWrite, moFileWrite)
  record.path = path
  record.result = callResult.int64
  record.flags = uint32(fd)
  emitRecord(record)
  true

proc recordRawFileCopy(inFd, outFd: cint; callResult: clong;
                       paths = RawFdPaths()): bool {.raises: [].} =
  if callResult <= 0:
    return callResult >= 0
  let readOk = recordRawRead(inFd, callResult, paths)
  let writeOk = recordRawWrite(outFd, callResult, paths)
  readOk and writeOk

proc recordRawSplice(fdIn, fdOut: cint; callResult: clong;
                     paths = RawFdPaths()): bool {.raises: [].} =
  if callResult <= 0:
    return callResult >= 0
  var recorded = false
  if fdIn > 2:
    let inPath = rawFdPath(fdIn, paths)
    if inPath.len > 0:
      recorded = true
      if paths.overridden(fdIn) or podFileReadMarkIsNew(fdIn):
        var record = baseRecord(mrFileRead, moFileRead)
        record.path = inPath
        record.result = callResult.int64
        record.flags = uint32(fdIn)
        emitRecord(record)
  if fdOut > 2:
    let outPath = rawFdPath(fdOut, paths)
    if outPath.len > 0:
      var record = baseRecord(mrFileWrite, moFileWrite)
      record.path = outPath
      record.result = callResult.int64
      record.flags = uint32(fdOut)
      emitRecord(record)
      recorded = true
  recorded

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

# The memory-mapping lifecycle a call changed, observed AFTER the call, as the
# libc-symbol hooks (`repro_hook_mmap` & co.) record it. `observeMunmapResult`
# is shared with the raw-syscall classifier (see `LinuxSysMmap` there).
proc observeMmapResult(result: pointer; length: csize_t; prot, flags, fd: cint)
    {.raises: [].} =
  if isAnonymousPrivateMmap(flags, fd):
    recordAnonymousPrivateMmap(result, length)
    if protIncludesExec(prot):
      if protIncludesWrite(prot):
        emitEventLoss("linux anonymous executable mmap is writable; " &
          "raw syscall scan requires a later mprotect transition " &
          "source=mmap-anonymous-exec")
      let status = scanInlineSyscallPatchesForOwnedAnonymousRange(
        result, length)
      recordLateInlineSyscallScanCoverage(status, "mmap-anonymous-exec")

proc observeMprotectResult(address: pointer; length: csize_t; prot: cint;
                           result: cint) {.raises: [].} =
  if result == 0 and protIncludesExec(prot) and protIncludesWrite(prot):
    # Writable AND executable: the inline raw-syscall scan reads the code that
    # is there NOW, and a region that stays writable gets its code later — a
    # JIT writing in place (Node 24's V8 makes its whole 512 MiB code range
    # RWX this way). Nothing written after this point is ever scanned, so a
    # raw syscall in it would go unobserved. Fail closed, exactly as the mmap
    # hook already does for a writable executable mapping; scanning once and
    # trusting the result (what this path used to do for small ranges) is
    # unsound. A W^X JIT (RW -> RX transitions) is scanned at each RX
    # transition and stays complete; `node --jitless` makes no executable
    # anonymous memory at all.
    emitEventLoss("linux anonymous executable mprotect is writable; code " &
      "written into it later cannot be scanned for inline syscalls " &
      "source=mprotect-anonymous-writable-exec")
    return
  if result == 0 and protIncludesExec(prot):
    let coverage = liveAnonymousExecutableCoverage(address, length)
    if coverage.liveIntersects and coverage.mapsAvailable and
        coverage.fullyTracked:
      let status = scanInlineSyscallPatchesForTrackedMprotectRange(
        address, length)
      recordLateInlineSyscallScanCoverage(status, "mprotect-anonymous-exec")
    elif coverage.liveIntersects:
      emitEventLoss("linux anonymous executable mprotect is not owned by " &
        "the preload mmap lifecycle source=mprotect-anonymous-untracked")

proc observeMunmapResult(address: pointer; length: csize_t; result: cint)
    {.raises: [].} =
  if result == 0:
    removeAnonymousPrivateRange(address, length)

proc intArg(raw: clong): cint {.inline, raises: [].} =
  ## A raw syscall's `int`-typed argument, as the kernel reads it: the low 32
  ## bits of the register. A caller that passes an `int` through
  ## `syscall(2)`'s varargs leaves the upper half unspecified (a 32-bit move
  ## zero-extends, so `-1` arrives as 0xFFFFFFFF), and a checked `cint(raw)`
  ## then raises a RangeDefect inside the hook, which leaves the thread's Nim
  ## error state set and makes every later hook on that thread return without
  ## calling through.
  cast[cint](uint32(raw and 0xFFFF_FFFF'i64))

proc recordRawGetdents(fd: cint; callResult: clong;
                       paths = RawFdPaths()): bool {.raises: [].} =
  ## `getdents64(fd, ...)` classification; see `LinuxSysGetdents64`.
  if callResult <= 0:
    # Error, or end of directory: nothing was enumerated by this call.
    return true
  var path = rawFdPath(fd, paths)
  if path.len == 0 and not paths.overridden(fd):
    # Not opened through a hook (inherited across exec, or opened before the
    # shim initialised): ask the kernel which directory the fd names, as
    # `recoverNamedFdRead` does for reads. A deleted directory, or anything
    # that is not an absolute path, cannot be attributed: loss.
    var buf = hookScratchString()
    if c_fd_proc_path(fd, addr buf[0], csize_t(buf.len)) != 0:
      let resolved = $cast[cstring](addr buf[0])
      if resolved.isAbsolute and not isLinuxDeletedProcFdTarget(resolved):
        path = resolved
        updateFdPath(fd, cstring(resolved))
  if path.len == 0:
    return false
  var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
  record.path = path
  record.result = 1
  record.detail = "getdents64"
  emitRecord(record)
  true

proc rawSyscallFailed(callResult: clong): bool {.inline, raises: [].} =
  ## A raw syscall's -errno return (-4095 .. -1), as opposed to a value such
  ## as an mmap address that merely has the top bit set.
  callResult < 0 and callResult >= -4095

proc classifyRawPathMutation(number, a1, a2, a3, callResult: clong;
                             inlineTrap: cint): bool {.raises: [].} =
  ## The path-mutation syscalls reached through `syscall(2)` or an inline
  ## `syscall` instruction rather than the libc symbols, recorded exactly as
  ## the libc interpositions record them (`repro_linux_observe_mutation`).
  ## `creat` is `open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)` and is
  ## recorded as that open. For an inline trap the path arguments are the
  ## strings captured when it trapped (`classifyTrappedInlineEvent`).
  if resultLooksFaulted(callResult):
    return false
  if rawSyscallFailed(callResult):
    # It changed nothing; see the path-mutation block above.
    return true
  case number
  of LinuxSysCreat:
    recordOpen(cstringArg(a1), OCreat or OWrOnly or OTrunc, intArg(a2),
      cint(callResult), trackFd = inlineTrap == 0)
  of LinuxSysUnlink:
    recordPathMutation(LinuxAtFdcwd, cstringArg(a1), "unlink")
  of LinuxSysUnlinkat:
    recordPathMutation(intArg(a1), cstringArg(a2),
      unlinkatDetail(intArg(a1), intArg(a3)))
  of LinuxSysRmdir:
    recordPathMutation(LinuxAtFdcwd, cstringArg(a1), "rmdir")
  of LinuxSysMkdir:
    recordPathMutation(LinuxAtFdcwd, cstringArg(a1), "mkdir")
  of LinuxSysMkdirat:
    recordPathMutation(intArg(a1), cstringArg(a2),
      "mkdirat dirfd=" & $intArg(a1))
  of LinuxSysSymlink:
    recordPathMutation(LinuxAtFdcwd, cstringArg(a2),
      "symlink target=" & $cstringArg(a1))
  of LinuxSysSymlinkat:
    recordPathMutation(intArg(a2), cstringArg(a3),
      "symlinkat dirfd=" & $intArg(a2) & " target=" & $cstringArg(a1))
  of LinuxSysTruncate:
    recordPathTruncate(cstringArg(a1), int64(a2), "truncate")
  else:
    return false
  true

proc classifyRawFileSyscall(number, a1, a2, a3, a4, a5, a6, callResult: clong;
                            inlineTrap: cint;
                            fdPaths = RawFdPaths()): bool {.raises: [].} =
  ## Classify one raw syscall. `inlineTrap` != 0: a trapped inline syscall,
  ## classified after the fact from what was captured when it trapped (see
  ## `classifyTrappedInlineEvent`), so its pathname arguments are already
  ## absolute and `fdPaths` says what its descriptors named. Such an event
  ## must not touch the live descriptor table: it describes descriptors as
  ## they were, and the numbers may name other files by now.
  let trackFd = inlineTrap == 0
  case number
  of LinuxSysOpen:
    if callResult < 0 or resultLooksFaulted(callResult):
      return true
    recordOpen(cstringArg(a1), intArg(a2), intArg(a3), cint(callResult),
      trackFd = trackFd)
    true
  of LinuxSysOpenat:
    if callResult < 0 or resultLooksFaulted(callResult):
      return true
    recordOpen(cstringArg(a2), intArg(a3), intArg(a4), cint(callResult),
      intArg(a1), trackFd)
    true
  of LinuxSysOpenat2:
    var flags, mode: cint
    if not openHowFlags(a3, callResult, flags, mode):
      return false
    recordOpen(cstringArg(a2), flags, mode, cint(callResult), intArg(a1),
      trackFd)
    true
  of LinuxSysRead:
    recordRawRead(intArg(a1), callResult, fdPaths)
  of LinuxSysSendfile:
    recordRawFileCopy(intArg(a2), intArg(a1), callResult, fdPaths)
  of LinuxSysCopyFileRange:
    recordRawFileCopy(intArg(a1), intArg(a3), callResult, fdPaths)
  of LinuxSysSplice:
    recordRawSplice(intArg(a1), intArg(a3), callResult, fdPaths)
  of LinuxSysClose:
    if callResult >= 0 and trackFd:
      removeFdPath(intArg(a1))
    true
  of LinuxSysStat, LinuxSysLstat, LinuxSysAccess, LinuxSysReadlink:
    if resultLooksFaulted(callResult):
      return false
    emitProbe(cstringArg(a1), probeResultFromRaw(callResult))
    true
  of LinuxSysNewfstatat, LinuxSysFaccessat, LinuxSysReadlinkat, LinuxSysStatx:
    # A relative pathname is resolved against the directory fd (a1), as the
    # libc probe hooks resolve it, not against the working directory.
    if resultLooksFaulted(callResult):
      return false
    emitProbe(cstringArg(a2), probeResultFromRaw(callResult), intArg(a1))
    true
  of LinuxSysCreat, LinuxSysUnlink, LinuxSysUnlinkat, LinuxSysRmdir,
      LinuxSysMkdir, LinuxSysMkdirat, LinuxSysSymlink, LinuxSysSymlinkat,
      LinuxSysTruncate:
    classifyRawPathMutation(number, a1, a2, a3, callResult, inlineTrap)
  of LinuxSysGettid:
    # SYS_gettid (nr=186) returns the calling thread's tid: no I/O side
    # effects, no filesystem interaction, no observation to record. Classify
    # as supported so callers like meson's Python runtime (which invokes
    # `syscall(SYS_gettid)` per-thread) do not trip `unsupported nr=186`
    # event-loss. Documented by M9.R.65 close-out as the residual
    # `libc raw syscall unsupported nr=186` class on mesonbin-setup.
    true
  of LinuxSysGetrandom:
    # `getrandom(2)` reached through libc's raw `syscall()` rather than
    # through the `getrandom()` symbol. Nim's own `std/sysrand` does exactly
    # this (`syscall(SYS_getrandom, …)`), so every Nim binary that touches
    # `std/tempfiles` — including reprobuild's own monitored helper edges —
    # tripped `libc raw syscall unsupported nr=318`. Unknown loss details
    # classify as Level 2 (unknown scope) in the consumer, which sets
    # `disableCacheHits` and skips the action-cache publish: the edge could
    # never hit cache on this or any later build.
    #
    # This is a CLASSIFICATION gap, not a monitoring gap. The same call is
    # already observed on both other paths into it — `repro_hook_getrandom`
    # (the libc symbol) and `repro_vdso_getrandom` (the vDSO entry) — and
    # both record it as `mrNonDeterministic`. Do the same here so all three
    # entry points produce identical evidence.
    #
    # `mrNonDeterministic` is deliberately NOT a completeness downgrade
    # (`io_mon/types.nim`, record 16): io-mon OBSERVED the entropy read, so
    # nothing is missing; whether entropy invalidates a result is a caller
    # policy decision made on the record, not a loss.
    if callResult >= 0:
      recordNonDeterministic("getrandom")
    true
  of LinuxSysMmap:
    # `syscall(SYS_mmap|SYS_mprotect|SYS_munmap, ...)`: allocators issue the
    # memory syscalls directly — Chromium's PartitionAlloc calls
    # `syscall(SYS_mprotect)` under its lock — and these were all
    # `unsupported` event-loss, so every such host was permanently
    # mcIncomplete. What makes them matter is EXECUTABLE memory: the inline
    # raw-syscall scanner only trusts executable anonymous memory created
    # through the preload mmap lifecycle (the libc-symbol hooks), and a raw
    # syscall stays outside that lifecycle by design (the fail-closed cases in
    # `tests/linux/test_io_mon_linux_stdio_ipc`). So:
    #   * a mapping or protection change that does not grant PROT_EXEC reads
    #     no file and creates no code: supported, recorded as nothing, and the
    #     mapping stays UNTRACKED — if it is made executable later, the
    #     mprotect hook finds it untracked and fails closed exactly as before;
    #   * one that grants PROT_EXEC stays `unsupported` (fail closed);
    #   * munmap removes the range from the lifecycle table — the same update
    #     the munmap hook makes. Dropping ownership can only make a later
    #     check fail closed, so this is sound even on the inline-trap path,
    #     whose events are classified after the fact.
    # A file mapping without PROT_EXEC adds nothing the libc mmap hook would
    # record either: the descriptor's open was observed.
    not protIncludesExec(intArg(a3))
  of LinuxSysMprotect, LinuxSysPkeyMprotect:
    # pkey_mprotect is mprotect plus a protection key (V8/PartitionAlloc use
    # it for W^X): the same rule applies to its prot argument.
    not protIncludesExec(intArg(a3))
  of LinuxSysMunmap:
    observeMunmapResult(cast[pointer](a1), cast[csize_t](a2),
      (if rawSyscallFailed(callResult): -1.cint else: 0.cint))
    true
  of LinuxSysGetpid, LinuxSysCapget, LinuxSysPkeyAlloc, LinuxSysPkeyFree:
    # Pure queries of the calling process's own state (its pid; its
    # capability sets) or management of its own protection-key slots. None
    # reads the filesystem or any external input, so there is no dependency
    # to record and nothing to lose. Node 24 calls capget at startup and
    # Chromium calls getpid/pkey_* through syscall(2); each used to make the
    # whole run mcIncomplete.
    true
  of LinuxSysCapset:
    # Changes the calling thread's capability sets (Chromium drops
    # capabilities at startup). It reads nothing; it can only change what
    # LATER calls are allowed to do, and those calls are observed through
    # their own hooks, failures included (a denied open is recorded as a
    # probe). So there is no dependency here either.
    true
  of LinuxSysEventfd2, LinuxSysMemfdCreate:
    # Create anonymous kernel objects — an event counter, or an anonymous
    # file that has no name in any filesystem. Neither depends on filesystem
    # state. The creation is recorded as an in-tree `localfd role=create`
    # (IM-3), as pipe/socketpair are, so a descendant that reads the fd it
    # inherited pairs with it instead of reporting an out-of-tree channel.
    # An executable mapping of a memfd is covered where mappings are.
    #
    # Not for an INLINE trap: those events are classified only at shutdown
    # (`drainInlineRawSyscallEvents`), when the descriptor number may name a
    # different object — possibly one received from outside the tree — and an
    # extra create would pair it. A missing create can only leave a later
    # read unpaired (a conservative re-run), so skipping is the safe side.
    if inlineTrap == 0 and callResult >= 0 and
        not rawSyscallFailed(callResult):
      recordLocalFdCreate(cint(callResult))
    true
  of LinuxSysGetdents64:
    # Directory enumeration through the raw syscall (Chromium's file
    # enumerator issues it directly). Recorded exactly as the libc readdir
    # hook records it: a directory-enumerate of the directory the fd names
    # (from the shim's fd table, else the kernel's /proc/self/fd link). An fd
    # that names no attributable directory stays a loss (fail closed).
    # An INLINE trap is classified after the fact, when the fd may have been
    # closed and reused for another directory, so it is attributed to the
    # directory captured when it trapped (`fdPaths`), never to the live
    # table; without that capture an enumeration that returned entries stays
    # a loss.
    if inlineTrap != 0 and callResult > 0 and not fdPaths.overridden(intArg(a1)):
      return false
    recordRawGetdents(intArg(a1), callResult, fdPaths)
  of LinuxSysFutex:
    # SYS_futex only coordinates threads through caller-owned memory. It does
    # not access filesystem state or introduce an external input, so treating
    # it as unknown event loss makes ordinary threaded tools permanently
    # non-cacheable without protecting any dependency channel.
    true
  of LinuxSysLandlockCreateRuleset, LinuxSysLandlockAddRule,
      LinuxSysLandlockRestrictSelf:
    # Landlock only narrows the caller's future filesystem access. Creating a
    # ruleset observes kernel capability state, adding a rule refers to an fd
    # whose open was already monitored, and restricting the current thread has
    # no filesystem read of its own. Subsequent allowed filesystem operations
    # still pass through the regular hooks; denied operations are captured as
    # probes. XZ uses these raw syscalls to install its optional sandbox.
    true
  of LinuxSysIoUringSetup, LinuxSysIoUringEnter:
    # M9.R.67.2 — Python 3.13's stdlib uses io_uring under the hood for
    # its internal buffering / signal-fd / eventfd wake-ups when the
    # kernel supports it (WSL2 with recent kernels + native Linux since
    # ~5.19). The io_uring_setup+io_uring_enter pair fires 47× per meson
    # invocation on the pixman recipe alone, tripping
    # `libc raw syscall unsupported nr=425 / 426` with the fail-closed
    # policy that M9.R.66.1 added for SYS_gettid.
    #
    # Classify as supported without recording. The tradeoff is
    # documented in the M9.R.67 close-out:
    #
    #   * Python's own io_uring usage in the stdlib does NOT perform
    #     file-open / file-read / file-write against sources or outputs
    #     — those still route through the normal open(2) / read(2) /
    #     write(2) libc symbols the shim already hooks and observes.
    #   * A monitored application that DELIBERATELY submits real I/O
    #     SQEs would go unmonitored — this is a genuine residual for
    #     io-mon's Linux backend and is called out in
    #     `io_mon/capabilities.nim`'s `linux-preload-hooks` backend
    #     profile. A future `-During:on` extension can decode SQEs.
    #
    # Documented in the M9.R.67 close-out and pinned by
    # `tests/linux/test_io_mon_linux_stdio_ipc.nim`'s "raw libc
    # io_uring_setup probe (failing) is supported (no event-loss)"
    # test (which now also runs on kernels that succeed — the return
    # value polarity is deliberately checked by the classifier).
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

proc classifyTrappedInlineEvent(index: int; number: clong;
                                args: array[6, clong]; callResult: clong;
                                source: cint) {.raises: [].} =
  ## Classify trapped event `index` from what `ct_raw_capture_event` captured
  ## when it trapped, never from its raw arguments: by now a pathname pointer
  ## may name freed, reused or unmapped memory, the working directory may have
  ## changed, and a descriptor number may name another file. Each pathname is
  ## made absolute against the directory captured with it and passed in place
  ## of the pointer (with AT_FDCWD in place of the directory fd); a symlink
  ## target and openat2's open_how are passed the same way; what each
  ## descriptor named is passed as `RawFdPaths`. A capture the event needed
  ## but could not get is event-loss.
  var a = args
  case rawSyscallEventCaptureState(index)
  of rcsFailed:
    emitEventLoss(rawSyscallSourceName(source) & " nr=" & $number &
      " arguments not captured when it trapped", int64(number))
    return
  of rcsNone:
    recordRawSyscallClassification(number, a[0], a[1], a[2], a[3], a[4], a[5],
      callResult, source)
    return
  of rcsCaptured:
    discard
  let raw = rawSyscallEventCapture(index, rcsPath)
  let base = rawSyscallEventCapture(index, rcsBase)
  let target = rawSyscallEventCapture(index, rcsTarget)
  let absolute =
    if raw.ok and base.ok and raw.text.len > 0 and not raw.text.isAbsolute:
      base.text / raw.text
    else:
      raw.text
  var how: LinuxOpenHow
  var fdPaths: RawFdPaths
  let fd0 = rawSyscallEventCapture(index, rcsFd0)
  let fd1 = rawSyscallEventCapture(index, rcsFd1)
  template pathArg(): clong = cast[clong](cstring(absolute))
  template targetArg(): clong = cast[clong](cstring(target.text))
  template overrideFds(first, second: clong) =
    fdPaths.known0 = fd0.ok
    fdPaths.fd0 = cint(first)
    fdPaths.path0 = fd0.text
    fdPaths.known1 = fd1.ok
    fdPaths.fd1 = cint(second)
    fdPaths.path1 = fd1.text
  case number
  of LinuxSysOpen, LinuxSysCreat, LinuxSysUnlink, LinuxSysRmdir, LinuxSysMkdir,
      LinuxSysStat, LinuxSysLstat, LinuxSysAccess, LinuxSysReadlink,
      LinuxSysTruncate:
    a[0] = pathArg()
  of LinuxSysOpenat, LinuxSysUnlinkat, LinuxSysMkdirat, LinuxSysNewfstatat,
      LinuxSysFaccessat, LinuxSysReadlinkat, LinuxSysStatx:
    a[0] = clong(LinuxAtFdcwd)
    a[1] = pathArg()
  of LinuxSysOpenat2:
    a[0] = clong(LinuxAtFdcwd)
    a[1] = pathArg()
    let captured = rawSyscallEventOpenHow(index)
    if captured.ok:
      how.flags = captured.flags
      how.mode = captured.mode
      a[2] = cast[clong](addr how)
    else:
      a[2] = 0
  of LinuxSysSymlink:
    a[0] = targetArg()
    a[1] = pathArg()
  of LinuxSysSymlinkat:
    a[0] = targetArg()
    a[1] = clong(LinuxAtFdcwd)
    a[2] = pathArg()
  of LinuxSysRead, LinuxSysGetdents64:
    overrideFds(a[0], -1)
  of LinuxSysSendfile:
    overrideFds(a[1], a[0])   # sendfile(out_fd, in_fd, ...)
  of LinuxSysCopyFileRange, LinuxSysSplice:
    overrideFds(a[0], a[2])
  else:
    discard
  if classifyRawFileSyscall(number, a[0], a[1], a[2], a[3], a[4], a[5],
                            callResult, source, fdPaths):
    return
  emitEventLoss(rawSyscallSourceName(source) & " unsupported nr=" & $number,
    int64(number))

proc drainInlineRawSyscallEvents() {.raises: [].} =
  ## Classify every trapped inline syscall of THIS process not classified
  ## yet. Runs at process exit, before an exec, and before an exit or exec
  ## that would go around both (`ct_linux_drain_inline_events_before_image_end`).
  ## Events are taken one at a time (`rawSyscallEventClaim`), so two threads
  ## draining at once classify each event once; an event another process
  ## trapped (the copy a fork child inherits, or a vfork child's in the
  ## shared buffer) is left to that process.
  if shouldBypass():
    return
  if rawSyscallEventOverflowed():
    emitEventLoss("inline raw syscall event buffer overflow")
  let pid = rawCurrentPid()
  let count = rawSyscallEventCount()
  for i in 0 ..< count:
    case rawSyscallEventClaim(i, pid)
    of 1:
      let event = rawSyscallEventAt(i)
      if not event.ok:
        emitEventLoss("inline raw syscall event read failed index=" & $i)
        continue
      classifyTrappedInlineEvent(i, event.number,
        [event.a1, event.a2, event.a3, event.a4, event.a5, event.a6],
        event.result, event.source)
    of -1:
      # Another thread of this process is still writing it; whatever drain
      # this is, nothing later is guaranteed to see it.
      emitEventLoss("inline raw syscall event still being written index=" & $i)
    else:
      discard

proc repro_linux_drain_inline_events() {.cdecl, raises: [].} =
  ## Registered with the runtime as the drain the exit/exec trap paths run.
  ensureInitializedPreservingErrno()
  drainInlineRawSyscallEvents()

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

proc modeLooksWritable(mode: cstring): bool =
  ## True when the stdio mode string grants WRITE access, i.e. the open is an
  ## OUTPUT-side event.
  ##
  ## `"w"`/`"w+"` create+truncate, `"a"`/`"a+"` create+append, and `"r+"` opens
  ## an existing file for update. `modeLooksReadable` is deliberately NOT the
  ## complement of this: `"w+"` and `"a+"` and `"r+"` are BOTH, and the two
  ## questions have to be asked separately or the answer to one silently
  ## overrides the other (see `recordFopen`).
  if mode == nil or mode[0] == '\0':
    return false
  if mode[0] in {'w', 'a'}:
    return true
  var i = 0
  while mode[i] != '\0':
    if mode[i] == '+':
      return true
    inc i
  result = false

proc recordFopen(path, mode: cstring; stream: pointer) {.raises: [].} =
  ## A stdio open is recorded on EVERY access side the mode actually grants.
  ##
  ## THE BUG THIS FIXES. The classification used to be a single either/or:
  ## `if modeLooksReadable(mode): moFileOpen else: moFileWrite`. `"w+"` is
  ## readable (it has a `+`), so a gcc-produced object file — which `as` opens
  ## through stdio as `"w+"` — took the `moFileOpen` arm and was recorded ONLY
  ## as an `mrFileOpen`, with the write-ness surviving nowhere but the free-text
  ## `detail=stdio:w+` string. So a file that was CREATED and TRUNCATED by the
  ## action produced no write-side record at all, while `mcapFileCreate` and
  ## `mcapFileTruncate` were both advertised Linux capabilities.
  ##
  ## The consumer consequence is the part that matters: reprobuild splits an
  ## action's INPUTS from its OUTPUTS by record kind. `mrFileOpen` is on the
  ## input side (see `oracle.nim:observedPaths`), and there was no `mrFileWrite`
  ## — so the compile's own product was classified as an input, or as neither,
  ## depending on how the consumer reads it. Free-text `detail` parsing is not a
  ## classification API and no consumer should have to do it.
  ##
  ## Both sides are now emitted when the mode grants both, because `"w+"`,
  ## `"a+"` and `"r+"` genuinely ARE both, and the set transport dedups them
  ## under distinct element keys.
  ##
  ## DA-1d — WHY `result` IS NO LONGER THE `FILE*`.
  ##
  ## These three records used to store `cast[int64](stream)`: the raw stdio
  ## handle, a per-process HEAP ADDRESS, in a field that is part of the
  ## dependency identity. Two consequences, one latent and one live:
  ##
  ##   * Latent. `mrFileOpen` is path-scoped, so the set encoder reduces its
  ##     `result` to success/failure and the address never reached the key —
  ##     laundered by luck, in an arm written for descriptor numbers. Path-scope
  ##     `mrFileWrite` (a plausible future milestone) with no such arm and the
  ##     address becomes the key outright.
  ##   * LIVE. `mrFileWrite` is process-scoped TODAY, so nothing normalised it
  ##     and the address travelled all the way into the depfile: every stdio
  ##     write record carried an ASLR-dependent value, so a depfile was not
  ##     reproducible across runs, and two `fopen(p, "w")` calls in one process
  ##     published two elements for one fact.
  ##
  ## A `FILE*` is not an observation. `updateStreamPath` already owns the
  ## stream→path mapping that the later `fwrite`/`fclose` hooks need, so nothing
  ## reads this field for a stdio record. It is now a plain success code.
  ##
  ## Deliberately 0 and NOT `if stream == nil: -1 else: 0`: a failed `fopen`
  ## already encoded as 0 (`cast[int64](nil)`), and `result < 0` is what
  ## `types.nim`'s reads-only evidence gate reads as "absent". Making failure
  ## visible here would move that gate, which is DA-1i's axis and not this
  ## milestone's call — recorded as a finding instead of changed in passing.
  let resolved = pathForAt(LinuxAtFdcwd, path)
  if stream != nil:
    updateStreamPath(stream, cstring(resolved))
  let detail = if mode != nil: "stdio:" & $mode else: ""
  if modeLooksReadable(mode):
    var record = baseRecord(mrFileOpen, moFileOpen)
    record.result = 0
    record.path = resolved
    record.detail = detail
    emitRecord(record)
  if modeLooksWritable(mode):
    var record = baseRecord(mrFileWrite, moFileWrite)
    record.result = 0
    record.path = resolved
    record.detail = detail
    emitRecord(record)
  if not modeLooksReadable(mode) and not modeLooksWritable(mode):
    # An unparseable / exotic mode string: record the open itself so the path is
    # never lost, and leave the access side unclaimed rather than guessed.
    var record = baseRecord(mrFileOpen, moFileOpen)
    record.result = 0
    record.path = resolved
    record.detail = detail
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
  # `fclose` closes the stream's descriptor inside libc, where the `close` hook
  # never sees it. The descriptor's fd -> path entry must be dropped here, or the
  # next open that reuses the number inherits the OLD path and its raw
  # `write(2)`s are recorded against a file the process never wrote (the
  # libstdc++ ifstream-then-ofstream pattern). `fileno` must be read before the
  # stream is released.
  let fd = if ctx.stream == nil: -1.cint else: c_fileno(ctx.stream)
  callNext(ctx)
  let savedErrno = c_get_errno()
  removeStreamPath(ctx.stream)
  if fd >= 0:
    removeFdPath(fd)
  c_set_errno(savedErrno)

proc recordIpcConnect(fd: cint; address: pointer; addrLen: uint32) {.raises: [].} =
  let family = c_sockaddr_family(address, addrLen)
  if family == 0:
    return
  var peerPid: uint64 = 0
  var peerUid: clong = -1
  var endpoint = ""
  var familyName = "af_other"
  case family
  of 1: # AF_UNIX
    familyName = "af_unix"
    let pid = c_socket_peer_pid(fd)
    if pid > 0:
      peerPid = uint64(pid)
    peerUid = c_socket_peer_uid(fd)
    # The address the client DIALLED. On a socket-activated host every peer is
    # the activator (pid 1), so the pid cannot say which service was reached;
    # the endpoint can, and it is what a daemon trust declaration names
    # (reprobuild Dev-Env-Warm-Entry.md §3). Carried in `path`, where the macOS
    # shim already records its endpoint.
    var buf: array[256, char]
    let n = c_sockaddr_un_path(address, addrLen, addr buf[0], cint(buf.len))
    if n > 0:
      endpoint = newString(n)
      copyMem(addr endpoint[0], addr buf[0], n)
  of 2, 10: # AF_INET / AF_INET6
    familyName = "af_inet"
  else:
    discard

  var record = baseRecord(mrIpcConnect, moIpcConnect)
  record.childOsPid = peerPid
  record.result = int64(fd)
  record.path = endpoint
  record.detail = "connect " & familyName &
    (if peerPid == 0: " peer=unknown" else: " peer=" & $peerPid) &
    (if peerUid >= 0: " peeruid=" & $peerUid else: "")
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

proc repro_hook_pipe*(ctx: var PipeContext) {.raises: [].} =
  ## IM-3 — `pipe(2)`. Both fds are recorded as in-tree local-fd creates so a
  ## downstream in-tree consumer's inherited opaque read pairs and does not
  ## downgrade. Reads `ctx.fds` only after the real call reported success.
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    recordLocalFdPair(ctx.fds)
  c_set_errno(savedErrno)

proc repro_hook_pipe2*(ctx: var Pipe2Context) {.raises: [].} =
  ## IM-3 — `pipe2(2)`. Same as `pipe`; `O_CLOEXEC`/`O_NONBLOCK` in `ctx.flags`
  ## do not change the channel identity, so the flags are not consulted.
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    recordLocalFdPair(ctx.fds)
  c_set_errno(savedErrno)

proc repro_hook_socketpair*(ctx: var SocketpairContext) {.raises: [].} =
  ## IM-3 — `socketpair(2)`. The two ends have DISTINCT inodes, so both must be
  ## recorded for either end's inherited read to pair.
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result == 0:
    recordLocalFdPair(ctx.sv)
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
  recordPathRead(pathForAt(LinuxAtFdcwd, path), detail)

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
  recordPathWrite(pathForAt(LinuxAtFdcwd, path), detail)

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
    if (uint32(ctx.flags) and LinuxRenameExchange) != 0'u32:
      recordPathWrite(oldPath, detail & " exchange-left")
      recordPathWrite(newPath, detail & " exchange-right")
    else:
      recordPathRead(oldPath, detail & " source")
      recordPathWrite(newPath, detail & " destination")
  c_set_errno(savedErrno)

proc repro_hook_dlopen*(ctx: var DlopenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  # Establish the exact pre-call link map. If an object was unloaded after the
  # preceding call, a reload now appears as a normal transition instead of an
  # unidentifiable load/unload window.
  cooperativeLibraryScan("pre-dlopen")
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != nil:
    # LIBRARY-LOAD OBSERVATION — scan HERE, before the wrapper returns to the
    # caller. The object is mapped and the program has not yet been handed the
    # handle, so the dependency is published before the program can act on it
    # (the LF-7 publish-before-return discipline the read hooks follow), and the
    # object is still present so a later `dlclose` cannot make it unobservable.
    cooperativeLibraryScan("dlopen")
    let status = scanInlineSyscallPatchesForNewMappings()
    recordLateInlineSyscallScanCoverage(status, "dlopen")
    if ctx.path != nil and ($ctx.path == "linux-vdso.so.1" or
        ($ctx.path).endsWith("/linux-vdso.so.1")):
      emitLinuxVdsoPatchFailures("dlopen")
  c_set_errno(savedErrno)

proc repro_hook_dlmopen*(ctx: var DlmopenContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  cooperativeLibraryScan("pre-dlmopen")
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != nil:
    cooperativeLibraryScan("dlmopen")
    let status = scanInlineSyscallPatchesForNewMappings()
    recordLateInlineSyscallScanCoverage(status, "dlmopen")
    if ctx.namespaceId != 0:
      emitEventLoss("linux dlmopen non-base namespace unmonitored " &
        "namespace-id=" & $ctx.namespaceId)
  c_set_errno(savedErrno)

proc linuxVdsoReplacementFor(name: cstring): pointer {.raises: [].} =
  if name == nil:
    return nil
  when defined(amd64):
    case $name
    of "__vdso_clock_gettime":
      cast[pointer](repro_vdso_clock_gettime)
    of "__vdso_gettimeofday":
      cast[pointer](repro_vdso_gettimeofday)
    of "__vdso_time":
      cast[pointer](repro_vdso_time)
    of "__vdso_clock_getres":
      cast[pointer](repro_vdso_clock_getres)
    of "__vdso_getcpu":
      cast[pointer](repro_vdso_getcpu)
    of "__vdso_getrandom":
      cast[pointer](repro_vdso_getrandom)
    else:
      nil
  else:
    nil

proc repro_hook_dlsym*(ctx: var DlsymContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  let replacement = linuxVdsoReplacementFor(ctx.name)
  if replacement != nil and ctx.result != nil:
    if linuxVdsoPatchFailureDetails.len > 0:
      emitLinuxVdsoPatchFailures("dlsym")
    ctx.result = replacement
  c_set_errno(savedErrno)

proc repro_hook_mmap*(ctx: var MmapContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  observeMmapResult(ctx.result, ctx.length, ctx.prot, ctx.flags, ctx.fd)
  c_set_errno(savedErrno)

proc repro_hook_mprotect*(ctx: var MprotectContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  observeMprotectResult(ctx.address, ctx.length, ctx.prot, ctx.result)
  c_set_errno(savedErrno)

proc repro_hook_munmap*(ctx: var MunmapContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  observeMunmapResult(ctx.address, ctx.length, ctx.result)
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
  if not podObservedInsertIsNew(cstring(key)):
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
  ## Record the program's consumption of ENTROPY as policy evidence, on the same
  ## terms as every other non-file observation and as the macOS shim
  ## (`io_mon/types.nim`, record 16): DEDUPED per process per source, `path` =
  ## the API name, `detail` = the shared `NonDeterministicEntropyDetail`.
  ##
  ## This used to build the record by hand and call `emitRecord` directly — the
  ## ONLY non-file recorder on this shim that skipped `recordObservedNonFile` —
  ## so a program drawing entropy in a loop or from N threads emitted N records
  ## for one fact, while the same program on macOS emitted one. Nothing needed
  ## the extra copies: the evidence is "this process consumed entropy from this
  ## API", and it is complete after the first observation.
  ##
  ## This does NOT downgrade completeness: io-mon SAW the entropy read, so
  ## nothing is missing; whether entropy invalidates a cached result is a caller
  ## policy decision made on the record.
  recordObservedNonFile(mrNonDeterministic, moNonDeterministic, source,
    NonDeterministicEntropyDetail)

proc ptrArg(value: pointer): clong {.inline, raises: [].} =
  clong(cast[int](value))

proc syscallResultToCint(ret: clong): cint {.inline, raises: [].} =
  if ret < 0 and ret >= -4095:
    c_set_errno(cint(-ret))
    return -1
  cint(ret)

proc syscallResultToClong(ret: clong): clong {.inline, raises: [].} =
  if ret < 0 and ret >= -4095:
    c_set_errno(cint(-ret))
    return -1
  ret

proc queueLinuxVdsoPatchFailure(detail: string) {.raises: [].} =
  linuxVdsoPatchFailureDetails.add detail

proc emitLinuxVdsoPatchFailures(source: string) {.raises: [].} =
  if linuxVdsoPatchFailureEmitted or linuxVdsoPatchFailureDetails.len == 0:
    return
  linuxVdsoPatchFailureEmitted = true
  for detail in linuxVdsoPatchFailureDetails:
    emitEventLoss(detail & " source=" & source)

proc queueLinuxVdsoPatchFailure(name: string; tx: LinuxVdsoPatchTransaction)
    {.raises: [].} =
  queueLinuxVdsoPatchFailure("linux vdso patch failed symbol=" & name &
    " diagnostic=" & $tx.diagnostic &
    " direct=" & $tx.directDiagnostic &
    " overlay=" & $tx.overlayDiagnostic &
    " path=" & $tx.path &
    " errno=" & $tx.osErrno)

proc queueLinuxVdsoResolveFailure(name: string;
                                   diagnostic: LinuxRawSyscallDiagnostic)
    {.raises: [].} =
  queueLinuxVdsoPatchFailure("linux vdso symbol resolve failed symbol=" & name &
    " diagnostic=" & $diagnostic)

proc installLinuxVdsoReplacement(image: LinuxVdsoImage; name: string;
                                 replacement: pointer) {.raises: [].} =
  let cname = cstring(name)
  let sym = resolveLinuxVdsoSymbol(image, cname)
  if sym.diagnostic == lrsVdsoSymbolNotFound:
    return
  if sym.diagnostic != lrsOk or sym.address == nil:
    queueLinuxVdsoResolveFailure(name, sym.diagnostic)
    return
  let tx = installLinuxVdsoSymbolPatchTransaction(image, cname, replacement,
    allowOverlay = true)
  if tx.diagnostic != lrsOk:
    queueLinuxVdsoPatchFailure(name, tx)

proc installLinuxVdsoPatches() {.raises: [].} =
  let image = locateLinuxVdsoImage()
  if image.diagnostic == lrsVdsoNotFound:
    return
  if image.diagnostic != lrsOk:
    queueLinuxVdsoPatchFailure("linux vdso image locate failed diagnostic=" &
      $image.diagnostic & " errno=" & $image.osErrno)
    return
  installLinuxVdsoReplacement(image, "__vdso_clock_gettime",
    cast[pointer](repro_vdso_clock_gettime))
  installLinuxVdsoReplacement(image, "__vdso_gettimeofday",
    cast[pointer](repro_vdso_gettimeofday))
  installLinuxVdsoReplacement(image, "__vdso_time",
    cast[pointer](repro_vdso_time))
  installLinuxVdsoReplacement(image, "__vdso_clock_getres",
    cast[pointer](repro_vdso_clock_getres))
  installLinuxVdsoReplacement(image, "__vdso_getcpu",
    cast[pointer](repro_vdso_getcpu))
  installLinuxVdsoReplacement(image, "__vdso_getrandom",
    cast[pointer](repro_vdso_getrandom))

proc repro_vdso_clock_gettime*(clockId: cint; tp: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].} =
  let ret = c_raw_syscall6(LinuxSysClockGettime, clong(clockId), ptrArg(tp),
    0, 0, 0, 0)
  result = syscallResultToCint(ret)
  let savedErrno = c_get_errno()
  if not shouldBypass() and result == 0:
    recordTimeRead("clock_gettime:" & $clockId)
  c_set_errno(savedErrno)

proc repro_vdso_gettimeofday*(tv, tz: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].} =
  let ret = c_raw_syscall6(LinuxSysGettimeofday, ptrArg(tv), ptrArg(tz),
    0, 0, 0, 0)
  result = syscallResultToCint(ret)
  let savedErrno = c_get_errno()
  if not shouldBypass() and result == 0:
    recordTimeRead("gettimeofday")
  c_set_errno(savedErrno)

proc repro_vdso_time*(tloc: ptr clong): clong
    {.exportc, cdecl, dynlib, raises: [].} =
  result = syscallResultToClong(c_raw_syscall6(LinuxSysTime, ptrArg(tloc),
    0, 0, 0, 0, 0))
  let savedErrno = c_get_errno()
  if not shouldBypass() and result != -1:
    recordTimeRead("time")
  c_set_errno(savedErrno)

proc repro_vdso_clock_getres*(clockId: cint; res: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].} =
  let ret = c_raw_syscall6(LinuxSysClockGetres, clong(clockId), ptrArg(res),
    0, 0, 0, 0)
  result = syscallResultToCint(ret)
  let savedErrno = c_get_errno()
  if not shouldBypass() and result == 0:
    recordTimeRead("clock_getres:" & $clockId)
  c_set_errno(savedErrno)

proc repro_vdso_getcpu*(cpu, node: ptr cuint; unused: pointer): cint
    {.exportc, cdecl, dynlib, raises: [].} =
  let ret = c_raw_syscall6(LinuxSysGetcpu, ptrArg(cpu), ptrArg(node),
    ptrArg(unused), 0, 0, 0)
  result = syscallResultToCint(ret)
  let savedErrno = c_get_errno()
  if not shouldBypass() and result == 0:
    recordObservedNonFile(mrSysctlRead, moSysctlRead, "getcpu",
      "linux vdso getcpu")
  c_set_errno(savedErrno)

proc repro_vdso_getrandom*(buf: pointer; buflen: csize_t; flags: cuint): clong
    {.exportc, cdecl, dynlib, raises: [].} =
  result = syscallResultToClong(c_raw_syscall6(LinuxSysGetrandom, ptrArg(buf),
    clong(buflen), clong(flags), 0, 0, 0))
  let savedErrno = c_get_errno()
  if not shouldBypass() and result >= 0:
    recordNonDeterministic("getrandom")
  c_set_errno(savedErrno)

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

proc repro_hook_entropy*(ctx: var EntropyContext) {.raises: [].} =
  ## ENTROPY-PARITY — getentropy / arc4random / arc4random_buf /
  ## arc4random_uniform, the glibc >= 2.36 BSD entropy set. These were
  ## previously INVISIBLE on Linux while macOS recorded all four, so a program
  ## seeding a PRNG through `arc4random_buf` was flagged as an entropy consumer
  ## on one platform and not the other.
  ##
  ## They do NOT reduce to the existing `getrandom` hook — by two DIFFERENT
  ## mechanisms, both read out of the shipped glibc 2.42 `libc.so.6`:
  ##   * `getentropy` issues `getrandom(2)` ITSELF, as an inline `syscall`
  ##     instruction in its own body (`mov $0x13e,%eax; syscall`). It never
  ##     calls the public `getrandom` symbol, and an instruction inside libc's
  ##     own text is not on the `syscall()`-wrapper path either
  ##     (`repro_hook_raw_syscall`), so the kernel entry happens with no
  ##     interposed frame anywhere in the chain.
  ##   * `arc4random` / `arc4random_buf` / `arc4random_uniform` funnel into
  ##     `__GI___arc4random_buf`, which calls `__getrandom_nocancel` — a LOCAL
  ##     symbol, absent from libc's DYNAMIC symbol table, so it cannot cross an
  ##     interposed PLT entry — and only when re-seeding its ChaCha20 stream:
  ##     2000 `arc4random*` calls made exactly 2 `getrandom` syscalls, so
  ##     nearly every call reaches the kernel not at all.
  ## Net effect, measured: a probe calling all four produced ZERO entropy
  ## records before this hook existed, even though a real `getrandom(2)`
  ## syscall demonstrably occurred inside it.
  ##
  ## `ctx.value`/`ctx.result` are the forwarded genuine results — the hook only
  ## observes. No caller attribution: LD_PRELOAD interposes the PUBLIC symbol,
  ## which libc's own internal users bypass, so what arrives here is the
  ## program's own call (see `io_mon/types.nim`, record 16).
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  callNext(ctx)
  let savedErrno = c_get_errno()
  # `getentropy` is the only one of the four that can fail; a failed call
  # produced no entropy, so it is not evidence that the program consumed any.
  if ctx.source != lesGetentropy or ctx.result == 0:
    recordNonDeterministic($ctx.source)
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
  withShimMuted:
    content = readProcFile("/proc/self/status")
  if content.len == 0:
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
  sampleKillDiag("fork-enter")
  if shouldBypass():
    sampleKillDiag("fork-bypassed")
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  # Sampled in the parent, before the fork, and inherited by the child.
  let parentSingleThreaded = processIsSingleThreaded()
  # DEP-FLUSH-4 — flush the parent's in-flight batch BEFORE the fork so no
  # buffered frames straddle the boundary: after the fork the child holds a
  # COW copy of any un-flushed batch bytes + the shared fd, and (in the
  # single-threaded-parent path) discards them. Flushing here guarantees the
  # parent's buffered frames are durable in the PARENT's fragment and are
  # never the child's to replay.
  withShimMuted:
    try: flushFragmentBatch()
    except CatchableError: discard
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
        # DEP-SHM-2 — re-attach the dep queue fresh in the child so its records
        # publish through the child's own fd, not the parent's inherited mapping.
        try: discardDepQueueAfterFork(depShmPath)
        except CatchableError: discard
      sampleKillDiag("fork-child-single")
      recordProcessStart()
    else:
      # Multi-threaded parent: another thread may have held a Nim lock at fork,
      # so the child must avoid monitor bookkeeping until exec loads a fresh
      # image and re-runs the preload constructor.
      inForkChild = true
      sampleKillDiag("fork-child-multi")
  c_set_errno(savedErrno)

proc repro_linux_raw_fork_sample(): cint {.cdecl, raises: [].} =
  ## Before a raw fork-like system call (syscall(SYS_clone), ...): whether
  ## this process is single-threaded, exactly as `repro_hook_fork` samples it.
  if processIsSingleThreaded(): 1 else: 0

proc repro_linux_raw_fork_child(parentSingleThreaded: cint)
    {.cdecl, raises: [].} =
  ## In the child of a raw fork-like system call (through syscall(2), an
  ## inline `syscall` the trap handler replays, or glibc's clone(3) without
  ## CLONE_VM), which ran no atfork handlers. A multi-threaded parent may have held any shim lock at that
  ## instant, so the child skips monitor bookkeeping until exec, as the child
  ## of a libc fork does (`repro_hook_fork`); recording the clone itself
  ## would otherwise wait on such a lock forever. A single-threaded parent's
  ## child keeps recording, as before.
  if parentSingleThreaded == 0:
    inForkChild = true
    sampleKillDiag("raw-fork-child-multi")

proc ct_linux_preload_register_raw_fork(sample, child: pointer)
  {.importc, cdecl, raises: [].}
ct_linux_preload_register_raw_fork(cast[pointer](repro_linux_raw_fork_sample),
  cast[pointer](repro_linux_raw_fork_child))

proc repro_linux_exec_env_for(envp: cstringArray): cstringArray
    {.cdecl, raises: [].} =
  ## The environment the PATH-searching exec family passes to glibc's execvpe:
  ## `envp` plus LD_PRELOAD and the next exec generation, exactly as the execve
  ## hook prepares it. See `ct_linux_preload_exec_with_prepared_env`.
  envWithExecGen(envp, currentExecGen + 1)

proc repro_linux_exec_env_release(prepared, envp: cstringArray)
    {.cdecl, raises: [].} =
  ## The exec failed: free what `repro_linux_exec_env_for` allocated.
  freeOwnedEnv(prepared, envp)

proc ct_linux_preload_register_exec_env(prepare, release: pointer)
  {.importc, cdecl, raises: [].}
ct_linux_preload_register_exec_env(cast[pointer](repro_linux_exec_env_for),
  cast[pointer](repro_linux_exec_env_release))

proc emitExecAttempt(path: cstring; envp: cstringArray) {.raises: [].} =
  ## The exec record, and a loss when the child's capture route is invalid.
  ## A proc of its own so that everything it allocates is freed before the
  ## exec: a successful exec never returns to the hook, and after vfork the
  ## hook's frame and heap are the suspended parent's, so anything still live
  ## across the exec would be leaked into the parent once per exec.
  var record = baseRecord(mrProcessExec, moExecute)
  if path != nil:
    record.path = $path
  emitRecord(record)
  let routeStatus = childCaptureRouteStatus(envp)
  if routeStatus != 0:
    emitEventLoss("linux child capture route invalid code=" & $routeStatus)

proc repro_hook_execve*(ctx: var ExecveContext) {.raises: [].} =
  sampleKillDiag("execve-enter")
  if shouldBypass():
    sampleKillDiag("execve-bypassed")
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  emitExecAttempt(ctx.path, ctx.envp)
  # io-mon-Lossless-Event-Capture M3 — inject LD_PRELOAD AND an INCREMENTED exec
  # generation into the child env. exec replaces the address space in the SAME
  # pid, so without a per-exec generation a same-image re-exec (the Nix
  # gcc/rustc bash-wrapper) would emit a byte-identical post-exec process-start
  # that the SET source-dedup collapses → execs>=starts → mrEventLoss →
  # mcIncomplete. The PATH-searching exec family (execvp/execlp/execvpe) gets
  # the same prepared environment through `repro_linux_exec_env_for`; the
  # process's own `environ` is never replaced. Nothing allocated here may
  # stay live across `callNext` (see `emitExecAttempt`); the prepared
  # environment is released by the resuming parent after a vfork child's
  # successful exec (`ct_exec_env_pending`).
  let originalEnv = ctx.envp
  let preparedEnv = envWithExecGen(ctx.envp, currentExecGen + 1)
  ctx.envp = preparedEnv
  sampleKillDiag("execve-pre-flush")
  # A successful exec discards this image with every trapped inline syscall
  # not classified yet.
  drainInlineRawSyscallEvents()
  discard repro_monitor_shim_flush()
  sampleKillDiag("execve-post-flush")
  callNext(ctx)
  # M9.R.68.3 — control only returns here if the execve syscall FAILED
  # (successful execve replaces the address space; the caller never
  # comes back). Capture the failure so the writer's T0 signal (b)
  # invariant does not falsely count this as a "last exec was un-
  # injectable" trip. Bash configure's platform-probe cascade forks
  # 12+ children that execve nonexistent paths (/bin/uname,
  # /usr/bin/oslevel, /usr/bin/hostinfo, /usr/convex/getsysinfo, ...);
  # each fires a legitimate process-start after fork + a failed exec.
  # Under the previous shim the record shape (start=1, exec=1, no
  # post-exec start) tripped signal (b) 12 times per bash configure.
  #
  # Emit a follow-up mrProcessExec carrying an ``execstatus=failed``
  # detail token + result=-errno. The writer treats these as failed-
  # exec markers that RETRACT the preceding pre-flush exec record's
  # contribution to execCount for signal (b). See
  # writer.nim :: unmonitoredSubtreeLossCount.
  let execFailedErrno = c_get_errno()
  freeOwnedEnv(preparedEnv, originalEnv)
  ctx.envp = originalEnv
  sampleKillDiag("execve-failed")
  var failRecord = baseRecord(mrProcessExec, moExecute)
  if ctx.path != nil:
    failRecord.path = $ctx.path
  failRecord.result = -int64(execFailedErrno)
  failRecord.detail = "execstatus=failed errno=" & $execFailedErrno
  emitRecord(failRecord)
  c_set_errno(execFailedErrno)

proc repro_hook_posix_spawn*(ctx: var PosixSpawnContext) {.raises: [].} =
  if shouldBypass():
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  let routeStatus = childCaptureRouteStatus(ctx.envp)
  if routeStatus != 0:
    emitEventLoss("linux child capture route invalid code=" & $routeStatus)
  let originalEnv = ctx.envp
  let preparedEnv = envWithPreload(ctx.envp)
  ctx.envp = preparedEnv
  callNext(ctx)
  let savedErrno = c_get_errno()
  freeOwnedEnv(preparedEnv, originalEnv)
  ctx.envp = originalEnv
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
  let routeStatus = childCaptureRouteStatus(ctx.envp)
  if routeStatus != 0:
    emitEventLoss("linux child capture route invalid code=" & $routeStatus)
  let originalEnv = ctx.envp
  let preparedEnv = envWithPreload(ctx.envp)
  ctx.envp = preparedEnv
  callNext(ctx)
  let savedErrno = c_get_errno()
  freeOwnedEnv(preparedEnv, originalEnv)
  ctx.envp = originalEnv
  if ctx.result == 0 and ctx.pid != nil:
    var record = baseRecord(mrProcessSpawn, moExecute)
    record.childOsPid = uint64(ctx.pid[])
    record.result = ctx.result.int64
    if ctx.path != nil:
      record.path = $ctx.path
    record.detail = "posix_spawnp"
    emitRecord(record)
  c_set_errno(savedErrno)

proc repro_hook_exit*(ctx: var ExitContext) {.raises: [].} =
  sampleKillDiag("exit-enter")
  if not shouldBypass():
    discard repro_monitor_shim_shutdown()
  else:
    sampleKillDiag("exit-bypassed")
  callNext(ctx)

setPreloadShimEnvVar("REPRO_MONITOR_SHIM_LIB")
# Observe-only interpositions (access, readlink, realpath, scandir, statx,
# fstatat, fdopendir, pkey_mprotect and the LFS aliases) — see "LARGE-FILE
# ALIASES AND OBSERVE-ONLY INTERPOSITIONS" in linux_preload_runtime.nim.
proc repro_linux_observe_probe(dirfd: cint; path: cstring; rc: cint)
    {.cdecl, raises: [].} =
  ## A path-probing call (access, readlink, realpath, statx, fstatat, ...)
  ## returned `rc`: record it as a path probe, like the stat hook does. An
  ## empty path with a dirfd (AT_EMPTY_PATH) inspects the descriptor, not a
  ## path, and is not a probe.
  if shouldBypass() or path == nil or path[0] == '\0':
    return
  ensureInitializedPreservingErrno()
  emitProbe(path, (if rc >= 0: 0.cint else: -1.cint), dirfd)

proc linuxLstatKind(path: cstring): cint
  {.importc: "ct_linux_preload_lstat_kind", raises: [].}
proc linuxRealReadlink(path: cstring; buf: pointer; size: csize_t): clong
  {.importc: "ct_linux_preload_real_readlink", raises: [].}

const LinuxMaxSymlinkHops = 40
  ## glibc's MAXSYMLINKS / the kernel's limit; a walk past it is a loop that
  ## realpath itself reports as ELOOP.

proc unnormalizedPathForAt(dirfd: cint; path: cstring): string
    {.raises: [].} =
  ## `path` made absolute against `dirfd` (or the working directory) by plain
  ## concatenation, "" when the base is unknown. Unlike `pathForAt`, whose
  ## `os./` collapses `..` lexically, this keeps every component as spelled:
  ## in `link/../x` the kernel resolves `..` against where `link` POINTS, so
  ## dropping `link` before the walk would resolve a different path.
  let raw = $path
  if raw.isAbsolute:
    return raw
  var base = ""
  if dirfd == LinuxAtFdcwd:
    # Heap, not a stack array — see `hookScratchString`.
    var cwdBuf = hookScratchString()
    let n = c_raw_syscall6(LinuxSysGetcwd,
      cast[clong](addr cwdBuf[0]), clong(cwdBuf.len), 0, 0, 0, 0)
    if n > 0:
      base = $cast[cstring](addr cwdBuf[0])
  else:
    base = pathForFd(dirfd)
  if not base.isAbsolute:
    return ""
  base & "/" & raw

proc pushResolutionComponents(pending: var seq[string]; spelled: string)
    {.raises: [].} =
  ## Queue the components of `spelled` so that the first is popped next.
  let parts = spelled.split('/')
  for i in countdown(parts.high, 0):
    if parts[i].len > 0 and parts[i] != ".":
      pending.add parts[i]

proc repro_linux_observe_resolution(dirfd: cint; path: cstring;
                                    followFinal: cint) {.cdecl, raises: [].} =
  ## realpath, canonicalize_file_name and the readlink family resolve their
  ## path inside libc, so no interposition sees the components on the way.
  ## Replay that resolution (unrecorded lstat/readlink) and record what it
  ## depends on, as probes:
  ##
  ## * each component walked through that is NOT a link. The answer depends
  ##   on that too: a directory later replaced by a link to another directory
  ##   holding the same names changes what realpath returns, while every
  ##   name probed through it still exists. The consumer records the probe's
  ##   state (`lstat`), which tells a directory from a link to one;
  ## * each link met, with detail `symlink target=<target>`;
  ## * where the walk stops: the first absent component, or the path it
  ##   ends at once a link was followed (absent when it is);
  ## * for the readlink family, the link it reads, with its target.
  ##
  ## The final component is followed only when `followFinal` is set
  ## (realpath); readlink reads the link itself, so for it only the
  ## directories before the last component are resolved. The root is not
  ## recorded: it cannot be replaced. See path_resolution(7).
  if shouldBypass() or path == nil or path[0] == '\0':
    return
  ensureInitializedPreservingErrno()
  let start = unnormalizedPathForAt(dirfd, path)
  if start.len == 0:
    return
  # Components still to resolve, last one first, so `pop` takes the next.
  var pending: seq[string] = @[]
  pushResolutionComponents(pending, start)
  var resolved = ""   # "" is the root directory
  var hops = 0
  var sawLink = false
  var target = hookScratchString()
  while pending.len > 0:
    let component = pending.pop()
    if component == "..":
      let cut = resolved.rfind('/')
      resolved = if cut <= 0: "" else: resolved[0 ..< cut]
      continue
    let candidate = resolved & "/" & component
    let isFinal = pending.len == 0
    if isFinal and followFinal == 0:
      # readlink reads this name itself rather than following it. What it
      # returns is the link's target, so record that, the same way a link met
      # on the way is recorded. A name that is not a link (EINVAL) or is
      # absent is already the probe the caller's call produced.
      if linuxLstatKind(cstring(candidate)) == 1:
        let n = linuxRealReadlink(cstring(candidate), addr target[0],
          csize_t(target.len - 1))
        if n > 0:
          var record = baseRecord(mrPathProbe, moPathProbe)
          record.result = 0
          record.probeResult = probeFromResult(0)
          record.path = candidate
          record.detail = "symlink target=" & target[0 ..< int(n)]
          emitRecord(record)
      resolved = candidate
      break
    let kind = linuxLstatKind(cstring(candidate))
    if kind < 0:
      # The walk stops where realpath fails: this name is part of the answer.
      emitProbe(cstring(candidate), -1.cint)
      return
    if kind == 0:
      # Not a link. The final component of a realpath walk is recorded once,
      # below or by the caller's own probe; a component on the way is
      # recorded here.
      if not isFinal:
        emitProbe(cstring(candidate), 0.cint)
      resolved = candidate
      continue
    inc hops
    if hops > LinuxMaxSymlinkHops:
      return
    let n = linuxRealReadlink(cstring(candidate), addr target[0],
      csize_t(target.len - 1))
    if n <= 0:
      return
    let link = target[0 ..< int(n)]
    sawLink = true
    var record = baseRecord(mrPathProbe, moPathProbe)
    record.result = 0
    record.probeResult = probeFromResult(0)
    record.path = candidate
    record.detail = "symlink target=" & link
    emitRecord(record)
    if link.startsWith("/"):
      resolved = ""
    pushResolutionComponents(pending, link)
  if sawLink:
    # The walk's end: realpath's answer, or the name readlink reads. Its
    # existence is looked up rather than assumed, because readlink's last
    # component is never examined above and may well be absent.
    let final = if resolved.len == 0: "/" else: resolved
    let finalKind = linuxLstatKind(cstring(final))
    emitProbe(cstring(final), (if finalKind >= 0: 0.cint else: -1.cint))

proc ct_linux_preload_register_resolution_observer(observer: pointer)
  {.importc, cdecl, raises: [].}
ct_linux_preload_register_resolution_observer(
  cast[pointer](repro_linux_observe_resolution))

proc repro_linux_observe_enumerate(dirfd: cint; path: cstring; rc: cint)
    {.cdecl, raises: [].} =
  ## scandir(path) returned `rc` entries (or -1): a successful one enumerated
  ## the directory, exactly what the readdir hook records per entry; a failed
  ## one is a probe of a path that is absent or unreadable.
  if shouldBypass() or path == nil or path[0] == '\0':
    return
  ensureInitializedPreservingErrno()
  if rc < 0:
    emitProbe(path, -1.cint, dirfd)
    return
  var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
  record.path = pathForAt(dirfd, path)
  record.result = 1
  record.detail = "scandir"
  emitRecord(record)

proc repro_linux_observe_glob_scan(path: cstring) {.cdecl, raises: [].} =
  ## glob(3) opened `path` to match a pattern component against its entries:
  ## an enumeration of the directory, whatever the pattern then matched
  ## (`glob` in linux_preload_runtime.nim). A relative path is glob's own
  ## spelling of a directory under the working directory.
  if shouldBypass() or path == nil or path[0] == '\0':
    return
  ensureInitializedPreservingErrno()
  var record = baseRecord(mrDirectoryEnumerate, moDirectoryEnumerate)
  record.path = pathForAt(LinuxAtFdcwd, path)
  record.result = 1
  record.detail = "glob"
  emitRecord(record)

proc ct_linux_preload_register_glob_scan_observer(observer: pointer)
  {.importc, cdecl, raises: [].}
ct_linux_preload_register_glob_scan_observer(
  cast[pointer](repro_linux_observe_glob_scan))

proc repro_linux_observe_fdopendir(fd: cint; dirp: pointer)
    {.cdecl, raises: [].} =
  ## A DIR* now reads the directory `fd` names; let the readdir hook
  ## attribute its entries to that path.
  if shouldBypass():
    return
  let path = pathForFd(fd)
  if path.len > 0:
    updateDirPath(dirp, cstring(path))

proc repro_linux_observe_mprotect(address: pointer; length: csize_t;
                                  prot: cint; rc: cint) {.cdecl, raises: [].} =
  ## pkey_mprotect: the same executable-lifecycle check as mprotect.
  if shouldBypass():
    return
  ensureInitializedPreservingErrno()
  observeMprotectResult(address, length, prot, rc)

proc repro_linux_observe_localfd_create(fd: cint) {.cdecl, raises: [].} =
  ## eventfd/timerfd_create created a local channel in-tree (IM-3 create).
  if shouldBypass():
    return
  ensureInitializedPreservingErrno()
  recordLocalFdCreate(fd)

# The operation codes `ct_mutation_observer_fn` passes; they must match the
# CT_MUTATION_* values in linux_preload_runtime.nim.
const
  MutationUnlink = 1.cint
  MutationUnlinkat = 2.cint
  MutationRmdir = 3.cint
  MutationMkdir = 4.cint
  MutationMkdirat = 5.cint
  MutationSymlink = 6.cint
  MutationSymlinkat = 7.cint
  MutationRemove = 8.cint
  MutationTruncate = 9.cint

proc repro_linux_observe_mutation(op, dirfd: cint; path, target: cstring;
                                  arg: clong; rc: cint) {.cdecl, raises: [].} =
  ## A path-mutation call (unlink, mkdir, rmdir, symlink, remove, truncate and
  ## their *at forms) returned `rc`. `arg` is unlinkat's flags or truncate's
  ## length; `target` is a symlink's contents. See the path-mutation block
  ## above `classifyRawPathMutation` for what is recorded and why.
  if shouldBypass() or rc != 0:
    return
  ensureInitializedPreservingErrno()
  case op
  of MutationUnlink:
    recordPathMutation(LinuxAtFdcwd, path, "unlink")
  of MutationUnlinkat:
    recordPathMutation(dirfd, path, unlinkatDetail(dirfd, cint(arg)))
  of MutationRmdir:
    recordPathMutation(LinuxAtFdcwd, path, "rmdir")
  of MutationMkdir:
    recordPathMutation(LinuxAtFdcwd, path, "mkdir")
  of MutationMkdirat:
    recordPathMutation(dirfd, path, "mkdirat dirfd=" & $dirfd)
  of MutationSymlink:
    recordPathMutation(LinuxAtFdcwd, path,
      "symlink target=" & (if target == nil: "" else: $target))
  of MutationSymlinkat:
    recordPathMutation(dirfd, path, "symlinkat dirfd=" & $dirfd &
      " target=" & (if target == nil: "" else: $target))
  of MutationRemove:
    # remove(3) is unlink, or rmdir for a directory; libc decides inside, so
    # the detail cannot say which.
    recordPathMutation(LinuxAtFdcwd, path, "remove")
  of MutationTruncate:
    recordPathTruncate(path, int64(arg), "truncate")
  else:
    discard

proc ct_linux_preload_register_mutation_observer(observer: pointer)
  {.importc, cdecl, raises: [].}
ct_linux_preload_register_mutation_observer(
  cast[pointer](repro_linux_observe_mutation))

proc ct_linux_preload_register_observers(probe, enumerate, fdopendirFn,
                                         mprotectFn, createFn: pointer)
  {.importc, cdecl, raises: [].}

ct_linux_preload_register_observers(cast[pointer](repro_linux_observe_probe),
  cast[pointer](repro_linux_observe_enumerate),
  cast[pointer](repro_linux_observe_fdopendir),
  cast[pointer](repro_linux_observe_mprotect),
  cast[pointer](repro_linux_observe_localfd_create))
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
registerPipeHook(repro_hook_pipe)
registerPipe2Hook(repro_hook_pipe2)
registerSocketpairHook(repro_hook_socketpair)
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
registerDlsymHook(repro_hook_dlsym)
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
registerEntropyHook(repro_hook_entropy)
registerForkHook(repro_hook_fork)
registerExecveHook(repro_hook_execve)
registerPosixSpawnHook(repro_hook_posix_spawn)
registerPosixSpawnpHook(repro_hook_posix_spawnp)
registerExitHook(repro_hook_exit)
registerRawSyscallHook(repro_hook_raw_syscall)
registerInlineRawSyscallDrain(repro_linux_drain_inline_events)
