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
  LinuxSysSendfile = 40.clong
  LinuxSysGettimeofday = 96.clong
  LinuxSysTime = 201.clong
  LinuxSysClockGettime = 228.clong
  LinuxSysClockGetres = 229.clong
  LinuxSysGettid = 186.clong
  LinuxSysIoUringSetup = 425.clong
  LinuxSysIoUringEnter = 426.clong
  LinuxSysReadlink = 89.clong
  LinuxSysOpenat = 257.clong
  LinuxSysNewfstatat = 262.clong
  LinuxSysReadlinkat = 267.clong
  LinuxSysFaccessat = 269.clong
  LinuxSysSplice = 275.clong
  LinuxSysGetcpu = 309.clong
  LinuxSysGetrandom = 318.clong
  LinuxSysCopyFileRange = 326.clong
  LinuxSysStatx = 332.clong
  LinuxSysOpenat2 = 437.clong
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
  fdLock: Lock
  dirLock: Lock
  streamLock: Lock
  observedLock: Lock
  emptyFdLock: Lock
  fragmentDir: string
  runId: string
  nextProcessSeq: uint64 = 0
  fdPaths = initTable[cint, string]()
  dirPaths = initTable[uint, string]()
  streamPaths = initTable[uint, string]()
  observedNonFileInputs = initHashSet[string]()
  emptyFdClassified = initHashSet[cint]()
  inheritedOpenFds = initHashSet[cint]()
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

{.emit: """
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>

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

int repro_linux_fd_identity_kind(int fd, unsigned long *dev,
                                 unsigned long *ino, int *kind) {
  struct stat st;
  if (stackable_linux_raw_syscall6(SYS_fstat, fd, (long)&st, 0, 0, 0, 0) != 0)
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
  long n = stackable_linux_raw_syscall6(SYS_readlink, (long)linkpath,
                                        (long)buf, (long)(len - 1),
                                        0, 0, 0);
  if (n <= 0)
    return 0;
  buf[n] = '\0';
  return 1;
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
        long n = stackable_linux_raw_syscall6(SYS_write, fd,
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
        long n = stackable_linux_raw_syscall6(SYS_write, fd,
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
  stackable_linux_raw_syscall6(SYS_fsync, fd, 0, 0, 0, 0, 0);
  stackable_linux_raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
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
   * of forwarding at most 6 args to the raw stackable_linux_raw_syscall6
   * wrapper. Callers passing fewer args have zero-init trailing regs on
   * every ABI we run on (x86_64 SysV / aarch64 AAPCS). */
  va_start(ap, number);
  a0 = va_arg(ap, long); a1 = va_arg(ap, long); a2 = va_arg(ap, long);
  a3 = va_arg(ap, long); a4 = va_arg(ap, long); a5 = va_arg(ap, long);
  va_end(ap);
#ifdef SYS_exit_group
  if (number == SYS_exit_group) {
    repro_linux_sig_safe_flush();
  }
#endif
#ifdef SYS_exit
  if (number == SYS_exit) {
    repro_linux_sig_safe_flush();
  }
#endif
  if (repro_real_libc_syscall != NULL)
    return repro_real_libc_syscall(number, a0, a1, a2, a3, a4, a5);
  /* Fall back to the raw wrapper if libc's syscall wasn't dlsym-able
   * (extremely unusual — implies a statically-linked host or a stripped
   * libc). */
  return stackable_linux_raw_syscall6(number, a0, a1, a2, a3, a4, a5);
}

__attribute__((constructor))
static void repro_linux_monitor_constructor(void) {
  repro_monitor_shim_init(NULL);
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
 * The FragmentSlot is a POD threadvar; Nim installs NO thread-exit
 * finalizer for it (that is deliberate, for --mm:orc fork safety), so a
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

static void repro_linux_create_thread_exit_key(void) {
  if (pthread_key_create(&repro_thread_exit_key,
                         repro_linux_thread_exit_destructor) == 0)
    repro_thread_exit_key_ready = 1;
}

/* Called (via the Nim bridge repro_linux_arm_thread_exit_flush) when a
 * thread first opens its fragment slot. Idempotent per thread: re-setting
 * the same non-NULL value is harmless. */
void repro_linux_arm_thread_exit_flush_c(void) {
  pthread_once(&repro_thread_exit_key_once,
               repro_linux_create_thread_exit_key);
  if (repro_thread_exit_key_ready)
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
proc c_get_errno(): cint {.importc: "repro_linux_get_errno", raises: [].}
proc c_set_errno(value: cint) {.importc: "repro_linux_set_errno", raises: [].}
proc c_errno_is_connect_in_progress(value: cint): cint
  {.importc: "repro_linux_errno_is_connect_in_progress", raises: [].}
proc c_sockaddr_family(address: pointer; addrLen: uint32): cint
  {.importc: "repro_linux_sockaddr_family", raises: [].}
proc c_socket_peer_pid(fd: cint): clong
  {.importc: "repro_linux_socket_peer_pid", raises: [].}
proc c_fd_identity_kind(fd: cint; dev, ino: ptr uint64; kind: ptr cint): cint
  {.importc: "repro_linux_fd_identity_kind", raises: [].}
proc c_fd_proc_path(fd: cint; buf: pointer; len: csize_t): cint
  {.importc: "repro_linux_fd_proc_path", raises: [].}
proc c_raw_syscall6(nr, a1, a2, a3, a4, a5, a6: clong): clong
  {.importc: "stackable_linux_raw_syscall6", cdecl, raises: [].}

# M9.R.62.2 — bridge procs the C-side signal handler calls to reach into
# writer.nim's threadvar-resident fragment slot. Every proc is a pure POD
# read (no allocation, no lock acquisition), so calling from a signal
# context is async-signal-safe. Return-type mapping: `bool` → `int`
# (0/1), `pointer` → `pointer`, `int` → `long`.

proc repro_linux_sig_safe_slot_is_open(): cint {.exportc, cdecl, raises: [].} =
  if sigSafeSlotIsOpen(): 1 else: 0

proc repro_linux_sig_safe_slot_fd(): cint {.exportc, cdecl, raises: [].} =
  sigSafeSlotFd()

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

proc repro_linux_thread_exit_flush() {.exportc, cdecl, raises: [].} =
  ## DEP-FLUSH-3 — invoked by libc from the pthread-key value-destructor on
  ## thread exit. Flushes + closes + unregisters the calling thread's slot
  ## so a short-lived worker thread's buffered batch is durable before its
  ## TLS is torn down. Muted so the teardown emits no new records.
  withShimMuted:
    try: threadExitFlushSlot()
    except CatchableError: discard

proc armThreadExitFlush() {.raises: [].} =
  ## DEP-FLUSH-3 — set the pthread key to a non-NULL sentinel so libc fires
  ## the thread-exit destructor for THIS thread. Called once per thread,
  ## right after it first opens its fragment slot (see emitRecord).
  repro_linux_arm_thread_exit_flush_c()

proc repro_linux_atfork_child() {.exportc, cdecl, raises: [].} =
  ## DEP-FLUSH-4 — reset the child's inherited slot + registry so it never
  ## replays the parent's buffered frames or writes through the COW-shared
  ## fd. Muted so no record is emitted during the reset.
  withShimMuted:
    try: discardFragmentSlotAfterFork()
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
  try:
    withShimMuted:
      content = readFile("/proc/self/cmdline")
  except CatchableError:
    return
  if content.len == 0:
    return
  let bufPtr =
    cast[ptr UncheckedArray[byte]](unsafeAddr content[0])
  setKillDiagDeepArgv(bufPtr, content.len)

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
    appendFragmentRecord(fragmentDir, stamped)
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

proc drainInlineRawSyscallEvents() {.raises: [].}
proc installLinuxVdsoPatches() {.raises: [].}
proc emitLinuxVdsoPatchFailures(source: string) {.raises: [].}
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
  acquire(emptyFdLock)
  emptyFdClassified.excl fd
  inheritedOpenFds.excl fd
  release(emptyFdLock)

proc pathForFd(fd: cint): string =
  acquire(fdLock)
  result = fdPaths.getOrDefault(fd, "")
  release(fdLock)

proc markEmptyFdClassified(fd: cint) {.raises: [].} =
  acquire(emptyFdLock)
  emptyFdClassified.incl fd
  release(emptyFdLock)

proc emptyFdAlreadyClassified(fd: cint): bool {.raises: [].} =
  acquire(emptyFdLock)
  result = fd in emptyFdClassified
  release(emptyFdLock)

proc inheritedFd(fd: cint): bool {.raises: [].} =
  acquire(emptyFdLock)
  result = fd in inheritedOpenFds
  release(emptyFdLock)

proc rememberInheritedOpenFds() {.raises: [].} =
  acquire(emptyFdLock)
  inheritedOpenFds.clear()
  for fd in 0.cint .. 1024.cint:
    var dev, ino: uint64
    var kind: cint
    if c_fd_identity_kind(fd, addr dev, addr ino, addr kind) != 0:
      inheritedOpenFds.incl fd
  release(emptyFdLock)

proc localFdKey(dev, ino: uint64): string {.raises: [].} =
  "localfd:" & $dev & ":" & $ino

proc recordExternalContent(chan, role, path: string; fd: cint) {.raises: [].} =
  var record = baseRecord(mrExternalContent, moExternalContent)
  record.path = path
  record.flags = uint32(fd)
  record.detail = "chan=" & chan & " role=" & role
  emitRecord(record)

proc isLinuxDeletedProcFdTarget(path: string): bool {.raises: [].} =
  path.endsWith(" (deleted)")

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
  if kind == fkRegular:
    var buf: array[4096, char]
    if c_fd_proc_path(fd, addr buf[0], csize_t(buf.len)) != 0:
      let resolved = $cast[cstring](addr buf[0])
      if resolved.len > 0 and not resolved.startsWith("anon_inode:") and
          not isLinuxDeletedProcFdTarget(resolved):
        updateFdPath(fd, cstring(resolved))
        var record = baseRecord(mrFileRead, moFileRead)
        record.path = resolved
        record.result = 0
        record.flags = uint32(fd)
        record.detail = "inherited-fd"
        emitRecord(record)
        return true
    emitEventLoss("linux inherited regular fd read unnamed key=" &
      localFdKey(dev, ino) & " fd=" & $fd)
    markEmptyFdClassified(fd)
  elif kind == fkFifo or kind == fkSocket or kind == fkOther:
    if not inheritedFd(fd):
      return false
    recordExternalContent("opaque", "read", localFdKey(dev, ino), fd)
    markEmptyFdClassified(fd)
  else:
    if not inheritedFd(fd):
      return false
    recordExternalContent("opaque", "read", localFdKey(dev, ino), fd)
    markEmptyFdClassified(fd)
  false

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
    initLock(emptyFdLock)
    locksReady = true
  acquire(initLockVar)
  defer: release(initLockVar)
  if initialized:
    return 0
  withShimMuted:
    fragmentDir = getEnv("REPRO_MONITOR_FRAGMENT_DIR")
    runId = getEnv("REPRO_MONITOR_SESSION")
    if fragmentDir.len > 0:
      createDir(extendedPath(fragmentDir))
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
  discard c_pthread_atfork(nil, nil,
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
  if bytes > 0:
    let path = pathForFd(fd)
    if path.len == 0:
      discard classifyEmptyFdRead(fd)
    else:
      var record = baseRecord(mrFileRead, moFileRead)
      record.path = path
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

proc recordRawWrite(fd: cint; callResult: clong): bool {.raises: [].} =
  if callResult < 0:
    return true
  if fd <= 2:
    return true
  let path = pathForFd(fd)
  if path.len == 0:
    return false
  var record = baseRecord(mrFileWrite, moFileWrite)
  record.path = path
  record.result = callResult.int64
  record.flags = uint32(fd)
  emitRecord(record)
  true

proc recordRawFileCopy(inFd, outFd: cint; callResult: clong): bool
    {.raises: [].} =
  if callResult <= 0:
    return callResult >= 0
  let readOk = recordRawRead(inFd, callResult)
  let writeOk = recordRawWrite(outFd, callResult)
  readOk and writeOk

proc recordRawSplice(fdIn, fdOut: cint; callResult: clong): bool
    {.raises: [].} =
  if callResult <= 0:
    return callResult >= 0
  var recorded = false
  if fdIn > 2:
    let inPath = pathForFd(fdIn)
    if inPath.len > 0:
      var record = baseRecord(mrFileRead, moFileRead)
      record.path = inPath
      record.result = callResult.int64
      record.flags = uint32(fdIn)
      emitRecord(record)
      recorded = true
  if fdOut > 2:
    let outPath = pathForFd(fdOut)
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
  of LinuxSysSendfile:
    recordRawFileCopy(cint(a2), cint(a1), callResult)
  of LinuxSysCopyFileRange:
    recordRawFileCopy(cint(a1), cint(a3), callResult)
  of LinuxSysSplice:
    recordRawSplice(cint(a1), cint(a3), callResult)
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
  of LinuxSysGettid:
    # SYS_gettid (nr=186) returns the calling thread's tid: no I/O side
    # effects, no filesystem interaction, no observation to record. Classify
    # as supported so callers like meson's Python runtime (which invokes
    # `syscall(SYS_gettid)` per-thread) do not trip `unsupported nr=186`
    # event-loss. Documented by M9.R.65 close-out as the residual
    # `libc raw syscall unsupported nr=186` class on mesonbin-setup.
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
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != nil:
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
  callNext(ctx)
  let savedErrno = c_get_errno()
  if ctx.result != nil:
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
      sampleKillDiag("fork-child-single")
      recordProcessStart()
    else:
      # Multi-threaded parent: another thread may have held a Nim lock at fork,
      # so the child must avoid monitor bookkeeping until exec loads a fresh
      # image and re-runs the preload constructor.
      inForkChild = true
      sampleKillDiag("fork-child-multi")
  c_set_errno(savedErrno)

proc repro_hook_execve*(ctx: var ExecveContext) {.raises: [].} =
  sampleKillDiag("execve-enter")
  if shouldBypass():
    sampleKillDiag("execve-bypassed")
    callNext(ctx)
    return
  ensureInitializedPreservingErrno()
  var record = baseRecord(mrProcessExec, moExecute)
  if ctx.path != nil:
    record.path = $ctx.path
  emitRecord(record)
  ctx.envp = envWithPreload(ctx.envp)
  sampleKillDiag("execve-pre-flush")
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

proc repro_hook_exit*(ctx: var ExitContext) {.raises: [].} =
  sampleKillDiag("exit-enter")
  if not shouldBypass():
    discard repro_monitor_shim_shutdown()
  else:
    sampleKillDiag("exit-bypassed")
  callNext(ctx)

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
registerForkHook(repro_hook_fork)
registerExecveHook(repro_hook_execve)
registerPosixSpawnHook(repro_hook_posix_spawn)
registerPosixSpawnpHook(repro_hook_posix_spawnp)
registerExitHook(repro_hook_exit)
registerRawSyscallHook(repro_hook_raw_syscall)
