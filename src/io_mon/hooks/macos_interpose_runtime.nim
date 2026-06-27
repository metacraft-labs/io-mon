when not defined(macosx):
  {.error: "repro_monitor_hooks/macos_interpose_runtime is macOS-only".}

import std/os
import stackable_hooks/propagation as ct_propagation

# Bridge from C-level spawn hooks back into ct_interpose's SIP-rewrite
# helper. On macOS, /bin/, /sbin/, /usr/bin/, /usr/sbin/ are SIP-protected,
# so DYLD_INSERT_LIBRARIES is stripped when those binaries are exec'd. The
# helper consults CT_SANDBOX_TOOLS_DIR (populated by repro-fs-snoop) and, if
# a sandbox copy of the requested binary exists, returns its path instead.
#
# We can't reuse ct_interpose's private static C symbol _ct_rewrite_sip_path
# directly (it depends on private state), so we expose the Nim helper to C
# via an exportc shim. The returned cstring points into a per-thread Nim
# string that lives until the next call from the same thread — the spawn
# hook consumes it immediately, so the lifetime is sufficient.
var sipRewriteBuf {.threadvar.}: string

proc repro_macos_rewrite_sip_path*(path: cstring): cstring
    {.exportc: "repro_macos_rewrite_sip_path", cdecl.} =
  if path == nil:
    return path
  let original = $path
  let rewritten = ct_propagation.rewriteExecPathForSip(original)
  if rewritten == original:
    return path
  sipRewriteBuf = rewritten
  result = cstring(sipRewriteBuf)

var sandboxDirBuf {.threadvar.}: string

proc repro_macos_get_sandbox_tools_dir*(): cstring
    {.exportc: "repro_macos_get_sandbox_tools_dir", cdecl.} =
  ## Returns the active CT_SANDBOX_TOOLS_DIR (or the propagation default)
  ## so the C-level env builder can propagate it to the child env. Returns
  ## nil if the env var is unset and we should not synthesise one.
  let envDir = getEnv("CT_SANDBOX_TOOLS_DIR")
  if envDir.len == 0:
    return nil
  sandboxDirBuf = envDir
  result = cstring(sandboxDirBuf)

{.emit: """
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <xpc/xpc.h>

extern char **environ;
extern char *repro_macos_rewrite_sip_path(char *path);
extern char *repro_macos_get_sandbox_tools_dir(void);

int repro_macos_real_open_syscall(char *path, int flags, int mode) {
  return (int)syscall(SYS_open, path, flags, mode);
}

int repro_macos_real_openat_syscall(int dirfd, char *path, int flags, int mode) {
  return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}

ssize_t repro_macos_real_read_syscall(int fd, void *buf, size_t count) {
  return (ssize_t)syscall(SYS_read, fd, buf, count);
}

ssize_t repro_macos_real_write_syscall(int fd, void *buf, size_t count) {
  return (ssize_t)syscall(SYS_write, fd, buf, count);
}

int repro_macos_real_close_syscall(int fd) {
  return (int)syscall(SYS_close, fd);
}

/*
 * Raw-syscall stat/lstat/access/fstatat forwarders for the body-patch backend.
 *
 * The body-patch backend replaces the high-level libsystem `stat`/`lstat`/...
 * entry points themselves, so it must NOT forward through the named symbol or
 * through dlsym(RTLD_DEFAULT, "stat") — that symbol is now patched and would
 * re-enter infinitely. It forwards via the raw kernel syscall instead.
 *
 * We use the *64 syscall variants (SYS_stat64/SYS_lstat64/SYS_fstatat64),
 * which fill the modern 64-bit-inode `struct stat` — the same layout the
 * userland `stat$INODE64` family (the default since the 64-bit-inode era)
 * exposes to callers, so the caller's `struct stat *buf` is filled correctly.
 */
int repro_macos_real_stat64_syscall(char *path, void *buf) {
  return (int)syscall(SYS_stat64, path, buf);
}

int repro_macos_real_lstat64_syscall(char *path, void *buf) {
  return (int)syscall(SYS_lstat64, path, buf);
}

int repro_macos_real_fstatat64_syscall(int dirfd, char *path, void *buf,
                                       int flag) {
  return (int)syscall(SYS_fstatat64, dirfd, path, buf, flag);
}

int repro_macos_real_access_syscall(char *path, int mode) {
  return (int)syscall(SYS_access, path, mode);
}

/*
 * Raw-syscall rename/renameat forwarders for BOTH backends.
 *
 * gnulib's atomic-write idiom (`chmod a-w $@t; mv $@t $@`) issues a rename(2) to
 * move a freshly-written temp file onto its final output path. Monitoring rename
 * lets the §16.7.8 closure record the output move; the forward MUST reach the
 * kernel directly (not via the named `rename`/`renameat` symbol or dlsym, which
 * the body-patch backend may have replaced — that would re-enter the hook).
 *
 * Darwin exposes the modern rename via SYS_rename / SYS_renameat; renaming is a
 * thin syscall wrapper (unlike posix_spawn), so a raw syscall is faithful.
 */
int repro_macos_real_rename_syscall(char *from, char *to) {
  return (int)syscall(SYS_rename, from, to);
}

int repro_macos_real_renameat_syscall(int fromfd, char *from, int tofd,
                                      char *to) {
  return (int)syscall(SYS_renameat, fromfd, from, tofd, to);
}

/*
 * T2 content/metadata-dependency forwarders (see reprobuild-specs/
 * MacOS-Monitoring-Adversarial-Hardening.milestones.org breaks #3/#5/#7).
 *
 * Each reaches the kernel via the RAW syscall, exactly like the stat/rename
 * forwarders above, so a body-patched libsystem entry of the same name is never
 * re-entered (the body-patch backend overwrites those entries IN PLACE; a
 * by-name / dlsym forward would resolve the patch and loop — see the spawn
 * family's `inSpawnForward` discussion). clonefile/link/getattrlist are thin
 * syscall wrappers, so a raw syscall is semantically faithful.
 *
 * Break #3 (clonefile/link): an APFS `clonefile` copy-on-write clone — and a
 * hardlink `link` — consume the SOURCE file's content WITHOUT ever issuing a
 * hooked open/read on it (CoW reads zero source bytes; a hardlink merely aliases
 * the inode). The call itself is therefore the ONLY signal that the source is a
 * content dependency. `clonefile(src,dst,flags)` is libsystem sugar for
 * `clonefileat(AT_FDCWD,src,AT_FDCWD,dst,flags)`, so we issue SYS_clonefileat.
 */
int repro_macos_real_clonefile_syscall(char *src, char *dst, int flags) {
  return (int)syscall(SYS_clonefileat, AT_FDCWD, src, AT_FDCWD, dst, flags);
}
int repro_macos_real_clonefileat_syscall(int srcfd, char *src, int dstfd,
                                         char *dst, int flags) {
  return (int)syscall(SYS_clonefileat, srcfd, src, dstfd, dst, flags);
}
int repro_macos_real_fclonefileat_syscall(int srcfd, int dstfd, char *dst,
                                          int flags) {
  return (int)syscall(SYS_fclonefileat, srcfd, dstfd, dst, flags);
}
int repro_macos_real_link_syscall(char *src, char *dst) {
  return (int)syscall(SYS_link, src, dst);
}
int repro_macos_real_linkat_syscall(int fd1, char *src, int fd2, char *dst,
                                    int flag) {
  return (int)syscall(SYS_linkat, fd1, src, fd2, dst, flag);
}

/*
 * Break #5 (getattrlist family): an existence/metadata probe (mtime, objtype,
 * fsid/fileid) that — unlike stat/lstat/fstatat — leaves NO stat record, so a
 * build tool that checks "does this header exist / what is its mtime" via
 * getattrlist hides the dependency. We classify it as a path-probe (like stat).
 */
int repro_macos_real_getattrlist_syscall(char *path, void *al, void *buf,
                                         size_t size, unsigned long opts) {
  return (int)syscall(SYS_getattrlist, path, al, buf, size, opts);
}
int repro_macos_real_getattrlistat_syscall(int fd, char *path, void *al,
                                           void *buf, size_t size,
                                           unsigned long opts) {
  return (int)syscall(SYS_getattrlistat, fd, path, al, buf, size, opts);
}
int repro_macos_real_fgetattrlist_syscall(int fd, void *al, void *buf,
                                          size_t size, unsigned long opts) {
  return (int)syscall(SYS_fgetattrlist, fd, al, buf, size, opts);
}

/*
 * Per-entry directory enumeration (getattrlistbulk / the libsystem
 * getdirentries wrapper). opendir/readdir are hooked, but a tool can open() a
 * directory fd and bulk-scan its entries via these syscalls with NO readdir
 * call. We forward via the raw syscall and record a directory-enumerate at the
 * dir granularity (per-child name extraction from getattrlistbulk's packed
 * attribute buffer is deferred — see the hook comment). NOTE: a program issuing
 * the RAW `syscall(SYS_getdirentries64, …)` inline (never touching the libsystem
 * wrapper) is the structurally-unfixable raw-syscall gap (#6); only the
 * libsystem-wrapper call sites are reachable in-process.
 */
int repro_macos_real_getattrlistbulk_syscall(int dirfd, void *al, void *buf,
                                             size_t size, uint64_t opts) {
  return (int)syscall(SYS_getattrlistbulk, dirfd, al, buf, size, opts);
}
int repro_macos_real_getdirentries_syscall(int fd, void *buf, int nbytes,
                                           long *basep) {
  return (int)syscall(SYS_getdirentries, fd, buf, nbytes, basep);
}

/*
 * T3a (Phase 2 / findings-doc break #1): the DAEMON-OVER-SOCKET / out-of-tree
 * breakaway escape. A persistent daemon (sccache/ccache server, distcc/icecc,
 * the Gradle daemon, a Bazel persistent worker, tsserver, watchman, the nix
 * daemon, …) is started OUTSIDE the monitored invocation; a monitored client
 * sends it a path over an AF_UNIX (or AF_INET) socket; the DAEMON opens+reads
 * the file on the client's behalf and returns the bytes. io-mon records the
 * client's socket send/recv as PATH-LESS file-write/file-read but NOT the file,
 * and — because the daemon predates the process tree — sees NO process-start for
 * it, so the existing subtree fail-safe (which anchors on a spawn) cannot fire.
 * The depfile is stamped mcComplete ⇒ a PROVEN false cache hit (two different
 * daemon-side inputs produced byte-identical depfiles).
 *
 * The fix hooks connect(2) (the latent path-less socket records ARE the hook
 * point named in the spec). connect is a thin syscall wrapper, so — exactly like
 * the stat/rename/clonefile families — the hook forwards via the RAW SYS_connect
 * syscall, bypassing any body-patched libsystem `connect` entry so a single call
 * records once and never re-enters the patch.
 */
int repro_macos_real_connect_syscall(int fd, void *addr,
                                     unsigned int addrlen) {
  return (int)syscall(SYS_connect, fd, addr, (socklen_t)addrlen);
}

/*
 * Describe a connect() target for the IPC-breakaway hook. Returns the address
 * family (AF_UNIX / AF_INET / AF_INET6 / …) or -1 on bad args. Fills `out_dest`
 * with the AF_UNIX socket path or an "ip:port" / "[ip6]:port" string. Sets
 * `*out_peer_pid` to the PEER's pid:
 *   * AF_UNIX  → the local peer pid via getsockopt(SOL_LOCAL, LOCAL_PEERPID).
 *                After a successful connect() the client socket is connected to
 *                the listener, so the kernel-tracked peer credentials name the
 *                daemon process — the crucial signal for the merge-time peer-set
 *                check (a daemon predating the tree has NO process-start, so its
 *                pid is not in the injected set ⇒ downgrade).
 *   * AF_INET/INET6 → 0 (a remote/loopback peer's pid is not locally knowable;
 *                the merge treats an unknown peer conservatively as out-of-tree).
 * getsockopt/inet_ntop/snprintf are not hooked, so this is reentrancy-free.
 */
int repro_macos_socket_describe(int fd, void *addr, unsigned int addrlen,
                                void *out_dest_raw, size_t out_dest_len,
                                int *out_peer_pid) {
  char *out_dest = (char *)out_dest_raw;
  if (out_peer_pid) *out_peer_pid = 0;
  if (out_dest && out_dest_len) out_dest[0] = '\0';
  if (!addr || addrlen < sizeof(sa_family_t)) return -1;
  const struct sockaddr *sa = (const struct sockaddr *)addr;
  int family = sa->sa_family;
  if (family == AF_UNIX) {
    const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
    /* sun_path need not be NUL-terminated within addrlen; bound the copy. */
    size_t maxp = sizeof(un->sun_path);
    size_t pl = strnlen(un->sun_path, maxp);
    if (out_dest && pl + 1 <= out_dest_len) {
      memcpy(out_dest, un->sun_path, pl);
      out_dest[pl] = '\0';
    }
    if (out_peer_pid) {
      pid_t pid = 0;
      socklen_t plen = sizeof(pid);
      if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &plen) == 0)
        *out_peer_pid = (int)pid;
    }
  } else if (family == AF_INET) {
    const struct sockaddr_in *in4 = (const struct sockaddr_in *)addr;
    char ip[INET_ADDRSTRLEN];
    ip[0] = '\0';
    inet_ntop(AF_INET, &in4->sin_addr, ip, sizeof ip);
    if (out_dest && out_dest_len)
      snprintf(out_dest, out_dest_len, "%s:%d", ip, ntohs(in4->sin_port));
  } else if (family == AF_INET6) {
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
    char ip[INET6_ADDRSTRLEN];
    ip[0] = '\0';
    inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof ip);
    if (out_dest && out_dest_len)
      snprintf(out_dest, out_dest_len, "[%s]:%d", ip, ntohs(in6->sin6_port));
  }
  return family;
}

/*
 * ROUND-2 R7 ((pid, start-time) process identity): macOS pids WRAP (~40k
 * allocations recycle the namespace, see research/.../r2_machinery/pidwrap.c).
 * The merge-time matching of spawn children / IPC peers / process-start records
 * keyed on the BARE pid then false-matches a recycled pid against a stale
 * monitored process-start. The kernel process-creation time disambiguates: a
 * recycled pid has a DIFFERENT start time than the stale process that last held
 * it. `proc_pidinfo(PROC_PIDTBSDINFO)` returns the BSD-info start timeval for ANY
 * pid the caller can see (it works cross-process, so a parent can stamp a freshly
 * spawned child's start time, and a client can stamp a daemon peer's). Returns
 * microseconds-since-epoch, or 0 when the pid is gone / unqueryable (the merge
 * then degrades to bare-pid matching for that record — safe, never a false
 * downgrade). proc_pidinfo / arc4random are not hooked, so this is reentrancy-free.
 */
unsigned long long repro_macos_proc_start_usec(int pid) {
  if (pid <= 0) return 0ull;
  struct proc_bsdinfo info;
  int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, (int)sizeof(info));
  if (n != (int)sizeof(info)) return 0ull;
  return (unsigned long long)info.pbi_start_tvsec * 1000000ull +
         (unsigned long long)info.pbi_start_tvusec;
}

/*
 * ROUND-2 R8 (trusted-daemon report authentication): a cryptographically random
 * per-connection nonce stamped into each `mrIpcConnect` record (and offered to a
 * cooperating daemon via the ticket sidecar). The merge rejects a breakaway
 * report whose `nonce` token does not match a nonce the shim actually recorded
 * for an observed connection, so a report cannot be fabricated for a connection
 * the monitor never saw. arc4random_buf is CSPRNG-grade and unguessable.
 */
unsigned long long repro_macos_random_u64(void) {
  unsigned long long v = 0ull;
  arc4random_buf(&v, sizeof v);
  return v;
}

/*
 * Break #7 (path fidelity): recover the canonical real path behind an open fd
 * via fcntl(F_GETPATH). This resolves BOTH a symlink target (open follows the
 * link, so the fd names the real target) AND a /.vol/<dev>/<inode> firmlink open
 * (the fd names the real path the opaque inode path points at). `fcntl` is not
 * hooked and we issue the raw syscall, so this is reentrancy-free. Returns 1 and
 * fills `out` (which MUST be >= MAXPATHLEN) on success, 0 otherwise.
 */
int repro_macos_fd_real_path(int fd, void *out, size_t outlen) {
  if (fd < 0 || out == NULL || outlen < 1024) return 0;
  char tmp[1024]; /* MAXPATHLEN */
  if (syscall(SYS_fcntl, fd, F_GETPATH, tmp) != 0) return 0;
  size_t n = strlen(tmp);
  if (n + 1 > outlen) return 0;
  memcpy(out, tmp, n + 1);
  return 1;
}

/*
 * Canonicalise a path via realpath(3) (resolves symlink components). Used by the
 * stat/lstat hooks to ALSO record the resolved symlink target as a path-probe so
 * editing the target while the link is unchanged is visible. realpath's internal
 * lstat calls are body-patched, but the caller invokes this with the shim muted
 * (disabled>0), so those forward without recording (no recursion). Returns 1 +
 * canonical path on success, 0 otherwise.
 */
int repro_macos_canonical_path(char *path, void *out, size_t outlen) {
  if (!path || !out || outlen < 1024) return 0;
  char buf[1024]; /* MAXPATHLEN */
  if (realpath(path, buf) == NULL) return 0;
  size_t n = strlen(buf);
  if (n + 1 > outlen) return 0;
  memcpy(out, buf, n + 1);
  return 1;
}

/* True if the (64-bit-inode) struct stat buffer describes a symlink. Used to
 * gate the lstat hook's symlink-target resolution so realpath() is only paid for
 * actual symlinks, not every probe. The SYS_lstat64-filled buffer is the modern
 * `struct stat` layout on arm64 (stat == stat64), so the cast is correct. */
int repro_macos_stat_is_symlink(void *buf) {
  if (!buf) return 0;
  struct stat *st = (struct stat *)buf;
  return S_ISLNK(st->st_mode) ? 1 : 0;
}

/*
 * ROUND-2 R4 — extract (st_dev, st_ino) from a (64-bit-inode) struct stat buffer.
 * realpath() resolves symlinks/case/dot/dot-dot so two NAMES of the same file map to
 * one canonical path — but it CANNOT collapse a HARDLINK (two independent
 * directory entries, same inode, neither a symlink of the other). Recording the
 * (dev, ino) identity lets a consumer match the hardlink-alternate-name case by
 * inode rather than by path. Returns 1 and fills *out_dev/*out_ino on success.
 * The SYS_*stat64-filled buffer is the modern arm64 `struct stat`, so the cast is
 * correct (stat == stat64).
 */
int repro_macos_stat_dev_ino(void *buf, unsigned long long *out_dev,
                             unsigned long long *out_ino) {
  if (!buf || !out_dev || !out_ino) return 0;
  struct stat *st = (struct stat *)buf;
  *out_dev = (unsigned long long)st->st_dev;
  *out_ino = (unsigned long long)st->st_ino;
  return 1;
}

/*
 * ROUND-2 R4 — (dev, ino) for an open fd via a RAW fstat syscall (unhooked →
 * reentrancy-free). Used to stamp inode identity on file-open records so a
 * hardlink-alternate-name open can be matched by inode. Returns 1 on success.
 */
int repro_macos_fd_dev_ino(int fd, unsigned long long *out_dev,
                           unsigned long long *out_ino) {
  if (fd < 0 || !out_dev || !out_ino) return 0;
  struct stat st;
  if (syscall(SYS_fstat64, fd, &st) != 0) return 0;
  *out_dev = (unsigned long long)st.st_dev;
  *out_ino = (unsigned long long)st.st_ino;
  return 1;
}

/*
 * ROUND-2 R9 — mmap forwarder for the file-content-via-memory hook. Issues the
 * BSD mmap syscall via INLINE ASM (svc #0x80), capturing the FULL 64-bit x0
 * return. This is ALLOCATION-FREE and re-entry-free — the two properties an mmap
 * forwarder absolutely needs (see the hook + the not-ready thunk):
 *   * NOT the libc `syscall()` shim: on Darwin it is declared `int syscall(int,
 *     ...)`, so `(void*)syscall(SYS_mmap, …)` TRUNCATES the 64-bit mapping address
 *     to 32 bits → a corrupt pointer → a hard SIGSEGV the instant malloc/dyld
 *     touched the mapping (verified: a raw `syscall(SYS_mmap)` crashed in
 *     isolation with -Wint-to-pointer-cast). The asm path returns x0 in full.
 *   * NOT the resolved libsystem `_mmap` function pointer: resolving it (an image
 *     walk + dladdr) MALLOCs, and malloc mmaps, so a lazy resolve inside the hot
 *     hook RE-ENTERS mmap and recurses to a stack-overflow crash — and the
 *     resolution cannot be done before our constructor, yet the interpose tuple is
 *     live (and firing mmaps) from image-load. The asm path needs no resolution.
 * Darwin/arm64 BSD syscall ABI: trap number in x16, args x0-x5, `svc #0x80`; the
 * carry flag is set on error (errno in x0). Mirrors repro_macos_real_fork_syscall.
 */
void *repro_macos_real_mmap_syscall(void *addr, size_t len, int prot, int flags,
                                    int fd, long long offset) {
#if defined(__arm64__) || defined(__aarch64__)
  register long x0 __asm__("x0") = (long)addr;
  register long x1 __asm__("x1") = (long)len;
  register long x2 __asm__("x2") = (long)prot;
  register long x3 __asm__("x3") = (long)flags;
  register long x4 __asm__("x4") = (long)fd;
  register long x5 __asm__("x5") = (long)offset;
  register long x16 __asm__("x16") = SYS_mmap;
  register long err __asm__("x6");
  __asm__ volatile(
    "svc #0x80\n\t"
    "cset x6, cs\n"
    : "+r"(x0), "=r"(err)
    : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x16)
    : "cc", "memory");
  if (err) { errno = (int)x0; return MAP_FAILED; }
  return (void *)x0;
#else
  /* Non-arm64 Darwin is not a supported host for this shim. */
  errno = ENOSYS;
  return MAP_FAILED;
#endif
}

/*
 * T3b (findings-doc break #4 + the dlopen arm of #7): classify a dyld IMAGE — a
 * dependent dylib dyld mapped via low-level kernel mmap, OR a dlopen'd one — as
 * a NON-SYSTEM, real-on-disk library-load dependency, or reject it.
 *
 * WHY this exists: dyld maps an executable's dependent dylibs (and dlopen'd
 * ones) DIRECTLY via the kernel, bypassing the interposed/body-patched
 * open/openat. A real clang-21 + ld64 link loaded 620 dylibs while io-mon
 * recorded ZERO; the 24 non-system toolchain dylibs missed include
 * libclang-cpp.dylib, libLLVM.dylib, libcrypto.3, libxml2, … A content-addressed
 * cache fingerprinting only the depfile would then serve a STALE result after an
 * in-place compiler-library upgrade (e.g. libclang.dylib updated beside a stable
 * driver path). We capture the image set via _dyld_register_func_for_add_image
 * instead (see the shim constructor): dyld invokes that callback for EVERY
 * already-loaded image AND every future dlopen — the only path that sees these
 * maps.
 *
 * FILTER (aggressive, to avoid recording the ~600-image SYSTEM BASELINE — both
 * gratuitous noise and a per-dlopen cost — while keeping the toolchain's own
 * dylibs):
 *   - filetype must be MH_DYLIB / MH_BUNDLE. The MAIN EXECUTABLE (MH_EXECUTE) is
 *     already recorded as a process-exec, so skipping it avoids a duplicate.
 *   - reject our OWN injected shim (librepro_monitor_shim) — it is not a build
 *     input — by substring (matches the shim under any sandbox drop-in path too).
 *   - reject /usr/lib/** and /System/** (the OS framework baseline).
 *   - reject anything resident in the dyld SHARED CACHE
 *     (_dyld_shared_cache_contains_path): on modern macOS essentially every
 *     system dylib lives ONLY in the shared cache with NO separate on-disk
 *     Mach-O, so this is the dominant baseline filter.
 *   - require the path to exist as a real on-disk REGULAR FILE (raw SYS_stat64,
 *     unhooked → reentrancy-free): a shared-cache-only image is intentionally NOT
 *     recorded (it is not a separate cacheable input). This is also the backstop
 *     should the shared-cache predicate be unavailable.
 * What SURVIVES is exactly the target: the toolchain's /nix/store, /opt/homebrew,
 * /usr/local dylibs and a ./plugin.dylib-style dlopen'd image (dladdr resolves a
 * relative dlopen path to its absolute on-disk path).
 *
 * DEADLOCK SAFETY: this runs INSIDE dyld's add-image callback (dyld holds its
 * loader lock). It must NOT re-enter dyld. It uses dladdr (a lock-safe read) for
 * the image path and a RAW stat syscall for the existence probe — NEVER the
 * by-name image walk (repro_macos_lookup_image_symbol), which calls _dyld_* /
 * NSLookupSymbolInImage and could deadlock. Returns 1 and fills `out` (>= 1024)
 * when the image is a recordable dependency, 0 otherwise.
 */
/*
 * ROUND-2 R6 — the shim's OWN image identity, captured ONCE at init (see
 * repro_macos_capture_shim_image, called from the constructor before the
 * add-image callback is registered). The library-load filter must exclude OUR
 * injected shim — but the round-1 code did so by the SUBSTRING test
 * `strstr(path,"librepro_monitor_shim")`, which ALSO dropped any genuine
 * dependency dylib whose path merely CONTAINED that substring (e.g.
 * `/tmp/x_librepro_monitor_shim_dep.dylib`, or a dir
 * `…/librepro_monitor_shim_plugins/…`). Because dyld-mmap'd dylibs have NO open
 * backstop, such a dependency then vanished from the dep set → a false cache hit
 * (demonstrated in research/.../r2_implicit). We now exclude the shim by
 * UNSPOOFABLE identity: the mach_header POINTER dyld passes for the shim equals
 * the shim's own captured header (a candidate cannot forge its load address), with
 * a realpath'd exact-path backstop. A dependency whose path merely contains the
 * substring has a DIFFERENT header and a different realpath, so it is recorded.
 */
static const struct mach_header *repro_shim_mach_header = NULL;
static char repro_shim_real_path[1024] = {0};

void repro_macos_capture_shim_image(void) {
  /* dladdr on an address INSIDE this image yields the shim's load base
   * (dli_fbase == its mach_header) and its on-disk path. Runs single-threaded at
   * init, before body-patch is installed and before runtime_ready, so realpath's
   * internal lstat reaches genuine libsystem (no hook, no recording). */
  Dl_info di;
  if (dladdr((const void *)&repro_macos_capture_shim_image, &di)) {
    repro_shim_mach_header = (const struct mach_header *)di.dli_fbase;
    if (di.dli_fname != NULL) {
      char buf[1024];
      if (realpath(di.dli_fname, buf) != NULL) {
        size_t n = strlen(buf);
        if (n + 1 <= sizeof(repro_shim_real_path))
          memcpy(repro_shim_real_path, buf, n + 1);
      }
    }
  }
}

int repro_macos_dyld_image_dep_path(void *mh_raw, void *out_raw,
                                    size_t outlen) {
  char *out = (char *)out_raw;
  if (mh_raw == NULL || out == NULL || outlen < 1) return 0;
  out[0] = '\0';
  const struct mach_header *mh = (const struct mach_header *)mh_raw;
  /* R6: exclude our OWN shim by UNSPOOFABLE mach_header identity (the header
   * pointer dyld passes for the shim image == our captured header). This replaces
   * the round-1 substring test that false-dropped genuine deps containing the
   * substring in their path. Checked FIRST and cheapest. */
  if (repro_shim_mach_header != NULL && mh == repro_shim_mach_header) return 0;
  /* mh->filetype occupies the same offset in the 32- and 64-bit mach_header, so
   * reading it through the 32-bit struct is correct for our arm64/arm64e images. */
  uint32_t ft = mh->filetype;
  if (ft != MH_DYLIB && ft != MH_BUNDLE) return 0;
  Dl_info di;
  if (!dladdr((const void *)mh, &di) || di.dli_fname == NULL) return 0;
  /* R6: CANONICALISE the candidate path (realpath) BEFORE the /usr/lib//System/
   * prefix tests and the shim-path backstop, so a dot-dot-laden or
   * /private/var/…/usr/lib/… path can neither DODGE the baseline filter nor
   * FALSELY trip it. realpath's internal lstat is body-patched, but the Nim caller
   * (repro_hook_dyld_add_image) invokes us with the shim MUTED, so it forwards
   * without recording (no recursion). Fall back to the raw dladdr path if realpath
   * fails (e.g. an unreadable component). */
  const char *path = di.dli_fname;
  char realbuf[1024];
  if (realpath(di.dli_fname, realbuf) != NULL) path = realbuf;
  size_t plen = strlen(path);
  if (plen == 0 || plen + 1 > outlen) return 0;
  /* R6 backstop: exclude the shim by its realpath'd EXACT path (not substring),
   * covering the unlikely case the mach_header capture was unavailable. */
  if (repro_shim_real_path[0] != '\0' &&
      strcmp(path, repro_shim_real_path) == 0) return 0;
  /* OS framework baseline by path prefix (now on the canonicalised path). */
  if (strncmp(path, "/usr/lib/", 9) == 0) return 0;
  if (strncmp(path, "/System/", 8) == 0) return 0;
  /* Shared-cache-resident system images (the bulk of the ~600 baseline). Guarded
   * by availability; the on-disk stat below is the backstop if it is absent. */
  if (__builtin_available(macOS 11.0, *)) {
    if (_dyld_shared_cache_contains_path(path)) return 0;
  }
  /* Must be a real on-disk REGULAR file: a shared-cache-only image has no
   * separate Mach-O to fingerprint and is intentionally skipped. Raw syscall —
   * no dyld re-entry. */
  struct stat st;
  if (syscall(SYS_stat64, path, &st) != 0) return 0;
  if (!S_ISREG(st.st_mode)) return 0;
  memcpy(out, path, plen + 1);
  return 1;
}

int repro_macos_path_is_dir(char *path) {
  struct stat st;
#ifdef SYS_stat64
  if (syscall(SYS_stat64, path, &st) != 0) return 0;
#else
  if (syscall(SYS_stat, path, &st) != 0) return 0;
#endif
  return S_ISDIR(st.st_mode) ? 1 : 0;
}

/*
 * Return the value part of envp's first NAME= entry, or NULL if absent.
 */
static const char *repro_macos_env_value(char **envp, const char *name) {
  if (!envp) envp = environ;
  size_t name_len = strlen(name);
  for (char **env = envp; env && *env; env++) {
    if (strncmp(*env, name, name_len) == 0 && (*env)[name_len] == '=') {
      return *env + name_len + 1;
    }
  }
  return NULL;
}

/*
 * True if colon-delimited `list` already contains `item` as a whole element.
 * Used to keep our shim present EXACTLY ONCE in DYLD_INSERT_LIBRARIES across a
 * deep monitored process tree (prepending unconditionally would grow the value
 * shim:shim:shim… at every generation).
 */
static int repro_macos_pathlist_has(const char *list, const char *item) {
  if (!list || !item || !item[0]) return 0;
  size_t item_len = strlen(item);
  const char *p = list;
  while (*p) {
    const char *end = strchr(p, ':');
    size_t seg_len = end ? (size_t)(end - p) : strlen(p);
    if (seg_len == item_len && strncmp(p, item, item_len) == 0) return 1;
    if (!end) break;
    p = end + 1;
  }
  return 0;
}

/*
 * Build the monitored child's environment: OVERRIDE (not skip-if-present) the
 * injection vars (findings doc T1, break #2). A caller that scrubs or sets an
 * EMPTY/bogus DYLD_INSERT_LIBRARIES / CT_SANDBOX_TOOLS_DIR previously BLOCKED
 * re-propagation (the old skip-if-present logic), so the child ran un-injected
 * and unmonitored. We now:
 *   * Force DYLD_INSERT_LIBRARIES to our shim, PREPENDED so it is always first,
 *     while preserving any genuine additional libraries the caller listed (and
 *     never duplicating our own shim — see repro_macos_pathlist_has).
 *   * Force CT_SANDBOX_TOOLS_DIR to the active sandbox-tools dir.
 * The caller's matching entries are dropped and our overrides appended, so the
 * result has exactly one authoritative value for each.
 */
static char **repro_macos_env_with_preload(char **envp) {
  const char *shim = getenv("REPRO_MONITOR_SHIM_LIB");
  char *sandbox_dir = repro_macos_get_sandbox_tools_dir();
  int want_dyld = shim && shim[0] != '\0';
  int want_sandbox = sandbox_dir && sandbox_dir[0] != '\0';
  if (!want_dyld && !want_sandbox) return envp;

  char **source = envp ? envp : environ;
  /* Capture the caller's existing DYLD list BEFORE we drop it, so we can keep
   * any non-shim libraries the caller legitimately wanted inserted. */
  const char *existing_dyld =
    want_dyld ? repro_macos_env_value(source, "DYLD_INSERT_LIBRARIES") : NULL;

  size_t count = 0;
  while (source && source[count]) count++;

  /* Worst case: every source entry kept + our two overrides + NULL. */
  char **result = (char **)calloc(count + 3, sizeof(char *));
  if (!result) return envp;

  size_t slot = 0;
  for (size_t i = 0; i < count; i++) {
    if (want_dyld &&
        strncmp(source[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) {
      continue; /* dropped; re-added as the override below */
    }
    if (want_sandbox &&
        strncmp(source[i], "CT_SANDBOX_TOOLS_DIR=", 21) == 0) {
      continue;
    }
    result[slot++] = source[i];
  }

  if (want_dyld) {
    const char *prefix = "DYLD_INSERT_LIBRARIES=";
    /* Append the caller's other libraries after ours, unless they already
     * include our shim (avoid unbounded shim:shim… growth across the tree). */
    int append_existing =
      existing_dyld && existing_dyld[0] != '\0' &&
      !repro_macos_pathlist_has(existing_dyld, shim);
    size_t value_len = strlen(prefix) + strlen(shim) +
      (append_existing ? 1 + strlen(existing_dyld) : 0) + 1;
    char *value = (char *)malloc(value_len);
    if (!value) { free(result); return envp; }
    if (append_existing)
      snprintf(value, value_len, "%s%s:%s", prefix, shim, existing_dyld);
    else
      snprintf(value, value_len, "%s%s", prefix, shim);
    result[slot++] = value;
  }
  if (want_sandbox) {
    const char *prefix = "CT_SANDBOX_TOOLS_DIR=";
    size_t value_len = strlen(prefix) + strlen(sandbox_dir) + 1;
    char *value = (char *)malloc(value_len);
    if (!value) { free(result); return envp; }
    snprintf(value, value_len, "%s%s", prefix, sandbox_dir);
    result[slot++] = value;
  }
  result[slot] = NULL;
  return result;
}

int repro_macos_real_execve_syscall(char *path, char **argv, char **envp) {
  char **effective_envp = repro_macos_env_with_preload(envp);
  char *effective_path = repro_macos_rewrite_sip_path(path);
  return (int)syscall(SYS_execve, effective_path, argv, effective_envp);
}

/*
 * Raw fork forwarder for the body-patch backend. The body-patch backend
 * replaces the libsystem `fork` entry, so it must NOT forward through the named
 * symbol or dlsym (that address is now patched and would re-enter infinitely).
 *
 * WHY NOT `syscall(SYS_fork)`: on Darwin/arm64 the `fork` trap does NOT follow
 * the ordinary "x0 == return value" convention. The kernel returns the child
 * pid in x0 for BOTH processes and distinguishes the child by setting x1 = 1
 * (the parent gets x1 = 0). libsystem's `fork()`/`__fork()` wrapper inspects x1
 * and rewrites the child's return to 0. The generic `syscall()` libc shim
 * returns only x0, so a forked CHILD invoking `syscall(SYS_fork)` would observe
 * the PARENT's pid (non-zero) instead of 0 — making the child mis-identify
 * itself as the parent, return a bogus pid to its caller, and SKIP its own
 * `fork()==0` branch (e.g. the `execve` in a fork+exec). That silently breaks
 * monitoring of every fork+exec'd grandchild (a FALSE SKIP). We therefore issue
 * the trap inline and apply the SAME x1-based child rewrite the libc wrapper
 * does, so the child correctly sees 0.
 *
 * IMPORTANT: the bare kernel fork SKIPS libsystem's userland fork bookkeeping
 * (pthread_atfork handlers, and — critically — libsystem_malloc's fork child
 * handler that resets the allocator across the fork). On macOS 26 / Apple
 * Silicon that left fork CHILDREN with an inconsistent xzone allocator, crashing
 * them with a `brk` SIGTRAP on their first `malloc` (it broke monitored gnulib
 * `make` subshells). The fork HOOK therefore NO LONGER uses this raw forwarder
 * for its normal path: it forwards into the libsystem fork BODY via a trampoline
 * (repro_macos_bodypatch_call_fork) so the malloc/atfork handlers run. This raw
 * forwarder is retained only as a last-resort fallback (and as a reusable,
 * documented entry point that captures the Darwin fork x1-child ABI); it must
 * NOT be used where a child will allocate before exec.
 *
 * Darwin/arm64 BSD syscall ABI: trap number in x16, `svc #0x80`; carry flag set
 * on error (errno in x0). For fork the child indicator is x1.
 */
pid_t repro_macos_real_fork_syscall(void) {
#if defined(__arm64__) || defined(__aarch64__)
  register long x16 __asm__("x16") = SYS_fork;
  register long x0 __asm__("x0");
  register long x1 __asm__("x1");
  __asm__ volatile(
    "svc #0x80\n"
    : "=r"(x0), "=r"(x1)
    : "r"(x16)
    : "cc", "memory");
  /* Child: x1 == 1 → the libc wrapper returns 0 in the child. */
  if (x1 != 0) return 0;
  return (pid_t)x0;
#else
  /* x86_64 (and any non-arm64 Darwin): the carry flag carries the child flag in
   * EDX per the i386/x86_64 BSD fork convention, which `syscall()` also drops.
   * We are arm64-only in practice; fall back to the libc symbol resolved by
   * NAME here. The body-patch backend is arm64-only, so this branch is not
   * reached under `both`; interpose-only builds resolve fork by name safely. */
  return (pid_t)syscall(SYS_fork);
#endif
}

typedef int (*repro_macos_posix_spawn_fn)(pid_t *, const char *,
  const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
  char *const [], char *const []);
typedef DIR *(*repro_macos_opendir_fn)(const char *);
typedef struct dirent *(*repro_macos_readdir_fn)(DIR *);
typedef int (*repro_macos_closedir_fn)(DIR *);
typedef int (*repro_macos_stat_fn)(const char *, struct stat *);
typedef pid_t (*repro_macos_fork_fn)(void);

static repro_macos_posix_spawn_fn repro_macos_real_posix_spawn_ptr = NULL;
static repro_macos_posix_spawn_fn repro_macos_real_posix_spawnp_ptr = NULL;
static repro_macos_opendir_fn repro_macos_real_opendir_ptr = NULL;
static repro_macos_readdir_fn repro_macos_real_readdir_ptr = NULL;
static repro_macos_closedir_fn repro_macos_real_closedir_ptr = NULL;
static repro_macos_stat_fn repro_macos_real_stat_ptr = NULL;
static repro_macos_stat_fn repro_macos_real_lstat_ptr = NULL;
static repro_macos_fork_fn repro_macos_real_fork_ptr = NULL;

/*
 * Resolve `symbol` (the mangled "_name" form) to a REAL libsystem address,
 * SKIPPING the shim's own image. This matters under the body-patch (`both`)
 * backend: the shim installs __DATA,__interpose tuples that dyld applies
 * globally, so a plain per-image walk that included the shim — or a dlsym() —
 * would resolve the shim's own `repro_wrap_<name>` wrapper. The by-name `real`
 * forwarders below are used as the re-entry-FREE fallback for the spawn family
 * (see macos_interpose.nim `inSpawnForward`); if they resolved back to the
 * wrapper they would re-enter the hook and loop. Skipping the shim image
 * guarantees the forwarder reaches the genuine libsystem entry. (The shim image
 * is identified by the librepro_monitor_shim substring in its dyld path; see the
 * body-patch resolver for the matching rationale.)
 */
static int repro_macos_image_is_shim(const char *path) {
  return path != NULL && strstr(path, "librepro_monitor_shim") != NULL;
}

static void *repro_macos_lookup_image_symbol(const char *symbol) {
  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; i++) {
    if (repro_macos_image_is_shim(_dyld_get_image_name(i))) continue;
    const struct mach_header *header = _dyld_get_image_header(i);
    if (header == NULL) continue;
    NSSymbol sym = NSLookupSymbolInImage(header, symbol,
      NSLOOKUPSYMBOLINIMAGE_OPTION_BIND |
      NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR);
    if (sym) {
      void *ptr = NSAddressOfSymbol(sym);
      if (ptr) {
        /* Defensive: never return an address inside the shim image. */
        Dl_info di;
        if (dladdr(ptr, &di) && repro_macos_image_is_shim(di.dli_fname)) continue;
        return ptr;
      }
    }
  }
  return NULL;
}

/*
 * Public (non-static) accessor for the shim-skipping libsystem symbol resolver.
 *
 * The interpose-DISABLE diagnostic path (IO_MON_DEBUG_DISABLE_INTERPOSE, a
 * debug-only A/B knob) needs to forward an interposed call to the libsystem
 * function's ACTUAL entry address — which the body-patch backend overwrites IN
 * PLACE — so that body-patch records the call if active (and a genuine,
 * unrecorded libsystem call happens if it is not). Calling through the resolved
 * address bypasses the `__DATA,__interpose` tuple (which only rebinds import
 * STUBS, not direct address calls), so the forward cannot re-enter the interpose
 * wrapper via the tuple. Resolving via the SAME shim-skipping image walk keeps a
 * single source of truth for "find the real libsystem `_name`" (DRY). `symbol`
 * is the mangled "_name" form (e.g. "_write").
 */
void *repro_macos_resolve_libsystem_symbol(const char *symbol) {
  return repro_macos_lookup_image_symbol(symbol);
}

static void repro_macos_resolve_spawn(void) {
  if (repro_macos_real_posix_spawn_ptr && repro_macos_real_posix_spawnp_ptr) return;
  repro_macos_real_posix_spawn_ptr =
    (repro_macos_posix_spawn_fn)repro_macos_lookup_image_symbol("_posix_spawn");
  repro_macos_real_posix_spawnp_ptr =
    (repro_macos_posix_spawn_fn)repro_macos_lookup_image_symbol("_posix_spawnp");
  /* NOTE: deliberately NO dlsym(RTLD_DEFAULT, ...) fallback. Under the body-patch
   * backend dlsym resolves the shim's OWN `repro_wrap_posix_spawn` wrapper (dyld
   * applies the shim's __interpose tuples to its own lookups), so a dlsym
   * fallback would make this "real" forwarder re-enter the hook and loop. The
   * shim-skipping image walk above is the only correct resolution. */
}

static void repro_macos_resolve_dir(void) {
  if (!repro_macos_real_opendir_ptr) {
    repro_macos_real_opendir_ptr =
      (repro_macos_opendir_fn)repro_macos_lookup_image_symbol("_opendir");
  }
  if (!repro_macos_real_readdir_ptr) {
    repro_macos_real_readdir_ptr =
      (repro_macos_readdir_fn)repro_macos_lookup_image_symbol("_readdir");
  }
  if (!repro_macos_real_closedir_ptr) {
    repro_macos_real_closedir_ptr =
      (repro_macos_closedir_fn)repro_macos_lookup_image_symbol("_closedir");
  }
}

static void repro_macos_resolve_stat(void) {
  if (!repro_macos_real_stat_ptr) {
    repro_macos_real_stat_ptr =
      (repro_macos_stat_fn)repro_macos_lookup_image_symbol("_stat");
  }
  if (!repro_macos_real_lstat_ptr) {
    repro_macos_real_lstat_ptr =
      (repro_macos_stat_fn)repro_macos_lookup_image_symbol("_lstat");
  }
  /* No dlsym(RTLD_DEFAULT) fallback: it would resolve the shim's own stat/lstat
   * interpose wrapper under the body-patch backend (see repro_macos_resolve_spawn). */
}

static void repro_macos_resolve_fork(void) {
  if (!repro_macos_real_fork_ptr) {
    repro_macos_real_fork_ptr =
      (repro_macos_fork_fn)repro_macos_lookup_image_symbol("_fork");
  }
  /* No dlsym(RTLD_DEFAULT) fallback: it would resolve the shim's own fork
   * interpose wrapper under the body-patch backend (see repro_macos_resolve_spawn). */
}

void *repro_macos_real_opendir(char *path) {
  repro_macos_resolve_dir();
  if (!repro_macos_real_opendir_ptr) return NULL;
  return repro_macos_real_opendir_ptr(path);
}

void *repro_macos_real_readdir(void *dirp) {
  repro_macos_resolve_dir();
  if (!repro_macos_real_readdir_ptr) return NULL;
  return repro_macos_real_readdir_ptr((DIR *)dirp);
}

int repro_macos_real_closedir(void *dirp) {
  repro_macos_resolve_dir();
  if (!repro_macos_real_closedir_ptr) return -1;
  return repro_macos_real_closedir_ptr((DIR *)dirp);
}

int repro_macos_real_stat(char *path, void *buf) {
  repro_macos_resolve_stat();
  if (!repro_macos_real_stat_ptr) {
    errno = ENOSYS;
    return -1;
  }
  return repro_macos_real_stat_ptr(path, (struct stat *)buf);
}

int repro_macos_real_lstat(char *path, void *buf) {
  repro_macos_resolve_stat();
  if (!repro_macos_real_lstat_ptr) {
    errno = ENOSYS;
    return -1;
  }
  return repro_macos_real_lstat_ptr(path, (struct stat *)buf);
}

pid_t repro_macos_real_fork(void) {
  repro_macos_resolve_fork();
  if (!repro_macos_real_fork_ptr) {
    errno = ENOSYS;
    return -1;
  }
  return repro_macos_real_fork_ptr();
}

int repro_macos_real_posix_spawn(pid_t *pid, char *path, void *file_actions,
                                 void *attrp, char **argv, char **envp) {
  repro_macos_resolve_spawn();
  if (!repro_macos_real_posix_spawn_ptr) return -1;
  char **effective_envp = repro_macos_env_with_preload(envp);
  char *effective_path = repro_macos_rewrite_sip_path(path);
  return repro_macos_real_posix_spawn_ptr(pid, effective_path,
    (const posix_spawn_file_actions_t *)file_actions,
    (const posix_spawnattr_t *)attrp, argv, effective_envp);
}

int repro_macos_real_posix_spawnp(pid_t *pid, char *path, void *file_actions,
                                  void *attrp, char **argv, char **envp) {
  repro_macos_resolve_spawn();
  if (!repro_macos_real_posix_spawnp_ptr) return -1;
  char **effective_envp = repro_macos_env_with_preload(envp);
  char *effective_path = repro_macos_rewrite_sip_path(path);
  return repro_macos_real_posix_spawnp_ptr(pid, effective_path,
    (const posix_spawn_file_actions_t *)file_actions,
    (const posix_spawnattr_t *)attrp, argv, effective_envp);
}

/*
 * Forward into the ORIGINAL libsystem `fork` via a TRAMPOLINE (built by
 * macos_bodypatch). This is the CORRECT body-patch fork forwarder — it runs
 * libsystem's own `fork()` wrapper body, which executes the registered
 * `pthread_atfork` handlers AND, critically, libsystem_malloc's
 * `_malloc_fork_prepare`/`_malloc_fork_parent`/`_malloc_fork_child` hooks that
 * reset the allocator's internal locks/zone state across the fork.
 *
 * WHY THIS REPLACES THE RAW `SYS_fork` FORWARDER: the bare-kernel fork above
 * SKIPS that userland bookkeeping. On macOS 26 / Apple Silicon the modern
 * `libsystem_malloc` "xzone" allocator keeps deferred-reclaim state that, when
 * inherited by a fork CHILD without the malloc child-handler running, leaves the
 * child's freelist inconsistent — the child's first `malloc` then hits an
 * internal consistency `brk #0x1` (SIGTRAP) in `_xzm_*`. Empirically this
 * crashed `bash`/`sh` subshells (command substitution, simple-command exec)
 * during a monitored gnulib `make`, breaking the build. Forwarding through the
 * libsystem fork body (trampoline) runs the malloc atfork child handler, so the
 * child's allocator is consistent and the crash is eliminated. The libsystem
 * wrapper also applies the correct x1-based child-return rewrite, so we no
 * longer need the hand-rolled `svc` sequence for the body-patch path.
 *
 * `tramp` has the exact `pid_t fork(void)` ABI (the trampoline runs fork's
 * displaced, relocatable prologue then resumes into its body). Returns the
 * libsystem fork result (0 in the child, child pid in the parent, -1 on error).
 */
pid_t repro_macos_bodypatch_call_fork(void *tramp) {
  if (tramp == NULL) {
    /* No trampoline. Two cases:
     *  - interpose-only backend: the named `fork` entry is NOT body-patched, so
     *    the by-name real (resolved to the genuine libsystem fork via the
     *    shim-skipping image walk) runs libsystem's full fork bookkeeping AND is
     *    re-entry-free. This is the correct, malloc-safe path there.
     *  - body-patch backend but the fork trampoline build was skipped: calling
     *    by-name would re-enter the patched entry, so we must NOT; we fall back
     *    to the raw syscall (degraded — lacks the malloc atfork reset — but the
     *    only re-entry-free option, and the banner reports fork_tramp=skip).
     * We cannot tell the two apart here, so the SHIM passes a nil trampoline only
     * in the interpose-only case (it sets the trampoline whenever the body-patch
     * backend is active); thus reaching here with tramp==NULL means interpose-
     * only, where by-name is correct and safe. */
    return repro_macos_real_fork();
  }
  repro_macos_fork_fn fn = (repro_macos_fork_fn)tramp;
  return fn();
}

/*
 * Forward into the ORIGINAL posix_spawn/posix_spawnp via a TRAMPOLINE (built by
 * macos_bodypatch). The trampoline runs the original wrapper's displaced
 * prologue then resumes into its body, so libsystem's own
 * `_posix_spawn_args_desc` marshalling runs — we must NOT hand-marshal a raw
 * SYS_posix_spawn. `tramp` has the exact posix_spawn ABI. The hook has already
 * applied env-propagation + SIP-rewrite to `envp`/`path` (via
 * `repro_macos_bodypatch_spawn_rewrite`); we just call through.
 *
 * This is the body-patch forwarding path. It deliberately does NOT reuse
 * `repro_macos_real_posix_spawn` (which resolves the real symbol by NAME): under
 * body-patching the named symbol points at OUR hook, so a name-based forward
 * would re-enter infinitely. The trampoline is the only re-entry-free path into
 * the original marshalling body.
 */
int repro_macos_bodypatch_call_posix_spawn(void *tramp, pid_t *pid, char *path,
    void *file_actions, void *attrp, char **argv, char **envp) {
  if (tramp == NULL) return -1;
  repro_macos_posix_spawn_fn fn = (repro_macos_posix_spawn_fn)tramp;
  return fn(pid, path,
    (const posix_spawn_file_actions_t *)file_actions,
    (const posix_spawnattr_t *)attrp, argv, envp);
}

/*
 * Apply env-propagation + SIP-rewrite to a spawn, returning the effective
 * path and writing the effective envp through *out_envp. Mirrors what the
 * existing `repro_macos_real_posix_spawn*` helpers do internally, factored out
 * so the body-patch hook (which forwards via trampoline, not via the named
 * symbol) reuses the SAME propagation logic (DRY).
 */
char *repro_macos_bodypatch_spawn_rewrite(char *path, char **envp,
                                          char ***out_envp) {
  if (out_envp) *out_envp = repro_macos_env_with_preload(envp);
  return repro_macos_rewrite_sip_path(path);
}

/*
 * copyfile / fcopyfile forwarders (break #3, the COPYFILE_CLONE arm).
 *
 * Unlike clonefile/link, copyfile(3) is NOT a thin syscall wrapper: the kernel
 * SYS_copyfile is a legacy stub the modern libcopyfile does not use — it does
 * open/read/write (data mode) or an internal clonefile (clone mode) in
 * userland. So the forward MUST run the genuine libsystem copyfile body. We
 * therefore DELIBERATELY do NOT body-patch copyfile (only interpose it); the
 * forward resolves the real libsystem entry via the shim-skipping image walk
 * (genuine + unpatched because we never patched it), so there is no re-entry.
 * The hook records the SOURCE as a read ONLY for the clone modes — the data
 * mode's internal open/read is already captured by those hooks, so recording it
 * again would double-count (see the §"Coverage wins" note in the findings doc).
 */
typedef int (*repro_copyfile_fn)(const char *, const char *, void *, uint32_t);
typedef int (*repro_fcopyfile_fn)(int, int, void *, uint32_t);
static repro_copyfile_fn repro_real_copyfile_ptr = NULL;
static repro_fcopyfile_fn repro_real_fcopyfile_ptr = NULL;

int repro_macos_real_copyfile_call(char *from, char *to, void *state,
                                   uint32_t flags) {
  if (!repro_real_copyfile_ptr)
    repro_real_copyfile_ptr =
      (repro_copyfile_fn)repro_macos_lookup_image_symbol("_copyfile");
  if (!repro_real_copyfile_ptr) { errno = ENOSYS; return -1; }
  return repro_real_copyfile_ptr(from, to, state, flags);
}

int repro_macos_real_fcopyfile_call(int from, int to, void *state,
                                    uint32_t flags) {
  if (!repro_real_fcopyfile_ptr)
    repro_real_fcopyfile_ptr =
      (repro_fcopyfile_fn)repro_macos_lookup_image_symbol("_fcopyfile");
  if (!repro_real_fcopyfile_ptr) { errno = ENOSYS; return -1; }
  return repro_real_fcopyfile_ptr(from, to, state, flags);
}

/* POSIX_SPAWN_SETEXEC detection (break #2). A SETEXEC spawn REPLACES the calling
 * process image and never returns on success, so the spawn hook must emit +
 * flush its exec record BEFORE forwarding (mirroring execve). Reads the attr
 * flags via the public getter; returns 1 if SETEXEC is set. attrp==NULL ⇒ no
 * attributes ⇒ not SETEXEC. */
int repro_macos_spawnattr_has_setexec(void *attrp) {
  if (attrp == NULL) return 0;
  short flags = 0;
  if (posix_spawnattr_getflags((const posix_spawnattr_t *)attrp, &flags) != 0)
    return 0;
  return (flags & POSIX_SPAWN_SETEXEC) ? 1 : 0;
}

/*
 * ROUND-2 R-C (XPC / Mach-port breakaway): close the connection-establishment
 * blind spot that DEFEATS the connect(2) breakaway fail-safe (round-2 findings,
 * the confirmed r2_xpc break). XPC and raw Mach RPC NEVER issue connect(2): a
 * client resolves a service name to a Mach send port via bootstrap_look_up +
 * mach_msg to launchd's bootstrap port. A monitored client that delegates a file
 * read to an OUT-OF-TREE service (research/.../r2_xpc: mach_server opens+reads
 * the marker on the client's behalf and returns the bytes) produces NO
 * mrIpcConnect, NO spawn, NO event-loss → a false `mcComplete` cache hit. We hook
 * the CONNECTION-ESTABLISHMENT boundary (bootstrap_look_up + the XPC client
 * entry), NOT the hot mach_msg send path — mirroring exactly how connect(2) is
 * handled for the socket-daemon breakaway.
 *
 * Forwarding (interpose-only, like copyfile): bootstrap_look_up /
 * xpc_connection_create_mach_service are NOT thin syscall wrappers and are NOT
 * body-patched, so the recording hook's forward resolves the GENUINE libsystem
 * entry via the shim-skipping image walk (a by-name call could re-enter the
 * shim's own __interpose binding and loop). dlsym(RTLD_NEXT) is the fallback so
 * the monitored program NEVER breaks if the image walk cannot resolve the symbol.
 */
typedef kern_return_t (*repro_bootstrap_look_up_fn)(mach_port_t, const char *,
                                                    mach_port_t *);
static repro_bootstrap_look_up_fn repro_real_bootstrap_look_up_ptr = NULL;

kern_return_t repro_macos_real_bootstrap_look_up_call(mach_port_t bp,
    char *name, mach_port_t *sp) {
  if (!repro_real_bootstrap_look_up_ptr)
    repro_real_bootstrap_look_up_ptr = (repro_bootstrap_look_up_fn)
      repro_macos_lookup_image_symbol("_bootstrap_look_up");
  if (!repro_real_bootstrap_look_up_ptr)
    repro_real_bootstrap_look_up_ptr = (repro_bootstrap_look_up_fn)
      dlsym(RTLD_NEXT, "bootstrap_look_up");
  if (!repro_real_bootstrap_look_up_ptr) return BOOTSTRAP_UNKNOWN_SERVICE;
  return repro_real_bootstrap_look_up_ptr(bp, name, sp);
}

typedef xpc_connection_t (*repro_xpc_create_fn)(const char *,
                                                dispatch_queue_t, uint64_t);
static repro_xpc_create_fn repro_real_xpc_create_ptr = NULL;

void *repro_macos_real_xpc_create_mach_service_call(char *name,
    void *targetq, unsigned long long flags) {
  if (!repro_real_xpc_create_ptr)
    repro_real_xpc_create_ptr = (repro_xpc_create_fn)
      repro_macos_lookup_image_symbol("_xpc_connection_create_mach_service");
  if (!repro_real_xpc_create_ptr)
    repro_real_xpc_create_ptr = (repro_xpc_create_fn)
      dlsym(RTLD_NEXT, "xpc_connection_create_mach_service");
  if (!repro_real_xpc_create_ptr) return NULL;
  return (void *)repro_real_xpc_create_ptr(name, (dispatch_queue_t)targetq,
                                           (uint64_t)flags);
}

/*
 * Classify a Mach service name: 1 if a bootstrap_look_up / XPC connection to it
 * should be RECORDED as a potential out-of-tree breakaway, 0 if it is a SYSTEM
 * BASELINE name that EVERY normal program resolves (the bootstrap analog of the
 * /usr/lib + /System + dyld-shared-cache library-load filter). The com.apple.*
 * namespace is the dominant baseline (notifyd, logd, distributed notifications,
 * the dyld/XPC system services, com.apple.dt.* developer tooling, …) and the
 * shim's own / libsystem's own startup lookups all fall in it; recording those
 * would self-downgrade EVERY capture — the CARDINAL SIN. A NON-Apple service
 * (sccache/distcc/icecc/custom build daemons, and the r2_xpc com.example.*
 * breakaway) is the conservative downgrade trigger: a normal compile/link/make
 * never resolves one, so the no-false-downgrade guard holds, while a delegated
 * file read to a custom out-of-tree daemon is caught.
 *
 * RESIDUAL (documented): a breakaway delegated to a com.apple.* service
 * (SourceKit com.apple.dt.*, Virtualization.framework, sandboxd) is NOT caught
 * here — an in-process hook cannot distinguish a benign com.apple.* lookup
 * (pervasive in every build) from a malicious one without false-downgrading
 * everything. The structural fix is the EndpointSecurity backend (T3c). This
 * in-process hook is the conservative stopgap for the non-Apple custom-daemon
 * breakaway surface the confirmed break exercises.
 */
int repro_macos_mach_service_recordable(char *name) {
  if (!name || !name[0]) return 0;
  if (strncmp(name, "com.apple.", 10) == 0) return 0;
  return 1;
}
""".}

type
  PidT* = cint

proc ct_macos_interpose_real_open*(path: cstring; flags, mode: cint): cint =
  proc realOpenSyscall(path: cstring; flags, mode: cint): cint
    {.importc: "repro_macos_real_open_syscall", cdecl.}
  realOpenSyscall(path, flags, mode)

proc ct_macos_interpose_real_openat*(dirfd: cint; path: cstring; flags, mode: cint): cint =
  proc realOpenatSyscall(dirfd: cint; path: cstring; flags, mode: cint): cint
    {.importc: "repro_macos_real_openat_syscall", cdecl.}
  realOpenatSyscall(dirfd, path, flags, mode)

proc ct_macos_interpose_real_read*(fd: cint; buf: pointer; count: csize_t): int =
  proc realReadSyscall(fd: cint; buf: pointer; count: csize_t): clong
    {.importc: "repro_macos_real_read_syscall", cdecl.}
  int(realReadSyscall(fd, buf, count))

proc ct_macos_interpose_real_write*(fd: cint; buf: pointer; count: csize_t): int =
  proc realWriteSyscall(fd: cint; buf: pointer; count: csize_t): clong
    {.importc: "repro_macos_real_write_syscall", cdecl.}
  int(realWriteSyscall(fd, buf, count))

proc ct_macos_interpose_real_close*(fd: cint): cint =
  proc realCloseSyscall(fd: cint): cint
    {.importc: "repro_macos_real_close_syscall", cdecl.}
  realCloseSyscall(fd)

proc ct_macos_interpose_real_opendir*(path: cstring): pointer =
  proc realOpendir(path: cstring): pointer
    {.importc: "repro_macos_real_opendir", cdecl.}
  realOpendir(path)

proc ct_macos_interpose_real_readdir*(dirp: pointer): pointer =
  proc realReaddir(dirp: pointer): pointer
    {.importc: "repro_macos_real_readdir", cdecl.}
  realReaddir(dirp)

proc ct_macos_interpose_real_closedir*(dirp: pointer): cint =
  proc realClosedir(dirp: pointer): cint
    {.importc: "repro_macos_real_closedir", cdecl.}
  realClosedir(dirp)

proc ct_macos_interpose_real_stat*(path: cstring; buf: pointer): cint =
  proc realStat(path: cstring; buf: pointer): cint
    {.importc: "repro_macos_real_stat", cdecl.}
  realStat(path, buf)

proc ct_macos_interpose_real_lstat*(path: cstring; buf: pointer): cint =
  proc realLstat(path: cstring; buf: pointer): cint
    {.importc: "repro_macos_real_lstat", cdecl.}
  realLstat(path, buf)

proc ct_macos_interpose_real_fork*(): PidT =
  proc realFork(): PidT {.importc: "repro_macos_real_fork", cdecl.}
  realFork()

proc ct_macos_interpose_real_execve*(path: cstring; argv, envp: cstringArray): cint =
  proc realExecveSyscall(path: cstring; argv, envp: cstringArray): cint
    {.importc: "repro_macos_real_execve_syscall", cdecl.}
  realExecveSyscall(path, argv, envp)

proc ct_macos_interpose_path_is_dir*(path: cstring): bool =
  proc pathIsDir(path: cstring): cint
    {.importc: "repro_macos_path_is_dir", cdecl.}
  path != nil and pathIsDir(path) != 0

proc ct_macos_interpose_real_posix_spawn*(pid: ptr PidT; path: cstring;
    fileActions, attrp: pointer; argv, envp: cstringArray): cint =
  proc realPosixSpawn(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                      argv, envp: cstringArray): cint
    {.importc: "repro_macos_real_posix_spawn", cdecl.}
  realPosixSpawn(pid, path, fileActions, attrp, argv, envp)

proc ct_macos_interpose_real_posix_spawnp*(pid: ptr PidT; path: cstring;
    fileActions, attrp: pointer; argv, envp: cstringArray): cint =
  proc realPosixSpawnp(pid: ptr PidT; path: cstring; fileActions, attrp: pointer;
                       argv, envp: cstringArray): cint
    {.importc: "repro_macos_real_posix_spawnp", cdecl.}
  realPosixSpawnp(pid, path, fileActions, attrp, argv, envp)

# Raw-syscall stat-family forwarders used ONLY by the body-patch backend, which
# patches the named stat/lstat/... symbols and therefore must bypass them when
# forwarding to the kernel (see the C source for why dlsym/named would recurse).

proc ct_macos_bodypatch_real_stat*(path: cstring; buf: pointer): cint =
  proc realStat64(path: cstring; buf: pointer): cint
    {.importc: "repro_macos_real_stat64_syscall", cdecl.}
  realStat64(path, buf)

proc ct_macos_bodypatch_real_lstat*(path: cstring; buf: pointer): cint =
  proc realLstat64(path: cstring; buf: pointer): cint
    {.importc: "repro_macos_real_lstat64_syscall", cdecl.}
  realLstat64(path, buf)

proc ct_macos_bodypatch_real_fstatat*(dirfd: cint; path: cstring; buf: pointer;
    flag: cint): cint =
  proc realFstatat64(dirfd: cint; path: cstring; buf: pointer; flag: cint): cint
    {.importc: "repro_macos_real_fstatat64_syscall", cdecl.}
  realFstatat64(dirfd, path, buf, flag)

proc ct_macos_bodypatch_real_access*(path: cstring; mode: cint): cint =
  proc realAccess(path: cstring; mode: cint): cint
    {.importc: "repro_macos_real_access_syscall", cdecl.}
  realAccess(path, mode)

proc ct_macos_real_rename*(fromPath, toPath: cstring): cint =
  ## Raw `SYS_rename` forwarder shared by the interpose + body-patch rename hook.
  ## Bypasses the named symbol so it never re-enters a body-patched `rename`.
  proc realRename(fromPath, toPath: cstring): cint
    {.importc: "repro_macos_real_rename_syscall", cdecl.}
  realRename(fromPath, toPath)

proc ct_macos_real_renameat*(fromfd: cint; fromPath: cstring; tofd: cint;
    toPath: cstring): cint =
  ## Raw `SYS_renameat` forwarder shared by the interpose + body-patch hook.
  proc realRenameat(fromfd: cint; fromPath: cstring; tofd: cint;
      toPath: cstring): cint
    {.importc: "repro_macos_real_renameat_syscall", cdecl.}
  realRenameat(fromfd, fromPath, tofd, toPath)

# Spawn-family forwarders used ONLY by the body-patch backend. The body-patch
# backend patches the named fork/posix_spawn symbols, so it must bypass them
# when forwarding (see the C source for why named/dlsym would recurse).

proc ct_macos_bodypatch_real_fork*(): PidT =
  ## Raw `SYS_fork` forwarder (no userland atfork bookkeeping — see the C doc).
  ## DEPRECATED for the fork hook's normal path: use ct_macos_bodypatch_call_fork
  ## with the fork trampoline so libsystem's malloc atfork handlers run. Kept as
  ## the trampoline-unavailable fallback only.
  proc realForkSyscall(): PidT {.importc: "repro_macos_real_fork_syscall", cdecl.}
  realForkSyscall()

proc ct_macos_bodypatch_call_fork*(tramp: pointer): PidT =
  ## Forward into the ORIGINAL libsystem `fork` via the trampoline `tramp`, so
  ## libsystem's `pthread_atfork` + malloc fork handlers run (resetting the
  ## allocator across the fork). This is the body-patch fork hook's correct
  ## forward path — the raw `SYS_fork` forwarder skipped that bookkeeping and
  ## crashed fork children in libsystem_malloc (`brk` SIGTRAP) on macOS 26. If
  ## `tramp` is nil the C helper falls back to the raw syscall. Returns 0 in the
  ## child, the child pid in the parent, -1 on error.
  proc callFork(tramp: pointer): PidT
    {.importc: "repro_macos_bodypatch_call_fork", cdecl.}
  callFork(tramp)

proc ct_macos_bodypatch_spawn_rewrite*(path: cstring; envp: cstringArray;
    outEnvp: ptr cstringArray): cstring =
  ## Apply env-propagation (re-add DYLD_INSERT_LIBRARIES + CT_SANDBOX_TOOLS_DIR)
  ## + SIP-rewrite to a spawn. Returns the effective path and writes the
  ## effective envp through `outEnvp`. The body-patch spawn hook calls this, then
  ## forwards into the original wrapper via the trampoline.
  proc spawnRewrite(path: cstring; envp: cstringArray;
      outEnvp: ptr cstringArray): cstring
    {.importc: "repro_macos_bodypatch_spawn_rewrite", cdecl.}
  spawnRewrite(path, envp, outEnvp)

proc ct_macos_bodypatch_call_posix_spawn*(tramp: pointer; pid: ptr PidT;
    path: cstring; fileActions, attrp: pointer; argv, envp: cstringArray): cint =
  ## Forward into the ORIGINAL posix_spawn/posix_spawnp via the trampoline
  ## `tramp` (re-entry-free; runs libsystem's own `_posix_spawn_args_desc`
  ## marshalling). `path`/`envp` must already be the rewritten effective values.
  proc callPosixSpawn(tramp: pointer; pid: ptr PidT; path: cstring;
      fileActions, attrp: pointer; argv, envp: cstringArray): cint
    {.importc: "repro_macos_bodypatch_call_posix_spawn", cdecl.}
  callPosixSpawn(tramp, pid, path, fileActions, attrp, argv, envp)

# --- T2 content/metadata-dependency raw-syscall forwarders ------------------
# Shared by the interpose + body-patch hooks for the clonefile/link/getattrlist
# families. Each bypasses the (possibly body-patched) named symbol via the raw
# syscall, exactly like the stat/rename forwarders, so a single call records
# once and never re-enters the patched entry.

proc ct_macos_real_clonefile*(src, dst: cstring; flags: cint): cint =
  proc realClonefile(src, dst: cstring; flags: cint): cint
    {.importc: "repro_macos_real_clonefile_syscall", cdecl.}
  realClonefile(src, dst, flags)

proc ct_macos_real_clonefileat*(srcfd: cint; src: cstring; dstfd: cint;
    dst: cstring; flags: cint): cint =
  proc realClonefileat(srcfd: cint; src: cstring; dstfd: cint; dst: cstring;
      flags: cint): cint
    {.importc: "repro_macos_real_clonefileat_syscall", cdecl.}
  realClonefileat(srcfd, src, dstfd, dst, flags)

proc ct_macos_real_fclonefileat*(srcfd, dstfd: cint; dst: cstring;
    flags: cint): cint =
  proc realFclonefileat(srcfd, dstfd: cint; dst: cstring; flags: cint): cint
    {.importc: "repro_macos_real_fclonefileat_syscall", cdecl.}
  realFclonefileat(srcfd, dstfd, dst, flags)

proc ct_macos_real_link*(src, dst: cstring): cint =
  proc realLink(src, dst: cstring): cint
    {.importc: "repro_macos_real_link_syscall", cdecl.}
  realLink(src, dst)

proc ct_macos_real_linkat*(fd1: cint; src: cstring; fd2: cint; dst: cstring;
    flag: cint): cint =
  proc realLinkat(fd1: cint; src: cstring; fd2: cint; dst: cstring;
      flag: cint): cint
    {.importc: "repro_macos_real_linkat_syscall", cdecl.}
  realLinkat(fd1, src, fd2, dst, flag)

proc ct_macos_real_getattrlist*(path: cstring; al, buf: pointer; size: csize_t;
    opts: culong): cint =
  proc realGetattrlist(path: cstring; al, buf: pointer; size: csize_t;
      opts: culong): cint
    {.importc: "repro_macos_real_getattrlist_syscall", cdecl.}
  realGetattrlist(path, al, buf, size, opts)

proc ct_macos_real_getattrlistat*(fd: cint; path: cstring; al, buf: pointer;
    size: csize_t; opts: culong): cint =
  proc realGetattrlistat(fd: cint; path: cstring; al, buf: pointer;
      size: csize_t; opts: culong): cint
    {.importc: "repro_macos_real_getattrlistat_syscall", cdecl.}
  realGetattrlistat(fd, path, al, buf, size, opts)

proc ct_macos_real_fgetattrlist*(fd: cint; al, buf: pointer; size: csize_t;
    opts: culong): cint =
  proc realFgetattrlist(fd: cint; al, buf: pointer; size: csize_t;
      opts: culong): cint
    {.importc: "repro_macos_real_fgetattrlist_syscall", cdecl.}
  realFgetattrlist(fd, al, buf, size, opts)

proc ct_macos_real_getattrlistbulk*(dirfd: cint; al, buf: pointer;
    size: csize_t; opts: uint64): cint =
  proc realGetattrlistbulk(dirfd: cint; al, buf: pointer; size: csize_t;
      opts: uint64): cint
    {.importc: "repro_macos_real_getattrlistbulk_syscall", cdecl.}
  realGetattrlistbulk(dirfd, al, buf, size, opts)

proc ct_macos_real_getdirentries*(fd: cint; buf: pointer; nbytes: cint;
    basep: ptr clong): cint =
  proc realGetdirentries(fd: cint; buf: pointer; nbytes: cint;
      basep: ptr clong): cint
    {.importc: "repro_macos_real_getdirentries_syscall", cdecl.}
  realGetdirentries(fd, buf, nbytes, basep)

proc ct_macos_real_connect*(fd: cint; address: pointer; addrLen: uint32): cint =
  ## Raw `SYS_connect` forwarder shared by the interpose + body-patch connect
  ## hook (T3a, break #1). Bypasses the named symbol so it never re-enters a
  ## body-patched `connect`.
  proc realConnect(fd: cint; address: pointer; addrLen: uint32): cint
    {.importc: "repro_macos_real_connect_syscall", cdecl.}
  realConnect(fd, address, addrLen)

proc ct_macos_real_bootstrap_look_up*(bp: uint32; serviceName: cstring;
    sp: ptr uint32): cint =
  ## ROUND-2 R-C — forward to the GENUINE libsystem `bootstrap_look_up` (resolved
  ## via the shim-skipping image walk; dlsym(RTLD_NEXT) fallback). bootstrap_look_up
  ## is interpose-only (never body-patched) and not a thin syscall, so — like
  ## copyfile — a by-name forward could re-enter the shim's own interpose binding.
  proc realLookup(bp: uint32; serviceName: cstring; sp: ptr uint32): cint
    {.importc: "repro_macos_real_bootstrap_look_up_call", cdecl.}
  realLookup(bp, serviceName, sp)

proc ct_macos_real_xpc_create_mach_service*(name: cstring; targetq: pointer;
    flags: uint64): pointer =
  ## ROUND-2 R-C — forward to the GENUINE libxpc `xpc_connection_create_mach_service`
  ## (interpose-only; resolved via the shim-skipping image walk + dlsym fallback).
  proc realCreate(name: cstring; targetq: pointer; flags: uint64): pointer
    {.importc: "repro_macos_real_xpc_create_mach_service_call", cdecl.}
  realCreate(name, targetq, flags)

proc ct_macos_mach_service_recordable*(name: cstring): bool =
  ## ROUND-2 R-C — true if a bootstrap_look_up / XPC connection to `name` should be
  ## recorded as a potential out-of-tree breakaway (non-`com.apple.*`). The
  ## `com.apple.*` system baseline is excluded so a normal build — whose only
  ## Mach-service lookups are system ones — is never falsely downgraded. See the C
  ## helper for the cardinal-sin rationale and the documented com.apple.* residual.
  proc recordable(name: cstring): cint
    {.importc: "repro_macos_mach_service_recordable", cdecl.}
  name != nil and recordable(name) != 0

proc ct_macos_socket_describe*(fd: cint; address: pointer; addrLen: uint32;
    outDest: pointer; outDestLen: csize_t; outPeerPid: ptr cint): cint =
  ## Describe a connect() target (T3a): returns the address family and fills
  ## `outDest` with the AF_UNIX path or "ip:port"; writes the AF_UNIX peer pid
  ## (LOCAL_PEERPID) through `outPeerPid` (0 when unobtainable). See the C doc.
  proc describe(fd: cint; address: pointer; addrLen: uint32; outDest: pointer;
      outDestLen: csize_t; outPeerPid: ptr cint): cint
    {.importc: "repro_macos_socket_describe", cdecl.}
  describe(fd, address, addrLen, outDest, outDestLen, outPeerPid)

proc ct_macos_proc_start_usec*(pid: cint): uint64 =
  ## ROUND-2 R7 — kernel process start time (microseconds since epoch) for `pid`,
  ## via `proc_pidinfo(PROC_PIDTBSDINFO)`; 0 when unqueryable. Used to stamp the
  ## (pid, start-time) identity on process-start / spawn-child / IPC-peer records
  ## so the merge cannot false-match a recycled (wrapped) pid against a stale
  ## monitored process-start. See the C helper for the pid-wrap rationale.
  proc impl(pid: cint): uint64
    {.importc: "repro_macos_proc_start_usec", cdecl.}
  impl(pid)

proc ct_macos_random_u64*(): uint64 =
  ## ROUND-2 R8 — an unguessable per-connection nonce (arc4random_buf) stamped on
  ## each IPC-connect record so a trusted-daemon breakaway report must echo a nonce
  ## the shim actually recorded for an observed connection.
  proc impl(): uint64 {.importc: "repro_macos_random_u64", cdecl.}
  impl()

proc ct_macos_real_copyfile*(src, dst: cstring; state: pointer;
    flags: uint32): cint =
  ## Forward to the GENUINE libsystem copyfile (copyfile is interpose-only, never
  ## body-patched — see the C forwarder doc), so it runs the real copy body.
  proc realCopyfile(src, dst: cstring; state: pointer; flags: uint32): cint
    {.importc: "repro_macos_real_copyfile_call", cdecl.}
  realCopyfile(src, dst, state, flags)

proc ct_macos_real_fcopyfile*(srcfd, dstfd: cint; state: pointer;
    flags: uint32): cint =
  proc realFcopyfile(srcfd, dstfd: cint; state: pointer; flags: uint32): cint
    {.importc: "repro_macos_real_fcopyfile_call", cdecl.}
  realFcopyfile(srcfd, dstfd, state, flags)

proc ct_macos_fd_real_path*(fd: cint; outBuf: pointer; outLen: csize_t): cint =
  ## fcntl(F_GETPATH) canonicalisation of an open fd (symlink target + /.vol
  ## firmlink resolution, break #7). Returns non-zero on success.
  proc fdRealPath(fd: cint; outBuf: pointer; outLen: csize_t): cint
    {.importc: "repro_macos_fd_real_path", cdecl.}
  fdRealPath(fd, outBuf, outLen)

proc ct_macos_canonical_path*(path: cstring; outBuf: pointer;
    outLen: csize_t): cint =
  ## realpath(3) canonicalisation of a path (symlink-target resolution for the
  ## stat/lstat hooks). MUST be called with the shim muted (disabled>0) so the
  ## internal lstat calls do not recurse into recording. Returns non-zero on ok.
  proc canonicalPath(path: cstring; outBuf: pointer; outLen: csize_t): cint
    {.importc: "repro_macos_canonical_path", cdecl.}
  canonicalPath(path, outBuf, outLen)

proc ct_macos_spawnattr_has_setexec*(attrp: pointer): bool =
  ## True if the spawn attributes set POSIX_SPAWN_SETEXEC (break #2). A SETEXEC
  ## spawn replaces the process image and never returns on success.
  proc hasSetexec(attrp: pointer): cint
    {.importc: "repro_macos_spawnattr_has_setexec", cdecl.}
  hasSetexec(attrp) != 0

proc ct_macos_stat_is_symlink*(buf: pointer): bool =
  ## True if a (64-bit-inode) struct stat buffer describes a symlink. Gates the
  ## lstat hook's realpath-based symlink-target resolution to actual symlinks.
  proc isSymlink(buf: pointer): cint
    {.importc: "repro_macos_stat_is_symlink", cdecl.}
  isSymlink(buf) != 0

proc ct_macos_capture_shim_image*() =
  ## ROUND-2 R6 — capture the shim's own (mach_header, realpath) ONCE at init so
  ## the library-load filter can exclude OUR injected shim by UNSPOOFABLE identity
  ## rather than the round-1 substring test that false-dropped genuine deps whose
  ## path merely contained "librepro_monitor_shim". Call from the constructor,
  ## single-threaded, before the add-image callback is registered.
  proc captureShimImage() {.importc: "repro_macos_capture_shim_image", cdecl.}
  captureShimImage()

proc ct_macos_real_mmap*(adr: pointer; length: csize_t; prot, flags, fd: cint;
    offset: int64): pointer =
  ## ROUND-2 R9 — forward mmap via the inline-asm BSD syscall (full 64-bit return).
  ## Allocation-free and re-entry-free; see the C forwarder for why neither the libc
  ## `syscall()` shim (truncates the pointer to 32 bits → crash) nor a resolved
  ## libsystem `_mmap` pointer (resolution mallocs → re-enters mmap → crash) works.
  proc realMmap(adr: pointer; length: csize_t; prot, flags, fd: cint;
      offset: int64): pointer
    {.importc: "repro_macos_real_mmap_syscall", cdecl.}
  realMmap(adr, length, prot, flags, fd, offset)

proc ct_macos_stat_dev_ino*(buf: pointer; outDev, outIno: ptr uint64): bool =
  ## ROUND-2 R4 — read (st_dev, st_ino) from a struct stat buffer (hardlink
  ## identity, which realpath cannot collapse). True on success.
  proc devIno(buf: pointer; outDev, outIno: ptr uint64): cint
    {.importc: "repro_macos_stat_dev_ino", cdecl.}
  devIno(buf, outDev, outIno) != 0

proc ct_macos_fd_dev_ino*(fd: cint; outDev, outIno: ptr uint64): bool =
  ## ROUND-2 R4 — (st_dev, st_ino) for an open fd via a raw fstat (reentrancy-free).
  proc fdDevIno(fd: cint; outDev, outIno: ptr uint64): cint
    {.importc: "repro_macos_fd_dev_ino", cdecl.}
  fdDevIno(fd, outDev, outIno) != 0

proc ct_macos_dyld_image_dep_path*(mh: pointer; outBuf: pointer;
    outLen: csize_t): cint =
  ## T3b: classify a dyld image (a dependent dylib dyld kernel-mmap'd, or a
  ## dlopen'd one) as a NON-SYSTEM, real-on-disk library-load dependency. Returns
  ## non-zero and fills `outBuf` with the dylib's real path when it is a
  ## recordable content dependency; 0 when it is filtered out (our own shim, the
  ## /usr/lib + /System framework baseline, a shared-cache-only image, or anything
  ## not present as an on-disk regular file). Deadlock-safe to call from inside a
  ## `_dyld` add-image callback (see the C doc): it uses dladdr + a raw stat and
  ## NEVER re-enters dyld.
  proc imageDepPath(mh: pointer; outBuf: pointer; outLen: csize_t): cint
    {.importc: "repro_macos_dyld_image_dep_path", cdecl.}
  imageDepPath(mh, outBuf, outLen)
