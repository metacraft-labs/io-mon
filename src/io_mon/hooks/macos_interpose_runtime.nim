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
#include <mach-o/getsect.h>
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
 * ROUND-3 S2d — raw-syscall forwarders for the fd-DUPLICATION family
 * (dup/dup2/fcntl(F_DUPFD*)). A read/write via a DUPLICATE of an open fd must be
 * attributed to the SAME file as the source, and a dup2 onto an already-open
 * destination closes the old destination INTERNALLY in the kernel (bypassing the
 * hooked close), so the shim's fd->path table must mirror the duplication.
 *
 * Each forwards via the RAW syscall (reentrancy-free; never re-enters its own
 * interpose wrapper). macOS has NO dup3 (and no SYS_dup3), so only dup/dup2 and
 * fcntl's F_DUPFD/F_DUPFD_CLOEXEC commands duplicate an fd here.
 */
int repro_macos_real_dup_syscall(int fd) {
  return (int)syscall(SYS_dup, fd);
}

int repro_macos_real_dup2_syscall(int oldfd, int newfd) {
  return (int)syscall(SYS_dup2, oldfd, newfd);
}

/*
 * Raw `fcntl` forwarder. fcntl is variadic (int fcntl(int, int, ...)); on Darwin
 * libsystem marshals the single optional argument into the third syscall slot
 * regardless of whether the command takes an int (F_DUPFD, F_SETFD, …) or a
 * pointer (F_GETPATH, F_PREALLOCATE, …). Forwarding the argument as a void*-sized
 * value through SYS_fcntl is therefore faithful for EVERY command — the kernel
 * reads only the bits the command defines — so a single forwarder both duplicates
 * (F_DUPFD*) and passes through every other command untouched. The interpose
 * wrapper reads the variadic argument via va_arg and hands it here. */
int repro_macos_real_fcntl_syscall(int fd, int cmd, void *arg) {
  return (int)syscall(SYS_fcntl, fd, cmd, arg);
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
 * ROUND-3 S1 content-channel raw-syscall forwarders. Each reaches the kernel via
 * the RAW syscall (the xattr/shm/sendfile/pread/readv entries are thin libsystem
 * wrappers over their syscalls), exactly like the connect/stat/rename forwarders,
 * so they are reentrancy-free and never re-enter the shim's own interpose
 * wrapper of the same name. These hooks are INTERPOSE-ONLY (see the thunks /
 * interpose tuple), so a not-ready or muted call forwards straight through here.
 *
 * macOS xattr ABI: the path/fd variants take a trailing (u_int32_t position,
 * int options) pair — see <sys/xattr.h>. listxattr/flistxattr take (buf, size,
 * options); removexattr/fremovexattr take (name, options). getxattrat does NOT
 * exist as a macOS syscall (no SYS_getxattrat in <sys/syscall.h>), so it is
 * intentionally not hooked here (the corpus exercises getxattr/fgetxattr/
 * listxattr only).
 */
ssize_t repro_macos_real_getxattr_syscall(char *path, char *name, void *value,
                                          size_t size, unsigned int position,
                                          int options) {
  return (ssize_t)syscall(SYS_getxattr, path, name, value, size, position,
                          options);
}
ssize_t repro_macos_real_fgetxattr_syscall(int fd, char *name, void *value,
                                           size_t size, unsigned int position,
                                           int options) {
  return (ssize_t)syscall(SYS_fgetxattr, fd, name, value, size, position,
                          options);
}
ssize_t repro_macos_real_listxattr_syscall(char *path, void *namebuf,
                                           size_t size, int options) {
  return (ssize_t)syscall(SYS_listxattr, path, namebuf, size, options);
}
ssize_t repro_macos_real_flistxattr_syscall(int fd, void *namebuf, size_t size,
                                            int options) {
  return (ssize_t)syscall(SYS_flistxattr, fd, namebuf, size, options);
}
int repro_macos_real_setxattr_syscall(char *path, char *name, void *value,
                                      size_t size, unsigned int position,
                                      int options) {
  return (int)syscall(SYS_setxattr, path, name, value, size, position, options);
}
int repro_macos_real_fsetxattr_syscall(int fd, char *name, void *value,
                                       size_t size, unsigned int position,
                                       int options) {
  return (int)syscall(SYS_fsetxattr, fd, name, value, size, position, options);
}
int repro_macos_real_removexattr_syscall(char *path, char *name, int options) {
  return (int)syscall(SYS_removexattr, path, name, options);
}
int repro_macos_real_fremovexattr_syscall(int fd, char *name, int options) {
  return (int)syscall(SYS_fremovexattr, fd, name, options);
}

/* POSIX shm_open: third arg (mode) is meaningful only with O_CREAT; passing it
 * unconditionally is harmless for a non-creating open (the kernel ignores it). */
int repro_macos_real_shm_open_syscall(char *name, int oflag, int mode) {
  return (int)syscall(SYS_shm_open, name, oflag, mode);
}

/* sendfile(2): SOURCE fd is arg 1; offset/len are off_t (64-bit, in a register
 * on arm64). hdtr may be NULL. */
int repro_macos_real_sendfile_syscall(int fd, int s, long long offset,
                                      long long *len, void *hdtr, int flags) {
  return (int)syscall(SYS_sendfile, fd, s, offset, len, hdtr, flags);
}

ssize_t repro_macos_real_pread_syscall(int fd, void *buf, size_t n,
                                       long long offset) {
  return (ssize_t)syscall(SYS_pread, fd, buf, n, offset);
}
ssize_t repro_macos_real_preadv_syscall(int fd, void *iov, int iovcnt,
                                        long long offset) {
  return (ssize_t)syscall(SYS_preadv, fd, iov, iovcnt, offset);
}
ssize_t repro_macos_real_readv_syscall(int fd, void *iov, int iovcnt) {
  return (ssize_t)syscall(SYS_readv, fd, iov, iovcnt);
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
 * downgrade). proc_pidinfo is not hooked, so this is reentrancy-free.
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
 *
 * ROUND-2 R-D — the shim now INTERPOSES arc4random_buf (entropy observation).
 * The shim's OWN nonce randomness here MUST NOT be recorded as the monitored
 * program's non-determinism — that would self-downgrade EVERY capture with an IPC
 * connect (the cardinal sin). We forward to the GENUINE libsystem arc4random_buf
 * resolved via dlsym(RTLD_NEXT) (RTLD_NEXT searches images loaded AFTER the shim,
 * so it skips the shim's own __interpose wrapper and reaches libsystem directly).
 * The direct-call fallback runs only if the (never-observed) resolution fails.
 */
unsigned long long repro_macos_random_u64(void) {
  static void (*real_arc4random_buf)(void *, size_t) = NULL;
  if (!real_arc4random_buf)
    real_arc4random_buf =
      (void (*)(void *, size_t))dlsym(RTLD_NEXT, "arc4random_buf");
  unsigned long long v = 0ull;
  if (real_arc4random_buf) real_arc4random_buf(&v, sizeof v);
  else arc4random_buf(&v, sizeof v);
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
 * ROUND-3 S1 — (dev, ino, FILE-TYPE) for an open fd in a SINGLE raw fstat
 * (unhooked → reentrancy-free). A superset of repro_macos_fd_dev_ino that ALSO
 * classifies the fd's underlying object so the open hook can detect a FIFO
 * (S1d — out-of-tree FIFO feeder) and the empty-path read hook can tell a real
 * file (resolve + record) from a socket/pipe (out-of-tree → downgrade), WITHOUT
 * paying a second fstat (the open hot path already pays this one for the dev/ino
 * stamp). `*out_kind` receives one of the REPRO_FD_KIND_* codes below.
 */
#define REPRO_FD_KIND_OTHER 0
#define REPRO_FD_KIND_REG   1   /* regular file                                */
#define REPRO_FD_KIND_FIFO  2   /* named FIFO or anonymous pipe                */
#define REPRO_FD_KIND_SOCK  3   /* socket                                      */
#define REPRO_FD_KIND_CHR   4   /* character device (tty, /dev/null, /dev/zero)*/
#define REPRO_FD_KIND_BLK   5   /* block device                                */
#define REPRO_FD_KIND_DIR   6   /* directory                                   */
int repro_macos_fd_dev_ino_kind(int fd, unsigned long long *out_dev,
                                unsigned long long *out_ino, int *out_kind) {
  if (fd < 0) return 0;
  struct stat st;
  if (syscall(SYS_fstat64, fd, &st) != 0) return 0;
  if (out_dev) *out_dev = (unsigned long long)st.st_dev;
  if (out_ino) *out_ino = (unsigned long long)st.st_ino;
  if (out_kind) {
    mode_t m = st.st_mode;
    *out_kind = S_ISREG(m)  ? REPRO_FD_KIND_REG  :
                S_ISFIFO(m) ? REPRO_FD_KIND_FIFO :
                S_ISSOCK(m) ? REPRO_FD_KIND_SOCK :
                S_ISCHR(m)  ? REPRO_FD_KIND_CHR  :
                S_ISBLK(m)  ? REPRO_FD_KIND_BLK  :
                S_ISDIR(m)  ? REPRO_FD_KIND_DIR  : REPRO_FD_KIND_OTHER;
  }
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

/* ROUND-2 R-D — CALLER ATTRIBUTION for entropy observations.
 *
 * The entropy hooks (arc4random*, getentropy) emit policy evidence, so false
 * positives still matter. The original R-D premise — that an interpose hook sees ONLY the
 * program's OWN direct entropy use because libsystem-internal randomness "never
 * crosses an import stub" — is FALSE: on every process startup /usr/lib/libobjc,
 * /usr/lib/swift/libswiftCore, /usr/lib/system/libsystem_malloc / _trace call
 * arc4random_buf and /usr/lib/system/libcorecrypto calls getentropy, ALL
 * cross-dylib (so they DO cross the interpose stub and WERE flagged). The result
 * was that EVERY non-trivial real program — `cc`/`clang`/`ld`/`bash` — auto-
 * downgraded to mcIncomplete (the CARDINAL SIN: every build re-runs).
 *
 * We attribute each entropy call to its CALLER (the return address the wrapper
 * passes) and flag ONLY when the caller is in the monitored program's OWN MAIN
 * EXECUTABLE — captured ONCE at init as the main image's __TEXT address range. A
 * program's own arc4random() call (the case the milestone targets, e.g. a tool
 * baking a random salt) lands in the main exe's __TEXT and is flagged; the
 * libsystem/libobjc/libswift baseline lands in a system dylib's __TEXT and is NOT.
 *
 * WHY A RANGE COMPARE, NOT dladdr: these hooks fire while libobjc/libswift run
 * their image INITIALISERS, i.e. UNDER dyld's loader lock. dladdr /
 * _dyld_shared_cache_contains_path can re-enter dyld there (a documented loader-lock
 * hazard), and they also allocate. A pure pointer-range compare touches no dyld, no
 * malloc, no lock — it is safe at any lifecycle point and re-entry-free, and far
 * cheaper per call. The narrower main-exe-only scope (a non-system toolchain DYLIB
 * that itself draws entropy is not flagged) is an accepted, documented FALSE
 * NEGATIVE — far cheaper than the cardinal-sin false positive the milestone ranks
 * worst. */
static const void *repro_main_text_start = NULL;
static const void *repro_main_text_end = NULL;

void repro_macos_capture_main_image(void) {
  /* Find the MAIN EXECUTABLE (the one MH_EXECUTE image) and record its __TEXT
   * address range. We must NOT use index 0: when the shim is injected via
   * DYLD_INSERT_LIBRARIES, the INSERTED dylibs occupy the low image indices, so
   * _dyld_get_image_header(0) is the SHIM, not the program (observed: capturing
   * the shim's range, so the program's own entropy use was never attributed). The
   * exactly-one MH_EXECUTE image is the program regardless of insertion order.
   * mh->filetype sits at the same offset in mach_header / mach_header_64, so the
   * 32-bit struct read is correct for arm64/arm64e. getsegmentdata returns the
   * actual (slid) mapped address + size, so the range already accounts for ASLR.
   * Called single-threaded at init (before runtime_ready), so it cannot race the
   * hot-path readers. */
  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0; i < count; i++) {
    const struct mach_header *mh = _dyld_get_image_header(i);
    if (mh == NULL || mh->filetype != MH_EXECUTE) continue;
    unsigned long size = 0;
    uint8_t *p = getsegmentdata((const struct mach_header_64 *)mh, "__TEXT",
                                &size);
    if (p != NULL && size > 0) {
      repro_main_text_start = (const void *)p;
      repro_main_text_end = (const void *)(p + size);
    }
    return;
  }
}

/* Return 1 iff `retaddr` lies in the monitored program's main-executable __TEXT
 * range (⇒ the program's OWN entropy use ⇒ flag). 0 otherwise (libsystem baseline,
 * a toolchain dylib, or an unknown/unset range ⇒ do NOT flag — conservative
 * against the cardinal sin). Pure compare; no dyld, no lock, no allocation. */
int repro_macos_addr_in_program(void *retaddr) {
  if (retaddr == NULL || repro_main_text_start == NULL) return 0;
  return (retaddr >= repro_main_text_start && retaddr < repro_main_text_end)
    ? 1 : 0;
}

/* ROUND-3 S3b — NON-SYSTEM IMAGE __TEXT registry for the entropy CALLER
 * ATTRIBUTION.
 *
 * The round-2 R-D attribution (repro_macos_addr_in_program above) flagged an
 * entropy call ONLY when its caller lay in the MAIN EXECUTABLE's __TEXT. That left
 * a confirmed hole (round-3 research/.../r3_residual/res1_dylib_entropy): a
 * NON-SYSTEM dylib the program loads — a compiler pass-plugin, a toolchain dylib,
 * whether a LINK-TIME dependency or a DLOPEN'd image (librnd.c via tool_dlopen.c) —
 * that itself calls arc4random/getentropy and bakes the result into the build
 * output was NOT flagged, so its non-determinism was invisible ⇒ a FALSE CACHE HIT.
 *
 * The fix attributes entropy to ANY NON-SYSTEM image: the main executable OR any
 * non-system dylib/bundle the program loaded — exactly the set the library-load
 * filter (repro_macos_dyld_image_dep_path) already classifies (NOT /usr/lib, NOT
 * /System, NOT the dyld shared cache, NOT our injected shim). The
 * libsystem/libobjc/libswift/libcorecrypto STARTUP BASELINE stays EXCLUDED — the
 * CARDINAL-SIN guard R-D established: every program's (and every cc/clang compile's)
 * startup entropy from those shared-cache/usr-lib images must NOT flag, or every
 * build re-runs.
 *
 * HOT-PATH SAFETY (the design constraint the milestone calls out): arc4random is
 * HOT, and dladdr on the entropy path is BOTH a per-call cost AND a documented
 * dyld-loader-lock re-entry hazard (these hooks can fire under the loader lock
 * during image init). So we do NOT dladdr per call. Instead each non-system image's
 * slid __TEXT [start,end) range is PRE-REGISTERED ONCE, from the dyld add-image
 * callback (repro_hook_dyld_add_image), which already classifies the image. The
 * entropy hot path is then a pure pointer-range scan over a handful of ranges (a
 * real clang link loads ~24 non-system dylibs) — no dladdr, no dyld, no lock, no
 * allocation, re-entry-safe at any lifecycle point. The add-image callback fires for
 * the program's full dependency closure at registration AND for every later dlopen,
 * so a plugin's range is registered before it runs (res1 dlopen: plugin_emit is
 * called from main(), long after the dlopen callback registered librnd's range).
 *
 * CONCURRENCY: the WRITER (register, from add-image) is serialized by dyld's loader
 * lock, so the read-modify-write of the count needs no CAS. A RELEASE store of the
 * count publishes the slot writes before the bump; the READER (entropy hot path)
 * does an ACQUIRE load, so a concurrent entropy call on another thread sees only
 * fully-written ranges. The cap is a FAIL-SAFE: an overflow simply drops a range ⇒
 * at worst a FALSE NEGATIVE (a missed downgrade), never a crash and never the
 * cardinal-sin false positive. */
#define REPRO_NONSYS_RANGE_CAP 8192
static const void *repro_nonsys_text_start[REPRO_NONSYS_RANGE_CAP];
static const void *repro_nonsys_text_end[REPRO_NONSYS_RANGE_CAP];
static volatile uint32_t repro_nonsys_range_count = 0;

/* ROUND-3 S3b — LINK-TIME vs DLOPEN discrimination for the entropy range set.
 *
 * The add-image callback fires SYNCHRONOUSLY for every image ALREADY loaded when
 * `_dyld_register_func_for_add_image` is called (the program's full LINK-TIME
 * dependency closure — dyld maps all static dependencies before our constructor),
 * and AGAIN for every later `dlopen`. The constructor sets this flag to 1 the
 * instant the register call returns, so a callback fired DURING the initial burst
 * (flag == 0) is a link-time dependency and a callback fired afterwards (flag == 1)
 * is a dlopen'd image.
 *
 * WHY this gates the entropy range set (but NOT recordLibraryLoad): on a real
 * toolchain the program's LINK-TIME runtime dylibs draw BENIGN entropy — a Nix/
 * Homebrew clang's libLLVM/libc++ call arc4random for a random TEMP-FILE NAME and
 * for hash-seed randomization, neither of which reaches the build OUTPUT (the same
 * benign pattern the /dev/urandom-for-mktemp cardinal-sin guard already exempts).
 * Those dylibs are NON-SYSTEM (they live in /nix/store, not /usr/lib or the shared
 * cache), so attributing their entropy would FALSE-DOWNGRADE every cc/clang compile
 * (the cardinal sin — observed: a real `cc -c` draws libLLVM temp-name entropy). A
 * DLOPEN'd image, by contrast, is an EXPLICITLY-loaded extension — a compiler
 * pass-plugin, the res1_dylib_entropy plugin — far more likely to bake entropy into
 * output, and NOT part of the trusted, pinned toolchain runtime. So we attribute
 * entropy to the MAIN EXECUTABLE (always) and to DLOPEN'd images, but NOT to
 * link-time dependency dylibs. recordLibraryLoad still records ALL non-system images
 * as content deps (break #4 unchanged); only the ENTROPY attribution is gated.
 *
 * DOCUMENTED RESIDUAL: a non-system dylib LINKED (not dlopen'd) into a build tool
 * that draws output-affecting entropy (res1's link-time `tool` variant) is NOT
 * flagged — it is structurally indistinguishable from the trusted toolchain runtime
 * (libLLVM/libc++), so the cardinal-sin guard wins. The structural endgame is the
 * EndpointSecurity backend (kernel-side accounting). */
static volatile int repro_addimage_burst_done = 0;

void repro_macos_mark_addimage_burst_done(void) {
  __atomic_store_n(&repro_addimage_burst_done, 1, __ATOMIC_RELEASE);
}

int repro_macos_addimage_burst_done(void) {
  return __atomic_load_n(&repro_addimage_burst_done, __ATOMIC_ACQUIRE);
}

void repro_macos_register_nonsystem_image(void *mh_raw) {
  if (mh_raw == NULL) return;
  const struct mach_header *mh = (const struct mach_header *)mh_raw;
  /* getsegmentdata returns the actual (slid) mapped __TEXT address + size, so the
   * range already accounts for ASLR — exactly as repro_macos_capture_main_image
   * does for the main executable. Lock-free memory walk: safe in the add-image
   * callback (no dyld re-entry). */
  unsigned long size = 0;
  uint8_t *p = getsegmentdata((const struct mach_header_64 *)mh, "__TEXT", &size);
  if (p == NULL || size == 0) return;
  uint32_t n = __atomic_load_n(&repro_nonsys_range_count, __ATOMIC_RELAXED);
  if (n >= REPRO_NONSYS_RANGE_CAP) return; /* cap ⇒ false negative, never a crash */
  repro_nonsys_text_start[n] = (const void *)p;
  repro_nonsys_text_end[n] = (const void *)(p + size);
  __atomic_store_n(&repro_nonsys_range_count, n + 1, __ATOMIC_RELEASE);
}

/* Return 1 iff `retaddr` lies in a NON-SYSTEM image's __TEXT — the main executable
 * (round-2 R-D range) OR any registered non-system dylib/bundle (round-3 S3b) ⇒ the
 * program's (or its plugin's) OWN entropy use ⇒ flag. 0 otherwise (the
 * libsystem/libobjc/libswift baseline, or an unknown caller ⇒ do NOT flag — the
 * cardinal-sin guard). Pure pointer-range scan; no dyld, no lock, no allocation. */
int repro_macos_addr_in_nonsystem(void *retaddr) {
  if (retaddr == NULL) return 0;
  if (repro_main_text_start != NULL &&
      retaddr >= repro_main_text_start && retaddr < repro_main_text_end)
    return 1;
  uint32_t n = __atomic_load_n(&repro_nonsys_range_count, __ATOMIC_ACQUIRE);
  for (uint32_t i = 0; i < n; i++) {
    if (retaddr >= repro_nonsys_text_start[i] &&
        retaddr < repro_nonsys_text_end[i])
      return 1;
  }
  return 0;
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
 * Mach-service-name classification MOVED TO NIM (ROUND-3 S0). The round-2 blunt
 * `com.apple.*` name-prefix exemption that used to live here was trivially
 * bypassable: any unsigned process can `bootstrap_register` an arbitrary UNUSED
 * `com.apple.<custom>` name and serve a monitored client a delegated file read
 * with no downgrade. The decision now lives in `machServiceRecordable` /
 * `isDeclaredAppleService` in shim/macos_interpose.nim, which exempts a
 * `com.apple.*` name ONLY when it is declared in the SIP-protected launchd plists
 * (an attacker-unforgeable allowlist). That code needs the shim's mute/lock
 * machinery to scan the plists without self-recording, so it belongs in the Nim
 * shim module rather than this header-only runtime helper.
 *
 * It does, however, need to READ the SIP-protected launchd plists without
 * tripping the shim's own hooks.
 *
 * It is implemented with PURE RAW SYSCALLS — `SYS_open(O_DIRECTORY)` +
 * `SYS_getdirentries64` for enumeration, `SYS_open`/`SYS_read`/`SYS_close` for the
 * files — and NO libsystem opendir/readdir at all. This is deliberate: under the
 * shim, BOTH `dlsym("readdir")` and the shim-skipping image walk resolve to a
 * `readdir` whose record layout is OFF BY ONE relative to the C `struct dirent`
 * (observed: every d_name comes back missing its first byte — "om.apple.…" for
 * "com.apple.…", "sh.plist" for "ssh.plist") because the interpose `__interpose`
 * tuple and the shim's wrapper forwarding perturb the resolution. The raw
 * `SYS_getdirentries64` kernel record format is fixed and self-describing
 * (d_ino,8 · d_seekoff,8 · d_reclen,2 · d_namlen,2 · d_type,1 · d_name[d_namlen]),
 * so we parse it directly and the first-byte corruption cannot occur (verified:
 * d_name="com.apple.srp-mdns-proxy.plist", "ssh.plist"). Raw syscalls also never
 * fire a file-I/O hook, so the scan records nothing.
 *
 * It concatenates every non-directory entry's bytes — with a NUL separator after
 * each so a service name cannot straddle two files — into the caller's buffer,
 * bounded by `cap`, starting at `pos`, and returns the new write position.
 * Unreadable entries are silently skipped (at worst a name is treated as
 * undeclared ⇒ a conservative re-run).
 */
size_t repro_macos_concat_sip_plists(char *dir, void *out_raw, size_t cap,
                                     size_t pos) {
  char *out = (char *)out_raw;
  if (!dir || !out || pos >= cap) return pos;
  /* The fixed SYS_getdirentries64 record layout (Darwin `struct dirent`, packed
   * here so d_name follows d_type with no implicit tail padding). */
  struct repro_dirent64 {
    uint64_t d_ino;
    uint64_t d_seekoff;
    uint16_t d_reclen;
    uint16_t d_namlen;
    uint8_t  d_type;
    char     d_name[];
  } __attribute__((packed));
  int dfd = (int)syscall(SYS_open, dir, O_RDONLY | O_DIRECTORY, 0);
  if (dfd < 0) return pos;
  size_t dirlen = strlen(dir);
  char dbuf[16384];
  long basep = 0;
  for (;;) {
    int n = (int)syscall(SYS_getdirentries64, dfd, dbuf, sizeof(dbuf), &basep);
    if (n <= 0) break;                       /* 0 = end, <0 = error */
    int off = 0;
    while (off + (int)sizeof(struct repro_dirent64) <= n) {
      struct repro_dirent64 *e = (struct repro_dirent64 *)(dbuf + off);
      if (e->d_reclen == 0) break;           /* defensive: avoid an infinite loop */
      /* Skip subdirectories and "." / ".."; accept regular files, symlinks, and
       * unknown-typed entries (a filesystem that does not populate d_type). */
      if (e->d_type != DT_DIR) {
        const char *nm = e->d_name;
        size_t nlen = e->d_namlen;
        int isDot = (nlen == 1 && nm[0] == '.') ||
                    (nlen == 2 && nm[0] == '.' && nm[1] == '.');
        char path[1100];
        if (!isDot && dirlen + 1 + nlen + 1 <= sizeof(path)) {
          memcpy(path, dir, dirlen);
          path[dirlen] = '/';
          memcpy(path + dirlen + 1, nm, nlen);
          path[dirlen + 1 + nlen] = '\0';
          int fd = (int)syscall(SYS_open, path, O_RDONLY, 0);
          if (fd >= 0) {
            for (;;) {
              if (pos >= cap) break;
              ssize_t r = (ssize_t)syscall(SYS_read, fd, out + pos, cap - pos);
              if (r <= 0) break;
              pos += (size_t)r;
            }
            syscall(SYS_close, fd);
            if (pos < cap) out[pos++] = '\0';  /* per-file NUL separator */
          }
        }
      }
      off += e->d_reclen;
    }
  }
  syscall(SYS_close, dfd);
  return pos;
}

/* ===================================================================== *
 * ROUND-2 R-D (break R10) — NON-FILE DETERMINISM INPUT forwarders.
 *
 * These reach the GENUINE libsystem entry for the env / sysctl / uname /
 * entropy / time functions the shim now interposes, so the recording hook can
 * forward the real call WITHOUT re-entering its own __interpose wrapper. All are
 * INTERPOSE-ONLY (not body-patched), which is DELIBERATE: it means the hooks see
 * ONLY the monitored program's OWN direct calls (an import-stub crossing), never
 * a libsystem-INTERNAL one (a direct intra-dylib call) — so benign internal
 * randomness (malloc cookies, stack-guard, mktemp, DNS query ids) and internal
 * env/clock reads are NOT misattributed to the program. The genuine entry is
 * resolved via dlsym(RTLD_NEXT, name): RTLD_NEXT searches images loaded AFTER the
 * shim, skipping the shim's own wrapper and reaching libsystem. Each resolver is
 * cached. Signatures use generic pointer / int / size types (matching Nim's
 * emitted importc prototypes) so no struct headers are needed here (the caller
 * passes the real struct pointers through as void pointers). A resolution failure
 * returns a benign error (ENOSYS / 0), never the shim's own wrapper.
 * ===================================================================== */

/* getenv: walk `environ` directly (exactly what libc getenv does): allocation-
 * and resolution-free, and inherently re-entry-free (never crosses an import
 * stub). Reuses the existing environ-scan helper. Returns the value or NULL. The
 * non-const `char *name` matches Nim's emitted importc prototype. */
char *repro_macos_real_getenv(char *name) {
  if (!name) return NULL;
  return (char *)repro_macos_env_value(environ, name);
}

/* Resolve a symbol to its GENUINE libsystem entry via the shim-skipping image walk
 * (`repro_macos_lookup_image_symbol`, the SAME resolver copyfile/bootstrap use),
 * with a per-function RECURSION GUARD.
 *
 * Why NOT dlsym(RTLD_NEXT): the __DATA,__interpose tuple makes dyld rebind the
 * symbol GLOBALLY, so dlsym(RTLD_NEXT, "uname") resolves to OUR OWN
 * `repro_wrap_uname` wrapper rather than the genuine libsystem uname — calling the
 * resolved pointer then re-enters the hook forever (observed: an infinite
 * repro_hook_uname ↔ ct_macos_real_uname recursion → Nim stack-overflow). The image
 * walk (NSLookupSymbolInImage on each non-shim image) returns the ACTUAL libsystem
 * symbol address, not the interpose binding, so it never loops. The `symbol` arg is
 * the MANGLED "_name" form.
 *
 * The thread-local `resolving` flag additionally breaks any re-entry DURING the
 * one-time walk (should the resolver internally touch the function being resolved):
 * the nested call takes the `fail` fallback once, then `fn` is cached and every
 * later call forwards normally. */
#define REPRO_RD_RESOLVE_GUARD(fnptr, type, symbol, fail) \
  do { \
    if (!(fnptr)) { \
      static __thread int repro_rd_resolving = 0; \
      if (repro_rd_resolving) { fail; } \
      repro_rd_resolving = 1; \
      (fnptr) = (type)repro_macos_lookup_image_symbol(symbol); \
      repro_rd_resolving = 0; \
    } \
  } while (0)

/* sysctlbyname / sysctl / gethostuuid / getentropy / gettimeofday forward via the
 * RAW SYSCALL, NOT dlsym. This is ESSENTIAL: sysctlbyname is called CROSS-DYLIB by
 * libdispatch (querying hw.ncpu/hw.activecpu for its thread pool) DURING libSystem
 * init — which runs BEFORE our shim constructor, with `repro_monitor_runtime_ready`
 * still 0, so the not-ready forward is exercised THEN. A dlsym there is unsafe
 * (libdispatch is mid-init; observed SIGSEGV). The raw syscall is allocation- and
 * dlsym-free and re-entry-free — exactly how the open/read/stat not-ready thunks
 * already forward. The SYS_sysctlbyname trap takes the name's strlen as `namelen`. */
int repro_macos_real_sysctlbyname_call(char *name, void *oldp,
    size_t *oldlenp, void *newp, size_t newlen) {
  return (int)syscall(SYS_sysctlbyname, name, name ? strlen(name) : (size_t)0,
                      oldp, oldlenp, newp, newlen);
}

int repro_macos_real_sysctl_call(int *name, unsigned int namelen, void *oldp,
    size_t *oldlenp, void *newp, size_t newlen) {
  return (int)syscall(SYS_sysctl, name, namelen, oldp, oldlenp, newp, newlen);
}

/* uname has NO direct syscall on Darwin (it is implemented via sysctl); it is not
 * called during early libdispatch init, so the guarded dlsym is safe here. */
int repro_macos_real_uname_call(void *buf) {
  static int (*fn)(void *) = NULL;
  REPRO_RD_RESOLVE_GUARD(fn, int (*)(void *), "_uname",
    { errno = ENOSYS; return -1; });
  if (!fn) { errno = ENOSYS; return -1; }
  return fn(buf);
}

/* gethostname has no direct syscall (implemented via sysctl KERN_HOSTNAME); not an
 * early-init function, so the guarded dlsym is safe. */
int repro_macos_real_gethostname_call(char *name, size_t namelen) {
  static int (*fn)(char *, size_t) = NULL;
  REPRO_RD_RESOLVE_GUARD(fn, int (*)(char *, size_t), "_gethostname",
    { errno = ENOSYS; return -1; });
  if (!fn) { errno = ENOSYS; return -1; }
  return fn(name, namelen);
}

int repro_macos_real_gethostuuid_call(void *uuid, void *timeout) {
  return (int)syscall(SYS_gethostuuid, uuid, timeout);
}

/* Build a stable identity string ("mib:6.5") for the integer-MIB sysctl(2) form,
 * whose name is an array of `namelen` ints rather than a string. The MIB integers
 * uniquely identify the queried system parameter, so the consumer folds the value
 * behind this key into its cache key. Returns the byte length written (excluding
 * NUL). Bounded by `outlen`. */
int repro_macos_sysctl_mib_describe(int *name, unsigned int namelen,
                                    void *out_raw, size_t outlen) {
  char *out = (char *)out_raw;
  if (!out || outlen < 5) return 0;
  size_t pos = 0;
  const char *prefix = "mib:";
  for (const char *p = prefix; *p && pos + 1 < outlen; p++) out[pos++] = *p;
  for (unsigned int i = 0; name && i < namelen && pos + 1 < outlen; i++) {
    if (i > 0 && pos + 1 < outlen) out[pos++] = '.';
    char num[16];
    int n = snprintf(num, sizeof num, "%d", name[i]);
    for (int j = 0; j < n && pos + 1 < outlen; j++) out[pos++] = num[j];
  }
  out[pos] = '\0';
  return (int)pos;
}

/* getentropy forwards via the raw SYS_getentropy syscall (dlsym-free; the kernel
 * entropy source). arc4random / stack-guard underlie this but call it intra-dylib. */
int repro_macos_real_getentropy_call(void *buf, size_t len) {
  return (int)syscall(SYS_getentropy, buf, len);
}

/* arc4random / arc4random_buf / arc4random_uniform forward via the raw
 * SYS_getentropy syscall (the same kernel CSPRNG source arc4random itself draws
 * from), NOT dlsym. arc4random is called CROSS-DYLIB at process teardown by
 * libSystem; a dlsym (or its thread-local resolution guard) at that late teardown
 * point ABORTS (observed SIGABRT — TLS/dyld are being torn down). The raw syscall
 * is dlsym-free, TLS-free and re-entry-free, so it is safe at any lifecycle point.
 * getentropy caps at 256 bytes per call, so arc4random_buf loops. */
unsigned int repro_macos_real_arc4random_call(void) {
  unsigned int v = 0u;
  (void)syscall(SYS_getentropy, &v, sizeof v);
  return v;
}

void repro_macos_real_arc4random_buf_call(void *buf, size_t n) {
  unsigned char *p = (unsigned char *)buf;
  while (n > 0) {
    size_t chunk = n > 256 ? 256 : n;
    if (syscall(SYS_getentropy, p, chunk) != 0) break;  /* best-effort */
    p += chunk;
    n -= chunk;
  }
}

unsigned int repro_macos_real_arc4random_uniform_call(unsigned int upper) {
  if (upper < 2u) return 0u;
  /* Rejection sampling — matches arc4random_uniform's unbiased semantics. */
  unsigned int min = (0u - upper) % upper;  /* == 2^32 mod upper */
  unsigned int v = 0u;
  do {
    if (syscall(SYS_getentropy, &v, sizeof v) != 0) { v = 0u; break; }
  } while (v < min);
  return v % upper;
}

int repro_macos_real_clock_gettime_call(int clk, void *ts) {
  static int (*fn)(int, void *) = NULL;
  REPRO_RD_RESOLVE_GUARD(fn, int (*)(int, void *), "_clock_gettime",
    { errno = ENOSYS; return -1; });
  if (!fn) { errno = ENOSYS; return -1; }
  return fn(clk, ts);
}

/* gettimeofday forwards via the genuine libc gettimeofday (image-walk resolved,
 * like clock_gettime/time) — NOT the raw SYS_gettimeofday syscall. The raw syscall
 * is UNSAFE on macOS arm64: the kernel's gettimeofday trap returns the seconds in
 * the result register (a commpage-fast-path ABI the libc stub unpacks), so a bare
 * `syscall(SYS_gettimeofday, …)` mis-signals (returns -1/EINVAL) and corrupts the
 * caller's stack frame (observed: a plain gettimeofday loop SIGSEGVs the caller —
 * e.g. bash's seedrand32). The genuine libc entry handles the commpage ABI. */
int repro_macos_real_gettimeofday_call(void *tp, void *tzp) {
  static int (*fn)(void *, void *) = NULL;
  REPRO_RD_RESOLVE_GUARD(fn, int (*)(void *, void *), "_gettimeofday",
    { errno = ENOSYS; return -1; });
  if (!fn) { errno = ENOSYS; return -1; }
  return fn(tp, tzp);
}

long long repro_macos_real_time_call(void *tloc) {
  static long long (*fn)(void *) = NULL;
  REPRO_RD_RESOLVE_GUARD(fn, long long (*)(void *), "_time", { return -1; });
  if (!fn) return -1;
  return fn(tloc);
}

/* NOTE on mach_absolute_time: it is DELIBERATELY NOT interposed. libdispatch calls
 * it CROSS-DYLIB during early libSystem init (before our constructor), so a
 * not-ready forward would be exercised then; it has no raw syscall (it is a
 * commpage / CNTVCT read), so a safe early-init forward is impractical, and
 * interposing it destabilises libdispatch. It is also a MONOTONIC TICK COUNTER, not
 * a wall clock — a relative interval value almost never baked into a build's output
 * as a determinism input — so the gettimeofday / time / clock_gettime wall-clock
 * signals cover the surface that matters. This is a documented residual (R-D). */

#undef REPRO_RD_RESOLVE_GUARD
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

proc ct_macos_real_dup*(fd: cint): cint =
  ## ROUND-3 S2d — raw `SYS_dup` forwarder for the fd-duplication hook.
  proc realDup(fd: cint): cint
    {.importc: "repro_macos_real_dup_syscall", cdecl.}
  realDup(fd)

proc ct_macos_real_dup2*(oldfd, newfd: cint): cint =
  ## ROUND-3 S2d — raw `SYS_dup2` forwarder for the fd-duplication hook.
  proc realDup2(oldfd, newfd: cint): cint
    {.importc: "repro_macos_real_dup2_syscall", cdecl.}
  realDup2(oldfd, newfd)

proc ct_macos_real_fcntl*(fd, cmd: cint; arg: pointer): cint =
  ## ROUND-3 S2d — raw `SYS_fcntl` forwarder. Faithful for EVERY command (the
  ## kernel reads only the bits the command defines), so the fcntl hook can
  ## duplicate on F_DUPFD/F_DUPFD_CLOEXEC and pass every other command through.
  proc realFcntl(fd, cmd: cint; arg: pointer): cint
    {.importc: "repro_macos_real_fcntl_syscall", cdecl.}
  realFcntl(fd, cmd, arg)

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

proc ct_macos_socket_describe*(fd: cint; address: pointer; addrLen: uint32;
    outDest: pointer; outDestLen: csize_t; outPeerPid: ptr cint): cint =
  ## Describe a connect() target (T3a): returns the address family and fills
  ## `outDest` with the AF_UNIX path or "ip:port"; writes the AF_UNIX peer pid
  ## (LOCAL_PEERPID) through `outPeerPid` (0 when unobtainable). See the C doc.
  proc describe(fd: cint; address: pointer; addrLen: uint32; outDest: pointer;
      outDestLen: csize_t; outPeerPid: ptr cint): cint
    {.importc: "repro_macos_socket_describe", cdecl.}
  describe(fd, address, addrLen, outDest, outDestLen, outPeerPid)

proc ct_macos_concat_sip_plists*(dir: cstring; outBuf: pointer; cap: csize_t;
    pos: csize_t): csize_t =
  ## ROUND-3 S0 — concatenate the raw bytes of every regular file in the
  ## SIP-protected launchd plist directory `dir` into `outBuf` (bounded by `cap`),
  ## starting at `pos`; returns the new write position. Reentrancy-safe: the C
  ## helper enumerates and reads via PURE RAW SYSCALLS (SYS_open(O_DIRECTORY) +
  ## SYS_getdirentries64 for the dir, SYS_open/read/close for the files) — no
  ## libsystem opendir/readdir at all — so it never re-enters the shim's hooks and
  ## never records its own I/O. See the C helper for why the read cannot go through
  ## libsystem/Nim's std/posix readdir (an off-by-one in the shimmed record layout).
  proc impl(dir: cstring; outBuf: pointer; cap: csize_t; pos: csize_t): csize_t
    {.importc: "repro_macos_concat_sip_plists", cdecl.}
  impl(dir, outBuf, cap, pos)

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

type
  FdKind* = enum
    ## ROUND-3 S1 — the underlying-object class of an open fd, returned by
    ## `ct_macos_fd_dev_ino_kind`. Mirrors the REPRO_FD_KIND_* C codes 1:1.
    fkOther = 0, fkRegular = 1, fkFifo = 2, fkSocket = 3,
    fkCharDevice = 4, fkBlockDevice = 5, fkDirectory = 6

proc ct_macos_fd_dev_ino_kind*(fd: cint; outDev, outIno: ptr uint64;
    outKind: ptr FdKind): bool =
  ## ROUND-3 S1 — (st_dev, st_ino, file-type) for an open fd in ONE raw fstat
  ## (reentrancy-free). Superset of ct_macos_fd_dev_ino; lets the open hot path
  ## stamp inode identity AND detect a FIFO without a second stat, and lets the
  ## empty-path read hook tell a real file from a socket/pipe. True on success.
  proc impl(fd: cint; outDev, outIno: ptr uint64; outKind: ptr cint): cint
    {.importc: "repro_macos_fd_dev_ino_kind", cdecl.}
  var k: cint
  result = impl(fd, outDev, outIno, addr k) != 0
  if result and outKind != nil:
    outKind[] = FdKind(k)

proc ct_macos_real_getxattr*(path, name: cstring; value: pointer; size: csize_t;
    position: uint32; options: cint): int =
  proc impl(path, name: cstring; value: pointer; size: csize_t; position: uint32;
      options: cint): clong
    {.importc: "repro_macos_real_getxattr_syscall", cdecl.}
  int(impl(path, name, value, size, position, options))

proc ct_macos_real_fgetxattr*(fd: cint; name: cstring; value: pointer;
    size: csize_t; position: uint32; options: cint): int =
  proc impl(fd: cint; name: cstring; value: pointer; size: csize_t;
      position: uint32; options: cint): clong
    {.importc: "repro_macos_real_fgetxattr_syscall", cdecl.}
  int(impl(fd, name, value, size, position, options))

proc ct_macos_real_listxattr*(path: cstring; namebuf: pointer; size: csize_t;
    options: cint): int =
  proc impl(path: cstring; namebuf: pointer; size: csize_t; options: cint): clong
    {.importc: "repro_macos_real_listxattr_syscall", cdecl.}
  int(impl(path, namebuf, size, options))

proc ct_macos_real_flistxattr*(fd: cint; namebuf: pointer; size: csize_t;
    options: cint): int =
  proc impl(fd: cint; namebuf: pointer; size: csize_t; options: cint): clong
    {.importc: "repro_macos_real_flistxattr_syscall", cdecl.}
  int(impl(fd, namebuf, size, options))

proc ct_macos_real_setxattr*(path, name: cstring; value: pointer; size: csize_t;
    position: uint32; options: cint): cint =
  proc impl(path, name: cstring; value: pointer; size: csize_t; position: uint32;
      options: cint): cint {.importc: "repro_macos_real_setxattr_syscall", cdecl.}
  impl(path, name, value, size, position, options)

proc ct_macos_real_fsetxattr*(fd: cint; name: cstring; value: pointer;
    size: csize_t; position: uint32; options: cint): cint =
  proc impl(fd: cint; name: cstring; value: pointer; size: csize_t;
      position: uint32; options: cint): cint
    {.importc: "repro_macos_real_fsetxattr_syscall", cdecl.}
  impl(fd, name, value, size, position, options)

proc ct_macos_real_removexattr*(path, name: cstring; options: cint): cint =
  proc impl(path, name: cstring; options: cint): cint
    {.importc: "repro_macos_real_removexattr_syscall", cdecl.}
  impl(path, name, options)

proc ct_macos_real_fremovexattr*(fd: cint; name: cstring; options: cint): cint =
  proc impl(fd: cint; name: cstring; options: cint): cint
    {.importc: "repro_macos_real_fremovexattr_syscall", cdecl.}
  impl(fd, name, options)

proc ct_macos_real_shm_open*(name: cstring; oflag, mode: cint): cint =
  proc impl(name: cstring; oflag, mode: cint): cint
    {.importc: "repro_macos_real_shm_open_syscall", cdecl.}
  impl(name, oflag, mode)

proc ct_macos_real_sendfile*(fd, s: cint; offset: int64; len: ptr int64;
    hdtr: pointer; flags: cint): cint =
  proc impl(fd, s: cint; offset: int64; len: ptr int64; hdtr: pointer;
      flags: cint): cint {.importc: "repro_macos_real_sendfile_syscall", cdecl.}
  impl(fd, s, offset, len, hdtr, flags)

proc ct_macos_real_pread*(fd: cint; buf: pointer; n: csize_t; offset: int64): int =
  proc impl(fd: cint; buf: pointer; n: csize_t; offset: int64): clong
    {.importc: "repro_macos_real_pread_syscall", cdecl.}
  int(impl(fd, buf, n, offset))

proc ct_macos_real_preadv*(fd: cint; iov: pointer; iovcnt: cint;
    offset: int64): int =
  proc impl(fd: cint; iov: pointer; iovcnt: cint; offset: int64): clong
    {.importc: "repro_macos_real_preadv_syscall", cdecl.}
  int(impl(fd, iov, iovcnt, offset))

proc ct_macos_real_readv*(fd: cint; iov: pointer; iovcnt: cint): int =
  proc impl(fd: cint; iov: pointer; iovcnt: cint): clong
    {.importc: "repro_macos_real_readv_syscall", cdecl.}
  int(impl(fd, iov, iovcnt))

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

# --- ROUND-2 R-D (break R10) non-file-determinism genuine-entry forwarders ----
# Each forwards a hooked env/sysctl/uname/entropy/time call to the GENUINE
# libsystem entry (resolved via dlsym(RTLD_NEXT), shim-skipping) so the recording
# hook never re-enters its own __interpose wrapper. See the C section.

proc ct_macos_real_getenv*(name: cstring): cstring =
  ## Genuine getenv (environ walk; allocation- and re-entry-free).
  proc impl(name: cstring): cstring {.importc: "repro_macos_real_getenv", cdecl.}
  impl(name)

proc ct_macos_real_sysctlbyname*(name: cstring; oldp: pointer;
    oldlenp: ptr csize_t; newp: pointer; newlen: csize_t): cint =
  proc impl(name: cstring; oldp: pointer; oldlenp: ptr csize_t; newp: pointer;
      newlen: csize_t): cint
    {.importc: "repro_macos_real_sysctlbyname_call", cdecl.}
  impl(name, oldp, oldlenp, newp, newlen)

proc ct_macos_real_sysctl*(name: ptr cint; namelen: cuint; oldp: pointer;
    oldlenp: ptr csize_t; newp: pointer; newlen: csize_t): cint =
  proc impl(name: ptr cint; namelen: cuint; oldp: pointer; oldlenp: ptr csize_t;
      newp: pointer; newlen: csize_t): cint
    {.importc: "repro_macos_real_sysctl_call", cdecl.}
  impl(name, namelen, oldp, oldlenp, newp, newlen)

proc ct_macos_real_uname*(buf: pointer): cint =
  proc impl(buf: pointer): cint {.importc: "repro_macos_real_uname_call", cdecl.}
  impl(buf)

proc ct_macos_real_gethostname*(name: cstring; namelen: csize_t): cint =
  proc impl(name: cstring; namelen: csize_t): cint
    {.importc: "repro_macos_real_gethostname_call", cdecl.}
  impl(name, namelen)

proc ct_macos_real_gethostuuid*(uuid: pointer; timeout: pointer): cint =
  proc impl(uuid: pointer; timeout: pointer): cint
    {.importc: "repro_macos_real_gethostuuid_call", cdecl.}
  impl(uuid, timeout)

proc ct_macos_sysctl_mib_describe*(name: ptr cint; namelen: cuint;
    outBuf: pointer; outLen: csize_t): cint =
  ## Build a stable "mib:6.5" identity for the integer-MIB sysctl(2) form.
  proc impl(name: ptr cint; namelen: cuint; outBuf: pointer; outLen: csize_t): cint
    {.importc: "repro_macos_sysctl_mib_describe", cdecl.}
  impl(name, namelen, outBuf, outLen)

proc ct_macos_capture_main_image*() =
  ## ROUND-2 R-D — capture the main executable's __TEXT range ONCE at init for the
  ## entropy caller-attribution (see ct_macos_addr_in_program). Single-threaded at
  ## shim init, before runtime_ready.
  proc impl() {.importc: "repro_macos_capture_main_image", cdecl.}
  impl()

proc ct_macos_addr_in_program*(caller: pointer): bool =
  ## ROUND-2 R-D — CALLER ATTRIBUTION for entropy observations. True iff
  ## `caller` (the return address captured at an entropy hook) is in the monitored
  ## program's OWN main-executable __TEXT — the program's direct entropy use (to
  ## flag). False for the benign libsystem/libobjc/libswift baseline or an unknown
  ## caller (do NOT flag — conservative against the cardinal sin). A pure pointer
  ## compare: safe under dyld's loader lock where dladdr would crash. See the C note.
  ##
  ## ROUND-3 S3b — superseded on the entropy path by `ct_macos_addr_in_nonsystem`
  ## (which also attributes a NON-SYSTEM dylib/plugin's entropy). Kept for any
  ## main-exe-only caller that wants the narrower test.
  proc impl(caller: pointer): cint
    {.importc: "repro_macos_addr_in_program", cdecl.}
  impl(caller) != 0

proc ct_macos_register_nonsystem_image*(mh: pointer) =
  ## ROUND-3 S3b — register a non-system image's slid __TEXT range so the entropy
  ## hooks attribute that image's OWN arc4random/getentropy as non-determinism.
  ## Called from the dyld add-image hook when the image is a recordable non-system
  ## dylib/bundle (the SAME classification the library-load filter uses). Deadlock-
  ## safe inside the add-image callback: a pure getsegmentdata memory walk, no dyld
  ## re-entry, no allocation.
  proc impl(mh: pointer)
    {.importc: "repro_macos_register_nonsystem_image", cdecl.}
  impl(mh)

proc ct_macos_mark_addimage_burst_done*() =
  ## ROUND-3 S3b — mark dyld's initial add-image burst (the link-time dependency
  ## closure) complete, so subsequent add-image callbacks are dlopen'd images. The
  ## constructor calls this the instant `_dyld_register_func_for_add_image` returns.
  proc impl() {.importc: "repro_macos_mark_addimage_burst_done", cdecl.}
  impl()

proc ct_macos_addimage_burst_done*(): bool =
  ## ROUND-3 S3b — true once the initial (link-time) add-image burst has finished,
  ## i.e. the current add-image callback is for a DLOPEN'd image. Used to gate the
  ## entropy range set to dlopen'd images (the toolchain's link-time runtime dylibs
  ## draw benign entropy and must NOT be attributed — the cardinal-sin guard).
  proc impl(): cint {.importc: "repro_macos_addimage_burst_done", cdecl.}
  impl() != 0

proc ct_macos_addr_in_nonsystem*(caller: pointer): bool =
  ## ROUND-3 S3b — CALLER ATTRIBUTION for entropy observations, widened from
  ## the round-2 main-exe-only test to ANY NON-SYSTEM image. True iff `caller` lies
  ## in the main executable's __TEXT OR any registered non-system dylib/bundle's
  ## __TEXT (a compiler pass-plugin, a toolchain dylib, a dlopen'd image) ⇒ the
  ## program's (or its plugin's) OWN entropy use ⇒ flag. False for the
  ## libsystem/libobjc/libswift/libcorecrypto startup baseline or an unknown caller
  ## (do NOT flag — the cardinal-sin guard). A pure pointer-range scan over a handful
  ## of registered ranges: no dladdr, no dyld, no lock, no allocation — safe under
  ## dyld's loader lock and cheap on the hot arc4random path. See the C note.
  proc impl(caller: pointer): cint
    {.importc: "repro_macos_addr_in_nonsystem", cdecl.}
  impl(caller) != 0

proc ct_macos_real_getentropy*(buf: pointer; len: csize_t): cint =
  proc impl(buf: pointer; len: csize_t): cint
    {.importc: "repro_macos_real_getentropy_call", cdecl.}
  impl(buf, len)

proc ct_macos_real_arc4random*(): cuint =
  proc impl(): cuint {.importc: "repro_macos_real_arc4random_call", cdecl.}
  impl()

proc ct_macos_real_arc4random_buf*(buf: pointer; n: csize_t) =
  proc impl(buf: pointer; n: csize_t)
    {.importc: "repro_macos_real_arc4random_buf_call", cdecl.}
  impl(buf, n)

proc ct_macos_real_arc4random_uniform*(upper: cuint): cuint =
  proc impl(upper: cuint): cuint
    {.importc: "repro_macos_real_arc4random_uniform_call", cdecl.}
  impl(upper)

proc ct_macos_real_clock_gettime*(clk: cint; ts: pointer): cint =
  proc impl(clk: cint; ts: pointer): cint
    {.importc: "repro_macos_real_clock_gettime_call", cdecl.}
  impl(clk, ts)

proc ct_macos_real_gettimeofday*(tp: pointer; tzp: pointer): cint =
  proc impl(tp: pointer; tzp: pointer): cint
    {.importc: "repro_macos_real_gettimeofday_call", cdecl.}
  impl(tp, tzp)

proc ct_macos_real_time*(tloc: pointer): clonglong =
  proc impl(tloc: pointer): clonglong
    {.importc: "repro_macos_real_time_call", cdecl.}
  impl(tloc)
# NOTE: mach_absolute_time is intentionally NOT hooked — see the C forwarder note
# (libdispatch early-init hazard + it is a monotonic counter, not a wall clock).
