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
#include <mach-o/nlist.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

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

int repro_macos_path_is_dir(char *path) {
  struct stat st;
#ifdef SYS_stat64
  if (syscall(SYS_stat64, path, &st) != 0) return 0;
#else
  if (syscall(SYS_stat, path, &st) != 0) return 0;
#endif
  return S_ISDIR(st.st_mode) ? 1 : 0;
}

static int repro_macos_env_has(char **envp, const char *name) {
  if (!envp) envp = environ;
  size_t name_len = strlen(name);
  for (char **env = envp; env && *env; env++) {
    if (strncmp(*env, name, name_len) == 0 && (*env)[name_len] == '=') {
      return 1;
    }
  }
  return 0;
}

static char **repro_macos_env_with_preload(char **envp) {
  const char *shim = getenv("REPRO_MONITOR_SHIM_LIB");
  char *sandbox_dir = repro_macos_get_sandbox_tools_dir();
  int need_dyld = shim && shim[0] != '\0' &&
    !repro_macos_env_has(envp, "DYLD_INSERT_LIBRARIES");
  int need_sandbox = sandbox_dir && sandbox_dir[0] != '\0' &&
    !repro_macos_env_has(envp, "CT_SANDBOX_TOOLS_DIR");
  if (!need_dyld && !need_sandbox) return envp;

  char **source = envp ? envp : environ;
  size_t count = 0;
  while (source && source[count]) count++;

  size_t extras = (need_dyld ? 1u : 0u) + (need_sandbox ? 1u : 0u);
  char **result = (char **)calloc(count + extras + 1, sizeof(char *));
  if (!result) return envp;
  for (size_t i = 0; i < count; i++) result[i] = source[i];

  size_t slot = count;
  if (need_dyld) {
    const char *prefix = "DYLD_INSERT_LIBRARIES=";
    size_t value_len = strlen(prefix) + strlen(shim) + 1;
    char *value = (char *)malloc(value_len);
    if (!value) { free(result); return envp; }
    snprintf(value, value_len, "%s%s", prefix, shim);
    result[slot++] = value;
  }
  if (need_sandbox) {
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
