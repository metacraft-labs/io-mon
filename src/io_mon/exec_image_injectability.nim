## Consumer-side access to the exec-target classifier (Linux).
##
## `exec_image_injectability.h` is the one definition of "an image the shim
## cannot enter" (other ELF class/machine, static, static-pie, or a `#!`
## script whose interpreter is one of those); read its header comment for
## the rules and their residual. The shim includes the same file into its
## runtime and reads files with raw system calls; this module includes it
## into the consumer and reads with plain libc, which is right here: the
## consumer is an ordinary process, and when it itself runs under an outer
## monitor those reads are ordinary, recordable file reads.

when not defined(linux):
  {.error: "io_mon/exec_image_injectability is Linux-only".}

import std/[os, strutils]

import ./exec_image_header

{.emit: execImageIncludeDirective.}

{.emit: """
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/* libc file access for the classifier: -errno on failure, errno kept. */
static long iomon_exec_libc_openat(int dirfd, const char *path, int flags) {
  int saved = errno;
  int fd = openat(dirfd, path, flags);
  long rc = fd >= 0 ? fd : -(long)errno;
  errno = saved;
  return rc;
}
static long iomon_exec_libc_pread(int fd, void *buf, unsigned long len,
                                  long offset) {
  int saved = errno;
  ssize_t n;
  do { n = pread(fd, buf, (size_t)len, (off_t)offset); }
  while (n < 0 && errno == EINTR);
  long rc = n >= 0 ? (long)n : -(long)errno;
  errno = saved;
  return rc;
}
static long iomon_exec_libc_is_regular(int fd) {
  int saved = errno;
  struct stat st;
  long rc = fstat(fd, &st) == 0 ? (S_ISREG(st.st_mode) ? 1 : 0)
                                : -(long)errno;
  errno = saved;
  return rc;
}
static long iomon_exec_libc_access_x(int dirfd, const char *path) {
  int saved = errno;
  long rc = faccessat(dirfd, path, X_OK, 0) == 0 ? 0 : -(long)errno;
  errno = saved;
  return rc;
}
static void iomon_exec_libc_close(int fd) {
  int saved = errno;
  close(fd);
  errno = saved;
}
static const iomon_exec_io iomon_exec_libc_io = {
  iomon_exec_libc_openat, iomon_exec_libc_pread, iomon_exec_libc_is_regular,
  iomon_exec_libc_access_x, iomon_exec_libc_close
};

static int iomon_exec_libc_classify(const char *path, char *detail,
                                    size_t cap) {
  return iomon_exec_image_classify(&iomon_exec_libc_io, AT_FDCWD, path, 0,
                                   NULL, detail, cap);
}
""".}

proc cClassify(path: cstring; detail: cstring; cap: csize_t): cint
  {.importc: "iomon_exec_libc_classify", nodecl, raises: [].}

const detailCap = 4096 + 512
  ## A full path plus the reason and a `#!` script's path.

proc uninjectableImageDetail*(path: string): string {.raises: [].} =
  ## "" when the shim can enter what `execve(path)` would run; otherwise
  ## "<reason> image=<image>[ script=<#! file>]", naming the image the loader
  ## will not inject and why. `path` is used as the kernel would, relative to
  ## this process's working directory when it is not absolute.
  if path.len == 0:
    return ""
  var buf = newString(detailCap)
  if cClassify(cstring(path), cstring(buf), csize_t(buf.len)) == 0:
    return ""
  result = $cstring(buf)

proc resolveSpawnTarget*(command, cwd: string): string {.raises: [].} =
  ## The file `osproc.startProcess(command, workingDir = cwd,
  ## options = {poUsePath})` executes on Linux: the child chdirs to `cwd`
  ## and then runs `findExe(command)` on the parent's PATH (it is a fork of
  ## the parent), so a path with a slash, and every relative PATH entry, is
  ## taken relative to `cwd`. "" when nothing would be found (the spawn
  ## fails, and there is nothing to classify).
  if command.len == 0:
    return ""
  proc anchored(p: string): string =
    if p.isAbsolute or cwd.len == 0: p else: cwd / p
  if '/' in command:
    let candidate = anchored(command)
    return (if fileExists(candidate): candidate else: "")
  for entry in getEnv("PATH").split(PathSep):
    if entry.len == 0:
      continue
    let candidate = anchored(expandTilde(entry) / command)
    if fileExists(candidate):
      return candidate
  ""
