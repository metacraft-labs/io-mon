#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_statx
#if defined(__x86_64__)
#define SYS_statx 332
#elif defined(__aarch64__)
#define SYS_statx 291
#endif
#endif

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s MARKER\n", argv[0]);
    return 2;
  }
#ifndef SYS_statx
  fprintf(stderr, "SYS_statx is not known on this architecture\n");
  return 77;
#else
  struct statx stx;
  int rc = (int)syscall(SYS_statx, AT_FDCWD, argv[1],
                        AT_STATX_SYNC_AS_STAT, STATX_SIZE | STATX_MTIME, &stx);
  if (rc != 0) {
    if (errno == ENOSYS) {
      fprintf(stderr, "statx unavailable on this kernel\n");
      return 77;
    }
    perror("syscall(SYS_statx)");
    return 1;
  }
  printf("raw_statx size=%lld mtime=%lld.%u\n",
         (long long)stx.stx_size,
         (long long)stx.stx_mtime.tv_sec,
         stx.stx_mtime.tv_nsec);
  return 0;
#endif
}
