#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_openat2
#if defined(__x86_64__)
#define SYS_openat2 437
#elif defined(__aarch64__)
#define SYS_openat2 56
#endif
#endif

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s MARKER\n", argv[0]);
    return 2;
  }
#ifndef SYS_openat2
  fprintf(stderr, "SYS_openat2 is not known on this architecture\n");
  return 77;
#else
  struct open_how how;
  memset(&how, 0, sizeof how);
  how.flags = O_RDONLY | O_CLOEXEC;

  int fd = (int)syscall(SYS_openat2, AT_FDCWD, argv[1], &how, sizeof how);
  if (fd < 0) {
    if (errno == ENOSYS) {
      fprintf(stderr, "openat2 unavailable on this kernel\n");
      return 77;
    }
    perror("syscall(SYS_openat2)");
    return 1;
  }

  char buf[4096];
  unsigned long long sum = 0;
  for (;;) {
    ssize_t n = read(fd, buf, sizeof buf);
    if (n == 0) break;
    if (n < 0) {
      perror("read");
      close(fd);
      return 1;
    }
    for (ssize_t i = 0; i < n; i++) sum += (unsigned char)buf[i];
  }
  close(fd);
  printf("raw_openat2_read sum=%llu\n", sum);
  return 0;
#endif
}
