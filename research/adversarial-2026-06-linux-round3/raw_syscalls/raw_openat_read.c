#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s MARKER\n", argv[0]);
    return 2;
  }

  int fd = (int)syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("syscall(SYS_openat)");
    return 1;
  }

  char buf[4096];
  unsigned long long sum = 0;
  for (;;) {
    ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof buf);
    if (n == 0) break;
    if (n < 0) {
      perror("syscall(SYS_read)");
      syscall(SYS_close, fd);
      return 1;
    }
    for (ssize_t i = 0; i < n; i++) sum += (unsigned char)buf[i];
  }
  syscall(SYS_close, fd);
  printf("raw_openat_read sum=%llu\n", sum);
  return 0;
}
