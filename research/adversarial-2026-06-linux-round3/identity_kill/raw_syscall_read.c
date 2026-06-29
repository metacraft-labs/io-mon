#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s marker\n", argv[0]);
    return 2;
  }
  long fd = syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY, 0);
  if (fd < 0) {
    perror("syscall openat");
    return 1;
  }
  char buf[64];
  long n = syscall(SYS_read, (int)fd, buf, sizeof(buf));
  if (n < 0) {
    perror("syscall read");
    return 1;
  }
  syscall(SYS_close, (int)fd);
  return 0;
}
