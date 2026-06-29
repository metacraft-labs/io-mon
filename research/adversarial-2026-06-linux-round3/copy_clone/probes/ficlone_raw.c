#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int xopenat(const char *path, int flags, mode_t mode) {
  return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <src> <out>\n", argv[0]);
    return 2;
  }

  int in = xopenat(argv[1], O_RDONLY, 0);
  if (in < 0) {
    perror("raw open src");
    return 1;
  }
  int out = xopenat(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) {
    perror("raw open out");
    return 1;
  }
  if (ioctl(out, FICLONE, in) != 0) {
    fprintf(stderr, "FICLONE: %s\n", strerror(errno));
    return 1;
  }
  return 0;
}
