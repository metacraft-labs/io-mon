#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s marker\n", argv[0]);
    return 2;
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  char buf[64];
  ssize_t n = read(fd, buf, sizeof(buf));
  if (n < 0) {
    perror("read");
    return 1;
  }
  fsync(2);
  kill(getpid(), SIGKILL);
  return 99;
}
