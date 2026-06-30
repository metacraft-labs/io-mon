#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s MARKER\n", argv[0]);
    return 2;
  }

  int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("open");
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
  printf("baseline_open_read sum=%llu\n", sum);
  return 0;
}
