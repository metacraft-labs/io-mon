#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: baseline_reader <marker>\n");
    return 2;
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  unsigned char buf[4096];
  uint64_t h = 1469598103934665603ULL;
  size_t total = 0;
  for (;;) {
    ssize_t n = read(fd, buf, sizeof buf);
    if (n < 0) {
      perror("read");
      close(fd);
      return 1;
    }
    if (n == 0) {
      break;
    }
    for (size_t i = 0; i < n; i++) {
      h ^= buf[i];
      h *= 1099511628211ULL;
    }
    total += (size_t)n;
  }
  close(fd);
  printf("baseline bytes=%zu hash=%llu path=%s\n",
         total, (unsigned long long)h, argv[1]);
  return 0;
}
