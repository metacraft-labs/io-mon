#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <src> <out>\n", argv[0]);
    return 2;
  }

  int in = open(argv[1], O_RDONLY);
  if (in < 0) {
    perror("open src");
    return 1;
  }
  int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) {
    perror("open out");
    return 1;
  }

  ssize_t n = copy_file_range(in, NULL, out, NULL, 1 << 20, 0);
  if (n < 0) {
    fprintf(stderr, "copy_file_range: %s\n", strerror(errno));
    return 1;
  }
  return n > 0 ? 0 : 3;
}
