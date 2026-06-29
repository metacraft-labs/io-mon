#include <fcntl.h>
#include <stdio.h>
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

  char buf[4096];
  ssize_t n = read(in, buf, sizeof(buf));
  if (n < 0) {
    perror("read");
    return 1;
  }
  if (write(out, buf, (size_t)n) != n) {
    perror("write");
    return 1;
  }
  return 0;
}
