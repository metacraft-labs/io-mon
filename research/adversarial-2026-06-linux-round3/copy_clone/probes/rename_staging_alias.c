#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <src> <stage> <final>\n", argv[0]);
    return 2;
  }

  if (linkat(AT_FDCWD, argv[1], AT_FDCWD, argv[2], 0) != 0) {
    perror("linkat stage");
    return 1;
  }
  if (rename(argv[2], argv[3]) != 0) {
    perror("rename final");
    return 1;
  }
  return 0;
}
