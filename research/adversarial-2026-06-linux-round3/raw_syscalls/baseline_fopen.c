#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s MARKER\n", argv[0]);
    return 2;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }

  char buf[4096];
  size_t n;
  unsigned long long sum = 0;
  while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
    for (size_t i = 0; i < n; i++) sum += (unsigned char)buf[i];
  }
  if (ferror(f)) {
    perror("fread");
    fclose(f);
    return 1;
  }
  fclose(f);
  printf("baseline_fopen sum=%llu\n", sum);
  return 0;
}
