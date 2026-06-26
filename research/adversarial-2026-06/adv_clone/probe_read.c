// Baseline: normal fopen+read of a source — SHOULD be captured by io-mon.
#include <stdio.h>
int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 1; }
  char buf[256]; size_t n = fread(buf, 1, sizeof buf, f);
  fwrite(buf, 1, n, stdout);
  fclose(f);
  return 0;
}
