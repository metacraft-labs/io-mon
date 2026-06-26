// BASELINE: a normal fopen()+fread() of the marker file. This MUST be captured
// by io-mon (proves the harness works and any later "absent" result is a real
// evasion, not a broken harness).
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 1; }
  char buf[256];
  size_t n = fread(buf, 1, sizeof buf, f);
  fwrite(buf, 1, n, stdout);
  fclose(f);
  return 0;
}
