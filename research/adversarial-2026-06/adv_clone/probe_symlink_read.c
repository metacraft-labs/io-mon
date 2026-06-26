// Read a config via a symlink: open() sees the LINK path, but the real
// dependency is the TARGET. Does io-mon record the target path?
#include <stdio.h>
int main(int argc, char **argv) {
  // argv[1] is a symlink pointing at the real source.
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 1; }
  char buf[256]; size_t n = fread(buf, 1, sizeof buf, f);
  fwrite(buf, 1, n, stdout);
  fclose(f);
  return 0;
}
