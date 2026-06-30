// CLEAN BREAK: the file ALREADY EXISTS (prior action / checked-in artifact / a DB
// file). The measured build step opens it O_RDWR and mutates content via pwrite ONLY
// -- no write(2), no mmap. io-mon classifies the O_RDWR open as INPUT (moFileOpen)
// and never sees a write => the mutated OUTPUT is recorded as a pure INPUT, with
// ZERO write records. This is the SQLite/LMDB in-place pwrite update pattern.
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  int fd = open(path, O_RDWR);          // pure O_RDWR -> INPUT classification
  if (fd < 0) { perror("open"); return 1; }
  const char *real = "MUTATED-BY-PWRITE-cafef00d\n";
  ssize_t n = pwrite(fd, real, strlen(real), 0);  // NOT hooked
  if (n < 0) { perror("pwrite"); return 1; }
  close(fd);
  fprintf(stderr, "pwrite mutated %s by %zd bytes\n", path, n);
  return 0;
}
