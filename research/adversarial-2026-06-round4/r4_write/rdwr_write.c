// CONTRAST probe (the CAUGHT baseline): identical to rdwr_pwrite.c but the
// mutation uses write(2), which IS hooked (repro_hook_write -> moFileWrite).
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  int c = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  const char *stale = "STALE-PLACEHOLDER-0000000000\n";
  if (write(c, stale, strlen(stale)) < 0) return 2;
  close(c);

  int fd = open(path, O_RDWR);            // pure O_RDWR -> classified INPUT...
  if (fd < 0) { perror("open"); return 1; }
  const char *real = "REAL-OUTPUT-CONTENT-deadbeef\n";
  ssize_t n = write(fd, real, strlen(real));   // ...but write(2) IS hooked
  if (n < 0) { perror("write"); return 1; }
  close(fd);
  fprintf(stderr, "write wrote %zd bytes to %s\n", n, path);
  return 0;
}
