// BREAK probe: open existing file O_RDWR (no O_CREAT/O_TRUNC), change content via
// ftruncate() only (shrink => destroys tail bytes). The open is classified INPUT;
// ftruncate is not hooked => output mutation invisible. This is the ld64-style
// "open O_RDWR, ftruncate to final size" pattern (minus the mmap-write region).
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  int c = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  const char *data = "FULL-CONTENT-AAAAAAAAAAAAAAAAAAAAAAAA\n";
  if (write(c, data, strlen(data)) < 0) return 2;
  close(c);

  int fd = open(path, O_RDWR);     // pure O_RDWR -> INPUT
  if (fd < 0) { perror("open"); return 1; }
  if (ftruncate(fd, 5) != 0) { perror("ftruncate"); return 1; } // NOT hooked
  close(fd);
  fprintf(stderr, "ftruncate %s to 5 bytes\n", path);
  return 0;
}
