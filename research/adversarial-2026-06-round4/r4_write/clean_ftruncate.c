// CLEAN BREAK: pre-existing file, mutate via ftruncate ONLY (shrink destroys tail).
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  int fd = open(path, O_RDWR);          // INPUT
  if (fd < 0) { perror("open"); return 1; }
  if (ftruncate(fd, 4) != 0) { perror("ftruncate"); return 1; } // NOT hooked
  close(fd);
  fprintf(stderr, "ftruncate mutated %s to 4 bytes\n", path);
  return 0;
}
