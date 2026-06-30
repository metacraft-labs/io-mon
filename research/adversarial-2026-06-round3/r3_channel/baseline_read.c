// Baseline: open + read(2). Establishes what a NORMAL content read looks like in
// the depfile (expect both moFileOpen and moFileRead on the marker path).
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "/tmp/r3_channel/markerBase.txt";
  int fd = open(path, O_RDONLY);
  if (fd < 0) { perror("open"); return 1; }
  char buf[256];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  if (n > 0) { buf[n] = 0; fprintf(stderr, "[baseline] read %zd bytes\n", n); }
  close(fd);
  return 0;
}
