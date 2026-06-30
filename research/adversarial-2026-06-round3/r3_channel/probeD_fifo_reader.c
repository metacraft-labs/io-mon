// Probe D consumer (MONITORED). Opens a FIFO and read(2)s the marker content an
// OUT-OF-TREE feeder pumps in. The open + read ARE captured -- but on the FIFO
// path, not on the real source file the feeder cat'd in. The content's true
// origin (an out-of-tree process) is unattributed and no incompleteness fires.
// Build: /usr/bin/clang -o probeD_fifo_reader probeD_fifo_reader.c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
  const char *fifo = argc > 1 ? argv[1] : "/tmp/r3_channel/fifoD";
  int fd = open(fifo, O_RDONLY);          // captured: open on the FIFO path
  if (fd < 0) { perror("open fifo"); return 1; }
  char buf[256]; ssize_t total = 0, n;
  while ((n = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0) {
    total += n;
    if (total >= (ssize_t)sizeof(buf) - 1) break;
  }
  buf[total] = 0;
  fprintf(stderr, "[fifo-reader] read %zd bytes via FIFO: %.60s\n", total, buf);
  close(fd);
  return 0;
}
