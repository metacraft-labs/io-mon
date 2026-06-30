// Probe E consumer (MONITORED). Reads content from fd 0 (stdin) / an inherited fd
// that was opened by an OUT-OF-TREE process (the shell redirect / a /dev/fd
// reference). No open(2) happens in THIS process for the backing file, so the
// read hook's fd->path map is empty -> the content is recorded with NO source
// path (or the opaque /dev/fd/N).
// Build: /usr/bin/clang -o probeE_stdin_reader probeE_stdin_reader.c
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  // Mode 1 (default): read inherited fd 0.
  // Mode 2 (argv[1]=="devfd"): open "/dev/fd/0" and read that.
  int fd = 0;
  if (argc > 1 && strcmp(argv[1], "devfd") == 0) {
    fd = open("/dev/fd/0", O_RDONLY);     // names "/dev/fd/0", not the backing file
    if (fd < 0) { perror("open /dev/fd/0"); return 1; }
  }
  char buf[256];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  if (n > 0) { buf[n] = 0; fprintf(stderr, "[stdin-reader] read %zd bytes: %.60s\n", n, buf); }
  return 0;
}
