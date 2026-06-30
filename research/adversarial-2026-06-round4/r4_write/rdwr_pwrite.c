// BREAK probe: open existing file O_RDWR (no O_CREAT/O_TRUNC), mutate content via
// pwrite() only. io-mon classifies a pure O_RDWR open as INPUT (moFileOpen) and
// only marks the path WRITTEN if it sees write(2) or a MAP_SHARED PROT_WRITE mmap.
// pwrite is NOT hooked -> the produced output is recorded as a pure INPUT.
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  // Represent a pre-existing / preallocated output file (prior build state).
  int c = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  // write a placeholder so the file exists with stale content
  const char *stale = "STALE-PLACEHOLDER-0000000000\n";
  // Use write() here only to establish the file out of the measured mutation;
  // but to keep the mutation pure, we close and reopen O_RDWR below.
  if (write(c, stale, strlen(stale)) < 0) return 2;
  close(c);

  // The actual OUTPUT-PRODUCING step: open O_RDWR, overwrite content via pwrite.
  int fd = open(path, O_RDWR);            // pure O_RDWR -> classified INPUT
  if (fd < 0) { perror("open"); return 1; }
  const char *real = "REAL-OUTPUT-CONTENT-deadbeef\n";
  ssize_t n = pwrite(fd, real, strlen(real), 0);   // NOT hooked
  if (n < 0) { perror("pwrite"); return 1; }
  close(fd);
  fprintf(stderr, "pwrite wrote %zd bytes to %s\n", n, path);
  return 0;
}
