// Probe A: open O_RDONLY (captured) then consume content via pread/readv ONLY
// (no read(2)). Tests whether the open-vs-read classification is lost: the file
// appears as moFileOpen but NEVER as moFileRead (a content read).
//
// Build: /usr/bin/clang -o probeA_pread probeA_pread.c
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "/tmp/r3_channel/markerA.txt";
  int fd = open(path, O_RDONLY);   // CAPTURED open -> moFileOpen
  if (fd < 0) { perror("open"); return 1; }

  char buf[256];
  // pread: positioned read, NOT the hooked read(2)
  ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
  if (n < 0) { perror("pread"); return 1; }
  buf[n] = 0;
  fprintf(stderr, "[probeA] pread got %zd bytes: %.40s\n", n, buf);

  // readv: scatter read, also NOT the hooked read(2)
  char vbuf[256];
  struct iovec iov = { vbuf, sizeof(vbuf) - 1 };
  lseek(fd, 0, SEEK_SET);
  ssize_t m = readv(fd, &iov, 1);
  if (m > 0) { vbuf[m] = 0; fprintf(stderr, "[probeA] readv got %zd bytes\n", m); }

  close(fd);
  return 0;
}
