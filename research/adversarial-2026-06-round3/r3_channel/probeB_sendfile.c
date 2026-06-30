// Probe B: sendfile(2) zero-copy. A monitored, IN-TREE sender opens a source file
// O_RDONLY (captured as moFileOpen) then sendfile()s its bytes straight to a
// socket. The kernel reads the source's content WITHOUT any read(2) the shim sees.
// Question: is the source recorded as a CONTENT read, or only as an open?
//
// macOS sendfile: int sendfile(int fd, int s, off_t offset, off_t *len,
//                              struct sf_hdtr *hdtr, int flags);
// Build: /usr/bin/clang -o probeB_sendfile probeB_sendfile.c
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *path = argc > 1 ? argv[1] : "/tmp/r3_channel/markerB.txt";

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }

  int fd = open(path, O_RDONLY);   // CAPTURED open -> moFileOpen on the SOURCE
  if (fd < 0) { perror("open"); return 1; }

  off_t len = 0;  // 0 == send to EOF
  // Zero-copy: source content goes to the socket with NO read(2).
  if (sendfile(fd, sv[0], 0, &len, NULL, 0) < 0) { perror("sendfile"); return 1; }
  fprintf(stderr, "[probeB] sendfile moved %lld bytes from source (no read syscall)\n",
          (long long)len);

  // Drain the socket so the bytes are really consumed.
  char buf[256];
  ssize_t n = recv(sv[1], buf, sizeof(buf) - 1, 0);
  if (n > 0) { buf[n] = 0; fprintf(stderr, "[probeB] receiver got: %.40s\n", buf); }

  close(fd); close(sv[0]); close(sv[1]);
  return 0;
}
