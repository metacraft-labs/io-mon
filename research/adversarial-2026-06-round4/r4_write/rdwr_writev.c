// BREAK probe: O_RDWR open, mutate via writev() (vectored write). writev not hooked.
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
  const char *path = argv[1];
  int c = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  const char *stale = "STALE-PLACEHOLDER\n";
  if (write(c, stale, strlen(stale)) < 0) return 2;
  close(c);

  int fd = open(path, O_RDWR);
  if (fd < 0) { perror("open"); return 1; }
  char *a = "REAL-VEC-PART-A-"; char *b = "deadbeef\n";
  struct iovec iov[2] = {{a, strlen(a)}, {b, strlen(b)}};
  ssize_t n = writev(fd, iov, 2);   // NOT hooked
  if (n < 0) { perror("writev"); return 1; }
  close(fd);
  fprintf(stderr, "writev wrote %zd bytes to %s\n", n, path);
  return 0;
}
