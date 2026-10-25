#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

/* No wall-clock timeout: a spinning wrapper consumes CPU even on a busy host.
 * Cap only this tiny fixture after startup, never its compiler or monitor. */
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  void *symbol = dlsym(RTLD_DEFAULT, argv[1]);
  if (!symbol) return 3;
  int at = strstr(argv[1], "openat") != NULL;
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core) != 0) return 5;
  struct rlimit cpu = {2, 2};
  if (setrlimit(RLIMIT_CPU, &cpu) != 0) return 5;
  int dirfd = open(argv[2], O_RDONLY | O_DIRECTORY, 0);
  if (dirfd < 0) return 4;
  if (strcmp(argv[3], "invalid-create") == 0 ||
      strcmp(argv[3], "invalid-tmpfile") == 0) {
    int flags = O_WRONLY | (strcmp(argv[3], "invalid-create") == 0
                            ? O_CREAT : O_TMPFILE);
    if (at) ((int (*)(int, const char *, int))symbol)(dirfd, ".", flags);
    else ((int (*)(const char *, int))symbol)(argv[2], flags);
    return 15; /* Missing mode must abort, never create a file or return. */
  }
  for (int op = 0; op < 4; ++op) {
    const char *name = op == 0 ? "absent" : argv[3];
    char absolute[4096];
    if (snprintf(absolute, sizeof absolute, "%s/%s", argv[2], name) >= sizeof absolute)
      return 6;
    const char *path = at ? name : absolute;
    int flags = op < 2 ? O_RDONLY : op == 2 ? O_WRONLY : O_RDWR;
    errno = 0;
    int fd = at ? ((int (*)(int, const char *, int))symbol)(dirfd, path, flags)
                : ((int (*)(const char *, int))symbol)(path, flags);
    if (op == 0) {
      if (fd != -1 || errno != ENOENT) return 10;
      continue;
    }
    if (fd < 0) return 11;
    char byte;
    if (op != 2 && (read(fd, &byte, 1) != 1 || byte != 'x')) return 12;
    if (op != 1 && write(fd, "x", 1) != 1) return 13;
    if (close(fd) != 0) return 14;
  }
  return close(dirfd) != 0;
}
