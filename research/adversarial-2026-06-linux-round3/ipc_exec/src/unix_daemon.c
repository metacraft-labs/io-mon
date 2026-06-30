#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int serve_path(int c, const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    dprintf(c, "ERR %s\n", strerror(errno));
    return 1;
  }
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof buf)) > 0) {
    if (write(c, buf, n) < 0) {
      break;
    }
  }
  close(fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: unix_daemon <sockpath> <ready-file>\n");
    return 2;
  }
  unlink(argv[1]);
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) {
    perror("socket");
    return 1;
  }
  struct sockaddr_un a;
  memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  strncpy(a.sun_path, argv[1], sizeof(a.sun_path) - 1);
  if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
    perror("bind");
    return 1;
  }
  if (listen(s, 32) < 0) {
    perror("listen");
    return 1;
  }
  FILE *r = fopen(argv[2], "w");
  if (r) {
    fprintf(r, "%d\n", getpid());
    fclose(r);
  }
  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c < 0) {
      continue;
    }
    char path[4096];
    int pos = 0;
    char ch = 0;
    while (pos < (int)sizeof(path) - 1 && read(c, &ch, 1) == 1) {
      if (ch == '\n') {
        break;
      }
      path[pos++] = ch;
    }
    path[pos] = 0;
    if (strcmp(path, "__QUIT__") == 0) {
      close(c);
      break;
    }
    serve_path(c, path);
    close(c);
  }
  close(s);
  unlink(argv[1]);
  return 0;
}
