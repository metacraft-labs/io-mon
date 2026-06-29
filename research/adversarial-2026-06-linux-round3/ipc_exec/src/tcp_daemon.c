#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void write_ready(const char *path, int port) {
  FILE *f = fopen(path, "w");
  if (f) {
    fprintf(f, "%d\n", port);
    fclose(f);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: tcp_daemon <ready-file>\n");
    return 2;
  }
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("socket");
    return 1;
  }
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
    perror("bind");
    return 1;
  }
  if (listen(s, 32) < 0) {
    perror("listen");
    return 1;
  }
  socklen_t alen = sizeof a;
  if (getsockname(s, (struct sockaddr *)&a, &alen) < 0) {
    perror("getsockname");
    return 1;
  }
  write_ready(argv[1], ntohs(a.sin_port));
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
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      dprintf(c, "ERR %s\n", strerror(errno));
      close(c);
      continue;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
      if (write(c, buf, n) < 0) {
        break;
      }
    }
    close(fd);
    close(c);
  }
  close(s);
  return 0;
}
