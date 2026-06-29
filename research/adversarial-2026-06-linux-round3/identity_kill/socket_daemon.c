#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int read_marker(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    perror("daemon open marker");
    return -1;
  }
  char buf[64];
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  return n < 0 ? -1 : 0;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s socket-path marker\n", argv[0]);
    return 2;
  }
  signal(SIGPIPE, SIG_IGN);
  unlink(argv[1]);
  int srv = socket(AF_UNIX, SOCK_STREAM, 0);
  if (srv < 0) {
    perror("socket");
    return 1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", argv[1]);
  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("bind");
    return 1;
  }
  if (listen(srv, 1) != 0) {
    perror("listen");
    return 1;
  }
  printf("ready\n");
  fflush(stdout);
  int c = accept(srv, NULL, NULL);
  if (c < 0) {
    perror("accept");
    return 1;
  }
  char cmd;
  if (read(c, &cmd, 1) != 1) {
    perror("read cmd");
    return 1;
  }
  int ok = read_marker(argv[2]) == 0;
  char reply = ok ? 'Y' : 'N';
  write(c, &reply, 1);
  close(c);
  close(srv);
  return ok ? 0 : 1;
}
