#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s socket-path\n", argv[0]);
    return 2;
  }
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", argv[1]);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("connect");
    return 1;
  }
  char cmd = 'R';
  if (write(fd, &cmd, 1) != 1) {
    perror("write");
    return 1;
  }
  char buf[64];
  ssize_t n = read(fd, buf, sizeof(buf));
  if (n <= 0) {
    perror("read reply");
    return 1;
  }
  close(fd);
  return 0;
}
