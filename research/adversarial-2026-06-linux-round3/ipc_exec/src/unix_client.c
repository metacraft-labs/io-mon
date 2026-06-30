#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: unix_client <sockpath> <marker>\n");
    return 2;
  }
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) {
    perror("socket");
    return 1;
  }
  struct sockaddr_un a;
  memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  strncpy(a.sun_path, argv[1], sizeof(a.sun_path) - 1);
  if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
    perror("connect");
    return 1;
  }
  dprintf(s, "%s\n", argv[2]);
  char buf[4096];
  uint64_t h = 5381;
  size_t total = 0;
  ssize_t n;
  while ((n = read(s, buf, sizeof buf)) > 0) {
    for (ssize_t i = 0; i < n; i++) {
      h = ((h << 5) + h) + (unsigned char)buf[i];
    }
    total += (size_t)n;
  }
  close(s);
  printf("unix-client bytes=%zu hash=%llu path=%s\n",
         total, (unsigned long long)h, argv[2]);
  return 0;
}
