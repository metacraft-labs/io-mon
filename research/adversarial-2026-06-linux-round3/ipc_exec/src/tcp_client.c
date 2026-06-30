#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: tcp_client <port> <marker>\n");
    return 2;
  }
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    perror("socket");
    return 1;
  }
  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons((uint16_t)atoi(argv[1]));
  if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
    perror("connect");
    return 1;
  }
  dprintf(s, "%s\n", argv[2]);
  char buf[4096];
  uint64_t h = 2166136261U;
  size_t total = 0;
  ssize_t n;
  while ((n = read(s, buf, sizeof buf)) > 0) {
    for (ssize_t i = 0; i < n; i++) {
      h ^= (unsigned char)buf[i];
      h *= 16777619U;
    }
    total += (size_t)n;
  }
  close(s);
  printf("tcp-client bytes=%zu hash=%llu path=%s\n",
         total, (unsigned long long)h, argv[2]);
  return 0;
}
