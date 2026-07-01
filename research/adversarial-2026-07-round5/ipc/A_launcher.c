// Launcher runs OUTSIDE io-mon. Creates a socketpair, forks an out-of-tree peer
// that reads the marker and writes its CONTENT over the socket. Then execs
// `io-mon run -- A_client <fd>` so the monitored client inherits an already
// connected socket. No connect()/socketpair() happens inside the injected tree.
#include "peer_common.h"
int main(int argc, char**argv){
  const char* marker = argv[1];
  const char* iomon = argv[2];
  const char* depfile = argv[3];
  const char* client = argv[4];
  int sv[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
  pid_t pid = fork();
  if(pid==0){
    close(sv[0]);
    // out-of-tree peer: read the real marker content
    int fd = open(marker, O_RDONLY);
    char buf[256]; ssize_t n = read(fd, buf, sizeof buf);
    write(sv[1], buf, n>0?n:0);
    close(sv[1]); _exit(0);
  }
  close(sv[1]);
  // pass sv[0] to the monitored client via a fixed fd number env
  char fdbuf[16]; snprintf(fdbuf, sizeof fdbuf, "%d", sv[0]);
  setenv("INHERITED_FD", fdbuf, 1);
  execl(iomon, iomon, "run", "--depfile", depfile, "--", client, (char*)NULL);
  perror("execl"); return 1;
}
