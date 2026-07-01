// Monitored client: reads marker CONTENT off an inherited, already-connected
// socket. It never opens marker.txt. If io-mon reports mcComplete, marker.txt
// (a real dependency) is absent from the depfile => BREAK.
#include "peer_common.h"
int main(void){
  const char* fds = getenv("INHERITED_FD");
  if(!fds){fprintf(stderr,"no fd\n");return 1;}
  int fd = atoi(fds);
  char buf[256]; ssize_t n = read(fd, buf, sizeof buf);
  if(n>0){ write(1, "CLIENT-GOT: ", 12); write(1, buf, n); }
  return 0;
}
