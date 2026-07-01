#include "peer_common.h"
int main(void){ int fd=atoi(getenv("INHERITED_FD"));
  char b[256]; ssize_t n=read(fd,b,sizeof b); if(n>0){write(1,"R: ",3);write(1,b,n);} return 0; }
