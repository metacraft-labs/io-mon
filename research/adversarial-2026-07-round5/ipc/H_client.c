#include "peer_common.h"
#include <sys/uio.h>
int main(int argc,char**argv){
  int fd=atoi(getenv("INHERITED_FD"));
  const char* how=getenv("HOW"); char b[256]; ssize_t n=0;
  if(!strcmp(how,"pread")) n=pread(fd,b,sizeof b,0);
  else if(!strcmp(how,"readv")){ struct iovec v={.iov_base=b,.iov_len=sizeof b}; n=readv(fd,&v,1); }
  else if(!strcmp(how,"preadv")){ struct iovec v={.iov_base=b,.iov_len=sizeof b}; n=preadv(fd,&v,1,0); }
  if(n>0){ write(1,how,strlen(how)); write(1,": ",2); write(1,b,n); }
  return 0; }
