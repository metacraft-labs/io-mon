#include <sys/syscall.h>
#include <fcntl.h>
#include "probe_common.h"
int main(int argc,char**argv){
  long fd=syscall(SYS_open,argv[1],O_RDONLY,0);
  if(fd<0){fprintf(stderr,"open err %ld\n",fd);return 1;}
  char buf[128]; long n=syscall(SYS_read,fd,buf,sizeof buf);
  if(n>0) syscall(SYS_write,1,buf,n);
  syscall(SYS_close,fd);
  return 0;
}
