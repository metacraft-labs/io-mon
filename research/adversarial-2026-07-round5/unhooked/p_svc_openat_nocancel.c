#include <sys/syscall.h>
#include <fcntl.h>
#include "probe_common.h"
int main(int argc,char**argv){
  long fd=raw6(SYS_openat,AT_FDCWD,(long)argv[1],O_RDONLY,0,0,0);
  if(fd<0){return 1;}
  char buf[128]; long n=raw6(SYS_read_nocancel,fd,(long)buf,sizeof buf,0,0,0);
  if(n>0) raw6(SYS_write,1,(long)buf,n,0,0,0);
  raw6(SYS_close,fd,0,0,0,0,0);
  return 0;
}
