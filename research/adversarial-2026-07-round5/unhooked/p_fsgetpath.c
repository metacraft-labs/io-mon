#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include "probe_common.h"
int main(int argc,char**argv){
  struct statfs sfs; if(statfs(argv[1],&sfs)){perror("statfs");return 1;}
  struct stat st; if(stat(argv[1],&st)){perror("stat");return 1;}
  char path[1024];
  uint64_t objid=st.st_ino;
  long r=syscall(SYS_fsgetpath,path,sizeof path,&sfs.f_fsid,objid);
  if(r<0){perror("fsgetpath");return 2;}
  fprintf(stderr,"fsgetpath resolved: %s\n",path);
  long fd=raw6(SYS_open,(long)path,O_RDONLY,0,0,0,0);
  if(fd<0)return 3;
  char buf[128]; long n=raw6(SYS_read,fd,(long)buf,sizeof buf,0,0,0);
  if(n>0) raw6(SYS_write,1,(long)buf,n,0,0,0);
  raw6(SYS_close,fd,0,0,0,0,0);
  return 0;
}
