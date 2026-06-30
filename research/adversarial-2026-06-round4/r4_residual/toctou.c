/* Within ONE monitored process: probe+read link/f (link->dirA), repoint
   link->dirB, probe+read link/f again. Tests realpath-memo staleness. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
static void do_read(const char*p){int fd=open(p,O_RDONLY);char b[64];ssize_t n=read(fd,b,sizeof b-1);if(n>0){b[n]=0;fprintf(stderr,"  read %s -> %s",p,b);}close(fd);}
int main(int argc,char**argv){
  const char*link=argv[1];
  struct stat st;
  unlink(link); symlink("/tmp/r4_residual/dirA",link);
  stat(link,&st); do_read("/tmp/r4_residual/lnk/f");   /* via link spelled lnk */
  /* repoint */
  unlink(link); symlink("/tmp/r4_residual/dirB",link);
  stat(link,&st); do_read("/tmp/r4_residual/lnk/f");
  return 0;
}
