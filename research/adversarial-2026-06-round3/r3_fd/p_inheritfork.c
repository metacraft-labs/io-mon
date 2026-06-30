#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
int main(){ char b[64];
  int fd=open("/tmp/r3_fd/marker_inherit.txt",O_RDONLY); if(fd<0)return 1;
  pid_t p=fork();
  if(p==0){ read(fd,b,sizeof b); _exit(0); }   // child reads inherited fd, no open
  int st; waitpid(p,&st,0); close(fd); return 0; }
