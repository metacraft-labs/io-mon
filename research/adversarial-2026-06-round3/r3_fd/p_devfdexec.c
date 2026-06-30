#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
extern char **environ;
int main(){
  int fd=open("/tmp/r3_fd/tgt",O_RDONLY); if(fd<0)return 1;
  char p[64]; snprintf(p,sizeof p,"/dev/fd/%d",fd);
  char *argv[]={"tgt",0};
  execve(p,argv,environ);  // execute binary via its fd path
  return 99;
}
