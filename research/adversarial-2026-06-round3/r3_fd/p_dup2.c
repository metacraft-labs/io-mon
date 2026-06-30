#include <fcntl.h>
#include <unistd.h>
int main(){ char b[64];
  int fd=open("/tmp/r3_fd/marker_dup2.txt",O_RDONLY); if(fd<0)return 1;
  dup2(fd,7);                      // duplicate onto fd 7
  read(7,b,sizeof b);
  close(7); close(fd); return 0; }
