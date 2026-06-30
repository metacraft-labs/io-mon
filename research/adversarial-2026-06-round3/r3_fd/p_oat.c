#include <fcntl.h>
#include <unistd.h>
int main(){ char b[64];
  int dfd=open("/tmp/r3_fd",O_RDONLY|O_DIRECTORY); if(dfd<0)return 1;
  int fd=openat(dfd,"marker_oat.txt",O_RDONLY); if(fd<0)return 2;
  read(fd,b,sizeof b);
  close(fd); close(dfd); return 0; }
