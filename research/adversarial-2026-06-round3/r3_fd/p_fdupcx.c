#include <fcntl.h>
#include <unistd.h>
int main(){ char b[64];
  int fd=open("/tmp/r3_fd/marker_fdupcx.txt",O_RDONLY); if(fd<0)return 1;
  int fd2=fcntl(fd,F_DUPFD_CLOEXEC,30);
  read(fd2,b,sizeof b);
  close(fd2); close(fd); return 0; }
