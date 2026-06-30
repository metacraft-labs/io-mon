#include <fcntl.h>
#include <unistd.h>
int main(){ char b[64];
  int fd=open("/tmp/r3_fd/marker_dup.txt",O_RDONLY); if(fd<0)return 1;
  int fd2=dup(fd);                 // dup'd fd
  read(fd2,b,sizeof b);            // read via DUP'd fd
  close(fd2); close(fd); return 0; }
