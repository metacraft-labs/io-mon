#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char**argv){
  int fd = open(argv[1], O_RDONLY);
  if(fd<0){perror("open");return 1;}
  char buf[128]; ssize_t n=read(fd,buf,sizeof buf);
  if(n>0) write(1,buf,n);
  close(fd);
  return 0;
}
