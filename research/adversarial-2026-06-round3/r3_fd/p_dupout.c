#include <fcntl.h>
#include <unistd.h>
int main(){
  int fd=open("/tmp/r3_fd/out_dup.txt",O_WRONLY|O_CREAT|O_TRUNC,0644); if(fd<0)return 1;
  int fd2=dup(fd);                 // dup the OUTPUT fd
  write(fd2,"INVISIBLE_OUTPUT\n",17); // write via dup'd fd
  close(fd2); close(fd); return 0; }
