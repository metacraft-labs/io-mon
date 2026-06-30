#include <fcntl.h>
#include <unistd.h>
int main(){
  int dfd=open("/tmp/r3_fd",O_RDONLY|O_DIRECTORY); if(dfd<0)return 1;
  int fd=openat(dfd,"out_oatw.txt",O_WRONLY|O_CREAT|O_TRUNC,0644); if(fd<0)return 2;
  write(fd,"OUTPUT_VIA_DIRFD\n",17);
  close(fd); close(dfd); return 0; }
