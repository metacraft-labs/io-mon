#include <fcntl.h>
#include <unistd.h>
int main(){ int fd=open("/tmp/r3_fd/out_normw.txt",O_WRONLY|O_CREAT|O_TRUNC,0644); if(fd<0)return 1; write(fd,"NORMAL_OUTPUT\n",14); close(fd); return 0; }
