#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
int main(){ struct stat st;
  int dfd=open("/tmp/r3_fd",O_RDONLY|O_DIRECTORY); if(dfd<0)return 1;
  fstatat(dfd,"marker_fstat.txt",&st,0);
  close(dfd); return 0; }
