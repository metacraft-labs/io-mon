#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc,char**argv){
  // read a regular file (should be captured)
  int fd=open(argv[1],O_RDONLY); char b[64]; read(fd,b,16); close(fd);
  // read /dev/urandom (a file open - captured? but nondeterministic content)
  int u=open("/dev/urandom",O_RDONLY); unsigned char r[4]; read(u,r,4); close(u);
  printf("urandom=%02x%02x%02x%02x\n",r[0],r[1],r[2],r[3]);
  return 0;
}
