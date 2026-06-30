#include <fcntl.h>
#include <unistd.h>
int main(){
  char b[64];
  int fd = open("/tmp/r3_fd/marker_base.txt", O_RDONLY);
  if (fd<0) return 1;
  read(fd, b, sizeof b);
  close(fd);
  return 0;
}
