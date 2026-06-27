#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(){
  // normal read input
  int fd = open("/tmp/r2_mmap/marker_in.txt", O_RDONLY);
  char buf[64]; read(fd, buf, sizeof buf); close(fd);
  // normal write output
  int fo = open("/tmp/r2_mmap/marker_out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
  write(fo, "hello\n", 6); close(fo);
  return 0;
}
