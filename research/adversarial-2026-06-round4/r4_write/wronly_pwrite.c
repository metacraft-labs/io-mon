#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv){
  int fd = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0644); // -> moFileWrite at OPEN
  const char *s="OUT-VIA-PWRITE\n";
  pwrite(fd, s, strlen(s), 0);   // content not hooked, but open already = write
  close(fd);
  return 0;
}
