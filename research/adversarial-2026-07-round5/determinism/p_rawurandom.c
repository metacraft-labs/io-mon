#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
int main(void){
  // raw open syscall bypassing interposed open()
  int fd = syscall(SYS_open, "/dev/urandom", O_RDONLY, 0);
  unsigned char b[16];
  syscall(SYS_read, fd, b, sizeof b);
  syscall(SYS_close, fd);
  FILE* f=fopen("/tmp/r5_determinism/o_rawuran.txt","w");
  for(int i=0;i<16;i++) fprintf(f,"%02x",b[i]); fprintf(f,"\n"); fclose(f);
  return 0;
}
