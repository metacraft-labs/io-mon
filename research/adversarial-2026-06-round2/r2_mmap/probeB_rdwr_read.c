/* Attack 2 variant: O_RDWR open of an input, content read via plain read()
 * (so a file-read record DOES exist), but the OPEN is classified moFileWrite.
 * A "read-not-written" input filter excludes any file with a write observation,
 * dropping this genuine input. */
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(){
  int fd=open("/tmp/r2_mmap/rdwr_config.txt",O_RDWR);   /* lock-then-read idiom */
  char buf[128]; ssize_t n=read(fd,buf,sizeof buf); close(fd);
  long s=0; for(ssize_t i=0;i<n;i++) s+=(unsigned char)buf[i];
  int fo=open("/tmp/r2_mmap/rdwr_out.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
  char b[64]; int m=snprintf(b,sizeof b,"s=%ld\n",s); write(fo,b,m); close(fo);
  return 0;
}
