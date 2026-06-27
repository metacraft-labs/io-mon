/* Attack 2 (strongest): O_RDWR open of a CONFIG/INPUT file, content read via
 * mmap only (NO read() syscall, NO write()). The build output depends on the
 * file's content, but io-mon will (a) classify the open as moFileWrite and
 * (b) see no read at all -> the input is recorded purely as an OUTPUT. */
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
int main(){
  const char *cfg = "/tmp/r2_mmap/config_input.txt";
  int fd = open(cfg, O_RDWR);            /* defensive lock-then-read idiom */
  if (fd < 0){ perror("open"); return 1; }
  struct stat st; fstat(fd, &st);
  char *m = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED){ perror("mmap"); return 1; }
  /* "use" the content to drive an output */
  long sum=0; for (off_t i=0;i<st.st_size;i++) sum += (unsigned char)m[i];
  munmap(m, st.st_size);
  close(fd);
  /* produce an output whose value depends on the config content */
  int fo = open("/tmp/r2_mmap/derived_out.txt", O_WRONLY|O_CREAT|O_TRUNC,0644);
  char b[64]; int n=snprintf(b,sizeof b,"checksum=%ld\n",sum);
  write(fo,b,n); close(fo);
  return 0;
}
