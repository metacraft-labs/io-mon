#include "peer_common.h"
#include <sys/mman.h>
#include <sys/stat.h>
int main(void){
  int fd=atoi(getenv("INHERITED_FD"));
  struct stat st; fstat(fd,&st);
  size_t len=st.st_size>0?(size_t)st.st_size:64;
  void*p=mmap(NULL,len,PROT_READ,MAP_PRIVATE,fd,0);
  if(p==MAP_FAILED){perror("mmap");return 1;}
  write(1,"CLIENT-MMAP: ",13); write(1,p,len);
  return 0;
}
