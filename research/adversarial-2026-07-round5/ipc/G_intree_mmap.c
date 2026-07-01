#include "peer_common.h"
#include <sys/mman.h>
#include <sys/stat.h>
int main(int argc,char**argv){
  int fd=open(argv[1],O_RDONLY);
  struct stat st; fstat(fd,&st); size_t len=st.st_size>0?(size_t)st.st_size:64;
  void*p=mmap(NULL,len,PROT_READ,MAP_PRIVATE,fd,0);
  write(1,"IM: ",4); write(1,p,len); return 0; }
