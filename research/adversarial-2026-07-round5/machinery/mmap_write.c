#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
int main(){
  int fd=open("/tmp/r5_machinery/out_mmap.bin",O_RDWR|O_CREAT|O_TRUNC,0644);
  ftruncate(fd,32);
  char*p=mmap(0,32,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if(p==MAP_FAILED)return 2;
  memcpy(p,"MMAP-WRITTEN-CONTENT-1234567890",31);
  msync(p,32,MS_SYNC); munmap(p,32); close(fd); return 0;
}
