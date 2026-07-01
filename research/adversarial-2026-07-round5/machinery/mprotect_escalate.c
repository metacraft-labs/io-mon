#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
int main(){
  int fd=open("/tmp/r5_machinery/out_mprot.bin",O_RDWR|O_CREAT|O_TRUNC,0644);
  ftruncate(fd,32);
  char*p=mmap(0,32,PROT_READ,MAP_SHARED,fd,0);   /* read-only at mmap time */
  if(p==MAP_FAILED)return 2;
  if(mprotect(p,32,PROT_READ|PROT_WRITE)!=0)return 3;
  memcpy(p,"ESCALATED-INVISIBLE-WRITE-12345",31);  /* invisible content write */
  msync(p,32,MS_SYNC); munmap(p,32); close(fd); return 0;
}
