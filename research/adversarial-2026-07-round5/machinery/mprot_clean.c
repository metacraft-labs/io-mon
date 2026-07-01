#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
int main(){
  int fd=open("/tmp/r5_machinery/inout.txt",O_RDWR);      /* O_RDWR -> input */
  char*p=mmap(0,16,PROT_READ,MAP_SHARED,fd,0);
  if(p==MAP_FAILED)return 2;
  if(mprotect(p,16,PROT_READ|PROT_WRITE)!=0)return 3;
  memcpy(p,"TAMPERED-OUTPUT!",16);                        /* invisible write */
  msync(p,16,MS_SYNC); munmap(p,16); close(fd); return 0;
}
