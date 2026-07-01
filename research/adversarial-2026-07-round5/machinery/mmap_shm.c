#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(){
  const char*n="/r5_shm_obj";
  int fd=shm_open(n,O_CREAT|O_RDWR,0644);
  if(fd<0){perror("shm_open c");return 2;}
  ftruncate(fd,64);
  char*w=mmap(0,64,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  memcpy(w,"SHM-PAYLOAD",11); munmap(w,64);
  int rfd=shm_open(n,O_RDWR,0644);           /* attach side (no O_CREAT) */
  char*r=mmap(0,64,PROT_READ,MAP_SHARED,rfd,0);
  volatile char c=r[0]; (void)c;
  munmap(r,64); close(rfd); close(fd); shm_unlink(n); return 0;
}
