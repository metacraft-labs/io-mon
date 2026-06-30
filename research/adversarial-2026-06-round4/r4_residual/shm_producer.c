/* OUT-OF-TREE producer: create a POSIX shm object under the Apple system
   namespace and write a build-relevant marker into it, then exit (the shm
   object persists until shm_unlink). */
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(int argc,char**argv){
  const char*name=argv[1]; const char*marker=argv[2];
  int fd=shm_open(name,O_CREAT|O_RDWR,0600);
  if(fd<0){perror("shm_open");return 1;}
  ftruncate(fd,4096);
  void*p=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if(p==MAP_FAILED){perror("mmap");return 1;}
  strncpy((char*)p,marker,4095);
  munmap(p,4096); close(fd);
  fprintf(stderr,"producer wrote '%s' to shm '%s'\n",marker,name);
  return 0;
}
