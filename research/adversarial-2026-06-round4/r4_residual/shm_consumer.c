/* MONITORED consumer: attach the shm object read-only, read the marker via a
   plain memory load (no read(2)), and BAKE it into its build output file. */
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char**argv){
  const char*name=argv[1]; const char*out=argv[2];
  int fd=shm_open(name,O_RDONLY,0);
  if(fd<0){perror("shm_open");return 1;}
  void*p=mmap(0,4096,PROT_READ,MAP_SHARED,fd,0);
  if(p==MAP_FAILED){perror("mmap");return 1;}
  char marker[256]; strncpy(marker,(const char*)p,255); marker[255]=0;
  /* output depends entirely on the shm content -> non-reproducible if missed */
  int ofd=open(out,O_CREAT|O_WRONLY|O_TRUNC,0644);
  dprintf(ofd,"output-derived-from: %s\n",marker);
  close(ofd); munmap(p,4096); close(fd);
  fprintf(stderr,"consumer baked '%s' into %s\n",marker,out);
  return 0;
}
