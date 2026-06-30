/* Same entropy draw, but via dlopen AFTER startup (the res1 threat that IS flagged). */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
int main(int argc,char**argv){
  void*h=dlopen("/tmp/r4_residual/libentropy.dylib",RTLD_NOW);
  if(!h){fprintf(stderr,"dlopen fail: %s\n",dlerror());return 1;}
  unsigned(*f)(void)=(unsigned(*)(void))dlsym(h,"draw_entropy");
  unsigned r=f();
  int fd=open(argv[1],O_CREAT|O_WRONLY|O_TRUNC,0644);
  dprintf(fd,"nondeterministic-output: %u\n",r); close(fd);
  return 0;
}
