#include <stdio.h>
#include <dlfcn.h>
int main(int argc,char**argv){
  void*h=dlopen(argv[1],RTLD_NOW);
  if(!h){fprintf(stderr,"dlopen fail: %s\n",dlerror());return 1;}
  int(*f)(void)=(int(*)(void))dlsym(h,"dep_value");
  printf("dep_value=%d\n",f?f():-1);
  return 0;
}
