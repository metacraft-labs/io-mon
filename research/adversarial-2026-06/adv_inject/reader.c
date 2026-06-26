#include <stdio.h>
#include <stdlib.h>
int main(int argc, char**argv){
  const char*p = argc>1?argv[1]:"/tmp/adv_inject/marker_baseline.txt";
  FILE*f=fopen(p,"r"); if(!f){perror("fopen");return 1;}
  char buf[256]; size_t n=fread(buf,1,sizeof buf-1,f); buf[n]=0; fclose(f);
  printf("[reader] read %s => %s", p, buf);
  return 0;
}
