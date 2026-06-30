#include <stdio.h>
#include <stdlib.h>
int main(int argc, char**argv){
  FILE*f=fopen(argv[1],"rb"); if(!f){perror("open");return 1;}
  char buf[64]; size_t n=fread(buf,1,sizeof buf,f); fclose(f);
  printf("read %zu bytes\n", n);
  return 0;
}
