#include <stdio.h>
int main(int argc, char**argv){
  FILE*f=fopen(argv[1],"r");
  if(!f){perror("fopen");return 1;}
  char b[256]; size_t n=fread(b,1,sizeof b-1,f); b[n]=0; fclose(f);
  printf("baseline read: %s",b);
  return 0;
}
