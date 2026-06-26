#include <stdio.h>
#include <stdlib.h>
int main(int argc, char**argv){
  if(argc<2){fprintf(stderr,"usage\n");return 2;}
  FILE*f=fopen(argv[1],"rb");
  if(!f){perror("fopen");return 1;}
  char buf[4096]; size_t n; size_t tot=0;
  while((n=fread(buf,1,sizeof buf,f))>0){tot+=n;}
  fclose(f);
  printf("READ %zu bytes from %s\n",tot,argv[1]);
  return 0;
}
