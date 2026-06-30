#include <stdio.h>
#include <stdlib.h>
int main(int argc,char**argv){
  for(int i=0;i<5000;i++){
    char p[600]; snprintf(p,sizeof p,"%s/f_%d.txt",argv[1],i);
    FILE*f=fopen(p,"rb"); if(f){char b[16]; size_t n=fread(b,1,sizeof b,f);(void)n; fclose(f);}
  }
  return 0;
}
