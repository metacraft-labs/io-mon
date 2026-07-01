#include <unistd.h>
#include <stdio.h>
int main(void){
  pid_t p=getpid();
  FILE* f=fopen("/tmp/r5_determinism/o_getpid.txt","w");
  fprintf(f,"pid=%d\n",(int)p); fclose(f); return 0;
}
