#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
int main(void){
  unsigned char b[16];
  // SYS_getentropy on macOS
  long r = syscall(SYS_getentropy, b, sizeof b);
  FILE* f=fopen("/tmp/r5_determinism/o_rawge.txt","w");
  fprintf(f,"r=%ld ",r);
  for(int i=0;i<16;i++) fprintf(f,"%02x",b[i]);
  fprintf(f,"\n"); fclose(f);
  return 0;
}
