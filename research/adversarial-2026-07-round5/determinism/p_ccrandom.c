#include <stdio.h>
extern int CCRandomGenerateBytes(void* bytes, size_t count);
int main(void){
  unsigned char b[16];
  CCRandomGenerateBytes(b, sizeof b);
  FILE* f=fopen("/tmp/r5_determinism/o_ccrandom.txt","w");
  for(int i=0;i<16;i++) fprintf(f,"%02x",b[i]);
  fprintf(f,"\n"); fclose(f);
  return 0;
}
