#include <Security/SecRandom.h>
#include <stdio.h>
int main(void){
  unsigned char b[16];
  SecRandomCopyBytes(kSecRandomDefault, sizeof b, b);
  FILE* f=fopen("/tmp/r5_determinism/o_secrandom.txt","w");
  for(int i=0;i<16;i++) fprintf(f,"%02x",b[i]);
  fprintf(f,"\n"); fclose(f);
  return 0;
}
