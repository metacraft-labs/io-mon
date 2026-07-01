#include <sys/random.h>
#include <stdio.h>
int main(void){unsigned char b[16];getentropy(b,sizeof b);
FILE*f=fopen("/tmp/r5_determinism/oc_ge.txt","w");for(int i=0;i<16;i++)fprintf(f,"%02x",b[i]);fclose(f);return 0;}
