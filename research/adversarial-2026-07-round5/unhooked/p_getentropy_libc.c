#include <sys/random.h>
#include <stdio.h>
int main(void){unsigned char b[16]; if(getentropy(b,16))return 1;
 for(int i=0;i<16;i++)printf("%02x",b[i]); printf("\n"); return 0;}
