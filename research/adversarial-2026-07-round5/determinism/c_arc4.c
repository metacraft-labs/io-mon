#include <stdlib.h>
#include <stdio.h>
int main(void){uint32_t x=arc4random();FILE*f=fopen("/tmp/r5_determinism/oc_a4.txt","w");fprintf(f,"%u\n",x);fclose(f);return 0;}
