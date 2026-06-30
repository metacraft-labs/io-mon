#include <stdio.h>
#include <stdlib.h>
int main(){ FILE*f=fopen("/tmp/r3_residual/input.txt","r"); char b[64]; if(f){fgets(b,64,f);fclose(f);printf("read=%s",b);} return 0;}
