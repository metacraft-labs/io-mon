#include <time.h>
#include <stdio.h>
int main(void){time_t t=time(0);FILE*f=fopen("/tmp/r5_determinism/oc_ti.txt","w");fprintf(f,"%ld\n",(long)t);fclose(f);return 0;}
