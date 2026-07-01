#include <time.h>
#include <stdio.h>
int main(void){struct timespec ts;clock_gettime(CLOCK_REALTIME,&ts);FILE*f=fopen("/tmp/r5_determinism/oc_ck.txt","w");fprintf(f,"%ld\n",ts.tv_sec);fclose(f);return 0;}
