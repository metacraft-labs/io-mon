#include <sys/time.h>
#include <stdio.h>
int main(void){struct timeval tv;gettimeofday(&tv,0);FILE*f=fopen("/tmp/r5_determinism/oc_gt.txt","w");fprintf(f,"%ld\n",tv.tv_sec);fclose(f);return 0;}
