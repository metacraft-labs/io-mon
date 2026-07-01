#include <sys/sysctl.h>
#include <stdio.h>
int main(void){int n;size_t s=sizeof n;sysctlbyname("hw.ncpu",&n,&s,0,0);FILE*f=fopen("/tmp/r5_determinism/oc_sc.txt","w");fprintf(f,"%d\n",n);fclose(f);return 0;}
