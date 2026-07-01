#include <unistd.h>
#include <stdio.h>
int main(void){
  long n=sysconf(_SC_NPROCESSORS_ONLN);
  FILE* f=fopen("/tmp/r5_determinism/o_sysconf.txt","w");
  fprintf(f,"ncpu=%ld\n",n); fclose(f); return 0;
}
