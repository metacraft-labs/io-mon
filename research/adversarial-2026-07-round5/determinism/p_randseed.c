#include <mach/mach_time.h>
#include <stdlib.h>
#include <stdio.h>
int main(void){
  srand((unsigned)mach_absolute_time());
  int r=rand();
  FILE* f=fopen("/tmp/r5_determinism/o_randseed.txt","w");
  fprintf(f,"%d\n",r); fclose(f); return 0;
}
