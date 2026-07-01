#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
int main(void){
  CFAbsoluteTime t=CFAbsoluteTimeGetCurrent();
  FILE* f=fopen("/tmp/r5_determinism/o_cftime.txt","w");
  fprintf(f,"%f\n",t); fclose(f); return 0;
}
