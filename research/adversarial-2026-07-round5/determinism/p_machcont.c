#include <mach/mach_time.h>
#include <stdio.h>
int main(void){
  uint64_t t = mach_continuous_time();
  FILE* f=fopen("/tmp/r5_determinism/o_machcont.txt","w");
  fprintf(f,"%llu\n",(unsigned long long)t); fclose(f);
  return 0;
}
