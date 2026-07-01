#include <sys/resource.h>
#include <stdio.h>
int main(void){
  struct rlimit rl;
  getrlimit(RLIMIT_NOFILE,&rl);
  FILE* f=fopen("/tmp/r5_determinism/o_rlimit.txt","w");
  fprintf(f,"cur=%llu\n",(unsigned long long)rl.rlim_cur); fclose(f); return 0;
}
