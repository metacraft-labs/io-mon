#include <unistd.h>
#include <stdio.h>
int main(void){
  char buf[256];
  size_t n=confstr(_CS_PATH, buf, sizeof buf);
  FILE* f=fopen("/tmp/r5_determinism/o_confstr.txt","w");
  fprintf(f,"n=%zu path=%s\n",n,buf); fclose(f); return 0;
}
