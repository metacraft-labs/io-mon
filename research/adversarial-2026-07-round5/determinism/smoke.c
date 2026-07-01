#include <stdio.h>
#include <stdlib.h>
int main(void){
  const char* h = getenv("HOME");
  FILE* f = fopen("/tmp/r5_determinism/smoke_out.txt","w");
  fprintf(f, "HOME=%s\n", h?h:"(null)");
  fclose(f);
  printf("done\n");
  return 0;
}
