#include <sys/syscall.h>
#include "probe_common.h"
int main(void){
  unsigned char b[16];
  long r=raw6(SYS_getentropy,(long)b,sizeof b,0,0,0,0);
  if(r<0)return 1;
  for(int i=0;i<16;i++)printf("%02x",b[i]);
  printf("\n");
  return 0;
}
