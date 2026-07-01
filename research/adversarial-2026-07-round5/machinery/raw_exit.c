#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(){
  char b[64]; int f=open("/tmp/r5_machinery/marker.txt",O_RDONLY);
  int n=read(f,b,sizeof b); write(1,b,n>0?n:0);
  syscall(SYS_exit,0); return 0;
}
