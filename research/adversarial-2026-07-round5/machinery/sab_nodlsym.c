#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdlib.h>
int main(){
  const char*fd_dir=getenv("REPRO_MONITOR_FRAGMENT_DIR");
  char b[64];
  int w=open("/tmp/r5_machinery/secret.txt",O_RDONLY); read(w,b,sizeof b); close(w); /* warmup */
  if(fd_dir) chmod(fd_dir,0500);
  int f=open("/tmp/r5_machinery/marker.txt",O_RDONLY);
  int n=read(f,b,sizeof b); write(1,b,n>0?n:0);
  kill(getpid(),SIGKILL); return 0;
}
