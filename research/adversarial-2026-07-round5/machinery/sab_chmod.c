#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <stdlib.h>
typedef int (*flush_fn)(void);
int main(){
  const char*fd_dir=getenv("REPRO_MONITOR_FRAGMENT_DIR");
  flush_fn flush=(flush_fn)dlsym(RTLD_DEFAULT,"repro_monitor_shim_flush");
  if(flush) flush();                 /* process-start batch -> durable, sentinel cleared */
  if(fd_dir) chmod(fd_dir,0500);     /* dir unwritable: sentinel writeFile() will fail */
  char b[64]; int f=open("/tmp/r5_machinery/marker.txt",O_RDONLY);
  int n=read(f,b,sizeof b); write(1,b,n>0?n:0);   /* buffered read, sentinel create fails */
  kill(getpid(),SIGKILL);            /* no flush, no sentinel */
  return 0;
}
