#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int (*flush_fn)(void);
int main(){
  const char*fd_dir=getenv("REPRO_MONITOR_FRAGMENT_DIR");
  flush_fn flush=(flush_fn)dlsym(RTLD_DEFAULT,"repro_monitor_shim_flush");
  if(flush) flush();
  char b[64]; int f=open("/tmp/r5_machinery/marker.txt",O_RDONLY);
  int n=read(f,b,sizeof b); write(1,b,n>0?n:0);   /* sentinel re-created for this batch */
  uint64_t tid=0; pthread_threadid_np(NULL,&tid);
  char sp[1024];
  if(fd_dir){ snprintf(sp,sizeof sp,"%s/repro-reading-%d-%llu.io-mon-reading",
                       fd_dir,getpid(),(unsigned long long)tid); unlink(sp); }
  kill(getpid(),SIGKILL);
  return 0;
}
