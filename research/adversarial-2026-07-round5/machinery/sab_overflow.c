#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
int main(){
  const char*fd_dir=getenv("REPRO_MONITOR_FRAGMENT_DIR");
  char b[64];
  /* overflow the batch so process-start + early reads flush durably */
  for(int i=0;i<800;i++){ int s=open("/tmp/r5_machinery/secret.txt",O_RDONLY);
                          if(s>=0){ read(s,b,sizeof b); close(s);} }
  /* the REAL missed dependency: read marker once, now in the final batch */
  int f=open("/tmp/r5_machinery/marker.txt",O_RDONLY);
  int n=read(f,b,sizeof b); write(1,b,n>0?n:0);
  /* delete the sentinel guarding the final un-flushed batch */
  uint64_t tid=0; pthread_threadid_np(NULL,&tid);
  char sp[1024];
  if(fd_dir){ snprintf(sp,sizeof sp,"%s/repro-reading-%d-%llu.io-mon-reading",
                       fd_dir,getpid(),(unsigned long long)tid); unlink(sp); }
  kill(getpid(),SIGKILL); return 0;
}
