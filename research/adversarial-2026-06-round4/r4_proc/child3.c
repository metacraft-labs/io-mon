#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
// argv[1]=marker argv[2]=junkcount argv[3]=junkfile argv[4]=mode(_exit/exit)
// Worker thread: flush process-start with junk reads, then read UNIQUE marker last.
// Main thread: _exit immediately after worker signals it has issued the marker read.
static atomic_int did_read = 0;
static const char* g_marker; static int g_K; static const char* g_junk;
static void* worker(void* a){
  char b[64];
  for(int i=0;i<g_K;i++){ int fd=open(g_junk,O_RDONLY); if(fd>=0){read(fd,b,sizeof b);close(fd);} }
  int fd=open(g_marker,O_RDONLY); if(fd>=0){ read(fd,b,sizeof b); }
  atomic_store(&did_read,1);
  for(;;) pause(); // keep worker alive; main will _exit
  return 0;
}
int main(int argc,char**argv){
  g_marker=argv[1]; g_K=argc>2?atoi(argv[2]):1500; g_junk=argc>3?argv[3]:"/tmp/r4_proc/junk.txt";
  const char* mode=argc>4?argv[4]:"_exit";
  pthread_t t; pthread_create(&t,0,worker,0);
  while(!atomic_load(&did_read)) {}
  // main thread exits; worker's sentinel (different thread) holds the in-flight marker read
  if(!strcmp(mode,"_exit")) _exit(0);
  exit(0);
}
