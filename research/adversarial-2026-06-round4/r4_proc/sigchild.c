#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
static const char* g_marker; static atomic_int done=0;
static void handler(int s){
  char b[64]; int fd=open(g_marker,O_RDONLY); if(fd>=0){read(fd,b,sizeof b);close(fd);}
  atomic_store(&done,1);
}
int main(int argc,char**argv){
  g_marker=argv[1]; const char* mode=argc>2?argv[2]:"_exit";
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=handler; sigaction(SIGUSR1,&sa,0);
  raise(SIGUSR1);
  while(!atomic_load(&done)){}
  if(!strcmp(mode,"_exit")) _exit(0);
  if(!strcmp(mode,"abort")) abort();
  exit(0);
}
