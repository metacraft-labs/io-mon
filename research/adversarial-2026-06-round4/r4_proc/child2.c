#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
// argv[1]=marker path, argv[2]=mode, argv[3]=junk-read-count, argv[4]=junk file
int main(int argc,char**argv){
  const char* marker=argv[1]; const char* mode=argv[2];
  int K = argc>3?atoi(argv[3]):0; const char* junk=argc>4?argv[4]:"/tmp/r4_proc/junk.txt";
  char b[64];
  // Do K junk reads first to push process-start + early records past any flush threshold.
  for(int i=0;i<K;i++){ int fd=open(junk,O_RDONLY); if(fd>=0){read(fd,b,sizeof b);close(fd);} }
  // Now the UNIQUE marker read, as the very last buffered op:
  int fd=open(marker,O_RDONLY); if(fd>=0){ read(fd,b,sizeof b); }
  if(!strcmp(mode,"_exit")) _exit(0);
  else if(!strcmp(mode,"abort")) abort();
  else if(!strcmp(mode,"segv")) raise(SIGSEGV);
  exit(0);
}
