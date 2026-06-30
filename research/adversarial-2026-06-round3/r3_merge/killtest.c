/* Main thread reads a marker (buffered in the 64KB batch, NOT flushed since
 * main-thread batches until exit/100ms), then SIGKILLs itself immediately.
 * The read's bytes are lost unless flushed; R5 sentinel should force mcIncomplete.
 * BREAK = marker absent AND mcComplete. */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
int main(int argc,char**argv){
  char p[600]; snprintf(p,sizeof p,"%s/killmarker.txt",argv[1]);
  FILE*f=fopen(p,"rb"); if(f){char b[64]; size_t n=fread(b,1,sizeof b,f);(void)n; fclose(f);}
  raise(SIGKILL);   /* uncatchable: no dyld destructor, no flush */
  return 0;
}
