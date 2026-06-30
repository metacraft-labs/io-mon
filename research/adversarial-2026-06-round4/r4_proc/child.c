#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
// argv[1]=marker path, argv[2]=exit-mode, optional argv[3]=inherited-fd number
int main(int argc, char**argv){
  const char* mode = argc>2?argv[2]:"exit";
  char b[64];
  if(argc>3){
    // read from an inherited fd (posix_spawn file-action open path)
    int fd = atoi(argv[3]);
    read(fd, b, sizeof b);
  } else {
    int fd = open(argv[1], O_RDONLY);
    if(fd>=0){ read(fd,b,sizeof b); /* do NOT close to mimic fast exit */ }
  }
  // Now exit as fast as possible per mode:
  if(!strcmp(mode,"_exit"))      _exit(0);
  else if(!strcmp(mode,"exit"))  exit(0);
  else if(!strcmp(mode,"abort")) abort();
  else if(!strcmp(mode,"segv"))  { raise(SIGSEGV); }
  else if(!strcmp(mode,"sigkill")) raise(SIGKILL);
  return 0;
}
