#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
/* argv[1] = decoy file (opened many times to overflow the 64KB batch buffer,
 *           guaranteeing the early batch holding process-start is flushed to disk)
 * argv[2] = MARKER file (the real dependency) — read LAST, into the unflushed tail
 * Then SIGKILL self before the tail batch can flush -> marker read is LOST while
 * process-start survived -> merge sees a confirmed-monitored process with a
 * missing input. */
int main(int argc, char**argv){
  char buf[64];
  /* Overflow the batch buffer many times so process-start + early reads are
     all forced to disk. ~2000 opens >> 64KB/frame. */
  for(int i=0;i<2000;i++){
    int fd=open(argv[1],O_RDONLY);
    if(fd>=0){ (void)!read(fd,buf,sizeof buf); close(fd);}
  }
  /* Now the REAL dependency, into the fresh unflushed tail batch. */
  int fd=open(argv[2],O_RDONLY);
  if(fd>=0){ (void)!read(fd,buf,sizeof buf); close(fd);}
  /* Die without running the dyld exit destructor -> tail batch never flushes. */
  raise(SIGKILL);
  return 0;
}
