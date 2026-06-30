/* OUT-OF-TREE launcher: create a pipe, feed a marker, clear CLOEXEC on the read
   end, then exec io-mon so the monitored client inherits the pipe read fd. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
int main(int argc,char**argv){
  /* argv: io-mon depfile client out marker */
  int p[2]; if(pipe(p)){perror("pipe");return 2;}
  const char*marker=argv[5];
  write(p[1],marker,strlen(marker)); close(p[1]);
  fcntl(p[0],F_SETFD,fcntl(p[0],F_GETFD)&~FD_CLOEXEC);  /* keep across exec */
  char rfd[16]; snprintf(rfd,sizeof rfd,"%d",p[0]);
  /* exec: io-mon run --depfile <depfile> -- <client> <rfd> <out> */
  execl(argv[1],"io-mon","run","--depfile",argv[2],"--",argv[3],rfd,argv[4],(char*)NULL);
  perror("execl"); return 3;
}
