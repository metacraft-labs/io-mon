/* MONITORED client: read a build-relevant marker from an INHERITED fd (a pipe
   read-end set up by an out-of-tree parent) and bake it into the output. */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc,char**argv){
  int rfd=atoi(argv[1]); const char*out=argv[2];
  char buf[256]; ssize_t n=read(rfd,buf,sizeof buf-1);
  if(n<=0){fprintf(stderr,"[client] read inherited fd %d failed n=%zd\n",rfd,n);return 1;}
  buf[n]=0;
  int ofd=open(out,O_CREAT|O_WRONLY|O_TRUNC,0644);
  dprintf(ofd,"output-from-inherited-pipe: %s",buf); close(ofd);
  fprintf(stderr,"[client] read '%s' from inherited fd %d\n",buf,rfd);
  return 0;
}
