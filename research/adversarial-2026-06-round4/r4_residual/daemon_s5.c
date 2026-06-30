/* OUT-OF-TREE AF_UNIX daemon: serve served file content to any client. */
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char**argv){
  const char*sockpath=argv[1]; const char*srvfile=argv[2];
  unlink(sockpath);
  int s=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
  strncpy(a.sun_path,sockpath,sizeof a.sun_path-1);
  if(bind(s,(struct sockaddr*)&a,sizeof a)){perror("bind");return 2;}
  listen(s,8);
  int rf=open("/tmp/r4_residual/s5_ready",O_CREAT|O_WRONLY|O_TRUNC,0644); close(rf);
  for(;;){
    int c=accept(s,0,0); if(c<0)continue;
    char content[400]={0};
    int fd=open(srvfile,O_RDONLY); ssize_t n=fd>=0?read(fd,content,sizeof content-1):0; if(n<0)n=0; content[n]=0; if(fd>=0)close(fd);
    write(c,content,strlen(content));
    close(c);
  }
}
