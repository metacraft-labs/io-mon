// Thin client run UNDER io-mon. Sends a path to the daemon and prints the
// returned contents. The client itself never opens the target file.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc,char**argv){
  if(argc<3){fprintf(stderr,"usage: client <sockpath> <filepath>\n");return 2;}
  int s=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
  strncpy(a.sun_path,argv[1],sizeof(a.sun_path)-1);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  // send path
  dprintf(s,"%s\n",argv[2]);
  // read response (this influences our output -> proves dependency)
  char buf[8192]; ssize_t n; size_t tot=0; unsigned long h=5381;
  while((n=read(s,buf,sizeof buf))>0){ for(ssize_t i=0;i<n;i++) h=((h<<5)+h)+(unsigned char)buf[i]; tot+=n; }
  close(s);
  printf("CLIENT got %zu bytes hash=%lu from daemon for %s\n",tot,h,argv[2]);
  return 0;
}
