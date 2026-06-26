// Persistent file-reading daemon. Started OUTSIDE io-mon. Listens on a unix
// socket; for each connection, reads a newline-terminated path and returns the
// file's contents. Models a build/compiler server (sccache, gradle daemon...).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: daemon <sockpath>\n");return 2;}
  unlink(argv[1]);
  int s=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
  strncpy(a.sun_path,argv[1],sizeof(a.sun_path)-1);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  if(listen(s,16)<0){perror("listen");return 1;}
  fprintf(stderr,"daemon: listening on %s pid=%d\n",argv[1],getpid());
  // signal readiness
  FILE*rf=fopen("/tmp/adv_proctree/daemon.ready","w"); if(rf){fprintf(rf,"%d\n",getpid());fclose(rf);}
  for(;;){
    int c=accept(s,NULL,NULL);
    if(c<0)continue;
    char path[4096]; int pl=0; char ch;
    while(pl<(int)sizeof(path)-1 && read(c,&ch,1)==1){ if(ch=='\n')break; path[pl++]=ch; }
    path[pl]=0;
    if(strcmp(path,"__QUIT__")==0){close(c);break;}
    // THE FILE READ HAPPENS HERE, in the daemon, outside the monitored tree.
    FILE*f=fopen(path,"rb");
    if(!f){ const char*e="ERR\n"; write(c,e,4); close(c); continue; }
    char buf[8192]; size_t n;
    while((n=fread(buf,1,sizeof buf,f))>0){ if(write(c,buf,n)<0)break; }
    fclose(f); close(c);
  }
  close(s); unlink(argv[1]);
  return 0;
}
