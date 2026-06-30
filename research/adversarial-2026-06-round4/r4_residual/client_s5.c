/* MONITORED client: connect to out-of-tree daemon (observed -> would downgrade),
   receive served content, bake into output, then FORGE a breakaway report via a
   RAW write(2) (mode=raw) or a normal hooked write (mode=hooked, control). */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef SOL_LOCAL
#define SOL_LOCAL 0
#endif
#ifndef LOCAL_PEERPID
#define LOCAL_PEERPID 0x002
#endif
int main(int argc,char**argv){
  const char*sockpath=argv[1]; const char*out=argv[2]; const char*reportdir=argv[3];
  const char*mode=argv[4]; /* raw | hooked | none */
  int s=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
  strncpy(a.sun_path,sockpath,sizeof a.sun_path-1);
  if(connect(s,(struct sockaddr*)&a,sizeof a)){perror("connect");return 2;}
  /* peer (daemon) pid */
  pid_t peer=0; socklen_t pl=sizeof peer; getsockopt(s,SOL_LOCAL,LOCAL_PEERPID,&peer,&pl);
  char content[400]={0}; ssize_t n=read(s,content,sizeof content-1); if(n<0)n=0; content[n]=0; close(s);
  int ofd=open(out,O_CREAT|O_WRONLY|O_TRUNC,0644); dprintf(ofd,"output-from-daemon: %s\n",content); close(ofd);
  fprintf(stderr,"[client] pid=%d peer=%d served='%s' mode=%s\n",getpid(),peer,content,mode);
  if(strcmp(mode,"none")==0) return 0;
  /* forge a breakaway report that OMITS the served file, lists a decoy read */
  const char*session=getenv("REPRO_MONITOR_SESSION"); if(!session)session="";
  char report[1024];
  int rl=snprintf(report,sizeof report,
    "io-mon-breakaway-report v1\nrun %s\nclient %d\ndaemon %d\nread /tmp/r4_residual/decoy_input.txt\ncomplete\n",
    session,getpid(),peer);
  char rpath[512]; snprintf(rpath,sizeof rpath,"%s/forged.io-mon-report",reportdir);
  if(strcmp(mode,"raw")==0){
    /* RAW syscalls bypass the interposed libsystem open/write -> no moFileWrite record */
    int fd=syscall(SYS_open,rpath,O_CREAT|O_WRONLY|O_TRUNC,0644);
    if(fd<0){perror("raw open");return 3;}
    syscall(SYS_write,fd,report,rl);
    syscall(SYS_close,fd);
    fprintf(stderr,"[client] forged report via RAW write(2) -> %s\n",rpath);
  }else{ /* hooked: normal libsystem write -> recorded as in-tree output -> rejected */
    int fd=open(rpath,O_CREAT|O_WRONLY|O_TRUNC,0644);
    write(fd,report,rl); close(fd);
    fprintf(stderr,"[client] forged report via HOOKED write -> %s\n",rpath);
  }
  return 0;
}
