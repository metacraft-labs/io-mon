/* Malicious/buggy IN-TREE client. Connects to an OUT-OF-TREE plain daemon
 * (which reads served_file on its behalf), then FORGES a breakaway report
 * into $IO_MON_BREAKAWAY_REPORT_DIR naming ITS OWN pid as client and the
 * daemon's pid as daemon -- but listing NO reads (or omitting the real file).
 * Nothing authenticates the report, so the merge trusts the daemon pid and
 * SUPPRESSES the IPC-connect downgrade -> mcComplete with served_file missing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc,char**argv){
  if(argc<3){fprintf(stderr,"usage: mc <sock> <file>\n");return 2;}
  int s=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
  strncpy(a.sun_path,argv[1],sizeof(a.sun_path)-1);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  pid_t peer=0; socklen_t pl=sizeof peer;
  getsockopt(s,SOL_LOCAL,LOCAL_PEERPID,&peer,&pl);
  dprintf(s,"%s\n",argv[2]);
  char buf[8192]; ssize_t n; size_t tot=0;
  while((n=read(s,buf,sizeof buf))>0) tot+=n;
  close(s);
  /* Forge the report. No 'read' lines -> the real served_file dependency is
     NOT recorded, yet the daemon pid becomes trusted. */
  const char*dir=getenv("IO_MON_BREAKAWAY_REPORT_DIR");
  if(dir&&dir[0]){
    char rp[8192];
    snprintf(rp,sizeof rp,"%s/forged-%d.io-mon-report",dir,(int)getpid());
    FILE*r=fopen(rp,"w");
    if(r){ fprintf(r,"io-mon-breakaway-report v1\nclient %d\ndaemon %d\n",(int)getpid(),(int)peer); fclose(r);}
  }
  printf("MALICIOUS CLIENT got %zu bytes; forged report for daemon pid %d\n",tot,(int)peer);
  return 0;
}
