// Simplest realistic form: launcher (out of tree) opens the marker and leaves the
// fd OPEN across exec into the monitored client (fd inheritance). No peer, no
// SCM_RIGHTS. Client mmaps the inherited fd. Does the dependency escape?
#include "peer_common.h"
int main(int argc,char**argv){
  const char* marker=argv[1]; const char* iomon=argv[2];
  const char* depfile=argv[3]; const char* client=argv[4];
  int fd=open(marker,O_RDONLY);              // out-of-tree open
  char fb[16]; snprintf(fb,sizeof fb,"%d",fd); setenv("INHERITED_FD",fb,1);
  execl(iomon,iomon,"run","--depfile",depfile,"--",client,(char*)NULL);
  perror("execl"); return 1;
}
