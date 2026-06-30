/* OUT-OF-TREE daemon: register a com.apple.* MachService name and serve the
   contents of a file in reply to any request. Simulates an attacker-controlled
   service the build's monitored client depends on. */
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

typedef struct { mach_msg_header_t h; char data[512]; } msg_t;

int main(int argc,char**argv){
  const char*name=argv[1]; const char*srvfile=argv[2];
  mach_port_t port;
  if(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&port)) return 2;
  mach_port_insert_right(mach_task_self(),port,port,MACH_MSG_TYPE_MAKE_SEND);
  kern_return_t kr=bootstrap_register(bootstrap_port,(char*)name,port);
  fprintf(stderr,"[daemon] register('%s') kr=%d\n",name,kr);
  if(kr){return 1;}
  /* signal readiness */
  int rf=open("/tmp/r4_residual/daemon_ready",O_CREAT|O_WRONLY|O_TRUNC,0644); close(rf);
  for(;;){
    msg_t req; memset(&req,0,sizeof req);
    req.h.msgh_local_port=port; req.h.msgh_size=sizeof req;
    kr=mach_msg(&req.h,MACH_RCV_MSG,0,sizeof req,port,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL);
    if(kr) continue;
    mach_port_t reply=req.h.msgh_remote_port;
    if(reply==MACH_PORT_NULL) continue;
    /* read the served file fresh each time */
    char content[400]={0};
    int fd=open(srvfile,O_RDONLY); if(fd>=0){ssize_t n=read(fd,content,sizeof content-1); if(n<0)n=0; content[n]=0; close(fd);}
    msg_t rep; memset(&rep,0,sizeof rep);
    rep.h.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE,0);
    rep.h.msgh_remote_port=reply; rep.h.msgh_local_port=MACH_PORT_NULL;
    rep.h.msgh_size=sizeof rep;
    strncpy(rep.data,content,sizeof rep.data-1);
    mach_msg(&rep.h,MACH_SEND_MSG,sizeof rep,0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL);
  }
}
