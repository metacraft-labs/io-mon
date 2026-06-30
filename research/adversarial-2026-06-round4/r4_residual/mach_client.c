/* MONITORED client: look up the com.apple.* service, request content, BAKE it
   into the build output. The served content is a real build input. */
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
typedef struct { mach_msg_header_t h; char data[512]; } msg_t;
int main(int argc,char**argv){
  const char*name=argv[1]; const char*out=argv[2];
  mach_port_t svc=MACH_PORT_NULL;
  kern_return_t kr=bootstrap_look_up(bootstrap_port,(char*)name,&svc);
  fprintf(stderr,"[client] look_up('%s') kr=%d port=%u\n",name,kr,svc);
  if(kr||svc==MACH_PORT_NULL) return 1;
  mach_port_t reply;
  mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&reply);
  msg_t req; memset(&req,0,sizeof req);
  req.h.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,MACH_MSG_TYPE_MAKE_SEND_ONCE);
  req.h.msgh_remote_port=svc; req.h.msgh_local_port=reply; req.h.msgh_size=sizeof req;
  if(mach_msg(&req.h,MACH_SEND_MSG,sizeof req,0,MACH_PORT_NULL,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL)) return 2;
  msg_t rep; memset(&rep,0,sizeof rep); rep.h.msgh_local_port=reply; rep.h.msgh_size=sizeof rep;
  if(mach_msg(&rep.h,MACH_RCV_MSG,0,sizeof rep,reply,5000,MACH_PORT_NULL)) return 3;
  int ofd=open(out,O_CREAT|O_WRONLY|O_TRUNC,0644);
  dprintf(ofd,"output-derived-from-mach-service: %s\n",rep.data);
  close(ofd);
  fprintf(stderr,"[client] baked served content into %s\n",out);
  return 0;
}
