/* Lookup-only client: isolates io-mon's S0 exemption decision. Does a single
   bootstrap_look_up then writes a trivial output (so a clean injectable run). */
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc,char**argv){
  mach_port_t svc=MACH_PORT_NULL;
  kern_return_t kr=bootstrap_look_up(bootstrap_port,(char*)argv[1],&svc);
  fprintf(stderr,"[lookup] '%s' kr=%d port=%u\n",argv[1],kr,svc);
  int ofd=open(argv[2],O_CREAT|O_WRONLY|O_TRUNC,0644);
  dprintf(ofd,"looked-up %s -> port %u\n",argv[1],svc); close(ofd);
  return 0;
}
