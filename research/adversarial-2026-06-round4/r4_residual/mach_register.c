/* Probe: can an unsigned process bootstrap_register / check_in a com.apple.* name? */
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <stdio.h>
int main(int argc,char**argv){
  const char*name=argv[1];
  mach_port_t port=MACH_PORT_NULL;
  kern_return_t kr=mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&port);
  if(kr){printf("port_alloc fail %d\n",kr);return 2;}
  mach_port_insert_right(mach_task_self(),port,port,MACH_MSG_TYPE_MAKE_SEND);
  kr=bootstrap_register(bootstrap_port,(char*)name,port);
  printf("bootstrap_register('%s') -> kr=%d (%s)\n",name,kr,
         kr==0?"SUCCESS-OWNS-NAME":(kr==1100?"NOT_PRIVILEGED":kr==1101?"NAME_IN_USE/SERVICE_UNKNOWN":"other"));
  if(kr==0){
    /* confirm we can be looked up */
    mach_port_t look=MACH_PORT_NULL;
    kern_return_t kr2=bootstrap_look_up(bootstrap_port,(char*)name,&look);
    printf("  bootstrap_look_up after register -> kr=%d port=%u\n",kr2,look);
  }
  return kr==0?0:1;
}
