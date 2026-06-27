#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <stdio.h>
int main(){
  mach_port_t p=MACH_PORT_NULL;
  kern_return_t kr=mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&p);
  printf("allocate kr=%d\n",kr);
  kr=mach_port_insert_right(mach_task_self(),p,p,MACH_MSG_TYPE_MAKE_SEND);
  printf("insert kr=%d\n",kr);
  kr=bootstrap_register(bootstrap_port,"com.example.r2xpc.machreg",p);
  printf("bootstrap_register kr=%d (0=success)\n",kr);
  return 0;
}
