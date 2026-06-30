#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
int main(int argc,char**argv){
  const char* marker=argv[1];
  pid_t p1=fork();
  if(p1>0){ int st; waitpid(p1,&st,0); return 0; } // parent reaps first child
  setsid();
  pid_t p2=fork();
  if(p2>0){ _exit(0); } // first child exits -> grandchild reparented to launchd
  // grandchild (daemon): read marker then linger briefly then exit
  char b[64]; int fd=open(marker,O_RDONLY); if(fd>=0){read(fd,b,sizeof b);close(fd);}
  usleep(200000);
  _exit(0);
}
