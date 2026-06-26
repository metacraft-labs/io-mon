// vfork + execv of a SIP-protected binary (/bin/cat). io-mon does NOT hook
// vfork, and the kernel strips DYLD_INSERT_LIBRARIES when exec'ing a SIP
// binary -- so unless the spawn path re-injects via SIP-rewrite, the child
// escapes. We exec /bin/cat to read the marker.
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: vfork_exec <path>\n");return 2;}
  pid_t p=vfork();
  if(p==0){
    char*av[]={"/bin/cat",argv[1],NULL};
    execv("/bin/cat",av);
    _exit(127);
  }
  int st; waitpid(p,&st,0);
  return 0;
}
