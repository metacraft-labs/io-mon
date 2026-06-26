#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
extern char**environ;
int main(int argc,char**argv){
  char*child[]={argv[1],argv[2],NULL};
  pid_t pid; int rc=posix_spawn(&pid,argv[1],NULL,NULL,child,environ);
  if(rc){fprintf(stderr,"spawn rc=%d\n",rc);return 1;}
  int st; waitpid(pid,&st,0); return 0;
}
