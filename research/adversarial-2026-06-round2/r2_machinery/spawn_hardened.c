#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;
int main(int argc,char**argv){
  char *args[]={argv[1],argv[2],NULL};
  pid_t pid=0;
  int rc=posix_spawn(&pid,argv[1],NULL,NULL,args,environ);
  if(rc!=0){printf("spawn rc=%d\n",rc);return 1;}
  int st; waitpid(pid,&st,0);
  printf("SPAWNER child pid=%d\n",(int)pid);
  return 0;
}
