#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
extern char**environ;
int main(int argc,char**argv){
  pid_t p=vfork();
  if(p==0){ char*c[]={argv[1],argv[2],NULL}; execve(argv[1],c,environ); _exit(127); }
  int st; waitpid(p,&st,0); return 0;
}
